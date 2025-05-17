import logging
import ldap
from celery import shared_task
from django.contrib.auth.models import User
from django.db import transaction
from django.utils import timezone
from .models import LDAPConfig, Profile, Organization, Team, Role, UserRole

logger = logging.getLogger(__name__)

@shared_task
def sync_ldap_users(config_id):
    """
    Perform synchronization with LDAP/AD server for a specific configuration.
    
    Args:
        config_id: UUID of the LDAPConfig to synchronize
    """
    try:
        # Get the LDAP configuration
        try:
            ldap_config = LDAPConfig.objects.get(config_id=config_id)
        except LDAPConfig.DoesNotExist:
            logger.error(f"LDAP configuration with ID {config_id} not found.")
            return False
        
        # Initialize stats
        stats = {
            'users_created': 0,
            'users_updated': 0,
            'users_deactivated': 0,
            'errors': 0
        }
        
        # Update status to PENDING if not already
        if ldap_config.last_sync_status != 'PENDING':
            ldap_config.last_sync_status = 'PENDING'
            ldap_config.save(update_fields=['last_sync_status'])
        
        # Initialize LDAP connection
        try:
            ldap_connection = get_ldap_connection(ldap_config)
            
            # Bind with the provided credentials
            ldap_connection.simple_bind_s(ldap_config.bind_dn, ldap_config.bind_password)
        except Exception as e:
            logger.error(f"Failed to connect to LDAP server: {str(e)}")
            update_ldap_sync_status(ldap_config, 'FAILED', f"Failed to connect to LDAP server: {str(e)}")
            return False
        
        try:
            # Get LDAP users
            ldap_users = search_ldap_users(ldap_connection, ldap_config)
            
            # Process users
            with transaction.atomic():
                # Keep track of synced users for deprovisioning
                synced_user_identifiers = []
                
                # Process each LDAP user
                for user_dn, user_attributes in ldap_users:
                    try:
                        # Process the user (create or update)
                        result = process_ldap_user(ldap_config, user_dn, user_attributes)
                        if result:
                            action, user = result
                            if action == 'created':
                                stats['users_created'] += 1
                            elif action == 'updated':
                                stats['users_updated'] += 1
                            
                            # Add user identifier to synced list
                            synced_user_identifiers.append(user.profile.external_id)
                    except Exception as e:
                        logger.error(f"Error processing LDAP user {user_dn}: {str(e)}")
                        stats['errors'] += 1
                
                # Handle user deprovisioning if enabled
                if ldap_config.enable_user_deprovisioning:
                    try:
                        stats['users_deactivated'] = deprovision_users(ldap_config, synced_user_identifiers)
                    except Exception as e:
                        logger.error(f"Error during user deprovisioning: {str(e)}")
                        stats['errors'] += 1
                
                # Sync group memberships if enabled
                if ldap_config.group_base_dn and ldap_config.group_search_filter:
                    try:
                        sync_group_memberships(ldap_connection, ldap_config)
                    except Exception as e:
                        logger.error(f"Error during group membership synchronization: {str(e)}")
                        stats['errors'] += 1
            
            # Update sync status
            update_ldap_sync_status(
                ldap_config, 
                'SUCCESS',
                f"Synchronization completed successfully. "
                f"Created: {stats['users_created']}, "
                f"Updated: {stats['users_updated']}, "
                f"Deactivated: {stats['users_deactivated']}, "
                f"Errors: {stats['errors']}"
            )
            
            return True
        
        except Exception as e:
            logger.error(f"Error during LDAP synchronization: {str(e)}")
            update_ldap_sync_status(ldap_config, 'FAILED', f"Error during synchronization: {str(e)}")
            return False
        
        finally:
            # Always unbind the connection
            try:
                ldap_connection.unbind_s()
            except:
                pass  # Ignore errors during unbind
        
    except Exception as e:
        logger.error(f"Unexpected error during LDAP sync task: {str(e)}")
        try:
            ldap_config = LDAPConfig.objects.get(config_id=config_id)
            update_ldap_sync_status(ldap_config, 'FAILED', f"Unexpected error: {str(e)}")
        except:
            pass
        return False


def get_ldap_connection(ldap_config):
    """
    Create and return an LDAP connection based on the configuration.
    """
    # Set global LDAP options
    ldap.set_option(ldap.OPT_REFERRALS, 0)
    ldap.set_option(ldap.OPT_NETWORK_TIMEOUT, 30)
    
    # Create connection
    ldap_connection = ldap.initialize(ldap_config.server_url)
    
    # Configure TLS if enabled
    if ldap_config.ldap_tls_enabled:
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        if ldap_config.ldap_tls_ca_cert_path:
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, ldap_config.ldap_tls_ca_cert_path)
        
        if ldap_config.server_url.startswith('ldap://'):
            ldap_connection.start_tls_s()
    
    return ldap_connection


def search_ldap_users(ldap_connection, ldap_config):
    """
    Search for users in the LDAP directory.
    
    Returns:
        List of tuples (user_dn, user_attributes)
    """
    # Get attributes to retrieve from mapping
    attributes = list(ldap_config.user_attribute_mapping.values())
    
    # Ensure we get all required attributes for processing
    if 'userAccountControl' not in attributes and 'userAccountControl' in ldap_config.user_attribute_mapping.values():
        attributes.append('userAccountControl')
    
    # For AD, ensure we get the memberOf attribute for group processing
    if 'memberOf' not in attributes:
        attributes.append('memberOf')
    
    # Perform the search
    result = ldap_connection.search_s(
        ldap_config.user_base_dn,
        ldap.SCOPE_SUBTREE,
        ldap_config.user_search_filter,
        attributes
    )
    
    # Filter out referrals and non-user objects
    filtered_result = [(dn, attrs) for dn, attrs in result if isinstance(dn, str) and dn]
    
    return filtered_result


def process_ldap_user(ldap_config, user_dn, user_attributes):
    """
    Process a user from LDAP - create or update in the local database.
    
    Returns:
        Tuple ('created' or 'updated', User) if successful, None otherwise
    """
    # Map attributes from LDAP to local fields
    mapping = ldap_config.user_attribute_mapping
    user_data = {}
    
    for local_field, ldap_attr in mapping.items():
        if ldap_attr in user_attributes:
            # LDAP returns values as lists of bytes or lists of strings
            if ldap_attr in user_attributes and user_attributes[ldap_attr]:
                attr_value = user_attributes[ldap_attr][0]
                if isinstance(attr_value, bytes):
                    attr_value = attr_value.decode('utf-8')
                user_data[local_field] = attr_value
    
    # Check if user is active in LDAP
    is_active_in_ldap = True
    if 'userAccountControl' in user_attributes:
        # For Active Directory - check if account is disabled
        # 0x2 is the flag for disabled accounts
        uac = int(user_attributes['userAccountControl'][0])
        if uac & 2:  # Account is disabled
            is_active_in_ldap = False
    
    # Get the username from mapped attributes
    username_field = user_data.get('username')
    if not username_field:
        logger.warning(f"User {user_dn} does not have a mapped username attribute. Skipping.")
        return None
    
    # Check if user exists
    try:
        # First try to find by external ID
        user = None
        profiles = Profile.objects.filter(external_id=user_dn)
        if profiles.exists():
            user = profiles.first().user
        
        # If not found, try by username
        if not user:
            user = User.objects.get(username=username_field)
            created = False
        else:
            created = False
        
        # Update user fields if needed
        update_fields = []
        
        if 'email' in user_data and user.email != user_data['email']:
            user.email = user_data['email']
            update_fields.append('email')
        
        if 'first_name' in user_data and user.first_name != user_data['first_name']:
            user.first_name = user_data['first_name']
            update_fields.append('first_name')
        
        if 'last_name' in user_data and user.last_name != user_data['last_name']:
            user.last_name = user_data['last_name']
            update_fields.append('last_name')
        
        # Update active status based on LDAP if deprovisioning is enabled
        if ldap_config.enable_user_deprovisioning and user.is_active != is_active_in_ldap:
            user.is_active = is_active_in_ldap
            update_fields.append('is_active')
        
        if update_fields:
            user.save(update_fields=update_fields)
        
        # Update profile
        if hasattr(user, 'profile'):
            profile_update_fields = []
            
            if 'full_name' in user_data and user.profile.full_name != user_data['full_name']:
                user.profile.full_name = user_data['full_name']
                profile_update_fields.append('full_name')
            
            # Set LDAP identifier if not already set
            if not user.profile.external_id or user.profile.external_id != user_dn:
                user.profile.external_id = user_dn
                profile_update_fields.append('external_id')
            
            if not user.profile.managed_by_ldap:
                user.profile.managed_by_ldap = True
                profile_update_fields.append('managed_by_ldap')
            
            if profile_update_fields:
                user.profile.save(update_fields=profile_update_fields)
        else:
            # Create profile if it doesn't exist
            Profile.objects.create(
                user=user,
                full_name=user_data.get('full_name', ''),
                external_id=user_dn,
                managed_by_ldap=True,
                organization=ldap_config.organization
            )
        
        return ('updated', user)
    
    except User.DoesNotExist:
        # If user doesn't exist and provisioning is enabled, create
        if not ldap_config.enable_user_provisioning:
            logger.info(f"User {username_field} not found and provisioning is disabled. Skipping.")
            return None
        
        # Create new user
        user_kwargs = {
            'username': username_field,
            'email': user_data.get('email', ''),
            'first_name': user_data.get('first_name', ''),
            'last_name': user_data.get('last_name', ''),
            'is_active': is_active_in_ldap,
            'is_staff': False,
            'is_superuser': False
        }
        
        user = User.objects.create_user(**user_kwargs)
        
        # Create profile
        Profile.objects.create(
            user=user,
            full_name=user_data.get('full_name', ''),
            external_id=user_dn,
            managed_by_ldap=True,
            organization=ldap_config.organization
        )
        
        return ('created', user)


def deprovision_users(ldap_config, synced_user_identifiers):
    """
    Deprovision users who are managed by LDAP but not found in the current sync.
    
    Args:
        ldap_config: LDAPConfig object
        synced_user_identifiers: List of external_id values that were synced
    
    Returns:
        Number of users deactivated
    """
    # Find users that are managed by this LDAP config but not in the synced list
    query = Profile.objects.filter(managed_by_ldap=True)
    
    # If this is an organization-specific config, only consider users in that org
    if ldap_config.organization:
        query = query.filter(organization=ldap_config.organization)
    
    # Exclude users that were found in this sync
    query = query.exclude(external_id__in=synced_user_identifiers)
    
    # Get the users to deprovision
    users_to_deprovision = User.objects.filter(profile__in=query, is_active=True)
    
    count = users_to_deprovision.count()
    
    # Deactivate the users
    users_to_deprovision.update(is_active=False)
    
    return count


def sync_group_memberships(ldap_connection, ldap_config):
    """
    Synchronize group memberships from LDAP to local teams.
    """
    if not ldap_config.group_to_organization_team_mapping:
        # No mappings defined, nothing to do
        return
    
    # Get group mapping configuration
    group_mapping = ldap_config.group_to_organization_team_mapping
    
    # Get member attribute from mapping or use default
    member_attr = ldap_config.group_attribute_mapping.get('member_attribute', 'member')
    
    # For each group in the mapping
    for ldap_group_dn, mappings in group_mapping.items():
        try:
            # Search for the group
            result = ldap_connection.search_s(
                ldap_group_dn,
                ldap.SCOPE_BASE,
                '(objectClass=*)',
                [member_attr]
            )
            
            if not result:
                logger.warning(f"Group {ldap_group_dn} not found in LDAP.")
                continue
            
            # Get group members
            group_attrs = result[0][1]
            members_dns = []
            
            if member_attr in group_attrs:
                for member in group_attrs[member_attr]:
                    if isinstance(member, bytes):
                        members_dns.append(member.decode('utf-8'))
                    else:
                        members_dns.append(member)
            
            # Get local users that match these DNs
            local_users = User.objects.filter(profile__external_id__in=members_dns)
            
            # Get target organization and team
            org_id = mappings.get('organization_id')
            team_id = mappings.get('team_id')
            role_id = mappings.get('role_id')
            
            if not org_id:
                logger.warning(f"No organization ID specified for group {ldap_group_dn}.")
                continue
            
            try:
                organization = Organization.objects.get(organization_id=org_id)
            except Organization.DoesNotExist:
                logger.warning(f"Organization with ID {org_id} not found.")
                continue
            
            # If team_id is specified, add users to team
            if team_id:
                try:
                    team = Team.objects.get(team_id=team_id, organization=organization)
                    # Add users to team
                    team.members.add(*local_users)
                except Team.DoesNotExist:
                    logger.warning(f"Team with ID {team_id} not found in organization {org_id}.")
            
            # If role_id is specified, assign role to users in the organization
            if role_id:
                try:
                    role = Role.objects.get(id=role_id)
                    
                    # For each user, assign the role in the organization
                    for user in local_users:
                        # Check if user already has this role in this organization
                        if not UserRole.objects.filter(
                            user=user, 
                            role=role, 
                            organization=organization
                        ).exists():
                            UserRole.objects.create(
                                user=user,
                                role=role,
                                organization=organization
                            )
                except Role.DoesNotExist:
                    logger.warning(f"Role with ID {role_id} not found.")
            
            # Update user profiles with organization if not already set
            for user in local_users:
                if hasattr(user, 'profile') and not user.profile.organization:
                    user.profile.organization = organization
                    user.profile.save(update_fields=['organization'])
        
        except Exception as e:
            logger.error(f"Error processing group {ldap_group_dn}: {str(e)}")


def update_ldap_sync_status(ldap_config, status, message):
    """
    Update the sync status of an LDAP configuration.
    """
    ldap_config.last_sync_status = status
    ldap_config.last_sync_message = message
    ldap_config.last_sync_timestamp = timezone.now()
    ldap_config.save(update_fields=[
        'last_sync_status', 'last_sync_message', 'last_sync_timestamp'
    ])


@shared_task
def schedule_ldap_sync():
    """
    Task to schedule LDAP sync for configurations that are due to be synced.
    This task should be run periodically by Celery Beat.
    """
    now = timezone.now()
    
    # Find active LDAP configurations
    active_configs = LDAPConfig.objects.filter(is_active=True)
    
    for config in active_configs:
        # Check if sync is due
        if config.last_sync_timestamp:
            # Calculate next sync time
            next_sync = config.last_sync_timestamp + timezone.timedelta(minutes=config.sync_interval_minutes)
            
            # Skip if not due yet
            if now < next_sync:
                continue
        
        # Trigger sync for this configuration
        sync_ldap_users.delay(str(config.config_id))
        
        logger.info(f"Scheduled LDAP sync for configuration: {config.name}") 