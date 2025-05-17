from django.core.management.base import BaseCommand
from django.db import transaction
from django.conf import settings
from django.contrib.auth.models import User
from irp.accounts.services import RoleService, UserService, OrganizationService
from irp.accounts.models import Organization, Team, Profile, Role, Permission, UserRole, RolePermission
from irp.alerts.models import AlertSeverity, AlertStatus
from irp.cases.models import CaseSeverity, CaseStatus, TaskStatus
from irp.observables.models import ObservableType, TLPLevel, PAPLevel
import os
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Sets up and initializes the complete system: admin, organization, permissions, roles and reference data'

    def add_arguments(self, parser):
        parser.add_argument(
            '--admin-username', 
            default='admin',
            help='Username for the administrator'
        )
        parser.add_argument(
            '--admin-email',
            default='admin@example.com',
            help='Email for the administrator'
        )
        parser.add_argument(
            '--admin-password',
            default=None,
            help='Password for the administrator (if not provided, a random one will be generated)'
        )
        parser.add_argument(
            '--org-name',
            default='Main Organization',
            help='Name of the main organization'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force execution even if data already exists'
        )
        parser.add_argument(
            '--skip-reference-data',
            action='store_true',
            help='Skip creation of reference data (severities, statuses, etc.)'
        )

    @transaction.atomic
    def handle(self, *args, **options):
        self.stdout.write(self.style.MIGRATE_HEADING('Initializing complete system...'))

        # Get options
        username = options['admin_username']
        email = options['admin_email']
        password = options['admin_password']
        org_name = options['org_name']
        force = options['force']
        skip_reference = options['skip_reference_data']

        # Generate random password if not provided
        if not password:
            import secrets
            import string
            alphabet = string.ascii_letters + string.digits
            password = ''.join(secrets.choice(alphabet) for _ in range(12))
            self.stdout.write(f'Randomly generated password: {password}')

        # Check if admin and organization already exist
        admin_exists = User.objects.filter(is_superuser=True).exists()
        org_exists = Organization.objects.exists()

        # If data exists and not forced, abort
        if (admin_exists or org_exists) and not force:
            self.stdout.write(self.style.WARNING('The system already has initial data. Use --force to overwrite.'))
            return

        # STEP 1: BASIC PERMISSIONS AND ROLES CONFIGURATION
        # --------------------------------------------------
        self.stdout.write(self.style.MIGRATE_HEADING('STEP 1: Configuring basic permissions and roles...'))
        
        # Configure default permissions
        self.stdout.write('Configuring default permissions...')
        permissions = self._create_permissions()
        self.stdout.write(self.style.SUCCESS(f'  {len(permissions)} permissions configured.'))
        
        # Configure default roles
        self.stdout.write('Configuring default roles...')
        roles = self._create_roles()
        self.stdout.write(self.style.SUCCESS(f'  {len(roles)} roles configured.'))

        # STEP 2: ADMIN USER AND MAIN ORGANIZATION CONFIGURATION
        # -------------------------------------------------------------
        self.stdout.write(self.style.MIGRATE_HEADING('STEP 2: Configuring admin and main organization...'))
        
        # Create or get admin superuser
        if User.objects.filter(is_superuser=True).exists() and force:
            admin_user = User.objects.filter(is_superuser=True).first()
            self.stdout.write(f'  Using existing superuser: {admin_user.username}')
        else:
            admin_user = User.objects.create_superuser(
                username=username,
                email=email,
                password=password
            )
            self.stdout.write(self.style.SUCCESS(f'  Admin created: {admin_user.username}'))
        
        # Create or get main organization
        if Organization.objects.exists() and force:
            org = Organization.objects.first()
            self.stdout.write(f'  Using existing organization: {org.name}')
        else:
            org = OrganizationService.create_organization(
                name=org_name,
                description=f"Main organization created during system initialization",
                contact_info=email
            )
            self.stdout.write(self.style.SUCCESS(f'  Organization created: {org.name}'))
        
        # Associate admin with organization
        if not hasattr(admin_user, 'profile'):
            profile = Profile.objects.create(
                user=admin_user,
                full_name=admin_user.get_full_name() or "System Administrator",
                organization=org,
                is_system_admin=True
            )
            self.stdout.write(self.style.SUCCESS('  Admin profile created and associated with the organization'))
        elif admin_user.profile.organization != org:
            admin_user.profile.organization = org
            admin_user.profile.is_system_admin = True
            admin_user.profile.save()
            self.stdout.write(self.style.SUCCESS('  Admin profile updated with the new organization'))
        
        # Associate admin with administrator role
        admin_role = Role.objects.filter(name__icontains='Administrator').first()
        if admin_role:
            user_role, created = UserRole.objects.get_or_create(
                user=admin_user,
                role=admin_role,
                organization=org
            )
            if created:
                self.stdout.write(self.style.SUCCESS('  Admin associated with Administrator role'))
        
        # STEP 3: REFERENCE DATA CONFIGURATION (if not skipped)
        # ----------------------------------------------------------------
        if not skip_reference:
            self.stdout.write(self.style.MIGRATE_HEADING('STEP 3: Configuring reference data...'))
            
            # Create alert severities and statuses
            self.stdout.write('Configuring alert severities and statuses...')
            self._create_alert_severities()
            self._create_alert_statuses()
            
            # Create case severities and statuses
            self.stdout.write('Configuring case severities and statuses...')
            self._create_case_severities()
            self._create_case_statuses()
            
            # Create task statuses
            self.stdout.write('Configuring task statuses...')
            self._create_task_statuses()
            
            # Create observable types
            self.stdout.write('Configuring observable types...')
            self._create_observable_types()
            
            # Create TLP and PAP levels
            self.stdout.write('Configuring TLP and PAP levels...')
            self._create_tlp_levels()
            self._create_pap_levels()
            
            self.stdout.write(self.style.SUCCESS('  Reference data successfully configured'))
        
        # Display access information
        self.stdout.write('')
        self.stdout.write(self.style.SUCCESS('SYSTEM SUCCESSFULLY INITIALIZED!'))
        self.stdout.write('')
        self.stdout.write('Access information:')
        self.stdout.write(f'  URL: {settings.ALLOWED_HOSTS[0] if settings.ALLOWED_HOSTS else "localhost:8000"}')
        self.stdout.write(f'  Username: {admin_user.username}')
        self.stdout.write(f'  Password: {password if admin_user.username == username else "The previously set password"}')
        self.stdout.write('')
        self.stdout.write('Store this information in a secure location!')

    def _create_permissions(self):
        """Creates the system's default permissions"""
        permissions = [
            # Administrative permissions
            {"code": "manage_organizations", "name": "Manage Organizations", "description": "Create, edit and delete organizations"},
            {"code": "manage_teams", "name": "Manage Teams", "description": "Create, edit and delete teams"},
            {"code": "manage_users", "name": "Manage Users", "description": "Create, edit and delete users"},
            {"code": "manage_roles", "name": "Manage Roles", "description": "Create, edit and delete roles"},
            {"code": "manage_permissions", "name": "Manage Permissions", "description": "Create, edit and delete permissions"},
            {"code": "assign_roles", "name": "Assign Roles", "description": "Assign roles to users"},
            {"code": "assign_permissions", "name": "Assign Permissions", "description": "Assign permissions to roles"},
            
            # Alert permissions
            {"code": "alert:view", "name": "View Alerts", "description": "View alerts"},
            {"code": "alert:create", "name": "Create Alerts", "description": "Create new alerts"},
            {"code": "alert:edit", "name": "Edit Alerts", "description": "Edit existing alerts"},
            {"code": "alert:delete", "name": "Delete Alerts", "description": "Delete alerts"},
            {"code": "alert:comment", "name": "Comment on Alerts", "description": "Add comments to alerts"},
            {"code": "alert:escalate", "name": "Escalate Alerts", "description": "Escalate alerts to cases"},
            
            # Case permissions
            {"code": "case:view", "name": "View Cases", "description": "View cases"},
            {"code": "case:create", "name": "Create Cases", "description": "Create new cases"},
            {"code": "case:edit", "name": "Edit Cases", "description": "Edit existing cases"},
            {"code": "case:delete", "name": "Delete Cases", "description": "Delete cases"},
            {"code": "case:comment", "name": "Comment on Cases", "description": "Add comments to cases"},
            
            # Task permissions
            {"code": "task:view", "name": "View Tasks", "description": "View tasks"},
            {"code": "task:create", "name": "Create Tasks", "description": "Create new tasks"},
            {"code": "task:edit", "name": "Edit Tasks", "description": "Edit existing tasks"},
            {"code": "task:delete", "name": "Delete Tasks", "description": "Delete tasks"},
            
            # Observable permissions
            {"code": "observable:view", "name": "View Observables", "description": "View observables"},
            {"code": "observable:create", "name": "Create Observables", "description": "Create new observables"},
            {"code": "observable:edit", "name": "Edit Observables", "description": "Edit existing observables"},
            {"code": "observable:delete", "name": "Delete Observables", "description": "Delete observables"},
            
            # Settings permissions
            {"code": "manage_alert_settings", "name": "Manage Alert Settings", "description": "Manage severities, statuses and custom fields for alerts"},
            {"code": "manage_case_settings", "name": "Manage Case Settings", "description": "Manage severities, statuses and custom fields for cases"},
            {"code": "manage_case_templates", "name": "Manage Case Templates", "description": "Create, edit and delete case templates"},
            
            # Dashboard and Reports permissions
            {"code": "view_dashboard", "name": "View Dashboard", "description": "View the dashboard with statistics"},
            {"code": "generate_reports", "name": "Generate Reports", "description": "Generate and view reports"},
            
            # Basic user permissions
            {"code": "organization:view", "name": "View Organizations", "description": "Allows viewing organizations"},
            {"code": "organization:create", "name": "Create Organizations", "description": "Allows creating new organizations"},
            {"code": "organization:edit", "name": "Edit Organizations", "description": "Allows editing existing organizations"},
            {"code": "organization:delete", "name": "Delete Organizations", "description": "Allows deleting organizations"},
            {"code": "team:view", "name": "View Teams", "description": "Allows viewing teams"},
            {"code": "team:create", "name": "Create Teams", "description": "Allows creating new teams"},
            {"code": "team:edit", "name": "Edit Teams", "description": "Allows editing existing teams"},
            {"code": "team:delete", "name": "Delete Teams", "description": "Allows deleting teams"},
            {"code": "user:view", "name": "View Users", "description": "Allows viewing users"},
            {"code": "user:create", "name": "Create Users", "description": "Allows creating new users"},
            {"code": "user:edit", "name": "Edit Users", "description": "Allows editing existing users"},
            {"code": "user:delete", "name": "Delete Users", "description": "Allows deleting users"},
            
            # Wildcard permission
            {"code": "*", "name": "All Permissions", "description": "Grants all system permissions"},
        ]
        
        created_permissions = []
        
        for perm_data in permissions:
            perm, created = Permission.objects.update_or_create(
                code=perm_data["code"],
                defaults={
                    "name": perm_data["name"],
                    "description": perm_data["description"]
                }
            )
            if created:
                created_permissions.append(perm)
        
        return permissions

    def _create_roles(self):
        """Creates the system's default roles with their permissions"""
        roles = [
            {
                "name": "Administrator",
                "description": "Full system access",
                "permissions": ["*"]  # Wildcard for all permissions
            },
            {
                "name": "Analyst",
                "description": "Standard security analyst",
                "permissions": [
                    "alert:view", "alert:edit", "alert:comment", "alert:escalate",
                    "case:view", "case:edit", "case:comment",
                    "task:view", "task:create", "task:edit",
                    "observable:view", "observable:create", "observable:edit",
                    "view_dashboard"
                ]
            },
            {
                "name": "Coordinator",
                "description": "Security team coordinator",
                "permissions": [
                    "alert:view", "alert:create", "alert:edit", "alert:delete", "alert:comment", "alert:escalate",
                    "case:view", "case:create", "case:edit", "case:delete", "case:comment",
                    "task:view", "task:create", "task:edit", "task:delete",
                    "observable:view", "observable:create", "observable:edit", "observable:delete",
                    "manage_alert_settings", "manage_case_settings", "manage_case_templates",
                    "view_dashboard", "generate_reports"
                ]
            },
            {
                "name": "Read Only",
                "description": "Read-only system access",
                "permissions": [
                    "alert:view", "case:view", "task:view", "observable:view", "view_dashboard"
                ]
            },
            {
                "name": "Basic User",
                "description": "Basic view access",
                "permissions": [
                    "organization:view", "team:view", "user:view",
                    "case:view", "alert:view", "observable:view"
                ]
            }
        ]
        
        created_roles = []
        
        for role_data in roles:
            role, created = Role.objects.update_or_create(
                name=role_data["name"],
                defaults={
                    "description": role_data["description"]
                }
            )
            
            # Assign permissions
            if "*" in role_data["permissions"]:
                # For administrator, assign all permissions
                for perm in Permission.objects.all():
                    RolePermission.objects.update_or_create(role=role, permission=perm)
            else:
                for perm_code in role_data["permissions"]:
                    try:
                        perm = Permission.objects.get(code=perm_code)
                        RolePermission.objects.update_or_create(role=role, permission=perm)
                    except Permission.DoesNotExist:
                        self.stdout.write(self.style.WARNING(f'Permission {perm_code} not found for role {role.name}'))
            
            created_roles.append(role)
        
        return created_roles

    def _create_alert_severities(self):
        """Creates default alert severities"""
        severities = [
            {"name": "Low", "level_order": 1, "color_code": "#28a745"},
            {"name": "Medium", "level_order": 2, "color_code": "#ffc107"},
            {"name": "High", "level_order": 3, "color_code": "#fd7e14"},
            {"name": "Critical", "level_order": 4, "color_code": "#dc3545"}
        ]
        
        for sev_data in severities:
            AlertSeverity.objects.update_or_create(
                name=sev_data["name"],
                defaults={
                    "level_order": sev_data["level_order"],
                    "color_code": sev_data["color_code"]
                }
            )
        
        self.stdout.write(f'  {len(severities)} alert severities configured')

    def _create_alert_statuses(self):
        """Creates default alert statuses"""
        statuses = [
            {"name": "New", "description": "Newly created alert", "is_default_open_status": True, "is_terminal_status": False, "color_code": "#17a2b8"},
            {"name": "Open", "description": "Alert open for analysis", "is_default_open_status": False, "is_terminal_status": False, "color_code": "#007bff"},
            {"name": "In Progress", "description": "Analysis in progress", "is_default_open_status": False, "is_terminal_status": False, "color_code": "#6f42c1"},
            {"name": "Escalated", "description": "Escalated to case", "is_default_open_status": False, "is_terminal_status": True, "color_code": "#fd7e14"},
            {"name": "Closed - False Positive", "description": "Closed as false positive", "is_default_open_status": False, "is_terminal_status": True, "color_code": "#6c757d"},
            {"name": "Closed - Resolved", "description": "Closed as resolved", "is_default_open_status": False, "is_terminal_status": True, "color_code": "#28a745"}
        ]
        
        for status_data in statuses:
            AlertStatus.objects.update_or_create(
                name=status_data["name"],
                organization=None,  # Global status
                defaults={
                    "description": status_data["description"],
                    "is_default_open_status": status_data["is_default_open_status"],
                    "is_terminal_status": status_data["is_terminal_status"],
                    "color_code": status_data["color_code"]
                }
            )
        
        self.stdout.write(f'  {len(statuses)} alert statuses configured')

    def _create_case_severities(self):
        """Creates default case severities"""
        severities = [
            {"name": "Low", "level_order": 1, "color_code": "#28a745"},
            {"name": "Medium", "level_order": 2, "color_code": "#ffc107"},
            {"name": "High", "level_order": 3, "color_code": "#fd7e14"},
            {"name": "Critical", "level_order": 4, "color_code": "#dc3545"}
        ]
        
        for sev_data in severities:
            CaseSeverity.objects.update_or_create(
                name=sev_data["name"],
                defaults={
                    "level_order": sev_data["level_order"],
                    "color_code": sev_data["color_code"]
                }
            )
        
        self.stdout.write(f'  {len(severities)} case severities configured')

    def _create_case_statuses(self):
        """Creates default case statuses"""
        statuses = [
            {"name": "Open", "description": "Newly opened case", "is_default_open_status": True, "is_terminal_status": False, "color_code": "#17a2b8"},
            {"name": "Investigating", "description": "Investigation in progress", "is_default_open_status": False, "is_terminal_status": False, "color_code": "#007bff"},
            {"name": "Containment", "description": "Containment phase", "is_default_open_status": False, "is_terminal_status": False, "color_code": "#fd7e14"},
            {"name": "Eradication", "description": "Eradication phase", "is_default_open_status": False, "is_terminal_status": False, "color_code": "#6f42c1"},
            {"name": "Recovery", "description": "Recovery phase", "is_default_open_status": False, "is_terminal_status": False, "color_code": "#20c997"},
            {"name": "Closed", "description": "Case closed", "is_default_open_status": False, "is_terminal_status": True, "color_code": "#28a745"},
            {"name": "Closed - False Positive", "description": "Closed as false positive", "is_default_open_status": False, "is_terminal_status": True, "color_code": "#6c757d"}
        ]
        
        for status_data in statuses:
            CaseStatus.objects.update_or_create(
                name=status_data["name"],
                organization=None,  # Global status
                defaults={
                    "description": status_data["description"],
                    "is_default_open_status": status_data["is_default_open_status"],
                    "is_terminal_status": status_data["is_terminal_status"],
                    "color_code": status_data["color_code"]
                }
            )
        
        self.stdout.write(f'  {len(statuses)} case statuses configured')

    def _create_task_statuses(self):
        """Creates default task statuses"""
        statuses = [
            {"name": "ToDo", "color_code": "#17a2b8"},
            {"name": "In Progress", "color_code": "#007bff"},
            {"name": "Done", "color_code": "#28a745"},
            {"name": "Blocked", "color_code": "#dc3545"}
        ]
        
        for status_data in statuses:
            TaskStatus.objects.update_or_create(
                name=status_data["name"],
                defaults={
                    "color_code": status_data["color_code"]
                }
            )
        
        self.stdout.write(f'  {len(statuses)} task statuses configured')

    def _create_observable_types(self):
        """Creates default observable types"""
        types = [
            {"name": "ipv4-addr", "description": "IPv4 Address"},
            {"name": "ipv6-addr", "description": "IPv6 Address"},
            {"name": "domain-name", "description": "Domain Name"},
            {"name": "url", "description": "Complete URL"},
            {"name": "email-addr", "description": "Email Address"},
            {"name": "file-hash-md5", "description": "MD5 File Hash"},
            {"name": "file-hash-sha1", "description": "SHA1 File Hash"},
            {"name": "file-hash-sha256", "description": "SHA256 File Hash"},
            {"name": "file-name", "description": "File Name"},
            {"name": "user-account", "description": "User Account"},
            {"name": "process-name", "description": "Process Name"},
            {"name": "windows-registry-key", "description": "Windows Registry Key"},
            {"name": "mac-addr", "description": "MAC Address"}
        ]
        
        for type_data in types:
            ObservableType.objects.update_or_create(
                name=type_data["name"],
                defaults={
                    "description": type_data["description"]
                }
            )
        
        self.stdout.write(f'  {len(types)} observable types configured')

    def _create_tlp_levels(self):
        """Creates default TLP (Traffic Light Protocol) levels"""
        levels = [
            {"name": "RED", "description": "Not for disclosure, restricted to specific participants"},
            {"name": "AMBER", "description": "Limited disclosure, restricted to organization"},
            {"name": "GREEN", "description": "Limited disclosure to community"},
            {"name": "WHITE", "description": "Unlimited disclosure"}
        ]
        
        for level_data in levels:
            TLPLevel.objects.update_or_create(
                name=level_data["name"],
                defaults={
                    "description": level_data["description"]
                }
            )
        
        self.stdout.write(f'  {len(levels)} TLP levels configured')

    def _create_pap_levels(self):
        """Creates default PAP (Permissible Actions Protocol) levels"""
        levels = [
            {"name": "WHITE", "description": "May be distributed without restriction"},
            {"name": "GREEN", "description": "May be distributed to specific organizations or communities"},
            {"name": "AMBER", "description": "Limited disclosure, organizational use only"},
            {"name": "RED", "description": "Personal use only, do not share"}
        ]
        
        for level_data in levels:
            PAPLevel.objects.update_or_create(
                name=level_data["name"],
                defaults={
                    "description": level_data["description"]
                }
            )
        
        self.stdout.write(f'  {len(levels)} PAP levels configured') 