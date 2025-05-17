from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import uuid


class Organization(models.Model):
    organization_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True)
    contact_info = models.CharField(max_length=255, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    slug = models.SlugField(unique=True, blank=True)

    def __str__(self):
        return self.name


class Team(models.Model):
    team_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='teams')
    members = models.ManyToManyField(User, related_name='teams', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({self.organization.name})"


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    full_name = models.CharField(max_length=255, blank=True)
    phone = models.CharField(max_length=20, blank=True, null=True)
    job_title = models.CharField(max_length=100, blank=True, null=True)
    organization = models.ForeignKey(Organization, on_delete=models.SET_NULL, null=True, blank=True, related_name='users')
    is_system_admin = models.BooleanField(default=False)
    last_login_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    custom_fields = models.JSONField(default=dict, blank=True)
    # New fields for LDAP integration
    external_id = models.CharField(max_length=255, blank=True, null=True, help_text="External ID or Distinguished Name from LDAP/AD")
    managed_by_ldap = models.BooleanField(default=False, help_text="Whether this user is managed by LDAP/AD")

    def __str__(self):
        return self.user.username


class Role(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)

    def __str__(self):
        return self.name


class Permission(models.Model):
    code = models.CharField(max_length=100, unique=True)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)

    def __str__(self):
        return self.name


class UserRole(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_roles')
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='user_roles')
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='user_roles')

    class Meta:
        unique_together = ('user', 'role', 'organization')

    def __str__(self):
        return f"{self.user.username} - {self.role.name} ({self.organization.name})"


class RolePermission(models.Model):
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='role_permissions')
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE, related_name='role_permissions')

    class Meta:
        unique_together = ('role', 'permission')

    def __str__(self):
        return f"{self.role.name} - {self.permission.code}"


class LDAPConfig(models.Model):
    """
    Configuration for LDAP/AD synchronization.
    This model stores the connection and synchronization settings for LDAP/AD directories.
    """
    SYNC_STATUS_CHOICES = [
        ('SUCCESS', 'Success'),
        ('FAILED', 'Failed'),
        ('PENDING', 'Pending'),
        ('NEVER_RUN', 'Never Run'),
    ]
    
    config_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization, 
        on_delete=models.CASCADE, 
        null=True, 
        blank=True, 
        related_name='ldap_configs', 
        help_text="If set, this configuration applies only to this organization. If null, it's global."
    )
    name = models.CharField(max_length=100, help_text="A friendly name for this configuration")
    server_url = models.CharField(max_length=255, help_text="LDAP server URL (e.g., ldap://ad.example.com:389 or ldaps://ad.example.com:636)")
    bind_dn = models.CharField(max_length=255, help_text="Distinguished Name for binding to the LDAP server")
    bind_password = models.CharField(max_length=255, help_text="Password for the bind DN")
    user_base_dn = models.CharField(max_length=255, help_text="Base DN for user search")
    user_search_filter = models.CharField(max_length=255, default="(objectClass=person)", help_text="LDAP filter to find user objects")
    user_attribute_mapping = models.JSONField(
        default=dict, 
        help_text="Mapping of LDAP attributes to user fields (JSON format)"
    )
    group_base_dn = models.CharField(max_length=255, blank=True, null=True, help_text="Base DN for group search (optional)")
    group_search_filter = models.CharField(max_length=255, blank=True, null=True, help_text="LDAP filter to find group objects (optional)")
    group_attribute_mapping = models.JSONField(
        default=dict, 
        blank=True, 
        help_text="Mapping of LDAP group attributes (JSON format, optional)"
    )
    group_to_organization_team_mapping = models.JSONField(
        default=dict, 
        blank=True, 
        help_text="Mapping of LDAP groups to organizations, teams, and roles (JSON format, optional)"
    )
    sync_interval_minutes = models.IntegerField(default=1440, help_text="Synchronization interval in minutes (default: 1 day)")
    is_active = models.BooleanField(default=True, help_text="Whether this synchronization configuration is active")
    last_sync_status = models.CharField(
        max_length=20, 
        choices=SYNC_STATUS_CHOICES,
        default='NEVER_RUN', 
        help_text="Status of the last synchronization"
    )
    last_sync_message = models.TextField(blank=True, help_text="Details/error message from the last synchronization")
    last_sync_timestamp = models.DateTimeField(null=True, blank=True, help_text="When the last synchronization was performed")
    enable_user_provisioning = models.BooleanField(default=True, help_text="Create new users in the platform if found in LDAP")
    enable_user_deprovisioning = models.BooleanField(default=False, help_text="Deactivate/remove users in the platform if not found in LDAP or disabled in LDAP")
    ldap_tls_enabled = models.BooleanField(default=True, help_text="Whether to use TLS/StartTLS")
    ldap_tls_ca_cert_path = models.CharField(max_length=255, blank=True, null=True, help_text="Path to the CA cert for LDAPS (optional)")
    enable_delegated_authentication = models.BooleanField(default=False, help_text="Use LDAP for authentication instead of local passwords")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        if self.organization:
            return f"{self.name} ({self.organization.name})"
        return f"{self.name} (Global)"

    class Meta:
        verbose_name = "LDAP Configuration"
        verbose_name_plural = "LDAP Configurations"
