from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import uuid
from django.utils.text import slugify

# Create your models here.

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

# -------- Etapa 2: Alert e Case Management -------- #

class AlertSeverity(models.Model):
    name = models.CharField(max_length=50, unique=True)
    level_order = models.IntegerField()
    color_code = models.CharField(max_length=7)  # Hexadecimal color code
    
    def __str__(self):
        return self.name
    
    class Meta:
        verbose_name_plural = 'Alert Severities'

class AlertStatus(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True, related_name='alert_statuses')
    is_default_open_status = models.BooleanField(default=False)
    is_terminal_status = models.BooleanField(default=False)
    color_code = models.CharField(max_length=7, default='#808080')  # Hexadecimal color code
    
    def __str__(self):
        return self.name
    
    class Meta:
        unique_together = ('name', 'organization')
        verbose_name_plural = 'Alert Statuses'

class Alert(models.Model):
    alert_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    external_alert_id = models.CharField(max_length=255, blank=True, null=True, db_index=True)
    source_system = models.CharField(max_length=100, db_index=True)
    title = models.CharField(max_length=255, db_index=True)
    description = models.TextField(blank=True)
    severity = models.ForeignKey(AlertSeverity, on_delete=models.PROTECT, related_name='alerts')
    status = models.ForeignKey(AlertStatus, on_delete=models.PROTECT, related_name='alerts')
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='alerts')
    assignee = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_alerts')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    first_seen_at = models.DateTimeField(default=timezone.now)
    last_seen_at = models.DateTimeField(blank=True, null=True)
    raw_event_data = models.JSONField(blank=True, null=True)
    artifact_count = models.IntegerField(default=0)
    tags = models.JSONField(default=list, blank=True)
    is_deleted = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.title} - {self.source_system}"

class AlertComment(models.Model):
    comment_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    alert = models.ForeignKey(Alert, on_delete=models.CASCADE, related_name='comments')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='alert_comments')
    comment_text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Comment on {self.alert.title} by {self.user.username}"

class AlertCustomFieldDefinition(models.Model):
    TYPE_CHOICES = [
        ('TEXT', 'Text'),
        ('NUMBER', 'Number'),
        ('BOOLEAN', 'Boolean'),
        ('DATE', 'Date'),
        ('SELECT', 'Select'),
        ('MULTI_SELECT', 'Multi Select'),
    ]
    
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True, related_name='alert_custom_field_definitions')
    name = models.CharField(max_length=100)
    technical_name = models.CharField(max_length=50)
    field_type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    options = models.JSONField(default=list, blank=True)
    is_required = models.BooleanField(default=False)
    is_filterable = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.name} ({self.technical_name})"
    
    class Meta:
        unique_together = ('organization', 'technical_name')

class AlertCustomFieldValue(models.Model):
    alert = models.ForeignKey(Alert, on_delete=models.CASCADE, related_name='custom_field_values')
    field_definition = models.ForeignKey(AlertCustomFieldDefinition, on_delete=models.CASCADE, related_name='field_values')
    value_text = models.TextField(blank=True, null=True)
    value_number = models.DecimalField(blank=True, null=True, max_digits=20, decimal_places=5)
    value_boolean = models.BooleanField(blank=True, null=True)
    value_date = models.DateTimeField(blank=True, null=True)
    
    class Meta:
        unique_together = ('alert', 'field_definition')

# Case Management Models

class CaseSeverity(models.Model):
    name = models.CharField(max_length=50, unique=True)
    level_order = models.IntegerField()
    color_code = models.CharField(max_length=7)  # Hexadecimal color code
    
    def __str__(self):
        return self.name
    
    class Meta:
        verbose_name_plural = 'Case Severities'

class CaseStatus(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True, related_name='case_statuses')
    is_default_open_status = models.BooleanField(default=False)
    is_terminal_status = models.BooleanField(default=False)
    color_code = models.CharField(max_length=7, default='#808080')  # Hexadecimal color code
    
    def __str__(self):
        return self.name
    
    class Meta:
        unique_together = ('name', 'organization')
        verbose_name_plural = 'Case Statuses'

class CaseTemplate(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True, related_name='case_templates')
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    default_title_format = models.CharField(max_length=255, blank=True)
    default_severity = models.ForeignKey(CaseSeverity, on_delete=models.SET_NULL, null=True, blank=True)
    default_tags = models.JSONField(default=list, blank=True)
    predefined_tasks = models.JSONField(default=list, blank=True)
    custom_field_definitions = models.JSONField(default=list, blank=True)
    
    def __str__(self):
        return self.name

class Case(models.Model):
    case_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=255, db_index=True)
    description = models.TextField(blank=True)
    severity = models.ForeignKey(CaseSeverity, on_delete=models.PROTECT, related_name='cases')
    status = models.ForeignKey(CaseStatus, on_delete=models.PROTECT, related_name='cases')
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='cases')
    assignee = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_cases')
    reporter = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='reported_cases')
    template = models.ForeignKey(CaseTemplate, on_delete=models.SET_NULL, null=True, blank=True, related_name='cases')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    closed_at = models.DateTimeField(blank=True, null=True)
    tags = models.JSONField(default=list, blank=True)
    alerts = models.ManyToManyField(Alert, related_name='cases')
    
    def __str__(self):
        return self.title
    
    def save(self, *args, **kwargs):
        # Check if this is an existing case (not new)
        if self.pk:
            try:
                # Get the current status from the database
                old_case = Case.objects.get(pk=self.pk)
                
                # Track status changes for notifications
                if old_case.status != self.status:
                    self._status_changed = True
                    self._previous_status = old_case.status
                    
                    # Set closed_at when moving to a terminal status
                    if self.status.is_terminal_status and not self.closed_at:
                        self.closed_at = timezone.now()
                else:
                    self._status_changed = False
                    
                # Track assignee changes for notifications
                if old_case.assignee != self.assignee:
                    self._assignee_changed = True
                    self._previous_assignee = old_case.assignee
                else:
                    self._assignee_changed = False
                    
            except Case.DoesNotExist:
                # Handle case where somehow the PK exists but the object doesn't
                self._status_changed = False
                self._assignee_changed = False
                pass
                
        # Call the original save method
        super().save(*args, **kwargs)

class CaseComment(models.Model):
    comment_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='comments')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='case_comments')
    comment_text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Comment on {self.case.title} by {self.user.username}"

class CaseCustomFieldDefinition(models.Model):
    TYPE_CHOICES = [
        ('TEXT', 'Text'),
        ('NUMBER', 'Number'),
        ('BOOLEAN', 'Boolean'),
        ('DATE', 'Date'),
        ('SELECT', 'Select'),
        ('MULTI_SELECT', 'Multi Select'),
    ]
    
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True, related_name='case_custom_field_definitions')
    name = models.CharField(max_length=100)
    technical_name = models.CharField(max_length=50)
    field_type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    options = models.JSONField(default=list, blank=True)
    is_required = models.BooleanField(default=False)
    is_filterable = models.BooleanField(default=False)
    
    def __str__(self):
        return f"{self.name} ({self.technical_name})"
    
    class Meta:
        unique_together = ('organization', 'technical_name')

class CaseCustomFieldValue(models.Model):
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='custom_field_values')
    field_definition = models.ForeignKey(CaseCustomFieldDefinition, on_delete=models.CASCADE, related_name='field_values')
    value_text = models.TextField(blank=True, null=True)
    value_number = models.DecimalField(blank=True, null=True, max_digits=20, decimal_places=5)
    value_boolean = models.BooleanField(blank=True, null=True)
    value_date = models.DateTimeField(blank=True, null=True)
    
    class Meta:
        unique_together = ('case', 'field_definition')

class TaskStatus(models.Model):
    name = models.CharField(max_length=50, unique=True)
    color_code = models.CharField(max_length=7, default='#808080')  # Hexadecimal color code
    
    def __str__(self):
        return self.name

class Task(models.Model):
    task_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='tasks')
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    status = models.ForeignKey(TaskStatus, on_delete=models.PROTECT, related_name='tasks')
    assignee = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_tasks')
    due_date = models.DateField(blank=True, null=True)
    order = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.title} ({self.case.title})"
    
    def save(self, *args, **kwargs):
        # Check if this is an existing task (not new)
        if self.pk:
            try:
                # Get the current status from the database
                old_task = Task.objects.get(pk=self.pk)
                
                # Track status changes for notifications
                if old_task.status != self.status:
                    self._status_changed = True
                    self._previous_status = old_task.status
                else:
                    self._status_changed = False
                    
                # Track assignee changes for notifications
                if old_task.assignee != self.assignee:
                    self._assignee_changed = True
                    self._previous_assignee = old_task.assignee
                else:
                    self._assignee_changed = False
                    
            except Task.DoesNotExist:
                # Handle case where somehow the PK exists but the object doesn't
                self._status_changed = False
                self._assignee_changed = False
                pass
                
        # Call the original save method
        super().save(*args, **kwargs)

class ObservableType(models.Model):
    name = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True)
    
    def __str__(self):
        return self.name

class TLPLevel(models.Model):
    name = models.CharField(max_length=20, unique=True)  # RED, AMBER, GREEN, WHITE
    description = models.TextField(blank=True)
    
    def __str__(self):
        return self.name

class PAPLevel(models.Model):
    name = models.CharField(max_length=50, unique=True)  # Block Immediately, Monitor Traffic, etc.
    description = models.TextField(blank=True)
    
    def __str__(self):
        return self.name

class Observable(models.Model):
    observable_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    value = models.TextField(db_index=True)
    type = models.ForeignKey(ObservableType, on_delete=models.PROTECT, related_name='observables')
    description = models.TextField(blank=True)
    tags = models.JSONField(default=list, blank=True)
    is_ioc = models.BooleanField(default=False)
    tlp_level = models.ForeignKey(TLPLevel, on_delete=models.SET_NULL, null=True, blank=True, related_name='observables')
    pap_level = models.ForeignKey(PAPLevel, on_delete=models.SET_NULL, null=True, blank=True, related_name='observables')
    added_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='added_observables')
    added_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.value} ({self.type.name})"
    
    class Meta:
        unique_together = ('value', 'type')

class CaseObservable(models.Model):
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='case_observables')
    observable = models.ForeignKey(Observable, on_delete=models.CASCADE, related_name='case_observables')
    sighted_at = models.DateTimeField(default=timezone.now)
    
    class Meta:
        unique_together = ('case', 'observable')

class AlertObservable(models.Model):
    alert = models.ForeignKey(Alert, on_delete=models.CASCADE, related_name='alert_observables')
    observable = models.ForeignKey(Observable, on_delete=models.CASCADE, related_name='alert_observables')
    sighted_at = models.DateTimeField(default=timezone.now)
    
    class Meta:
        unique_together = ('alert', 'observable')

class AuditLog(models.Model):
    ENTITY_TYPES = [
        ('ALERT', 'Alert'),
        ('CASE', 'Case'),
        ('TASK', 'Task'),
        ('OBSERVABLE', 'Observable'),
        ('CASE_OBSERVABLE', 'Case Observable'),
        ('ALERT_OBSERVABLE', 'Alert Observable'),
        ('CASE_COMMENT', 'Case Comment'),
        ('ALERT_COMMENT', 'Alert Comment'),
        ('CASE_MITRE_TECHNIQUE', 'Case MITRE Technique'),
        ('MISP_INSTANCE', 'MISP Instance'),
        ('REPORT_TEMPLATE', 'Report Template'),
        ('KB_ARTICLE', 'Knowledge Base Article'),
        ('TIMELINE_EVENT', 'Timeline Event'),
    ]
    
    ACTION_TYPES = [
        ('CREATE', 'Create'),
        ('UPDATE', 'Update'),
        ('DELETE', 'Delete'),
        ('STATUS_CHANGE', 'Status Change'),
        ('ASSIGN', 'Assign'),
        ('PUBLISH', 'Publish'),
        ('TEST_CONNECTION', 'Test Connection'),
        ('IMPORT', 'Import'),
        ('MISP_EXPORT', 'MISP Export'),
        ('GENERATE_REPORT', 'Generate Report'),
    ]
    
    log_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='audit_logs')
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='audit_logs')
    entity_type = models.CharField(max_length=30, choices=ENTITY_TYPES)
    entity_id = models.UUIDField()
    action_type = models.CharField(max_length=30, choices=ACTION_TYPES)
    timestamp = models.DateTimeField(auto_now_add=True)
    details_before = models.JSONField(blank=True, null=True)
    details_after = models.JSONField(blank=True, null=True)
    
    def __str__(self):
        return f"{self.action_type} on {self.entity_type} by {self.user.username if self.user else 'Unknown'}"

# Timeline models
class TimelineEvent(models.Model):
    event_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case = models.ForeignKey('Case', related_name='timeline_events', on_delete=models.CASCADE)
    organization = models.ForeignKey('Organization', related_name='timeline_events', on_delete=models.CASCADE)
    event_type = models.CharField(max_length=100)
    description = models.TextField()
    actor = models.ForeignKey(User, related_name='timeline_events', on_delete=models.SET_NULL, null=True)
    target_entity_type = models.CharField(max_length=50, null=True, blank=True)
    target_entity_id = models.CharField(max_length=255, null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    occurred_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-occurred_at']
        indexes = [
            models.Index(fields=['case']),
            models.Index(fields=['organization']),
            models.Index(fields=['event_type']),
            models.Index(fields=['occurred_at']),
        ]

# MITRE ATT&CK models
class MitreTactic(models.Model):
    tactic_id = models.CharField(max_length=50, primary_key=True)
    name = models.CharField(max_length=255)
    description = models.TextField()
    url = models.CharField(max_length=255)
    version = models.CharField(max_length=20)

    def __str__(self):
        return f"{self.tactic_id} - {self.name}"

class MitreTechnique(models.Model):
    technique_id = models.CharField(max_length=50, primary_key=True)
    name = models.CharField(max_length=255)
    description = models.TextField()
    url = models.CharField(max_length=255)
    is_subtechnique = models.BooleanField(default=False)
    parent_technique = models.ForeignKey('self', null=True, blank=True, 
                                         related_name='subtechniques', 
                                         on_delete=models.CASCADE)
    version = models.CharField(max_length=20)
    tactics = models.ManyToManyField(MitreTactic, related_name='techniques', 
                                     through='TechniqueTactic')

    def __str__(self):
        return f"{self.technique_id} - {self.name}"

class TechniqueTactic(models.Model):
    technique = models.ForeignKey(MitreTechnique, on_delete=models.CASCADE)
    tactic = models.ForeignKey(MitreTactic, on_delete=models.CASCADE)

    class Meta:
        unique_together = ('technique', 'tactic')

class CaseMitreTechnique(models.Model):
    case = models.ForeignKey('Case', related_name='mitre_techniques', on_delete=models.CASCADE)
    technique = models.ForeignKey(MitreTechnique, related_name='cases', on_delete=models.CASCADE)
    linked_by = models.ForeignKey(User, related_name='case_technique_links', on_delete=models.SET_NULL, null=True)
    linked_at = models.DateTimeField(default=timezone.now)
    context_notes = models.TextField(blank=True, null=True)

    class Meta:
        unique_together = ('case', 'technique')

class AlertMitreTechnique(models.Model):
    alert = models.ForeignKey('Alert', related_name='mitre_techniques', on_delete=models.CASCADE)
    technique = models.ForeignKey(MitreTechnique, related_name='alerts', on_delete=models.CASCADE)
    linked_by = models.ForeignKey(User, related_name='alert_technique_links', on_delete=models.SET_NULL, null=True)
    linked_at = models.DateTimeField(default=timezone.now)
    context_notes = models.TextField(blank=True, null=True)

    class Meta:
        unique_together = ('alert', 'technique')

# Knowledge Base models
class KBCategory(models.Model):
    category_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    parent_category = models.ForeignKey('self', null=True, blank=True, 
                                        related_name='subcategories', 
                                        on_delete=models.CASCADE)
    organization = models.ForeignKey('Organization', related_name='kb_categories',
                                     null=True, blank=True, on_delete=models.CASCADE)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name_plural = "KB Categories"

class KBArticle(models.Model):
    STATUS_CHOICES = (
        ('DRAFT', 'Draft'),
        ('PUBLISHED', 'Published'),
        ('ARCHIVED', 'Archived'),
    )
    
    article_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=255)
    slug = models.SlugField(max_length=255, unique=True)
    content = models.TextField()
    category = models.ForeignKey(KBCategory, related_name='articles', 
                                null=True, blank=True, on_delete=models.SET_NULL)
    organization = models.ForeignKey('Organization', related_name='kb_articles',
                                    null=True, blank=True, on_delete=models.CASCADE)
    author = models.ForeignKey(User, related_name='kb_articles', on_delete=models.SET_NULL, null=True)
    version = models.IntegerField(default=1)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='DRAFT')
    tags = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    published_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.title

    def save(self, *args, **kwargs):
        # Generate slug if not provided
        if not self.slug:
            self.slug = slugify(self.title)
            
        # Set published_at if status changes to PUBLISHED
        if self.status == 'PUBLISHED' and not self.published_at:
            self.published_at = timezone.now()
            
        super().save(*args, **kwargs)

    class Meta:
        indexes = [
            models.Index(fields=['slug']),
            models.Index(fields=['status']),
            models.Index(fields=['organization']),
            models.Index(fields=['category']),
        ]

class KBArticleVersion(models.Model):
    version_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    article = models.ForeignKey(KBArticle, related_name='versions', on_delete=models.CASCADE)
    version_number = models.IntegerField()
    title = models.CharField(max_length=255)
    content = models.TextField()
    author = models.ForeignKey(User, related_name='kb_article_versions', on_delete=models.SET_NULL, null=True)
    changed_at = models.DateTimeField(default=timezone.now)

    class Meta:
        unique_together = ('article', 'version_number')
        ordering = ['-version_number']

# Notification Framework models
class NotificationEvent(models.Model):
    """
    Define os tipos de eventos que podem disparar notificações.
    """
    event_type_id = models.AutoField(primary_key=True)
    event_name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    payload_schema = models.JSONField(default=dict, blank=True)
    
    def __str__(self):
        return self.event_name

class NotificationChannel(models.Model):
    """
    Define os canais configurados pelos usuários/organizações para receber notificações.
    """
    CHANNEL_TYPES = [
        ('WEBHOOK', 'Webhook'),
        ('EMAIL', 'Email'),
        ('SLACK', 'Slack'),
        ('MATTERMOST', 'Mattermost'),
        ('CUSTOM_HTTP', 'Custom HTTP'),
    ]
    
    channel_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey('Organization', related_name='notification_channels', on_delete=models.CASCADE)
    channel_type = models.CharField(max_length=20, choices=CHANNEL_TYPES)
    name = models.CharField(max_length=100)
    configuration = models.JSONField(default=dict)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.name} ({self.get_channel_type_display()})"
    
    class Meta:
        unique_together = ('organization', 'name')
        indexes = [
            models.Index(fields=['organization']),
            models.Index(fields=['channel_type']),
            models.Index(fields=['is_active']),
        ]

class NotificationRule(models.Model):
    """
    Define regras que ligam eventos a canais sob certas condições.
    """
    rule_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey('Organization', related_name='notification_rules', on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    event_type = models.ForeignKey(NotificationEvent, related_name='rules', on_delete=models.CASCADE)
    channel = models.ForeignKey(NotificationChannel, related_name='rules', on_delete=models.CASCADE)
    conditions = models.JSONField(default=dict, blank=True)
    message_template = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name
    
    class Meta:
        unique_together = ('organization', 'name')
        indexes = [
            models.Index(fields=['organization']),
            models.Index(fields=['event_type']),
            models.Index(fields=['is_active']),
        ]

class NotificationLog(models.Model):
    """
    Registra as notificações enviadas.
    """
    STATUS_CHOICES = [
        ('SUCCESS', 'Success'),
        ('FAILED', 'Failed'),
        ('PENDING', 'Pending'),
        ('RETRYING', 'Retrying'),
    ]
    
    log_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    rule = models.ForeignKey(NotificationRule, related_name='logs', on_delete=models.SET_NULL, null=True)
    channel = models.ForeignKey(NotificationChannel, related_name='logs', on_delete=models.SET_NULL, null=True)
    organization = models.ForeignKey('Organization', related_name='notification_logs', on_delete=models.CASCADE)
    event_payload = models.JSONField(default=dict)
    sent_at = models.DateTimeField(default=timezone.now)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    response_details = models.TextField(blank=True)
    retry_count = models.IntegerField(default=0)
    
    class Meta:
        indexes = [
            models.Index(fields=['organization']),
            models.Index(fields=['status']),
            models.Index(fields=['sent_at']),
        ]

# Metrics and Dashboard models
class Metric(models.Model):
    """
    Define métricas disponíveis para visualização em dashboards.
    """
    METRIC_TYPES = [
        ('COUNT', 'Count'),
        ('AVERAGE', 'Average'),
        ('SUM', 'Sum'),
        ('PERCENTAGE', 'Percentage'),
        ('CUSTOM', 'Custom'),
    ]
    
    metric_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100, unique=True)
    display_name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    metric_type = models.CharField(max_length=20, choices=METRIC_TYPES)
    entity_type = models.CharField(max_length=50)  # 'ALERT', 'CASE', 'TASK', etc.
    calculation_query = models.TextField(blank=True)  # SQL or query reference
    
    def __str__(self):
        return self.display_name

class MetricSnapshot(models.Model):
    """
    Armazena snapshots periódicos de métricas para visualização rápida.
    """
    snapshot_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    metric = models.ForeignKey(Metric, related_name='snapshots', on_delete=models.CASCADE)
    organization = models.ForeignKey('Organization', related_name='metric_snapshots', on_delete=models.CASCADE)
    date = models.DateField()
    granularity = models.CharField(max_length=10)  # 'DAILY', 'WEEKLY', 'MONTHLY'
    dimensions = models.JSONField(default=dict, blank=True)  # Dimension values for the metric
    value = models.DecimalField(max_digits=15, decimal_places=2)
    
    class Meta:
        indexes = [
            models.Index(fields=['metric', 'organization', 'date']),
            models.Index(fields=['date']),
            models.Index(fields=['organization']),
        ]

class Dashboard(models.Model):
    """
    Define dashboards que podem ser visualizados pelos usuários.
    """
    dashboard_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    organization = models.ForeignKey('Organization', related_name='dashboards', 
                                    on_delete=models.CASCADE, null=True, blank=True)
    is_system = models.BooleanField(default=False)  # System dashboards cannot be deleted
    layout = models.JSONField(default=dict, blank=True)  # Layout configuration
    created_by = models.ForeignKey(User, related_name='created_dashboards', 
                                 on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name
    
    class Meta:
        unique_together = ('name', 'organization')
        indexes = [
            models.Index(fields=['organization']),
            models.Index(fields=['is_system']),
        ]

class DashboardWidget(models.Model):
    """
    Define widgets que compõem um dashboard.
    """
    WIDGET_TYPES = [
        ('LINE_CHART', 'Line Chart'),
        ('BAR_CHART', 'Bar Chart'),
        ('PIE_CHART', 'Pie Chart'),
        ('TABLE', 'Table'),
        ('KPI_CARD', 'KPI Card'),
        ('COUNTER', 'Counter'),
        ('GAUGE', 'Gauge'),
    ]
    
    widget_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    dashboard = models.ForeignKey(Dashboard, related_name='widgets', on_delete=models.CASCADE)
    title = models.CharField(max_length=100)
    widget_type = models.CharField(max_length=20, choices=WIDGET_TYPES)
    metric = models.ForeignKey(Metric, related_name='widgets', on_delete=models.CASCADE)
    config = models.JSONField(default=dict)  # Widget-specific configuration
    position = models.JSONField(default=dict)  # Position in the dashboard grid
    
    def __str__(self):
        return f"{self.title} ({self.get_widget_type_display()})"

# =========================================================================
# Etapa 5: Integrações Externas e Finalização
# =========================================================================

class MISPInstance(models.Model):
    """Configuração de instância MISP para integração com threat intelligence"""
    instance_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(max_length=100)
    url = models.CharField(max_length=255)
    api_key = models.CharField(max_length=255)  # Idealmente seria armazenado de forma segura ou criptografada
    verify_ssl = models.BooleanField(default=True)
    default_distribution = models.IntegerField(default=0, choices=[
        (0, 'Your Organization Only'),
        (1, 'This Community Only'),
        (2, 'Connected Communities'),
        (3, 'All Communities')
    ])
    default_threat_level = models.IntegerField(default=2, choices=[
        (1, 'High'),
        (2, 'Medium'),
        (3, 'Low'),
        (4, 'Undefined')
    ])
    default_analysis = models.IntegerField(default=0, choices=[
        (0, 'Initial'),
        (1, 'Ongoing'),
        (2, 'Completed')
    ])
    import_filter_tags = models.JSONField(null=True, blank=True)  # Lista de tags para filtrar eventos na importação
    export_default_tags = models.JSONField(null=True, blank=True)  # Tags padrão para eventos exportados
    is_active = models.BooleanField(default=True)
    last_import_timestamp = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name} ({self.url})"

    class Meta:
        unique_together = ('organization', 'name')
        verbose_name = "MISP Instance"
        verbose_name_plural = "MISP Instances"


class MISPExport(models.Model):
    """Registra exportações de casos para o MISP"""
    export_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    misp_instance = models.ForeignKey(MISPInstance, on_delete=models.CASCADE)
    case = models.ForeignKey(Case, on_delete=models.CASCADE)
    misp_event_uuid = models.UUIDField()
    export_timestamp = models.DateTimeField(auto_now_add=True)
    exported_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    status = models.CharField(max_length=20, choices=[
        ('SUCCESS', 'Success'),
        ('FAILURE', 'Failure'),
        ('PARTIAL', 'Partial')
    ])
    error_message = models.TextField(null=True, blank=True)
    exported_observables_count = models.IntegerField(default=0)

    def __str__(self):
        return f"Export to {self.misp_instance.name} ({self.export_timestamp})"


class MISPImport(models.Model):
    """Registra importações de eventos do MISP"""
    import_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    misp_instance = models.ForeignKey(MISPInstance, on_delete=models.CASCADE)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    import_timestamp = models.DateTimeField(auto_now_add=True)
    imported_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    status = models.CharField(max_length=20, choices=[
        ('SUCCESS', 'Success'),
        ('FAILURE', 'Failure'),
        ('PARTIAL', 'Partial')
    ])
    error_message = models.TextField(null=True, blank=True)
    imported_events_count = models.IntegerField(default=0)
    imported_attributes_count = models.IntegerField(default=0)
    created_alerts_count = models.IntegerField(default=0)
    created_observables_count = models.IntegerField(default=0)
    updated_observables_count = models.IntegerField(default=0)

    def __str__(self):
        return f"Import from {self.misp_instance.name} ({self.import_timestamp})"


class ObservableMISPMapping(models.Model):
    """Mapeia observáveis para atributos MISP, permitindo sincronização"""
    observable = models.ForeignKey(Observable, on_delete=models.CASCADE)
    misp_instance = models.ForeignKey(MISPInstance, on_delete=models.CASCADE)
    misp_event_uuid = models.UUIDField()
    misp_attribute_uuid = models.UUIDField()
    last_sync_timestamp = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('observable', 'misp_instance', 'misp_attribute_uuid')


class ReportTemplate(models.Model):
    """Templates para geração de relatórios de casos"""
    template_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    output_format = models.CharField(max_length=10, choices=[
        ('MARKDOWN', 'Markdown'),
        ('DOCX', 'Microsoft Word'),
        ('PDF', 'PDF')
    ])
    template_content = models.TextField()  # Conteúdo do template com placeholders
    default_sections = models.JSONField(default=list)  # Seções a serem incluídas por padrão
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_report_templates')

    def __str__(self):
        return f"{self.name} ({self.output_format})"

    class Meta:
        unique_together = ('organization', 'name')


class GeneratedReport(models.Model):
    """Registro de relatórios gerados"""
    report_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case = models.ForeignKey(Case, on_delete=models.CASCADE)
    template = models.ForeignKey(ReportTemplate, on_delete=models.SET_NULL, null=True)
    generated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    output_format = models.CharField(max_length=10)
    file_path = models.CharField(max_length=255)  # Caminho do arquivo salvo
    file_size = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=[
        ('PENDING', 'Pending'),
        ('GENERATING', 'Generating'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed')
    ], default='PENDING')
    error_message = models.TextField(blank=True)
    included_sections = models.JSONField(default=list)

    def __str__(self):
        return f"Report for {self.case.title} ({self.created_at})"
