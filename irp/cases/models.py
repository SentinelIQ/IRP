from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import uuid

from irp.accounts.models import Organization
from irp.mitre.models import MitreTechnique
from irp.alerts.models import Alert
from irp.observables.models import Observable

class CaseSeverity(models.Model):
    name = models.CharField(max_length=50, unique=True)
    level_order = models.IntegerField()
    color_code = models.CharField(max_length=7)  # Hexadecimal color code
    
    def __str__(self):
        return self.name
    
    class Meta:
        verbose_name_plural = 'Case Severities'
        ordering = ['level_order']

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
        indexes = [
            models.Index(fields=['organization', 'is_default_open_status']),
            models.Index(fields=['organization', 'is_terminal_status']),
        ]

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
    
    class Meta:
        indexes = [
            models.Index(fields=['organization']),
        ]

class TaskStatus(models.Model):
    name = models.CharField(max_length=50, unique=True)
    color_code = models.CharField(max_length=7, default='#808080')  # Hexadecimal color code
    
    def __str__(self):
        return self.name
    
    class Meta:
        ordering = ['name']

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
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            # Core filters used frequently
            models.Index(fields=['organization']),
            models.Index(fields=['organization', 'status']),
            models.Index(fields=['organization', 'severity']),
            models.Index(fields=['organization', 'assignee']),
            models.Index(fields=['reporter']),
            # Date range filters
            models.Index(fields=['organization', 'created_at']),
            models.Index(fields=['organization', 'updated_at']),
            models.Index(fields=['organization', 'closed_at']),
            # For status transitions
            models.Index(fields=['status', 'updated_at']),
        ]
    
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
    
    class Meta:
        ordering = ['created_at']
        indexes = [
            models.Index(fields=['case', 'created_at']),
            models.Index(fields=['user', 'created_at']),
        ]

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
        indexes = [
            models.Index(fields=['organization', 'field_type']),
            models.Index(fields=['organization', 'is_filterable']),
        ]

class CaseCustomFieldValue(models.Model):
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='custom_field_values')
    field_definition = models.ForeignKey(CaseCustomFieldDefinition, on_delete=models.CASCADE, related_name='field_values')
    value_text = models.TextField(blank=True, null=True)
    value_number = models.DecimalField(blank=True, null=True, max_digits=20, decimal_places=5)
    value_boolean = models.BooleanField(blank=True, null=True)
    value_date = models.DateTimeField(blank=True, null=True)
    
    class Meta:
        unique_together = ('case', 'field_definition')
        indexes = [
            models.Index(fields=['case', 'field_definition']),
            # For filtering on text values
            models.Index(fields=['field_definition', 'value_text']),
            # For filtering on numeric values
            models.Index(fields=['field_definition', 'value_number']),
            # For filtering on boolean values
            models.Index(fields=['field_definition', 'value_boolean']),
            # For filtering on date values
            models.Index(fields=['field_definition', 'value_date']),
        ]

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
    
    class Meta:
        ordering = ['case', 'order', 'created_at']
        indexes = [
            models.Index(fields=['case', 'status']),
            models.Index(fields=['case', 'assignee']),
            models.Index(fields=['case', 'due_date']),
            models.Index(fields=['assignee', 'due_date']),
            models.Index(fields=['status', 'due_date']),
        ]
    
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

class CaseObservable(models.Model):
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name='case_observables')
    observable = models.ForeignKey(Observable, on_delete=models.CASCADE, related_name='case_observables')
    sighted_at = models.DateTimeField(default=timezone.now)
    
    class Meta:
        unique_together = ('case', 'observable')
        indexes = [
            models.Index(fields=['case', 'sighted_at']),
            models.Index(fields=['observable', 'sighted_at']),
        ]

class CaseMitreTechnique(models.Model):
    case = models.ForeignKey(Case, related_name='case_module_techniques', on_delete=models.CASCADE)
    technique = models.ForeignKey(MitreTechnique, related_name='technique_cases', on_delete=models.CASCADE)
    linked_by = models.ForeignKey(User, related_name='case_technique_links', on_delete=models.SET_NULL, null=True)
    linked_at = models.DateTimeField(default=timezone.now)
    context_notes = models.TextField(blank=True, null=True)
    
    class Meta:
        unique_together = ('case', 'technique')
        indexes = [
            models.Index(fields=['case']),
            models.Index(fields=['technique']),
            models.Index(fields=['linked_by']),
            models.Index(fields=['linked_at']),
        ] 