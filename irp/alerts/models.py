from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import uuid

from irp.accounts.models import Organization


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


class AlertObservable(models.Model):
    alert = models.ForeignKey(Alert, on_delete=models.CASCADE, related_name='alert_observables')
    # Temporariamente usando uma string simples para criar migrações, será atualizado quando o modelo Observable existir
    observable = models.UUIDField()  # Este será substituído por ForeignKey quando o modelo Observable existir
    sighted_at = models.DateTimeField(default=timezone.now)
    
    class Meta:
        unique_together = ('alert', 'observable')

# AlertMitreTechnique model foi movido para o módulo irp.mitre.models
