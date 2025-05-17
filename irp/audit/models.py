import uuid
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class AuditLog(models.Model):
    """
    Registro de auditoria para ações realizadas no sistema.
    
    Armazena informações sobre as ações dos usuários, como quem fez o quê e quando,
    permitindo rastreabilidade e responsabilização.
    """
    ACTION_TYPES = [
        ('CREATE', 'Create'),
        ('UPDATE', 'Update'),
        ('DELETE', 'Delete'),
        ('VIEW', 'View'),
        ('EXPORT', 'Export'),
        ('IMPORT', 'Import'),
        ('LOGIN', 'Login'),
        ('LOGOUT', 'Logout'),
        ('OTHER', 'Other'),
    ]
    
    log_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='audit_logs')
    organization = models.ForeignKey('accounts.Organization', on_delete=models.CASCADE, related_name='audit_logs')
    entity_type = models.CharField(max_length=50)  # ALERT, CASE, TASK, OBSERVABLE, etc.
    entity_id = models.CharField(max_length=100)  # ID da entidade afetada
    action_type = models.CharField(max_length=20, choices=ACTION_TYPES)
    details_before = models.JSONField(null=True, blank=True)  # Estado antes da ação
    details_after = models.JSONField(null=True, blank=True)   # Estado após a ação
    timestamp = models.DateTimeField(default=timezone.now)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['organization']),
            models.Index(fields=['entity_type']),
            models.Index(fields=['action_type']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['user']),
        ]
        
    def __str__(self):
        username = self.user.username if self.user else 'Sistema'
        return f"{username} - {self.action_type} {self.entity_type} ({self.timestamp})" 