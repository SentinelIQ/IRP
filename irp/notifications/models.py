import uuid
from django.db import models
from django.utils import timezone


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
    organization = models.ForeignKey('accounts.Organization', related_name='notification_channels', on_delete=models.CASCADE)
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
    organization = models.ForeignKey('accounts.Organization', related_name='notification_rules', on_delete=models.CASCADE)
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
    organization = models.ForeignKey('accounts.Organization', related_name='notification_logs', on_delete=models.CASCADE)
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