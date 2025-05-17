import uuid
from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone

User = get_user_model()

class TimelineEvent(models.Model):
    event_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case = models.ForeignKey('cases.Case', related_name='timeline_events', on_delete=models.CASCADE)
    organization = models.ForeignKey('accounts.Organization', related_name='timeline_events', on_delete=models.CASCADE)
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
