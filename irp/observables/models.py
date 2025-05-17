from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import uuid

from irp.accounts.models import Organization


class ObservableType(models.Model):
    name = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True)
    
    def __str__(self):
        return self.name
    
    class Meta:
        ordering = ['name']


class TLPLevel(models.Model):
    name = models.CharField(max_length=10, unique=True)
    description = models.TextField(blank=True)
    color_code = models.CharField(max_length=7, default='#FFFFFF')
    
    def __str__(self):
        return self.name
    
    class Meta:
        ordering = ['name']


class PAPLevel(models.Model):
    name = models.CharField(max_length=50, unique=True)
    description = models.TextField(blank=True)
    color_code = models.CharField(max_length=7, default='#FFFFFF')
    
    def __str__(self):
        return self.name
    
    class Meta:
        ordering = ['name']


class Observable(models.Model):
    observable_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    type = models.ForeignKey(ObservableType, on_delete=models.PROTECT, related_name='observables')
    value = models.TextField(db_index=True)  # Valor do observável
    description = models.TextField(blank=True)
    is_ioc = models.BooleanField(default=False)  # Indicator of Compromise
    tlp_level = models.ForeignKey(TLPLevel, on_delete=models.SET_NULL, related_name='observables', null=True, blank=True)
    pap_level = models.ForeignKey(PAPLevel, on_delete=models.SET_NULL, related_name='observables', null=True, blank=True)
    first_seen_at = models.DateTimeField(default=timezone.now)
    last_seen_at = models.DateTimeField(blank=True, null=True)
    tags = models.JSONField(default=list, blank=True)
    added_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='added_observables')
    added_at = models.DateTimeField(default=timezone.now)
    reputation_score = models.IntegerField(default=0)  # Score from -100 (malicious) to 100 (trusted)
    
    def __str__(self):
        return f"{self.type}: {self.value}"
    
    class Meta:
        unique_together = ('type', 'value')
        indexes = [
            # For general queries
            models.Index(fields=['value']),
            models.Index(fields=['type', 'value']),
            models.Index(fields=['is_ioc']),
            # For TLP and PAP filtering
            models.Index(fields=['tlp_level']),
            models.Index(fields=['pap_level']),
            # For date-based filtering
            models.Index(fields=['first_seen_at']),
            models.Index(fields=['last_seen_at']),
            # For reputation filtering
            models.Index(fields=['reputation_score']),
            # For user-based filtering
            models.Index(fields=['added_by']),
        ]
