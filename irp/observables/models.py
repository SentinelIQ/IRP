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
