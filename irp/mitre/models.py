from django.db import models
import uuid

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
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case = models.ForeignKey('cases.Case', on_delete=models.CASCADE, related_name='mitre_module_techniques')
    technique = models.ForeignKey(MitreTechnique, on_delete=models.CASCADE)
    added_by = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True, related_name='+')
    added_at = models.DateTimeField(auto_now_add=True)
    notes = models.TextField(blank=True, null=True)

    class Meta:
        unique_together = ('case', 'technique')
        
    def __str__(self):
        return f"{self.case.title} - {self.technique.technique_id}"

class AlertMitreTechnique(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    alert = models.ForeignKey('alerts.Alert', on_delete=models.CASCADE, related_name='mitre_module_techniques')
    technique = models.ForeignKey(MitreTechnique, on_delete=models.CASCADE)
    added_by = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True, related_name='+')
    added_at = models.DateTimeField(auto_now_add=True)
    notes = models.TextField(blank=True, null=True)

    class Meta:
        unique_together = ('alert', 'technique')
        
    def __str__(self):
        return f"{self.alert.title} - {self.technique.technique_id}"
