from django.db import models
import uuid

class MitreTactic(models.Model):
    tactic_id = models.CharField(max_length=50, primary_key=True)
    name = models.CharField(max_length=255)
    short_name = models.CharField(max_length=100, null=True)
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
    case = models.ForeignKey('cases.Case', on_delete=models.CASCADE, related_name='mitre_module_techniques',
                          null=True, blank=True)
    alert = models.ForeignKey('alerts.Alert', on_delete=models.CASCADE, related_name='mitre_case_techniques',
                           null=True, blank=True)
    technique = models.ForeignKey(MitreTechnique, on_delete=models.CASCADE)
    added_by = models.ForeignKey('auth.User', on_delete=models.SET_NULL, null=True, related_name='+')
    added_at = models.DateTimeField(auto_now_add=True)
    notes = models.TextField(blank=True, null=True)
    
    # Novos campos
    kill_chain_phase = models.CharField(max_length=100, blank=True, null=True, 
                                        help_text="Fase da kill chain onde esta técnica foi observada")
    confidence_score = models.IntegerField(null=True, blank=True, 
                                          help_text="Nível de confiança (1-100) de que esta técnica foi usada no ataque")
    detection_method = models.CharField(max_length=255, null=True, blank=True,
                                       help_text="Como esta técnica foi detectada (ex: SIEM, EDR, análise manual)")
    artifacts = models.TextField(null=True, blank=True, 
                               help_text="Artefatos relevantes que evidenciam esta técnica (IOCs, logs, etc)")
    impact_level = models.CharField(max_length=50, null=True, blank=True,
                                  help_text="Nível de impacto desta técnica no caso (baixo, médio, alto)")
    mitigation_status = models.CharField(max_length=50, null=True, blank=True,
                                       help_text="Status da mitigação (não iniciada, em andamento, concluída)")
    
    # Campos para rastreamento temporal
    first_observed = models.DateTimeField(null=True, blank=True,
                                        help_text="Quando esta técnica foi observada pela primeira vez")
    last_observed = models.DateTimeField(null=True, blank=True,
                                       help_text="Quando esta técnica foi observada pela última vez")

    class Meta:
        unique_together = (('case', 'technique'), ('alert', 'technique'))
        verbose_name = "MITRE Technique Association"
        verbose_name_plural = "MITRE Technique Associations"
        
    def __str__(self):
        if self.case:
            return f"{self.case.title} - {self.technique.technique_id}"
        elif self.alert:
            return f"{self.alert.title} - {self.technique.technique_id}"
        else:
            return f"{self.technique.technique_id}"
            
    def clean(self):
        if not self.case and not self.alert:
            from django.core.exceptions import ValidationError
            raise ValidationError("Uma técnica MITRE deve estar associada a um caso ou um alerta.")

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
