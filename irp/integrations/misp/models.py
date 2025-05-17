import uuid
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class MISPInstance(models.Model):
    """Configuração de instância MISP para integração com threat intelligence"""
    instance_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey('accounts.Organization', on_delete=models.CASCADE, null=True, blank=True, related_name='misp_instances')
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
    misp_instance = models.ForeignKey(MISPInstance, on_delete=models.CASCADE, related_name='exports')
    case = models.ForeignKey('cases.Case', on_delete=models.CASCADE, related_name='misp_exports')
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

    class Meta:
        verbose_name = "MISP Export"
        verbose_name_plural = "MISP Exports"


class MISPImport(models.Model):
    """Registra importações de eventos do MISP"""
    import_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    misp_instance = models.ForeignKey(MISPInstance, on_delete=models.CASCADE, related_name='imports')
    organization = models.ForeignKey('accounts.Organization', on_delete=models.CASCADE, related_name='misp_imports')
    import_timestamp = models.DateTimeField(auto_now_add=True)
    imported_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    status = models.CharField(max_length=20, choices=[
        ('SUCCESS', 'Success'),
        ('FAILURE', 'Failure'),
        ('PARTIAL', 'Partial'),
        ('PENDING', 'Pending')
    ])
    error_message = models.TextField(null=True, blank=True)
    imported_events_count = models.IntegerField(default=0)
    imported_attributes_count = models.IntegerField(default=0)
    created_alerts_count = models.IntegerField(default=0)
    created_observables_count = models.IntegerField(default=0)
    updated_observables_count = models.IntegerField(default=0)

    def __str__(self):
        return f"Import from {self.misp_instance.name} ({self.import_timestamp})"

    class Meta:
        verbose_name = "MISP Import"
        verbose_name_plural = "MISP Imports"


class ObservableMISPMapping(models.Model):
    """Mapeia observáveis para atributos MISP, permitindo sincronização"""
    mapping_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    observable = models.ForeignKey('observables.Observable', on_delete=models.CASCADE, related_name='misp_mappings')
    misp_instance = models.ForeignKey(MISPInstance, on_delete=models.CASCADE, related_name='observable_mappings')
    misp_event_uuid = models.UUIDField()
    misp_attribute_uuid = models.UUIDField()
    last_sync_timestamp = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('observable', 'misp_instance', 'misp_attribute_uuid')
        verbose_name = "Observable MISP Mapping"
        verbose_name_plural = "Observable MISP Mappings"

    def __str__(self):
        return f"{self.observable} <-> MISP Attribute {self.misp_attribute_uuid}" 