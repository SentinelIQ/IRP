from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import uuid

from irp.accounts.models import Organization
from irp.cases.models import Case


class ReportTemplate(models.Model):
    """Templates para geração de relatórios de casos"""
    template_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, null=True, blank=True)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    output_format = models.CharField(max_length=10, choices=[
        ('MARKDOWN', 'Markdown'),
        ('DOCX', 'Microsoft Word'),
        ('PDF', 'PDF')
    ])
    template_content = models.TextField()  # Conteúdo do template com placeholders
    default_sections = models.JSONField(default=list)  # Seções a serem incluídas por padrão
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_report_templates')

    def __str__(self):
        return f"{self.name} ({self.output_format})"

    class Meta:
        unique_together = ('organization', 'name')


class GeneratedReport(models.Model):
    """Registro de relatórios gerados"""
    report_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    case = models.ForeignKey(Case, on_delete=models.CASCADE)
    template = models.ForeignKey(ReportTemplate, on_delete=models.SET_NULL, null=True)
    generated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    output_format = models.CharField(max_length=10)
    file_path = models.CharField(max_length=255)  # Caminho do arquivo salvo
    file_size = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=[
        ('PENDING', 'Pending'),
        ('GENERATING', 'Generating'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed')
    ], default='PENDING')
    error_message = models.TextField(blank=True)
    included_sections = models.JSONField(default=list)

    def __str__(self):
        return f"Report for {self.case.title} ({self.created_at})" 