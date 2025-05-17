from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import uuid
from datetime import timedelta

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


class ScheduledReport(models.Model):
    """Configuração para geração automática de relatórios"""
    schedule_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_scheduled_reports')
    
    # Filtro de casos
    case_filter = models.JSONField(default=dict)  # Exemplo: {"status": ["OPEN", "IN_PROGRESS"], "severity": ["HIGH"]}
    
    # Configurações do relatório
    template = models.ForeignKey(ReportTemplate, on_delete=models.SET_NULL, null=True)
    output_format = models.CharField(max_length=10, choices=[
        ('MARKDOWN', 'Markdown'),
        ('DOCX', 'Microsoft Word'),
        ('PDF', 'PDF')
    ])
    include_sections = models.JSONField(default=list)
    include_attachments = models.BooleanField(default=False)
    custom_header = models.TextField(blank=True)
    custom_footer = models.TextField(blank=True)
    
    # Configurações de agendamento
    frequency = models.CharField(max_length=20, choices=[
        ('DAILY', 'Daily'),
        ('WEEKLY', 'Weekly'),
        ('MONTHLY', 'Monthly'),
        ('QUARTERLY', 'Quarterly')
    ])
    day_of_week = models.IntegerField(null=True, blank=True)  # 0-6 (segunda a domingo)
    day_of_month = models.IntegerField(null=True, blank=True)  # 1-31
    hour = models.IntegerField(default=0)  # 0-23
    minute = models.IntegerField(default=0)  # 0-59
    
    # Configurações de notificação
    notify_users = models.ManyToManyField(User, related_name='scheduled_report_notifications', blank=True)
    send_email = models.BooleanField(default=True)
    
    # Status e controle
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_run = models.DateTimeField(null=True, blank=True)
    next_run = models.DateTimeField(null=True, blank=True)
    
    def __str__(self):
        return f"{self.name} ({self.frequency})"
    
    def save(self, *args, **kwargs):
        # Calcular próxima execução ao salvar
        if not self.next_run:
            self.calculate_next_run()
        super().save(*args, **kwargs)
    
    def calculate_next_run(self):
        """Calcula a próxima data de execução baseada na frequência configurada"""
        now = timezone.now()
        
        if self.frequency == 'DAILY':
            next_run = now.replace(hour=self.hour, minute=self.minute, second=0, microsecond=0)
            if next_run <= now:
                next_run = next_run + timedelta(days=1)
                
        elif self.frequency == 'WEEKLY':
            # day_of_week: 0=segunda, 1=terça, ..., 6=domingo
            current_weekday = now.weekday()
            days_ahead = self.day_of_week - current_weekday
            if days_ahead <= 0:  # Próxima semana
                days_ahead += 7
                
            next_run = now.replace(hour=self.hour, minute=self.minute, second=0, microsecond=0)
            next_run = next_run + timedelta(days=days_ahead)
            
        elif self.frequency == 'MONTHLY':
            # Obter o próximo mês
            if now.month == 12:
                next_month = 1
                next_year = now.year + 1
            else:
                next_month = now.month + 1
                next_year = now.year
                
            # Lidar com dias inválidos (ex: 31 de fevereiro)
            import calendar
            last_day = calendar.monthrange(next_year, next_month)[1]
            day = min(self.day_of_month, last_day)
            
            next_run = now.replace(year=next_year, month=next_month, day=day,
                                   hour=self.hour, minute=self.minute, second=0, microsecond=0)
                
        elif self.frequency == 'QUARTERLY':
            # Determinar o próximo trimestre
            current_quarter = (now.month - 1) // 3
            next_quarter_month = (current_quarter + 1) % 4 * 3 + 1  # 1=Jan, 4=Apr, 7=Jul, 10=Out
            
            next_year = now.year
            if current_quarter == 3:  # 4º trimestre (Out-Dez)
                next_year += 1
                
            # Lidar com dias inválidos
            import calendar
            last_day = calendar.monthrange(next_year, next_quarter_month)[1]
            day = min(self.day_of_month, last_day)
            
            next_run = now.replace(year=next_year, month=next_quarter_month, day=day,
                                   hour=self.hour, minute=self.minute, second=0, microsecond=0)
        
        self.next_run = next_run 