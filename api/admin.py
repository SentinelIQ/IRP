from django.contrib import admin
from .models import (
    Organization, Team, Profile, Role, Permission, UserRole, RolePermission,
    AlertSeverity, AlertStatus, Alert, AlertComment, AlertCustomFieldDefinition, AlertCustomFieldValue,
    CaseSeverity, CaseStatus, CaseTemplate, Case, CaseComment, CaseCustomFieldDefinition, CaseCustomFieldValue,
    TaskStatus, Task, ObservableType, TLPLevel, PAPLevel, Observable, CaseObservable, AlertObservable, AuditLog,
    TimelineEvent, MitreTactic, MitreTechnique, CaseMitreTechnique, AlertMitreTechnique,
    KBCategory, KBArticle, KBArticleVersion,
    NotificationEvent, NotificationChannel, NotificationRule, NotificationLog,
    Metric, MetricSnapshot, Dashboard, DashboardWidget,
    MISPInstance, MISPImport, MISPExport, ObservableMISPMapping, ReportTemplate, GeneratedReport
)
from django.db.models.signals import post_migrate
from django.dispatch import receiver

# Register your models here.
admin.site.register(Organization)
admin.site.register(Team)
admin.site.register(Profile)
admin.site.register(Role)
admin.site.register(Permission)
admin.site.register(UserRole)
admin.site.register(RolePermission)

# Registrar novos modelos da Etapa 2
admin.site.register(AlertSeverity)
admin.site.register(AlertStatus)
admin.site.register(Alert)
admin.site.register(AlertComment)
admin.site.register(AlertCustomFieldDefinition)
admin.site.register(AlertCustomFieldValue)
admin.site.register(CaseSeverity)
admin.site.register(CaseStatus)
admin.site.register(CaseTemplate)
admin.site.register(Case)
admin.site.register(CaseComment)
admin.site.register(CaseCustomFieldDefinition)
admin.site.register(CaseCustomFieldValue)
admin.site.register(TaskStatus)
admin.site.register(Task)
admin.site.register(ObservableType)
admin.site.register(TLPLevel)
admin.site.register(PAPLevel)
admin.site.register(Observable)
admin.site.register(CaseObservable)
admin.site.register(AlertObservable)
admin.site.register(AuditLog)

# Registrar modelos da Etapa 3 - Enriquecimento e Contexto
admin.site.register(TimelineEvent)
admin.site.register(MitreTactic)
admin.site.register(MitreTechnique)
admin.site.register(CaseMitreTechnique)
admin.site.register(AlertMitreTechnique)
admin.site.register(KBCategory)
admin.site.register(KBArticle)
admin.site.register(KBArticleVersion)

# Registrar modelos da Etapa 4 - Comunicação, Automação e Visibilidade
admin.site.register(NotificationEvent)
admin.site.register(NotificationChannel)
admin.site.register(NotificationRule)
admin.site.register(NotificationLog)
admin.site.register(Metric)
admin.site.register(MetricSnapshot)
admin.site.register(Dashboard)
admin.site.register(DashboardWidget)

# Registrar modelos da Etapa 5 - Integrações Externas e Finalização
admin.site.register(MISPInstance)
admin.site.register(MISPImport)
admin.site.register(MISPExport)
admin.site.register(ObservableMISPMapping)
admin.site.register(ReportTemplate)
admin.site.register(GeneratedReport)

@receiver(post_migrate)
def create_default_permissions(sender, **kwargs):
    if sender.name == 'api':
        # Criação de permissões iniciais para RBAC - Etapa 1
        if not Permission.objects.filter(code='manage_organizations').exists():
            Permission.objects.create(code='manage_organizations', name='Gerenciar Organizações')
        if not Permission.objects.filter(code='manage_teams').exists():
            Permission.objects.create(code='manage_teams', name='Gerenciar Times')
        if not Permission.objects.filter(code='manage_roles').exists():
            Permission.objects.create(code='manage_roles', name='Gerenciar Papéis')
        if not Permission.objects.filter(code='manage_permissions').exists():
            Permission.objects.create(code='manage_permissions', name='Gerenciar Permissões')
        if not Permission.objects.filter(code='assign_roles').exists():
            Permission.objects.create(code='assign_roles', name='Atribuir Papéis')
        if not Permission.objects.filter(code='assign_permissions').exists():
            Permission.objects.create(code='assign_permissions', name='Atribuir Permissões')
            
        # Novas permissões para Etapa 2 - Alert Management
        if not Permission.objects.filter(code='alert:view').exists():
            Permission.objects.create(code='alert:view', name='Visualizar Alertas')
        if not Permission.objects.filter(code='alert:create').exists():
            Permission.objects.create(code='alert:create', name='Criar Alertas')
        if not Permission.objects.filter(code='alert:edit').exists():
            Permission.objects.create(code='alert:edit', name='Editar Alertas')
        if not Permission.objects.filter(code='alert:delete').exists():
            Permission.objects.create(code='alert:delete', name='Excluir Alertas')
        if not Permission.objects.filter(code='alert:comment').exists():
            Permission.objects.create(code='alert:comment', name='Comentar em Alertas')
        if not Permission.objects.filter(code='alert:escalate').exists():
            Permission.objects.create(code='alert:escalate', name='Escalar Alertas para Casos')
            
        # Novas permissões para Etapa 2 - Case Management
        if not Permission.objects.filter(code='case:view').exists():
            Permission.objects.create(code='case:view', name='Visualizar Casos')
        if not Permission.objects.filter(code='case:create').exists():
            Permission.objects.create(code='case:create', name='Criar Casos')
        if not Permission.objects.filter(code='case:edit').exists():
            Permission.objects.create(code='case:edit', name='Editar Casos')
        if not Permission.objects.filter(code='case:delete').exists():
            Permission.objects.create(code='case:delete', name='Excluir Casos')
        if not Permission.objects.filter(code='case:comment').exists():
            Permission.objects.create(code='case:comment', name='Comentar em Casos')
            
        # Novas permissões para Etapa 2 - Tasks
        if not Permission.objects.filter(code='task:view').exists():
            Permission.objects.create(code='task:view', name='Visualizar Tarefas')
        if not Permission.objects.filter(code='task:create').exists():
            Permission.objects.create(code='task:create', name='Criar Tarefas')
        if not Permission.objects.filter(code='task:edit').exists():
            Permission.objects.create(code='task:edit', name='Editar Tarefas')
        if not Permission.objects.filter(code='task:delete').exists():
            Permission.objects.create(code='task:delete', name='Excluir Tarefas')
            
        # Novas permissões para Etapa 2 - Observables
        if not Permission.objects.filter(code='observable:view').exists():
            Permission.objects.create(code='observable:view', name='Visualizar Observáveis')
        if not Permission.objects.filter(code='observable:create').exists():
            Permission.objects.create(code='observable:create', name='Criar Observáveis')
        if not Permission.objects.filter(code='observable:edit').exists():
            Permission.objects.create(code='observable:edit', name='Editar Observáveis')
        if not Permission.objects.filter(code='observable:delete').exists():
            Permission.objects.create(code='observable:delete', name='Excluir Observáveis')
            
        # Permissões para configurações da Etapa 2
        if not Permission.objects.filter(code='manage_alert_settings').exists():
            Permission.objects.create(code='manage_alert_settings', name='Gerenciar Configurações de Alertas')
        if not Permission.objects.filter(code='manage_case_settings').exists():
            Permission.objects.create(code='manage_case_settings', name='Gerenciar Configurações de Casos')
        if not Permission.objects.filter(code='manage_case_templates').exists():
            Permission.objects.create(code='manage_case_templates', name='Gerenciar Templates de Casos')
            
        # Novas permissões para Etapa 3 - Knowledge Base
        if not Permission.objects.filter(code='kb:view').exists():
            Permission.objects.create(code='kb:view', name='Visualizar Base de Conhecimento')
        if not Permission.objects.filter(code='kb:create').exists():
            Permission.objects.create(code='kb:create', name='Criar Artigos na Base de Conhecimento')
        if not Permission.objects.filter(code='kb:edit').exists():
            Permission.objects.create(code='kb:edit', name='Editar Artigos na Base de Conhecimento')
        if not Permission.objects.filter(code='kb:delete').exists():
            Permission.objects.create(code='kb:delete', name='Excluir Artigos da Base de Conhecimento')
        if not Permission.objects.filter(code='kb:publish').exists():
            Permission.objects.create(code='kb:publish', name='Publicar Artigos na Base de Conhecimento')
        if not Permission.objects.filter(code='kb:manage_categories').exists():
            Permission.objects.create(code='kb:manage_categories', name='Gerenciar Categorias da Base de Conhecimento')
            
        # Novas permissões para Etapa 3 - MITRE ATT&CK
        if not Permission.objects.filter(code='manage_mitre_data').exists():
            Permission.objects.create(code='manage_mitre_data', name='Gerenciar Dados do MITRE ATT&CK')
            
        # Novas permissões para Etapa 4 - Notificações
        if not Permission.objects.filter(code='notification:view').exists():
            Permission.objects.create(code='notification:view', name='Visualizar Notificações')
        if not Permission.objects.filter(code='notification:manage').exists():
            Permission.objects.create(code='notification:manage', name='Gerenciar Notificações e Canais')
            
        # Novas permissões para Etapa 4 - Métricas e Dashboards
        if not Permission.objects.filter(code='metrics:view').exists():
            Permission.objects.create(code='metrics:view', name='Visualizar Métricas')
        if not Permission.objects.filter(code='dashboards:view').exists():
            Permission.objects.create(code='dashboards:view', name='Visualizar Dashboards')
        if not Permission.objects.filter(code='dashboards:manage').exists():
            Permission.objects.create(code='dashboards:manage', name='Gerenciar Dashboards')
            
        # Criar níveis TLP padrão
        create_default_data()

def create_default_data():
    # Criar níveis TLP padrão se não existirem
    from .models import (
        TLPLevel, PAPLevel, TaskStatus, AlertSeverity, CaseSeverity,
        AlertStatus, CaseStatus, ObservableType, NotificationEvent,
        Metric, Organization
    )
    from django_celery_beat.models import PeriodicTask, IntervalSchedule, CrontabSchedule
    from django.utils import timezone
    import json
    import logging
    
    logger = logging.getLogger(__name__)
    
    # TLP
    if not TLPLevel.objects.filter(name='RED').exists():
        TLPLevel.objects.create(name='RED', description='Não pode ser compartilhado')
    if not TLPLevel.objects.filter(name='AMBER').exists():
        TLPLevel.objects.create(name='AMBER', description='Compartilhamento limitado')
    if not TLPLevel.objects.filter(name='GREEN').exists():
        TLPLevel.objects.create(name='GREEN', description='Compartilhamento com a comunidade')
    if not TLPLevel.objects.filter(name='WHITE').exists():
        TLPLevel.objects.create(name='WHITE', description='Compartilhamento irrestrito')
    
    # PAP
    if not PAPLevel.objects.filter(name='RED').exists():
        PAPLevel.objects.create(name='RED', description='Bloquear imediatamente')
    if not PAPLevel.objects.filter(name='AMBER').exists():
        PAPLevel.objects.create(name='AMBER', description='Monitorar ativamente')
    if not PAPLevel.objects.filter(name='GREEN').exists():
        PAPLevel.objects.create(name='GREEN', description='Monitorar passivamente')
    if not PAPLevel.objects.filter(name='WHITE').exists():
        PAPLevel.objects.create(name='WHITE', description='Informativo apenas')
    
    # Status de Tarefas
    if not TaskStatus.objects.filter(name='Não Iniciada').exists():
        TaskStatus.objects.create(name='Não Iniciada', color_code='#6c757d')
    if not TaskStatus.objects.filter(name='Em Andamento').exists():
        TaskStatus.objects.create(name='Em Andamento', color_code='#007bff')
    if not TaskStatus.objects.filter(name='Concluída').exists():
        TaskStatus.objects.create(name='Concluída', color_code='#28a745')
    if not TaskStatus.objects.filter(name='Atrasada').exists():
        TaskStatus.objects.create(name='Atrasada', color_code='#dc3545')
    if not TaskStatus.objects.filter(name='Bloqueada').exists():
        TaskStatus.objects.create(name='Bloqueada', color_code='#ffc107')
    
    # Severidade de Alertas
    if not AlertSeverity.objects.filter(name='Critical').exists():
        AlertSeverity.objects.create(name='Critical', level_order=1, color_code='#dc3545')
    if not AlertSeverity.objects.filter(name='High').exists():
        AlertSeverity.objects.create(name='High', level_order=2, color_code='#fd7e14')
    if not AlertSeverity.objects.filter(name='Medium').exists():
        AlertSeverity.objects.create(name='Medium', level_order=3, color_code='#ffc107')
    if not AlertSeverity.objects.filter(name='Low').exists():
        AlertSeverity.objects.create(name='Low', level_order=4, color_code='#28a745')
    if not AlertSeverity.objects.filter(name='Info').exists():
        AlertSeverity.objects.create(name='Info', level_order=5, color_code='#17a2b8')
    
    # Severidade de Casos
    if not CaseSeverity.objects.filter(name='Critical').exists():
        CaseSeverity.objects.create(name='Critical', level_order=1, color_code='#dc3545')
    if not CaseSeverity.objects.filter(name='High').exists():
        CaseSeverity.objects.create(name='High', level_order=2, color_code='#fd7e14')
    if not CaseSeverity.objects.filter(name='Medium').exists():
        CaseSeverity.objects.create(name='Medium', level_order=3, color_code='#ffc107')
    if not CaseSeverity.objects.filter(name='Low').exists():
        CaseSeverity.objects.create(name='Low', level_order=4, color_code='#28a745')
    
    # Status de Alertas
    if not AlertStatus.objects.filter(name='Novo').exists():
        AlertStatus.objects.create(name='Novo', description='Alerta recém-recebido', 
                                  is_default_open_status=True, is_terminal_status=False, 
                                  color_code='#007bff')
    if not AlertStatus.objects.filter(name='Em Análise').exists():
        AlertStatus.objects.create(name='Em Análise', description='Alerta sendo investigado', 
                                  is_default_open_status=False, is_terminal_status=False, 
                                  color_code='#ffc107')
    if not AlertStatus.objects.filter(name='Falso Positivo').exists():
        AlertStatus.objects.create(name='Falso Positivo', description='Alerta identificado como falso positivo', 
                                  is_default_open_status=False, is_terminal_status=True, 
                                  color_code='#6c757d')
    if not AlertStatus.objects.filter(name='Resolvido').exists():
        AlertStatus.objects.create(name='Resolvido', description='Alerta resolvido', 
                                  is_default_open_status=False, is_terminal_status=True, 
                                  color_code='#28a745')
    if not AlertStatus.objects.filter(name='Escalado').exists():
        AlertStatus.objects.create(name='Escalado', description='Alerta escalado para caso', 
                                  is_default_open_status=False, is_terminal_status=True, 
                                  color_code='#17a2b8')
    
    # Status de Casos
    if not CaseStatus.objects.filter(name='Aberto').exists():
        CaseStatus.objects.create(name='Aberto', description='Caso recém-aberto', 
                                 is_default_open_status=True, is_terminal_status=False, 
                                 color_code='#007bff')
    if not CaseStatus.objects.filter(name='Em Investigação').exists():
        CaseStatus.objects.create(name='Em Investigação', description='Caso sendo investigado', 
                                 is_default_open_status=False, is_terminal_status=False, 
                                 color_code='#ffc107')
    if not CaseStatus.objects.filter(name='Contenção').exists():
        CaseStatus.objects.create(name='Contenção', description='Fase de contenção do incidente', 
                                 is_default_open_status=False, is_terminal_status=False, 
                                 color_code='#fd7e14')
    if not CaseStatus.objects.filter(name='Erradicação').exists():
        CaseStatus.objects.create(name='Erradicação', description='Fase de erradicação do incidente', 
                                 is_default_open_status=False, is_terminal_status=False, 
                                 color_code='#6f42c1')
    if not CaseStatus.objects.filter(name='Recuperação').exists():
        CaseStatus.objects.create(name='Recuperação', description='Fase de recuperação do incidente', 
                                 is_default_open_status=False, is_terminal_status=False, 
                                 color_code='#20c997')
    if not CaseStatus.objects.filter(name='Resolvido').exists():
        CaseStatus.objects.create(name='Resolvido', description='Caso resolvido', 
                                 is_default_open_status=False, is_terminal_status=True, 
                                 color_code='#28a745')
    if not CaseStatus.objects.filter(name='Fechado').exists():
        CaseStatus.objects.create(name='Fechado', description='Caso fechado', 
                                 is_default_open_status=False, is_terminal_status=True, 
                                 color_code='#6c757d')
    
    # Tipos de Observáveis
    observable_types = [
        {'name': 'IP Address', 'description': 'Endereço IP'},
        {'name': 'Domain', 'description': 'Nome de domínio'},
        {'name': 'URL', 'description': 'URL completa'},
        {'name': 'Email', 'description': 'Endereço de email'},
        {'name': 'Hash', 'description': 'Hash genérico'},
        {'name': 'MD5', 'description': 'Hash MD5'},
        {'name': 'SHA1', 'description': 'Hash SHA1'},
        {'name': 'SHA256', 'description': 'Hash SHA256'},
        {'name': 'Filename', 'description': 'Nome de arquivo'},
        {'name': 'File Path', 'description': 'Caminho de arquivo'},
        {'name': 'Registry Key', 'description': 'Chave de registro do Windows'},
        {'name': 'User Agent', 'description': 'User Agent de navegador'},
        {'name': 'Process Name', 'description': 'Nome de processo'},
        {'name': 'CVE', 'description': 'Identificador de vulnerabilidade CVE'},
    ]
    
    for ot in observable_types:
        if not ObservableType.objects.filter(name=ot['name']).exists():
            ObservableType.objects.create(name=ot['name'], description=ot['description'])
    
    # Eventos de Notificação
    notification_events = [
        {'event_name': 'CASE_CREATED', 'description': 'Um novo caso foi criado'},
        {'event_name': 'CASE_UPDATED', 'description': 'Um caso foi atualizado'},
        {'event_name': 'CASE_STATUS_CHANGED', 'description': 'O status de um caso foi alterado'},
        {'event_name': 'CASE_ASSIGNED', 'description': 'Um caso foi atribuído a um usuário'},
        {'event_name': 'CASE_COMMENT_ADDED', 'description': 'Um comentário foi adicionado a um caso'},
        {'event_name': 'TASK_CREATED', 'description': 'Uma nova tarefa foi criada'},
        {'event_name': 'TASK_UPDATED', 'description': 'Uma tarefa foi atualizada'},
        {'event_name': 'TASK_STATUS_CHANGED', 'description': 'O status de uma tarefa foi alterado'},
        {'event_name': 'TASK_ASSIGNED', 'description': 'Uma tarefa foi atribuída a um usuário'},
        {'event_name': 'TASK_DUE_SOON', 'description': 'Uma tarefa está próxima do prazo'},
        {'event_name': 'TASK_OVERDUE', 'description': 'Uma tarefa está atrasada'},
        {'event_name': 'ALERT_CREATED', 'description': 'Um novo alerta foi recebido'},
        {'event_name': 'ALERT_STATUS_CHANGED', 'description': 'O status de um alerta foi alterado'},
        {'event_name': 'ALERT_ASSIGNED', 'description': 'Um alerta foi atribuído a um usuário'},
        {'event_name': 'ALERT_ESCALATED', 'description': 'Um alerta foi escalado para caso'},
        {'event_name': 'OBSERVABLE_ADDED', 'description': 'Um observável foi adicionado'},
        {'event_name': 'IOC_DETECTED', 'description': 'Um indicador de comprometimento foi detectado'},
        {'event_name': 'DAILY_SUMMARY', 'description': 'Resumo diário de atividades'},
        {'event_name': 'MISP_IMPORT_COMPLETED', 'description': 'Importação do MISP concluída'},
        {'event_name': 'MISP_EXPORT_COMPLETED', 'description': 'Exportação para MISP concluída'},
        {'event_name': 'REPORT_GENERATED', 'description': 'Um relatório foi gerado'},
    ]
    
    for ne in notification_events:
        if not NotificationEvent.objects.filter(event_name=ne['event_name']).exists():
            NotificationEvent.objects.create(event_name=ne['event_name'], description=ne['description'])
    
    # Métricas
    metrics = [
        {'name': 'alerts_by_severity', 'display_name': 'Alertas por Severidade', 'description': 'Distribuição de alertas por nível de severidade', 'metric_type': 'COUNT', 'entity_type': 'ALERT'},
        {'name': 'alerts_by_status', 'display_name': 'Alertas por Status', 'description': 'Distribuição de alertas por status', 'metric_type': 'COUNT', 'entity_type': 'ALERT'},
        {'name': 'cases_by_severity', 'display_name': 'Casos por Severidade', 'description': 'Distribuição de casos por nível de severidade', 'metric_type': 'COUNT', 'entity_type': 'CASE'},
        {'name': 'cases_by_status', 'display_name': 'Casos por Status', 'description': 'Distribuição de casos por status', 'metric_type': 'COUNT', 'entity_type': 'CASE'},
        {'name': 'alerts_created_over_time', 'display_name': 'Alertas Criados ao Longo do Tempo', 'description': 'Número de alertas criados ao longo do tempo', 'metric_type': 'COUNT', 'entity_type': 'ALERT'},
        {'name': 'cases_created_over_time', 'display_name': 'Casos Criados ao Longo do Tempo', 'description': 'Número de casos criados ao longo do tempo', 'metric_type': 'COUNT', 'entity_type': 'CASE'},
        {'name': 'average_case_resolution_time', 'display_name': 'Tempo Médio de Resolução de Casos', 'description': 'Tempo médio para resolver casos', 'metric_type': 'AVERAGE', 'entity_type': 'CASE'},
        {'name': 'tasks_by_status', 'display_name': 'Tarefas por Status', 'description': 'Distribuição de tarefas por status', 'metric_type': 'COUNT', 'entity_type': 'TASK'},
        {'name': 'overdue_tasks', 'display_name': 'Tarefas Atrasadas', 'description': 'Número de tarefas atrasadas', 'metric_type': 'COUNT', 'entity_type': 'TASK'},
        {'name': 'observables_by_type', 'display_name': 'Observáveis por Tipo', 'description': 'Distribuição de observáveis por tipo', 'metric_type': 'COUNT', 'entity_type': 'OBSERVABLE'},
        {'name': 'misp_import_stats', 'display_name': 'Estatísticas de Importação MISP', 'description': 'Estatísticas de importações do MISP', 'metric_type': 'COUNT', 'entity_type': 'MISP_IMPORT'},
        {'name': 'misp_export_stats', 'display_name': 'Estatísticas de Exportação MISP', 'description': 'Estatísticas de exportações para MISP', 'metric_type': 'COUNT', 'entity_type': 'MISP_EXPORT'},
        {'name': 'reports_generated', 'display_name': 'Relatórios Gerados', 'description': 'Número de relatórios gerados', 'metric_type': 'COUNT', 'entity_type': 'REPORT'},
    ]
    
    for m in metrics:
        if not Metric.objects.filter(name=m['name']).exists():
            Metric.objects.create(
                name=m['name'],
                display_name=m['display_name'],
                description=m['description'],
                metric_type=m['metric_type'],
                entity_type=m['entity_type']
            )
    
    # Configurar tarefas periódicas do Celery Beat
    try:
        # Criar agendamentos de intervalo
        daily_schedule, _ = IntervalSchedule.objects.get_or_create(
            every=1,
            period=IntervalSchedule.DAYS,
        )
        
        weekly_schedule, _ = IntervalSchedule.objects.get_or_create(
            every=7,
            period=IntervalSchedule.DAYS,
        )
        
        monthly_schedule, _ = IntervalSchedule.objects.get_or_create(
            every=30,
            period=IntervalSchedule.DAYS,
        )
        
        # Criar agendamento crontab para resumo diário (todos os dias às 8:00)
        daily_summary_schedule, _ = CrontabSchedule.objects.get_or_create(
            minute='0',
            hour='8',
            day_of_week='*',
            day_of_month='*',
            month_of_year='*',
        )
        
        # Criar agendamento crontab para limpeza de logs (todo domingo à meia-noite)
        cleanup_schedule, _ = CrontabSchedule.objects.get_or_create(
            minute='0',
            hour='0',
            day_of_week='0',
            day_of_month='*',
            month_of_year='*',
        )
        
        # Criar agendamento para importação MISP (a cada 6 horas)
        misp_import_schedule, _ = IntervalSchedule.objects.get_or_create(
            every=6,
            period=IntervalSchedule.HOURS,
        )
        
        # Definir tarefas periódicas
        tasks = [
            {
                'name': 'Calculate Daily Metrics',
                'task': 'api.tasks.calculate_metrics',
                'schedule': daily_schedule,
                'args': json.dumps(['daily']),
                'kwargs': json.dumps({}),
                'enabled': True,
            },
            {
                'name': 'Calculate Weekly Metrics',
                'task': 'api.tasks.calculate_metrics',
                'schedule': weekly_schedule,
                'args': json.dumps(['weekly']),
                'kwargs': json.dumps({}),
                'enabled': True,
            },
            {
                'name': 'Calculate Monthly Metrics',
                'task': 'api.tasks.calculate_metrics',
                'schedule': monthly_schedule,
                'args': json.dumps(['monthly']),
                'kwargs': json.dumps({}),
                'enabled': True,
            },
            {
                'name': 'Send Daily Summary Notification',
                'task': 'api.tasks.send_daily_summary',
                'crontab': daily_summary_schedule,
                'args': json.dumps([]),
                'kwargs': json.dumps({}),
                'enabled': True,
            },
            {
                'name': 'Clean Old Notification Logs',
                'task': 'api.tasks.clean_old_notification_logs',
                'crontab': cleanup_schedule,
                'args': json.dumps([30]),  # Manter logs por 30 dias
                'kwargs': json.dumps({}),
                'enabled': True,
            },
            {
                'name': 'Auto Import from MISP',
                'task': 'api.tasks.auto_import_from_misp',
                'schedule': misp_import_schedule,
                'args': json.dumps([]),
                'kwargs': json.dumps({}),
                'enabled': True,
            }
        ]
        
        # Criar ou atualizar tarefas
        for task in tasks:
            if 'crontab' in task:
                defaults = {
                    'crontab': task['crontab'],
                    'task': task['task'],
                    'args': task['args'],
                    'kwargs': task['kwargs'],
                    'enabled': task['enabled']
                }
                PeriodicTask.objects.update_or_create(
                    name=task['name'],
                    defaults=defaults
                )
            else:
                defaults = {
                    'interval': task['schedule'],
                    'task': task['task'],
                    'args': task['args'],
                    'kwargs': task['kwargs'],
                    'enabled': task['enabled']
                }
                PeriodicTask.objects.update_or_create(
                    name=task['name'],
                    defaults=defaults
                )
        
        logger.info("Tarefas periódicas do Celery Beat configuradas com sucesso.")
    except Exception as e:
        logger.error(f"Erro ao configurar tarefas periódicas do Celery Beat: {str(e)}")
    
    logger.info("Dados padrão criados com sucesso.")
