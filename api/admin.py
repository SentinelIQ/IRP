from django.contrib import admin
from .models import (
    Organization, Team, Profile, Role, Permission, UserRole, RolePermission,
    AlertSeverity, AlertStatus, Alert, AlertComment, AlertCustomFieldDefinition, AlertCustomFieldValue,
    CaseSeverity, CaseStatus, CaseTemplate, Case, CaseComment, CaseCustomFieldDefinition, CaseCustomFieldValue,
    TaskStatus, Task, ObservableType, TLPLevel, PAPLevel, Observable, CaseObservable, AlertObservable, AuditLog,
    TimelineEvent, MitreTactic, MitreTechnique, CaseMitreTechnique, AlertMitreTechnique,
    KBCategory, KBArticle, KBArticleVersion,
    NotificationEvent, NotificationChannel, NotificationRule, NotificationLog,
    Metric, MetricSnapshot, Dashboard, DashboardWidget
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
        TLPLevel.objects.create(name='WHITE', description='Distribuição irrestrita')
        
    # PAP
    if not PAPLevel.objects.filter(name='PAP:RED').exists():
        PAPLevel.objects.create(name='PAP:RED', description='Bloquear imediatamente')
    if not PAPLevel.objects.filter(name='PAP:AMBER').exists():
        PAPLevel.objects.create(name='PAP:AMBER', description='Monitorar tráfego')
    if not PAPLevel.objects.filter(name='PAP:GREEN').exists():
        PAPLevel.objects.create(name='PAP:GREEN', description='Ação apenas se impacto confirmado')
    if not PAPLevel.objects.filter(name='PAP:WHITE').exists():
        PAPLevel.objects.create(name='PAP:WHITE', description='Nenhuma ação necessária')
        
    # Status de tarefas
    if not TaskStatus.objects.filter(name='ToDo').exists():
        TaskStatus.objects.create(name='ToDo', color_code='#ff0000')
    if not TaskStatus.objects.filter(name='InProgress').exists():
        TaskStatus.objects.create(name='InProgress', color_code='#ffaa00')
    if not TaskStatus.objects.filter(name='Done').exists():
        TaskStatus.objects.create(name='Done', color_code='#00ff00')
    if not TaskStatus.objects.filter(name='Blocked').exists():
        TaskStatus.objects.create(name='Blocked', color_code='#aa00ff')
        
    # Severidades de Alertas
    if not AlertSeverity.objects.filter(name='Low').exists():
        AlertSeverity.objects.create(name='Low', level_order=1, color_code='#00ff00')
    if not AlertSeverity.objects.filter(name='Medium').exists():
        AlertSeverity.objects.create(name='Medium', level_order=2, color_code='#ffff00')
    if not AlertSeverity.objects.filter(name='High').exists():
        AlertSeverity.objects.create(name='High', level_order=3, color_code='#ff9900')
    if not AlertSeverity.objects.filter(name='Critical').exists():
        AlertSeverity.objects.create(name='Critical', level_order=4, color_code='#ff0000')
        
    # Severidades de Casos
    if not CaseSeverity.objects.filter(name='Low').exists():
        CaseSeverity.objects.create(name='Low', level_order=1, color_code='#00ff00')
    if not CaseSeverity.objects.filter(name='Medium').exists():
        CaseSeverity.objects.create(name='Medium', level_order=2, color_code='#ffff00')
    if not CaseSeverity.objects.filter(name='High').exists():
        CaseSeverity.objects.create(name='High', level_order=3, color_code='#ff9900')
    if not CaseSeverity.objects.filter(name='Critical').exists():
        CaseSeverity.objects.create(name='Critical', level_order=4, color_code='#ff0000')
    
    # Status de Alertas
    if not AlertStatus.objects.filter(name='New').exists():
        AlertStatus.objects.create(name='New', is_initial_status=True, is_terminal_status=False, color_code='#0088ff')
    if not AlertStatus.objects.filter(name='In Progress').exists():
        AlertStatus.objects.create(name='In Progress', is_initial_status=False, is_terminal_status=False, color_code='#ffaa00')
    if not AlertStatus.objects.filter(name='False Positive').exists():
        AlertStatus.objects.create(name='False Positive', is_initial_status=False, is_terminal_status=True, color_code='#aaaaaa')
    if not AlertStatus.objects.filter(name='Closed').exists():
        AlertStatus.objects.create(name='Closed', is_initial_status=False, is_terminal_status=True, color_code='#00aa00')
    if not AlertStatus.objects.filter(name='Escalated').exists():
        AlertStatus.objects.create(name='Escalated', is_initial_status=False, is_terminal_status=True, color_code='#aa00ff')
    
    # Status de Casos
    if not CaseStatus.objects.filter(name='Open').exists():
        CaseStatus.objects.create(name='Open', is_initial_status=True, is_terminal_status=False, color_code='#0088ff')
    if not CaseStatus.objects.filter(name='Investigating').exists():
        CaseStatus.objects.create(name='Investigating', is_initial_status=False, is_terminal_status=False, color_code='#ffaa00')
    if not CaseStatus.objects.filter(name='Contained').exists():
        CaseStatus.objects.create(name='Contained', is_initial_status=False, is_terminal_status=False, color_code='#88cc00')
    if not CaseStatus.objects.filter(name='Remediated').exists():
        CaseStatus.objects.create(name='Remediated', is_initial_status=False, is_terminal_status=False, color_code='#88ff00')
    if not CaseStatus.objects.filter(name='Closed').exists():
        CaseStatus.objects.create(name='Closed', is_initial_status=False, is_terminal_status=True, color_code='#00aa00')
    
    # Tipos de Observáveis
    if not ObservableType.objects.filter(name='IP Address').exists():
        ObservableType.objects.create(name='IP Address', description='Endereço IP v4 ou v6', regex_validation=r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')
    if not ObservableType.objects.filter(name='Domain').exists():
        ObservableType.objects.create(name='Domain', description='Nome de domínio', regex_validation=r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')
    if not ObservableType.objects.filter(name='URL').exists():
        ObservableType.objects.create(name='URL', description='URL completa', regex_validation=r'^(https?|ftp)://[^\s/$.?#].[^\s]*$')
    if not ObservableType.objects.filter(name='MD5').exists():
        ObservableType.objects.create(name='MD5', description='Hash MD5', regex_validation=r'^[a-fA-F0-9]{32}$')
    if not ObservableType.objects.filter(name='SHA1').exists():
        ObservableType.objects.create(name='SHA1', description='Hash SHA1', regex_validation=r'^[a-fA-F0-9]{40}$')
    if not ObservableType.objects.filter(name='SHA256').exists():
        ObservableType.objects.create(name='SHA256', description='Hash SHA256', regex_validation=r'^[a-fA-F0-9]{64}$')
    if not ObservableType.objects.filter(name='Email').exists():
        ObservableType.objects.create(name='Email', description='Endereço de email', regex_validation=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

    # =========================================================================
    # Criar eventos de notificação padrão
    # =========================================================================
    logger.info('Criando eventos de notificação padrão...')
    
    # Definição de eventos padrão
    default_events = [
        {
            'event_name': 'ALERT_CREATED',
            'description': 'Disparado quando um novo alerta é criado',
            'payload_schema': {
                'alert_id': 'UUID do alerta',
                'title': 'Título do alerta',
                'description': 'Descrição do alerta',
                'severity': 'Severidade do alerta',
                'status': 'Status do alerta',
                'created_at': 'Data de criação',
                'created_by': 'Usuário que criou (se disponível)',
                'organization_id': 'ID da organização',
                'organization_name': 'Nome da organização'
            }
        },
        {
            'event_name': 'ALERT_UPDATED',
            'description': 'Disparado quando um alerta é atualizado',
            'payload_schema': {
                'alert_id': 'UUID do alerta',
                'title': 'Título do alerta',
                'description': 'Descrição do alerta',
                'severity': 'Severidade do alerta',
                'status': 'Status do alerta',
                'updated_at': 'Data de atualização',
                'updated_by': 'Usuário que atualizou',
                'organization_id': 'ID da organização',
                'organization_name': 'Nome da organização',
                'changes': 'Campos que foram alterados'
            }
        },
        {
            'event_name': 'CASE_CREATED',
            'description': 'Disparado quando um novo caso é criado',
            'payload_schema': {
                'case_id': 'UUID do caso',
                'title': 'Título do caso',
                'description': 'Descrição do caso',
                'severity': 'Severidade do caso',
                'status': 'Status do caso',
                'created_at': 'Data de criação',
                'created_by': 'Usuário que criou',
                'organization_id': 'ID da organização',
                'organization_name': 'Nome da organização'
            }
        },
        {
            'event_name': 'CASE_UPDATED',
            'description': 'Disparado quando um caso é atualizado',
            'payload_schema': {
                'case_id': 'UUID do caso',
                'title': 'Título do caso',
                'description': 'Descrição do caso',
                'severity': 'Severidade do caso',
                'status': 'Status do caso',
                'updated_at': 'Data de atualização',
                'updated_by': 'Usuário que atualizou',
                'organization_id': 'ID da organização',
                'organization_name': 'Nome da organização',
                'changes': 'Campos que foram alterados'
            }
        },
        {
            'event_name': 'CASE_STATUS_CHANGED',
            'description': 'Disparado quando o status de um caso muda',
            'payload_schema': {
                'case_id': 'UUID do caso',
                'title': 'Título do caso',
                'previous_status': 'Status anterior',
                'new_status': 'Novo status',
                'updated_at': 'Data da mudança',
                'updated_by': 'Usuário que alterou',
                'organization_id': 'ID da organização',
                'organization_name': 'Nome da organização'
            }
        },
        {
            'event_name': 'TASK_CREATED',
            'description': 'Disparado quando uma tarefa é criada',
            'payload_schema': {
                'task_id': 'UUID da tarefa',
                'case_id': 'UUID do caso associado',
                'case_title': 'Título do caso',
                'title': 'Título da tarefa',
                'description': 'Descrição da tarefa',
                'status': 'Status da tarefa',
                'created_at': 'Data de criação',
                'created_by': 'Usuário que criou',
                'organization_id': 'ID da organização',
                'organization_name': 'Nome da organização'
            }
        },
        {
            'event_name': 'TASK_UPDATED',
            'description': 'Disparado quando uma tarefa é atualizada',
            'payload_schema': {
                'task_id': 'UUID da tarefa',
                'case_id': 'UUID do caso associado',
                'case_title': 'Título do caso',
                'title': 'Título da tarefa',
                'description': 'Descrição da tarefa',
                'status': 'Status da tarefa',
                'updated_at': 'Data de atualização',
                'updated_by': 'Usuário que atualizou',
                'organization_id': 'ID da organização',
                'organization_name': 'Nome da organização',
                'changes': 'Campos que foram alterados'
            }
        },
        {
            'event_name': 'TASK_ASSIGNED',
            'description': 'Disparado quando uma tarefa é atribuída a um usuário',
            'payload_schema': {
                'task_id': 'UUID da tarefa',
                'case_id': 'UUID do caso associado',
                'case_title': 'Título do caso',
                'title': 'Título da tarefa',
                'assignee': 'Usuário atribuído',
                'assigned_by': 'Usuário que atribuiu',
                'updated_at': 'Data da atribuição',
                'organization_id': 'ID da organização',
                'organization_name': 'Nome da organização'
            }
        },
        {
            'event_name': 'COMMENT_ADDED_TO_CASE',
            'description': 'Disparado quando um comentário é adicionado a um caso',
            'payload_schema': {
                'comment_id': 'ID do comentário',
                'case_id': 'UUID do caso',
                'case_title': 'Título do caso',
                'text': 'Texto do comentário',
                'author': 'Autor do comentário',
                'created_at': 'Data de criação',
                'organization_id': 'ID da organização',
                'organization_name': 'Nome da organização'
            }
        },
        {
            'event_name': 'COMMENT_ADDED_TO_ALERT',
            'description': 'Disparado quando um comentário é adicionado a um alerta',
            'payload_schema': {
                'comment_id': 'ID do comentário',
                'alert_id': 'UUID do alerta',
                'alert_title': 'Título do alerta',
                'text': 'Texto do comentário',
                'author': 'Autor do comentário',
                'created_at': 'Data de criação',
                'organization_id': 'ID da organização',
                'organization_name': 'Nome da organização'
            }
        },
        {
            'event_name': 'DAILY_SUMMARY',
            'description': 'Resumo diário de atividades na plataforma (enviado automaticamente)',
            'payload_schema': {
                'organization_id': 'ID da organização',
                'organization_name': 'Nome da organização',
                'timestamp': 'Data e hora do resumo',
                'summary_date': 'Data do resumo',
                'new_alerts_count': 'Quantidade de novos alertas',
                'open_cases_count': 'Quantidade de casos abertos'
            }
        }
    ]
    
    # Criar eventos
    created_count = 0
    updated_count = 0
    
    for event_data in default_events:
        event, created = NotificationEvent.objects.update_or_create(
            event_name=event_data['event_name'],
            defaults={
                'description': event_data['description'],
                'payload_schema': event_data.get('payload_schema', {})
            }
        )
        
        if created:
            created_count += 1
            logger.info(f'Evento criado: {event.event_name}')
        else:
            updated_count += 1
            logger.info(f'Evento atualizado: {event.event_name}')
            
    logger.info(f'Notificações: {created_count} eventos criados, {updated_count} eventos atualizados.')

    # =========================================================================
    # Criar métricas padrão
    # =========================================================================
    logger.info('Criando métricas padrão...')
    
    # Definição de métricas padrão
    default_metrics = [
        {
            'metric_id': 'alert_count',
            'name': 'Alert Count',
            'description': 'Número de alertas criados em um período',
            'calculation_type': 'COUNT',
            'data_source': 'alert',
            'enabled': True,
            'display_order': 1
        },
        {
            'metric_id': 'alert_severity_distribution',
            'name': 'Alert Severity Distribution',
            'description': 'Distribuição de alertas por severidade',
            'calculation_type': 'DISTRIBUTION',
            'data_source': 'alert.severity',
            'enabled': True,
            'display_order': 2
        },
        {
            'metric_id': 'case_count',
            'name': 'Case Count',
            'description': 'Número de casos criados em um período',
            'calculation_type': 'COUNT',
            'data_source': 'case',
            'enabled': True,
            'display_order': 3
        },
        {
            'metric_id': 'case_severity_distribution',
            'name': 'Case Severity Distribution',
            'description': 'Distribuição de casos por severidade',
            'calculation_type': 'DISTRIBUTION',
            'data_source': 'case.severity',
            'enabled': True,
            'display_order': 4
        },
        {
            'metric_id': 'case_status_distribution',
            'name': 'Case Status Distribution',
            'description': 'Distribuição de casos por status',
            'calculation_type': 'DISTRIBUTION',
            'data_source': 'case.status',
            'enabled': True,
            'display_order': 5
        },
        {
            'metric_id': 'case_resolution_time',
            'name': 'Case Resolution Time',
            'description': 'Tempo médio para resolução de casos (em horas)',
            'calculation_type': 'AVERAGE',
            'data_source': 'case.resolution_time',
            'enabled': True,
            'display_order': 6
        },
        {
            'metric_id': 'task_completion_rate',
            'name': 'Task Completion Rate',
            'description': 'Percentual de tarefas concluídas vs. total',
            'calculation_type': 'RATIO',
            'data_source': 'task.completed',
            'enabled': True,
            'display_order': 7
        },
        {
            'metric_id': 'assignee_workload',
            'name': 'Assignee Workload',
            'description': 'Número de casos abertos por responsável',
            'calculation_type': 'DISTRIBUTION',
            'data_source': 'case.assignee',
            'enabled': True,
            'display_order': 8
        },
        {
            'metric_id': 'mitre_technique_frequency',
            'name': 'MITRE Technique Frequency',
            'description': 'Técnicas MITRE ATT&CK mais observadas',
            'calculation_type': 'FREQUENCY',
            'data_source': 'case.mitre_techniques',
            'enabled': True,
            'display_order': 9
        },
        {
            'metric_id': 'observable_type_distribution',
            'name': 'Observable Type Distribution',
            'description': 'Distribuição de observáveis por tipo',
            'calculation_type': 'DISTRIBUTION',
            'data_source': 'observable.type',
            'enabled': True,
            'display_order': 10
        }
    ]
    
    # Criar métricas
    metrics_created = 0
    metrics_updated = 0
    
    for metric_data in default_metrics:
        metric, created = Metric.objects.update_or_create(
            metric_id=metric_data['metric_id'],
            defaults={
                'name': metric_data['name'],
                'description': metric_data['description'],
                'calculation_type': metric_data['calculation_type'],
                'data_source': metric_data['data_source'],
                'enabled': metric_data['enabled'],
                'display_order': metric_data['display_order']
            }
        )
        
        if created:
            metrics_created += 1
            logger.info(f'Métrica criada: {metric.name}')
        else:
            metrics_updated += 1
            logger.info(f'Métrica atualizada: {metric.name}')
    
    logger.info(f'Métricas: {metrics_created} métricas criadas, {metrics_updated} métricas atualizadas.')

    # =========================================================================
    # Configurar tarefas periódicas do Celery Beat
    # =========================================================================
    logger.info('Configurando tarefas periódicas do Celery Beat...')
    
    # Criar ou recuperar schedules de intervalo
    daily_schedule, _ = IntervalSchedule.objects.get_or_create(
        every=1,
        period=IntervalSchedule.DAYS,
    )
    
    # Criar ou recuperar schedules de cron
    # Executa todos os dias às 1:00 AM
    daily_1am_crontab, _ = CrontabSchedule.objects.get_or_create(
        minute='0',
        hour='1',
        day_of_week='*',
        day_of_month='*',
        month_of_year='*',
    )
    
    # Executa semanalmente aos domingos às 2:00 AM
    weekly_crontab, _ = CrontabSchedule.objects.get_or_create(
        minute='0',
        hour='2',
        day_of_week='0',  # 0 = Domingo
        day_of_month='*',
        month_of_year='*',
    )
    
    # Executa no primeiro dia de cada mês às 3:00 AM
    monthly_crontab, _ = CrontabSchedule.objects.get_or_create(
        minute='0',
        hour='3',
        day_of_week='*',
        day_of_month='1',
        month_of_year='*',
    )
    
    # Executa a cada 30 dias para limpar logs antigos
    cleanup_crontab, _ = CrontabSchedule.objects.get_or_create(
        minute='0',
        hour='4',
        day_of_week='*',
        day_of_month='*/30',
        month_of_year='*',
    )
    
    # Defina as tarefas periódicas padrão
    tasks = [
        {
            'name': 'Daily Metrics Calculation',
            'task': 'api.tasks.calculate_daily_metrics',
            'crontab': daily_1am_crontab,
            'args': [],
            'kwargs': {},
            'description': 'Calcula métricas diárias para todas as organizações'
        },
        {
            'name': 'Weekly Metrics Calculation',
            'task': 'api.tasks.calculate_weekly_metrics',
            'crontab': weekly_crontab,
            'args': [],
            'kwargs': {},
            'description': 'Calcula métricas semanais para todas as organizações'
        },
        {
            'name': 'Monthly Metrics Calculation',
            'task': 'api.tasks.calculate_monthly_metrics',
            'crontab': monthly_crontab,
            'args': [],
            'kwargs': {},
            'description': 'Calcula métricas mensais para todas as organizações'
        },
        {
            'name': 'Daily Summary Notification',
            'task': 'api.tasks.process_scheduled_notifications',
            'crontab': daily_1am_crontab,
            'args': [],
            'kwargs': {},
            'description': 'Envia notificações de resumo diário para todas as organizações'
        },
        {
            'name': 'Clean Old Notification Logs',
            'task': 'api.tasks.cleanup_notification_logs',
            'crontab': cleanup_crontab,
            'args': [],
            'kwargs': {'days': 30},
            'description': 'Limpa logs de notificação mais antigos que 30 dias'
        }
    ]
    
    celery_created = 0
    celery_updated = 0
    
    # Criar ou atualizar tarefas
    for task_data in tasks:
        # Determinar se a tarefa usa intervalo ou crontab
        if 'interval' in task_data:
            defaults = {
                'interval': task_data['interval'],
                'crontab': None
            }
        else:
            defaults = {
                'interval': None,
                'crontab': task_data['crontab']
            }
        
        # Adicionar outros campos
        defaults.update({
            'task': task_data['task'],
            'kwargs': json.dumps(task_data.get('kwargs', {})),
            'args': json.dumps(task_data.get('args', [])),
            'description': task_data.get('description', ''),
            'enabled': True,
        })
        
        # Criar ou atualizar a tarefa
        task, task_created = PeriodicTask.objects.update_or_create(
            name=task_data['name'],
            defaults=defaults
        )
        
        if task_created:
            celery_created += 1
            logger.info(f'Tarefa criada: {task.name}')
        else:
            celery_updated += 1
            logger.info(f'Tarefa atualizada: {task.name}')
    
    logger.info(f'Tarefas Celery: {celery_created} tarefas criadas, {celery_updated} tarefas atualizadas.')
