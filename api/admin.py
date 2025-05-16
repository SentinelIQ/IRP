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
            
        # Criar níveis TLP padrão
        create_default_data()

def create_default_data():
    # Criar níveis TLP padrão se não existirem
    from .models import TLPLevel, PAPLevel, TaskStatus, AlertSeverity, CaseSeverity
    
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
