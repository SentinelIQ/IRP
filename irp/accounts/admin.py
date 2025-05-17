from django.contrib import admin
from .models import Organization, Team, Profile, Role, Permission, UserRole, RolePermission, LDAPConfig
from django.db.models.signals import post_migrate
from django.dispatch import receiver

# Register models
admin.site.register(Organization)
admin.site.register(Team)
admin.site.register(Profile)
admin.site.register(Role)
admin.site.register(Permission)
admin.site.register(UserRole)
admin.site.register(RolePermission)

class LDAPConfigAdmin(admin.ModelAdmin):
    list_display = ('name', 'organization', 'server_url', 'is_active', 'last_sync_status', 'last_sync_timestamp')
    list_filter = ('is_active', 'last_sync_status', 'organization')
    search_fields = ('name', 'server_url')
    readonly_fields = ('last_sync_status', 'last_sync_message', 'last_sync_timestamp', 'created_at', 'updated_at')
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'organization', 'is_active')
        }),
        ('Connection Settings', {
            'fields': ('server_url', 'bind_dn', 'bind_password', 'ldap_tls_enabled', 'ldap_tls_ca_cert_path')
        }),
        ('User Synchronization', {
            'fields': ('user_base_dn', 'user_search_filter', 'user_attribute_mapping', 
                     'enable_user_provisioning', 'enable_user_deprovisioning', 'enable_delegated_authentication')
        }),
        ('Group Synchronization', {
            'fields': ('group_base_dn', 'group_search_filter', 'group_attribute_mapping', 
                     'group_to_organization_team_mapping')
        }),
        ('Sync Schedule & Status', {
            'fields': ('sync_interval_minutes', 'last_sync_status', 'last_sync_message', 'last_sync_timestamp')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def save_model(self, request, obj, form, change):
        # Securely handle password, encrypt if needed
        super().save_model(request, obj, form, change)

admin.site.register(LDAPConfig, LDAPConfigAdmin)

@receiver(post_migrate)
def create_default_permissions(sender, **kwargs):
    if sender.name == 'irp.accounts':
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
            
        # Novas permissões para LDAP/AD
        if not Permission.objects.filter(code='ldap:manage').exists():
            Permission.objects.create(code='ldap:manage', name='Gerenciar Configurações LDAP/AD')
        if not Permission.objects.filter(code='ldap:sync').exists():
            Permission.objects.create(code='ldap:sync', name='Executar Sincronização LDAP/AD')
