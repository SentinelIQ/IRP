from django.contrib import admin
from .models import AuditLog


class AuditLogAdmin(admin.ModelAdmin):
    """
    Configuração de administração para o modelo AuditLog.
    """
    list_display = ['log_id', 'get_user_display', 'get_organization_display', 'entity_type', 
                   'entity_id', 'action_type', 'timestamp']
    list_filter = ['action_type', 'entity_type', 'timestamp', 'user', 'organization']
    search_fields = ['entity_id', 'details_after', 'user__username', 'user__email']
    readonly_fields = ['log_id', 'user', 'organization', 'entity_type', 'entity_id', 
                      'action_type', 'details_before', 'details_after', 'timestamp',
                      'ip_address', 'user_agent']
    date_hierarchy = 'timestamp'
    
    def get_user_display(self, obj):
        if obj.user:
            return f"{obj.user.first_name} {obj.user.last_name}".strip() or obj.user.username
        return "Sistema"
    get_user_display.short_description = 'Usuário'
    
    def get_organization_display(self, obj):
        if obj.organization:
            return obj.organization.name
        return "N/A"
    get_organization_display.short_description = 'Organização'
    
    def has_add_permission(self, request):
        return False  # Não permitir adição manual de logs
    
    def has_change_permission(self, request, obj=None):
        return False  # Não permitir alteração de logs


admin.site.register(AuditLog, AuditLogAdmin) 