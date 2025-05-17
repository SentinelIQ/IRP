from rest_framework import serializers
from .models import AuditLog


class AuditLogSerializer(serializers.ModelSerializer):
    """
    Serializador para o modelo AuditLog.
    Adiciona campos convenientes como user_name e organization_name.
    """
    user_name = serializers.SerializerMethodField()
    organization_name = serializers.SerializerMethodField()
    
    class Meta:
        model = AuditLog
        fields = [
            'log_id', 'user', 'user_name', 'organization', 'organization_name',
            'entity_type', 'entity_id', 'action_type', 'timestamp',
            'details_before', 'details_after', 'ip_address', 'user_agent'
        ]
        read_only_fields = ['log_id', 'timestamp']
    
    def get_user_name(self, obj):
        """Retorna o nome completo do usuário ou seu nome de usuário."""
        if obj.user:
            return f"{obj.user.first_name} {obj.user.last_name}".strip() or obj.user.username
        return None
    
    def get_organization_name(self, obj):
        """Retorna o nome da organização."""
        if obj.organization:
            return obj.organization.name
        return None 