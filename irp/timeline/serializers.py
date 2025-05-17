from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import TimelineEvent

User = get_user_model()

class UserMiniSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ['id', 'username', 'full_name', 'email']
        
    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip() or obj.username

class TimelineEventSerializer(serializers.ModelSerializer):
    actor_details = serializers.SerializerMethodField()
    event_icon = serializers.SerializerMethodField()
    event_color = serializers.SerializerMethodField()
    is_interactive = serializers.SerializerMethodField()
    formatted_date = serializers.SerializerMethodField()
    
    class Meta:
        model = TimelineEvent
        fields = [
            'event_id', 'case', 'event_type', 'description', 
            'target_entity_type', 'target_entity_id', 'metadata',
            'occurred_at', 'formatted_date', 'is_important',
            'actor_details', 'event_icon', 'event_color', 'is_interactive'
        ]
    
    def get_actor_details(self, obj):
        if obj.actor:
            return UserMiniSerializer(obj.actor).data
        return None
    
    def get_formatted_date(self, obj):
        return obj.occurred_at.strftime("%d/%m/%Y %H:%M")
    
    def get_event_icon(self, obj):
        """
        Retorna o nome do ícone apropriado para o tipo de evento.
        Estes nomes de ícones são baseados em bibliotecas comuns como FontAwesome ou Material Icons.
        """
        event_type = obj.event_type.upper()
        
        icon_mapping = {
            'CASE_CREATED': 'folder-plus',
            'CASE_UPDATED': 'folder-open',
            'CASE_CLOSED': 'folder-check',
            'STATUS_CHANGED': 'exchange-alt',
            'USER_ASSIGNED': 'user-check',
            
            'TASK_CREATED': 'tasks',
            'TASK_UPDATED': 'edit',
            'TASK_COMPLETED': 'check-circle',
            'TASK_STATUS_CHANGED': 'sync',
            'TASK_ASSIGNED': 'user-tag',
            'TASK_DELETED': 'trash',
            
            'COMMENT_ADDED': 'comment',
            'COMMENT_UPDATED': 'comment-dots',
            'COMMENT_DELETED': 'comment-slash',
            
            'OBSERVABLE_ADDED': 'eye',
            'OBSERVABLE_UPDATED': 'search-plus',
            'OBSERVABLE_REMOVED': 'eye-slash',
            'OBSERVABLE_EXTRACTED': 'magic',
            
            'MITRE_TECHNIQUE_ADDED': 'shield-alt',
            'MITRE_TECHNIQUE_REMOVED': 'shield',
            
            'ALERT_ESCALATED': 'arrow-circle-up',
            'ALERT_LINKED': 'link',
            
            'REPORT_GENERATED': 'file-alt',
            
            'MANUAL_EVENT': 'edit',
            'IMPORTANT_UPDATE': 'exclamation-circle'
        }
        
        return icon_mapping.get(event_type, 'calendar')
    
    def get_event_color(self, obj):
        """
        Retorna uma cor associada ao tipo de evento para destaque visual.
        """
        event_type = obj.event_type.upper()
        
        color_mapping = {
            'CASE_CREATED': '#4CAF50',  # Verde
            'CASE_UPDATED': '#2196F3',  # Azul
            'CASE_CLOSED': '#607D8B',   # Cinza Azulado
            'STATUS_CHANGED': '#3F51B5', # Índigo
            
            'TASK_CREATED': '#00BCD4',  # Ciano
            'TASK_COMPLETED': '#8BC34A', # Verde claro
            'TASK_DELETED': '#F44336',  # Vermelho
            
            'COMMENT_ADDED': '#9C27B0',  # Roxo
            
            'OBSERVABLE_ADDED': '#FF9800', # Laranja
            'OBSERVABLE_EXTRACTED': '#FF5722', # Laranja Escuro
            
            'MITRE_TECHNIQUE_ADDED': '#795548', # Marrom
            
            'ALERT_ESCALATED': '#E91E63', # Rosa
            
            'REPORT_GENERATED': '#009688', # Verde azulado
            
            'MANUAL_EVENT': '#9E9E9E',  # Cinza
            'IMPORTANT_UPDATE': '#FFC107' # Amarelo
        }
        
        return color_mapping.get(event_type, '#9E9E9E')  # Cinza como padrão
    
    def get_is_interactive(self, obj):
        """
        Determina se o evento pode ter interação na UI (como cliques para navegar).
        """
        has_target = bool(obj.target_entity_type and obj.target_entity_id)
        
        # Tipos de eventos que geralmente têm interação
        interactive_types = [
            'TASK_CREATED', 'TASK_UPDATED', 'TASK_COMPLETED',
            'COMMENT_ADDED', 'COMMENT_UPDATED',
            'OBSERVABLE_ADDED', 'OBSERVABLE_EXTRACTED',
            'MITRE_TECHNIQUE_ADDED',
            'ALERT_ESCALATED', 'ALERT_LINKED',
            'REPORT_GENERATED'
        ]
        
        return has_target or obj.event_type.upper() in interactive_types

class TimelineEventCreateSerializer(serializers.ModelSerializer):
    """
    Serializador usado para criar eventos manualmente na timeline.
    """
    class Meta:
        model = TimelineEvent
        fields = ['event_type', 'description', 'metadata', 'occurred_at', 'is_important']
        extra_kwargs = {
            'event_type': {'required': True},
            'description': {'required': True}
        }
