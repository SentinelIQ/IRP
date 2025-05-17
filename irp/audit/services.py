import json
import logging
from django.utils import timezone

from .models import AuditLog

logger = logging.getLogger(__name__)


class AuditService:
    """
    Serviço para registro de auditoria no sistema.
    Oferece métodos para criar logs de auditoria de forma centralizada.
    """
    
    @classmethod
    def log_action(cls, user, organization, entity_type, entity_id, action_type, 
                  details_before=None, details_after=None, request=None):
        """
        Registra uma ação no log de auditoria.
        
        Args:
            user: Usuário que realizou a ação
            organization: Organização do usuário
            entity_type: Tipo da entidade (ALERT, CASE, etc.)
            entity_id: ID da entidade
            action_type: Tipo da ação (CREATE, UPDATE, DELETE, etc.)
            details_before: Estado da entidade antes da ação
            details_after: Estado da entidade após a ação
            request: Objeto de requisição HTTP (opcional)
            
        Returns:
            AuditLog: Instância do log de auditoria criado
        """
        try:
            ip_address = None
            user_agent = None
            
            # Extrair informações do request se disponível
            if request:
                ip_address = cls._get_client_ip(request)
                user_agent = request.META.get('HTTP_USER_AGENT', '')
            
            # Criar o log de auditoria
            audit_log = AuditLog.objects.create(
                user=user,
                organization=organization,
                entity_type=entity_type,
                entity_id=str(entity_id),
                action_type=action_type,
                details_before=details_before,
                details_after=details_after,
                timestamp=timezone.now(),
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            return audit_log
        
        except Exception as e:
            logger.error(f"Erro ao registrar log de auditoria: {str(e)}")
            # Não propagar exceção, apenas logar o erro
            return None
    
    @classmethod
    def _get_client_ip(cls, request):
        """
        Obtém o endereço IP do cliente a partir do objeto de requisição.
        
        Args:
            request: Objeto de requisição HTTP
            
        Returns:
            str: Endereço IP do cliente
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    @classmethod
    def get_entity_history(cls, entity_type, entity_id, organization=None):
        """
        Obtém o histórico de auditoria para uma entidade específica.
        
        Args:
            entity_type: Tipo da entidade (ALERT, CASE, etc.)
            entity_id: ID da entidade
            organization: Organização (opcional, filtra por organização)
            
        Returns:
            QuerySet: QuerySet de logs de auditoria relacionados à entidade
        """
        queryset = AuditLog.objects.filter(
            entity_type=entity_type,
            entity_id=str(entity_id)
        ).order_by('-timestamp')
        
        if organization:
            queryset = queryset.filter(organization=organization)
        
        return queryset 