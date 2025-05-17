import functools
import logging
from django.utils import timezone

from irp.audit.services import AuditService
from irp.audit.models import AuditLog

logger = logging.getLogger(__name__)

def audit_action(entity_type, action_type):
    """
    Decorator para registrar ações de auditoria.
    
    Args:
        entity_type: Tipo da entidade (ALERT, CASE, etc.)
        action_type: Tipo da ação (CREATE, UPDATE, DELETE, etc.)
    
    Returns:
        Decorator que registra a ação no log de auditoria
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(self, request, *args, **kwargs):
            # Armazenar estado original se for uma atualização
            original_instance = None
            instance_id = kwargs.get('pk')
            
            # Para ações de atualização ou exclusão, obter o estado original
            if action_type in ['UPDATE', 'DELETE'] and instance_id and hasattr(self, 'get_object'):
                try:
                    original_instance = self.get_object()
                    details_before = getattr(original_instance, 'to_dict', lambda: str(original_instance))()
                except Exception as e:
                    logger.error(f"Erro ao obter instância original: {str(e)}")
                    details_before = None
            else:
                details_before = None
            
            # Executar a função original
            result = func(self, request, *args, **kwargs)
            
            try:
                # Obter o usuário e a organização
                user = request.user
                organization = getattr(request.user, 'organization', None)
                
                # Obter ID da entidade e detalhes após
                if action_type == 'CREATE' and hasattr(result, 'data'):
                    # Para criações, o ID vem do resultado
                    entity_id = result.data.get('id')
                    details_after = result.data
                elif hasattr(self, 'get_object') and instance_id:
                    # Para atualizações/exclusões, usar o ID dos kwargs
                    entity_id = instance_id
                    
                    if action_type == 'UPDATE':
                        try:
                            # Recarregar o objeto após a atualização
                            updated_instance = self.get_queryset().get(pk=instance_id)
                            details_after = getattr(updated_instance, 'to_dict', lambda: str(updated_instance))()
                        except Exception:
                            details_after = None
                    else:
                        # Para exclusões, não há estado posterior
                        details_after = None
                else:
                    # Caso não seja possível determinar o ID
                    entity_id = None
                    details_after = None
                
                # Registrar no log de auditoria se tiver ID da entidade
                if entity_id:
                    AuditService.log_action(
                        user=user,
                        organization=organization,
                        entity_type=entity_type,
                        entity_id=entity_id,
                        action_type=action_type,
                        details_before=details_before,
                        details_after=details_after,
                        request=request
                    )
            
            except Exception as e:
                # Não falhar a operação principal se o log de auditoria falhar
                logger.error(f"Erro ao registrar auditoria: {str(e)}")
            
            return result
        
        return wrapper
    
    return decorator 