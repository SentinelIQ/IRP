from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
import json
import logging

logger = logging.getLogger(__name__)

class WebSocketService:
    """
    Serviço para enviar atualizações em tempo real via WebSocket.
    """
    
    @staticmethod
    def send_update(entity_type, entity_id, event_type, data):
        """
        Envia uma atualização para todos os clientes inscritos em uma entidade específica.
        
        Args:
            entity_type (str): Tipo de entidade (ALERT, CASE, etc.)
            entity_id (str): ID da entidade
            event_type (str): Tipo de evento (create, update, delete, etc.)
            data (dict): Dados a serem enviados
        """
        try:
            # Obtém a camada de canais
            channel_layer = get_channel_layer()
            
            if not channel_layer:
                logger.error("Camada de canais WebSocket não disponível")
                return
            
            # Formata a mensagem
            message = {
                'entity_type': entity_type,
                'entity_id': str(entity_id),
                'event_type': event_type,
                'data': data
            }
            
            # Envia para o grupo específico da entidade
            group_name = f"{entity_type.lower()}_{entity_id}"
            
            async_to_sync(channel_layer.group_send)(
                group_name,
                {
                    'type': 'entity_update',
                    'data': message
                }
            )
            
            return True
        except Exception as e:
            logger.exception(f"Erro ao enviar atualização WebSocket: {e}")
            return False
    
    @staticmethod
    def send_alert_update(alert_id, event_type, data=None):
        """
        Envia uma atualização para todos os clientes inscritos em um alerta específico.
        
        Args:
            alert_id: ID do alerta
            event_type (str): Tipo de evento (create, update, delete, comment, etc.)
            data (dict, optional): Dados adicionais a serem enviados
        """
        return WebSocketService.send_update('ALERT', alert_id, event_type, data or {})
    
    @staticmethod
    def send_case_update(case_id, event_type, data=None):
        """
        Envia uma atualização para todos os clientes inscritos em um caso específico.
        
        Args:
            case_id: ID do caso
            event_type (str): Tipo de evento (create, update, delete, comment, task, etc.)
            data (dict, optional): Dados adicionais a serem enviados
        """
        return WebSocketService.send_update('CASE', case_id, event_type, data or {})
    
    @staticmethod
    def send_timeline_update(case_id, event_type, data=None):
        """
        Envia uma atualização de timeline para todos os clientes inscritos em um caso específico.
        
        Args:
            case_id: ID do caso
            event_type (str): Tipo de evento da timeline
            data (dict, optional): Dados do evento da timeline
        """
        message_data = data or {}
        message_data['timeline_event'] = True
        
        return WebSocketService.send_case_update(case_id, f'timeline_{event_type}', message_data)
    
    @staticmethod
    def send_user_notification(user_id, notification_type, data=None):
        """
        Envia uma notificação para um usuário específico.
        
        Args:
            user_id: ID do usuário
            notification_type (str): Tipo de notificação
            data (dict, optional): Dados adicionais a serem enviados
        """
        try:
            # Obtém a camada de canais
            channel_layer = get_channel_layer()
            
            if not channel_layer:
                logger.error("Camada de canais WebSocket não disponível")
                return
            
            # Formata a mensagem
            message = {
                'notification_type': notification_type,
                'data': data or {}
            }
            
            # Envia para o grupo do usuário
            group_name = f"user_{user_id}"
            
            async_to_sync(channel_layer.group_send)(
                group_name,
                {
                    'type': 'entity_update',
                    'data': message
                }
            )
            
            return True
        except Exception as e:
            logger.exception(f"Erro ao enviar notificação WebSocket: {e}")
            return False
    
    @staticmethod
    def broadcast_to_organization(organization_id, notification_type, data=None):
        """
        Envia uma notificação para todos os usuários de uma organização.
        
        Args:
            organization_id: ID da organização
            notification_type (str): Tipo de notificação
            data (dict, optional): Dados adicionais a serem enviados
        """
        try:
            # Obtém a camada de canais
            channel_layer = get_channel_layer()
            
            if not channel_layer:
                logger.error("Camada de canais WebSocket não disponível")
                return
            
            # Formata a mensagem
            message = {
                'notification_type': notification_type,
                'organization_id': str(organization_id),
                'data': data or {}
            }
            
            # Envia para o grupo da organização
            group_name = f"organization_{organization_id}"
            
            async_to_sync(channel_layer.group_send)(
                group_name,
                {
                    'type': 'entity_update',
                    'data': message
                }
            )
            
            return True
        except Exception as e:
            logger.exception(f"Erro ao enviar notificação para organização via WebSocket: {e}")
            return False 