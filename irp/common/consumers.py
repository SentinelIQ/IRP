import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import ObjectDoesNotExist
import uuid
import logging

logger = logging.getLogger(__name__)

class BaseIRPConsumer(AsyncWebsocketConsumer):
    """
    Consumidor base para funcionalidades compartilhadas entre entidades da plataforma.
    """
    async def connect(self):
        """
        Chamado quando o WebSocket é estabelecido.
        """
        self.user = self.scope['user']
        
        # Rejeitar conexões anônimas
        if isinstance(self.user, AnonymousUser):
            logger.warning("Tentativa de conexão anônima rejeitada")
            await self.close()
            return
        
        # Configurar grupo para o usuário
        self.user_group = f"user_{self.user.id}"
        await self.channel_layer.group_add(
            self.user_group,
            self.channel_name
        )
        
        # Adicionar ao grupo da organização, se disponível
        if hasattr(self.user, 'profile') and hasattr(self.user.profile, 'organization') and self.user.profile.organization:
            self.org_group = f"organization_{self.user.profile.organization.organization_id}"
            await self.channel_layer.group_add(
                self.org_group,
                self.channel_name
            )
        
        # Inicializar listas para rastrear assinaturas
        self.entity_groups = []
        
        # Aceitar a conexão
        await self.accept()

    async def disconnect(self, close_code):
        """
        Chamado quando a conexão WebSocket é fechada.
        """
        # Remove do grupo do usuário
        if hasattr(self, 'user_group'):
            await self.channel_layer.group_discard(
                self.user_group,
                self.channel_name
            )
        
        # Remove do grupo da organização
        if hasattr(self, 'org_group'):
            await self.channel_layer.group_discard(
                self.org_group,
                self.channel_name
            )
        
        # Remove de grupos específicos de entidade
        if hasattr(self, 'entity_groups'):
            for group in self.entity_groups:
                await self.channel_layer.group_discard(
                    group,
                    self.channel_name
                )
    
    async def receive(self, text_data):
        """
        Chamado quando o WebSocket recebe uma mensagem do cliente.
        """
        try:
            data = json.loads(text_data)
            action = data.get('action')
            
            if action == 'subscribe':
                await self.handle_subscribe(data)
            elif action == 'unsubscribe':
                await self.handle_unsubscribe(data)
            elif action == 'ping':
                # Handle simple ping to keep connection alive
                await self.send(text_data=json.dumps({'action': 'pong', 'timestamp': data.get('timestamp')}))
            else:
                await self.send(text_data=json.dumps({
                    'error': f'Ação desconhecida: {action}'
                }))
                
        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                'error': 'Formato JSON inválido'
            }))
        except Exception as e:
            logger.exception(f"Erro ao processar mensagem: {e}")
            await self.send(text_data=json.dumps({
                'error': 'Erro interno ao processar a requisição'
            }))
    
    async def handle_subscribe(self, data):
        """
        Processa a solicitação de assinatura para uma entidade específica.
        """
        entity_type = data.get('entity_type')
        entity_id = data.get('entity_id')
        include_timeline = data.get('include_timeline', False)
        
        if not entity_type or not entity_id:
            await self.send(text_data=json.dumps({
                'error': 'Parâmetros entity_type e entity_id são obrigatórios'
            }))
            return
        
        # Inicializa lista de grupos da entidade se não existir
        if not hasattr(self, 'entity_groups'):
            self.entity_groups = []
        
        # Verifica se o usuário tem permissão para acessar essa entidade
        try:
            has_permission = await self.check_entity_permission(entity_type, entity_id)
            if not has_permission:
                await self.send(text_data=json.dumps({
                    'error': f'Acesso negado para {entity_type} {entity_id}'
                }))
                return
                
            # Adiciona a um grupo para essa entidade específica
            entity_group = f"{entity_type.lower()}_{entity_id}"
            await self.channel_layer.group_add(
                entity_group,
                self.channel_name
            )
            
            # Armazena para desconexão posterior
            self.entity_groups.append(entity_group)
            
            # Se for um caso e o cliente solicitou timeline ou se a entidade for timeline
            if (entity_type.upper() == 'CASE' and include_timeline) or entity_type.upper() == 'TIMELINE':
                case_id = entity_id if entity_type.upper() == 'CASE' else data.get('case_id')
                if case_id:
                    timeline_group = f"timeline_{case_id}"
                    await self.channel_layer.group_add(
                        timeline_group,
                        self.channel_name
                    )
                    self.entity_groups.append(timeline_group)
                    
                    # Informar que timeline foi assinada também
                    await self.send(text_data=json.dumps({
                        'status': 'subscribed',
                        'entity_type': 'TIMELINE',
                        'entity_id': case_id
                    }))
            
            await self.send(text_data=json.dumps({
                'status': 'subscribed',
                'entity_type': entity_type,
                'entity_id': entity_id
            }))
            
        except Exception as e:
            logger.exception(f"Erro ao verificar permissão: {e}")
            await self.send(text_data=json.dumps({
                'error': f'Erro ao assinar {entity_type} {entity_id}: {str(e)}'
            }))
    
    async def handle_unsubscribe(self, data):
        """
        Processa a solicitação de cancelamento de assinatura para uma entidade específica.
        """
        entity_type = data.get('entity_type')
        entity_id = data.get('entity_id')
        include_timeline = data.get('include_timeline', False)
        
        if not entity_type or not entity_id:
            await self.send(text_data=json.dumps({
                'error': 'Parâmetros entity_type e entity_id são obrigatórios'
            }))
            return
        
        entity_group = f"{entity_type.lower()}_{entity_id}"
        
        # Remove do grupo específico
        await self.channel_layer.group_discard(
            entity_group,
            self.channel_name
        )
        
        # Se for um caso e o cliente solicitou desassinar timeline também
        if (entity_type.upper() == 'CASE' and include_timeline) or entity_type.upper() == 'TIMELINE':
            case_id = entity_id if entity_type.upper() == 'CASE' else data.get('case_id')
            if case_id:
                timeline_group = f"timeline_{case_id}"
                await self.channel_layer.group_discard(
                    timeline_group,
                    self.channel_name
                )
                if timeline_group in self.entity_groups:
                    self.entity_groups.remove(timeline_group)
                
                # Informar que timeline foi desassinada
                if entity_type.upper() == 'TIMELINE':
                    await self.send(text_data=json.dumps({
                        'status': 'unsubscribed',
                        'entity_type': 'TIMELINE',
                        'entity_id': case_id
                    }))
        
        # Remove da lista de grupos
        if hasattr(self, 'entity_groups') and entity_group in self.entity_groups:
            self.entity_groups.remove(entity_group)
        
        await self.send(text_data=json.dumps({
            'status': 'unsubscribed',
            'entity_type': entity_type,
            'entity_id': entity_id
        }))
    
    async def check_entity_permission(self, entity_type, entity_id):
        """
        Verifica se o usuário tem permissão para acessar uma entidade específica.
        Para ser sobrescrito por classes filhas.
        """
        return False
    
    async def entity_update(self, event):
        """
        Envia atualizações para clientes conectados a uma entidade específica.
        """
        # Apenas retransmite a mensagem para o cliente
        await self.send(text_data=json.dumps(event['data']))


class AlertConsumer(BaseIRPConsumer):
    """
    Consumidor para atualizações de alertas em tempo real.
    """
    @database_sync_to_async
    def check_entity_permission(self, entity_type, entity_id):
        if entity_type.upper() != 'ALERT':
            return False
            
        # Verificar se o alerta existe e se pertence à organização do usuário
        from irp.alerts.models import Alert
        try:
            if not hasattr(self.user, 'profile') or not self.user.profile.organization:
                return False
                
            # Verificar se o ID é um UUID válido
            try:
                alert_id = uuid.UUID(entity_id)
            except ValueError:
                return False
                
            # Verificar se o alerta existe e pertence à organização do usuário
            alert = Alert.objects.filter(
                alert_id=alert_id,
                organization=self.user.profile.organization,
                is_deleted=False
            ).exists()
            
            return alert
        except ObjectDoesNotExist:
            return False
        except Exception as e:
            logger.exception(f"Erro ao verificar permissão para alerta: {e}")
            return False


class CaseConsumer(BaseIRPConsumer):
    """
    Consumidor para atualizações de casos em tempo real.
    """
    @database_sync_to_async
    def check_entity_permission(self, entity_type, entity_id):
        if entity_type.upper() not in ['CASE', 'TIMELINE']:
            return False
            
        # Para a timeline, precisamos do ID do caso
        case_id = entity_id
        if entity_type.upper() == 'TIMELINE':
            case_id = entity_id  # O ID da timeline é o ID do caso
        
        # Verificar se o caso existe e se pertence à organização do usuário
        from irp.cases.models import Case
        try:
            if not hasattr(self.user, 'profile') or not self.user.profile.organization:
                return False
                
            # Verificar se o ID é um UUID válido
            try:
                uuid_case_id = uuid.UUID(case_id)
            except ValueError:
                return False
                
            # Verificar se o caso existe e pertence à organização do usuário
            case = Case.objects.filter(
                case_id=uuid_case_id,
                organization=self.user.profile.organization
            ).exists()
            
            return case
        except ObjectDoesNotExist:
            return False
        except Exception as e:
            logger.exception(f"Erro ao verificar permissão para caso/timeline: {e}")
            return False 