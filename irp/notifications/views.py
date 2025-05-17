import json
from django.utils import timezone
from django.db import transaction
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter, OpenApiExample

from irp.common.permissions import HasRolePermission
from irp.common.audit import audit_action
from .models import NotificationEvent, NotificationChannel, NotificationRule, NotificationLog
from .serializers import (
    NotificationEventSerializer, NotificationChannelSerializer,
    NotificationRuleSerializer, NotificationLogSerializer
)
from .services import NotificationService


@extend_schema_view(
    list=extend_schema(
        summary="Lista eventos de notificação disponíveis",
        description="Retorna todos os tipos de eventos de notificação que podem ser usados para regras de notificação.",
        tags=["Notifications"]
    ),
    retrieve=extend_schema(
        summary="Recupera detalhes de um evento de notificação",
        description="Retorna detalhes de um tipo específico de evento de notificação pelo ID.",
        tags=["Notifications"]
    )
)
class NotificationEventViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for notification events (readonly)
    """
    queryset = NotificationEvent.objects.all()
    serializer_class = NotificationEventSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    @audit_action(entity_type='NOTIFICATION_EVENT', action_type='VIEW')
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)


@extend_schema_view(
    list=extend_schema(
        summary="Lista canais de notificação",
        description="Retorna todos os canais de notificação configurados para a organização do usuário.",
        tags=["Notifications"]
    ),
    retrieve=extend_schema(
        summary="Recupera detalhes de um canal de notificação",
        description="Retorna detalhes de um canal de notificação específico pelo ID.",
        tags=["Notifications"]
    ),
    create=extend_schema(
        summary="Cria um novo canal de notificação",
        description="Cria um novo canal de notificação para a organização do usuário.",
        tags=["Notifications"]
    ),
    update=extend_schema(
        summary="Atualiza um canal de notificação",
        description="Atualiza um canal de notificação existente.",
        tags=["Notifications"]
    ),
    partial_update=extend_schema(
        summary="Atualiza parcialmente um canal de notificação",
        description="Atualiza parcialmente um canal de notificação existente.",
        tags=["Notifications"]
    ),
    destroy=extend_schema(
        summary="Remove um canal de notificação",
        description="Remove um canal de notificação existente.",
        tags=["Notifications"]
    )
)
class NotificationChannelViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing notification channels
    """
    queryset = NotificationChannel.objects.all()
    serializer_class = NotificationChannelSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'notification:manage'
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            return NotificationChannel.objects.filter(organization=user.profile.organization)
        return NotificationChannel.objects.none()
    
    @audit_action(entity_type='NOTIFICATION_CHANNEL', action_type='CREATE')
    def perform_create(self, serializer):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            serializer.save(organization=user.profile.organization)
        else:
            raise PermissionError("User must belong to an organization")
    
    @audit_action(entity_type='NOTIFICATION_CHANNEL', action_type='UPDATE')
    def perform_update(self, serializer):
        serializer.save()
    
    @audit_action(entity_type='NOTIFICATION_CHANNEL', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)
    
    @audit_action(entity_type='NOTIFICATION_CHANNEL', action_type='VIEW')
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

    @extend_schema(
        summary="Testa um canal de notificação",
        description="Envia uma notificação de teste para o canal específico para verificar se está configurado corretamente.",
        tags=["Notifications"],
        responses={
            200: OpenApiExample(
                'Sucesso',
                value={
                    'success': True,
                    'message': 'Test notification sent successfully',
                    'details': 'Notification delivered'
                }
            )
        }
    )
    @action(detail=True, methods=['post'])
    @audit_action(entity_type='NOTIFICATION_CHANNEL', action_type='TEST')
    def test(self, request, pk=None):
        """
        Test a notification channel
        """
        channel = self.get_object()
        
        # Create a test payload
        test_payload = {
            'message': 'This is a test notification',
            'timestamp': timezone.now().isoformat(),
            'sender': request.user.username
        }
        
        # Send test notification
        success, response_details = NotificationService._send_notification(
            channel=channel, 
            message="This is a test notification from your Incident Response Platform", 
            payload=test_payload
        )
        
        return Response({
            'success': success,
            'message': 'Test notification sent successfully' if success else 'Failed to send test notification',
            'details': response_details
        })


@extend_schema_view(
    list=extend_schema(
        summary="Lista regras de notificação",
        description="Retorna todas as regras de notificação configuradas para a organização do usuário.",
        tags=["Notifications"]
    ),
    retrieve=extend_schema(
        summary="Recupera detalhes de uma regra de notificação",
        description="Retorna detalhes de uma regra de notificação específica pelo ID.",
        tags=["Notifications"]
    ),
    create=extend_schema(
        summary="Cria uma nova regra de notificação",
        description="Cria uma nova regra de notificação para a organização do usuário.",
        tags=["Notifications"]
    ),
    update=extend_schema(
        summary="Atualiza uma regra de notificação",
        description="Atualiza uma regra de notificação existente.",
        tags=["Notifications"]
    ),
    partial_update=extend_schema(
        summary="Atualiza parcialmente uma regra de notificação",
        description="Atualiza parcialmente uma regra de notificação existente.",
        tags=["Notifications"]
    ),
    destroy=extend_schema(
        summary="Remove uma regra de notificação",
        description="Remove uma regra de notificação existente.",
        tags=["Notifications"]
    )
)
class NotificationRuleViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing notification rules
    """
    queryset = NotificationRule.objects.all()
    serializer_class = NotificationRuleSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'notification:manage'
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            return NotificationRule.objects.filter(organization=user.profile.organization)
        return NotificationRule.objects.none()
    
    @audit_action(entity_type='NOTIFICATION_RULE', action_type='CREATE')
    def perform_create(self, serializer):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            serializer.save(organization=user.profile.organization)
        else:
            raise PermissionError("User must belong to an organization")
    
    @audit_action(entity_type='NOTIFICATION_RULE', action_type='UPDATE')
    def perform_update(self, serializer):
        serializer.save()
    
    @audit_action(entity_type='NOTIFICATION_RULE', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)
    
    @audit_action(entity_type='NOTIFICATION_RULE', action_type='VIEW')
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

    @extend_schema(
        summary="Testa uma regra de notificação",
        description="""
        Testa uma regra de notificação com um payload de exemplo.
        Verifica se as condições são atendidas e, se forem, envia uma notificação de teste pelo canal configurado.
        """,
        tags=["Notifications"],
        request={
            'application/json': {
                'type': 'object',
                'properties': {
                    'payload': {
                        'type': 'object',
                        'description': 'Payload personalizado para o teste (opcional)'
                    }
                }
            }
        },
        responses={
            200: {
                'type': 'object',
                'properties': {
                    'conditions_met': {
                        'type': 'boolean',
                        'description': 'Se as condições da regra foram atendidas'
                    },
                    'notification_sent': {
                        'type': 'boolean',
                        'description': 'Se a notificação foi enviada com sucesso'
                    },
                    'message': {
                        'type': 'string',
                        'description': 'Mensagem de notificação formatada'
                    },
                    'details': {
                        'type': 'string',
                        'description': 'Detalhes da resposta do canal de notificação'
                    }
                }
            }
        }
    )
    @action(detail=True, methods=['post'])
    @audit_action(entity_type='NOTIFICATION_RULE', action_type='TEST')
    def test(self, request, pk=None):
        """
        Test a notification rule with a sample payload
        """
        rule = self.get_object()
        
        # Get or create a test payload
        test_payload = request.data.get('payload', {})
        if not test_payload:
            # Create default test payload based on event type
            event_name = rule.event_type.event_name
            if 'ALERT' in event_name:
                test_payload = {
                    'alert': {
                        'alert_id': 'test-alert-id',
                        'title': 'Test Alert',
                        'description': 'This is a test alert',
                        'severity': 'Critical',
                        'status': 'New',
                        'created_at': timezone.now().isoformat(),
                    },
                    'organization': {
                        'organization_id': str(rule.organization.organization_id),
                        'name': rule.organization.name,
                    }
                }
            elif 'CASE' in event_name:
                test_payload = {
                    'case': {
                        'case_id': 'test-case-id',
                        'title': 'Test Case',
                        'description': 'This is a test case',
                        'severity': 'High',
                        'status': 'Open',
                        'created_at': timezone.now().isoformat(),
                    },
                    'organization': {
                        'organization_id': str(rule.organization.organization_id),
                        'name': rule.organization.name,
                    }
                }
            else:
                test_payload = {
                    'event_name': event_name,
                    'timestamp': timezone.now().isoformat(),
                    'organization': {
                        'organization_id': str(rule.organization.organization_id),
                        'name': rule.organization.name,
                    },
                    'test': True
                }
        
        # Check conditions
        conditions_met = NotificationService._evaluate_conditions(rule.conditions, test_payload)
        
        # If conditions are met, send test notification
        if conditions_met:
            message = NotificationService._render_template(rule.message_template, test_payload) if rule.message_template else json.dumps(test_payload)
            success, response_details = NotificationService._send_notification(
                channel=rule.channel, 
                message=message, 
                payload=test_payload
            )
            
            return Response({
                'conditions_met': True,
                'notification_sent': success,
                'message': message,
                'details': response_details
            })
        else:
            return Response({
                'conditions_met': False,
                'message': 'Test payload does not meet rule conditions',
                'rule_conditions': rule.conditions,
                'test_payload': test_payload
            })


@extend_schema_view(
    list=extend_schema(
        summary="Lista logs de notificações",
        description="Retorna todos os logs de notificações enviadas para a organização do usuário.",
        tags=["Notifications"],
        parameters=[
            OpenApiParameter(
                name='status',
                description='Filtrar por status (SUCCESS, FAILED, PENDING, RETRYING)',
                required=False,
                type=str
            ),
            OpenApiParameter(
                name='rule_id',
                description='Filtrar por ID da regra',
                required=False,
                type=str
            ),
            OpenApiParameter(
                name='channel_id',
                description='Filtrar por ID do canal',
                required=False,
                type=str
            ),
            OpenApiParameter(
                name='since',
                description='Filtrar por data de envio (inicio)',
                required=False,
                type=str
            ),
            OpenApiParameter(
                name='until',
                description='Filtrar por data de envio (fim)',
                required=False,
                type=str
            )
        ]
    ),
    retrieve=extend_schema(
        summary="Recupera detalhes de um log de notificação",
        description="Retorna detalhes de um log de notificação específico pelo ID.",
        tags=["Notifications"]
    )
)
class NotificationLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for viewing notification logs (readonly)
    """
    queryset = NotificationLog.objects.all()
    serializer_class = NotificationLogSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'notification:view'
    
    @audit_action(entity_type='NOTIFICATION_LOG', action_type='VIEW')
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            queryset = NotificationLog.objects.filter(organization=user.profile.organization)
            
            # Apply filters
            status = self.request.query_params.get('status')
            rule_id = self.request.query_params.get('rule_id')
            channel_id = self.request.query_params.get('channel_id')
            since = self.request.query_params.get('since')
            until = self.request.query_params.get('until')
            
            if status:
                queryset = queryset.filter(status=status)
            
            if rule_id:
                queryset = queryset.filter(rule_id=rule_id)
                
            if channel_id:
                queryset = queryset.filter(channel_id=channel_id)
                
            if since:
                queryset = queryset.filter(sent_at__gte=since)
                
            if until:
                queryset = queryset.filter(sent_at__lte=until)
                
            return queryset.order_by('-sent_at')
            
        return NotificationLog.objects.none()


@extend_schema_view(
    trigger_event=extend_schema(
        summary="Dispara manualmente um evento de notificação",
        description="""
        Permite disparar manualmente um evento de notificação para testar o sistema ou enviar notificações ad-hoc.
        O evento será processado de acordo com as regras de notificação configuradas.
        """,
        tags=["Notifications"],
        request={
            'application/json': {
                'type': 'object',
                'properties': {
                    'event_name': {
                        'type': 'string',
                        'description': 'Nome do evento a ser disparado'
                    },
                    'payload': {
                        'type': 'object',
                        'description': 'Payload do evento'
                    }
                },
                'required': ['event_name']
            }
        },
        responses={
            200: {
                'type': 'object',
                'properties': {
                    'success': {
                        'type': 'boolean',
                        'description': 'Se o evento foi processado com sucesso'
                    },
                    'message': {
                        'type': 'string',
                        'description': 'Mensagem de resultado'
                    },
                    'notification_logs': {
                        'type': 'array',
                        'items': {
                            'type': 'string'
                        },
                        'description': 'IDs dos logs de notificação gerados'
                    }
                }
            },
            400: {
                'type': 'object',
                'properties': {
                    'detail': {
                        'type': 'string',
                        'description': 'Erro de validação'
                    }
                }
            }
        }
    )
)
class NotificationViewSet(viewsets.ViewSet):
    """
    ViewSet for triggering notifications manually and testing notification rules
    """
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'notification:manage'
    
    @action(detail=False, methods=['post'])
    @audit_action(entity_type='NOTIFICATION', action_type='TRIGGER_EVENT')
    def trigger_event(self, request):
        """
        Manually trigger a notification event
        """
        user = request.user
        if not hasattr(user, 'profile') or not user.profile.organization:
            return Response(
                {'detail': 'User not associated with an organization'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        event_name = request.data.get('event_name')
        payload = request.data.get('payload', {})
        
        if not event_name:
            return Response(
                {'detail': 'event_name is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Process the event using the notification service
            notification_logs = NotificationService.process_event(
                event_name=event_name,
                payload=payload,
                organization=user.profile.organization
            )
            
            if notification_logs:
                return Response({
                    'success': True,
                    'message': f"Event '{event_name}' processed successfully",
                    'notification_logs': notification_logs
                })
            else:
                return Response({
                    'success': False,
                    'message': f"No notifications were sent for event '{event_name}'",
                    'reason': "No matching active rules found or rule conditions not met"
                })
                
        except Exception as e:
            return Response(
                {'detail': f"Error processing event: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            ) 