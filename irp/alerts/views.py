from rest_framework import viewsets, permissions, status
from rest_framework.response import Response
from rest_framework.decorators import action
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.db import models
import uuid
from rest_framework import serializers

from .models import (
    AlertSeverity, AlertStatus, Alert, AlertComment,
    AlertCustomFieldDefinition, AlertCustomFieldValue,
    AlertObservable
)
from irp.mitre.models import MitreTechnique, AlertMitreTechnique
# AlertMitreTechnique foi movido para irp.mitre.models
from .serializers import (
    AlertSeveritySerializer, AlertStatusSerializer, AlertSerializer,
    AlertCommentSerializer, AlertCustomFieldDefinitionSerializer,
    AlertCustomFieldValueSerializer, AlertObservableSerializer
)
# AlertMitreTechniqueSerializer foi movido para irp.mitre.serializers
from irp.common.permissions import HasRolePermission
from irp.observables.services import ObservableService
from irp.common.websocket import WebSocketService

# This will be properly implemented in the audit module
from irp.common.audit import audit_action


class AlertSeverityViewSet(viewsets.ModelViewSet):
    queryset = AlertSeverity.objects.all()
    serializer_class = AlertSeveritySerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_alert_settings'


class AlertStatusViewSet(viewsets.ModelViewSet):
    queryset = AlertStatus.objects.all()
    serializer_class = AlertStatusSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_alert_settings'
    
    def get_queryset(self):
        # Retorna status globais (organization=None) ou específicos da organização
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            org_id = user.profile.organization.organization_id
            return AlertStatus.objects.filter(organization__isnull=True) | AlertStatus.objects.filter(organization_id=org_id)
        return AlertStatus.objects.filter(organization__isnull=True)
    
    def perform_create(self, serializer):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            serializer.save(organization=user.profile.organization)
        else:
            serializer.save()


class AlertViewSet(viewsets.ModelViewSet):
    queryset = Alert.objects.all()
    serializer_class = AlertSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'alert:view'
    
    def get_permissions(self):
        if self.action == 'create':
            self.required_permission = 'alert:create'
        elif self.action in ['update', 'partial_update']:
            self.required_permission = 'alert:edit'
        elif self.action == 'destroy':
            self.required_permission = 'alert:delete'
        elif self.action == 'escalate_to_case':
            self.required_permission = 'alert:escalate'
        elif self.action == 'similar':
            self.required_permission = 'alert:view'
        return super().get_permissions()
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            org_id = user.profile.organization.organization_id
            return Alert.objects.filter(organization_id=org_id, is_deleted=False)
        return Alert.objects.none()
    
    @audit_action(entity_type='ALERT', action_type='CREATE')
    def perform_create(self, serializer):
        user = self.request.user
        
        if not hasattr(user, 'profile') or not user.profile.organization:
            raise PermissionError("Usuário não possui organização")
        
        # Obter os valores necessários dos parâmetros
        severity_id = self.request.data.get('severity_id')
        status_id = self.request.data.get('status_id')
        
        # Obter técnicas MITRE opcionais
        mitre_technique_id = serializer.validated_data.pop('mitre_technique_id', None)
        mitre_subtechnique_id = serializer.validated_data.pop('mitre_subtechnique_id', None)
        
        # Verificar se há um status padrão, caso nenhum tenha sido fornecido
        if not status_id:
            default_status = AlertStatus.objects.filter(
                organization=user.profile.organization,
                is_default_open_status=True
            ).first() or AlertStatus.objects.filter(
                organization__isnull=True,
                is_default_open_status=True
            ).first()
            
            if default_status:
                status_id = default_status.id
        
        # Buscar os objetos relacionados
        severity = get_object_or_404(AlertSeverity, pk=severity_id) if severity_id else None
        status = get_object_or_404(AlertStatus, pk=status_id) if status_id else None
        
        # Criar o alerta
        alert = serializer.save(
            organization=user.profile.organization,
            severity=severity,
            status=status,
            first_seen_at=timezone.now()
        )
        
        # Associar técnicas MITRE, se fornecidas
        if mitre_technique_id and mitre_technique_id.strip():
            try:
                technique = MitreTechnique.objects.get(technique_id=mitre_technique_id)
                alert_technique = AlertMitreTechnique.objects.create(
                    alert=alert,
                    technique=technique,
                    added_by=user,
                    notes="Adicionado durante a criação do alerta"
                )
            except MitreTechnique.DoesNotExist:
                # Log error but continue alert creation
                pass
        
        # Associar subtécnica MITRE, se fornecida
        if mitre_subtechnique_id and mitre_subtechnique_id.strip():
            try:
                subtechnique = MitreTechnique.objects.get(technique_id=mitre_subtechnique_id)
                alert_subtechnique = AlertMitreTechnique.objects.create(
                    alert=alert,
                    technique=subtechnique,
                    added_by=user,
                    notes="Adicionado durante a criação do alerta"
                )
            except MitreTechnique.DoesNotExist:
                # Log error but continue alert creation
                pass
                
        # Notificar via WebSocket
        WebSocketService.send_alert_update(
            alert_id=alert.alert_id,
            event_type='created',
            data={'alert': AlertSerializer(alert).data}
        )
        
        return alert
    
    @audit_action(entity_type='ALERT', action_type='UPDATE')
    def perform_update(self, serializer):
        alert = self.get_object()
        
        # Capturar estado anterior para auditoria
        previous_status = alert.status
        
        # Realizar a atualização normal
        serializer.save()
        
        # Se status mudou, registrar também como mudança de status
        if 'status' in serializer.validated_data and previous_status != alert.status:
            # This will be implemented in the audit module
            pass
            # AuditLog.objects.create(
            #     user=self.request.user,
            #     organization=alert.organization,
            #     entity_type='ALERT',
            #     entity_id=alert.alert_id,
            #     action_type='STATUS_CHANGE',
            #     details_before={'status': str(previous_status)},
            #     details_after={'status': str(alert.status)}
            # )
        
        # Notificar via WebSocket
        WebSocketService.send_alert_update(
            alert_id=alert.alert_id,
            event_type='updated',
            data={'alert': AlertSerializer(alert).data}
        )
    
    @audit_action(entity_type='ALERT', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        alert = self.get_object()
        # Soft delete
        alert.is_deleted = True
        alert.save()
        
        # Notificar via WebSocket
        WebSocketService.send_alert_update(
            alert_id=alert.alert_id,
            event_type='deleted',
            data={'alert_id': str(alert.alert_id)}
        )
        
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    @action(detail=True, methods=['post'])
    @audit_action(entity_type='ALERT', action_type='ESCALATE')
    def escalate_to_case(self, request, pk=None):
        alert = self.get_object()
        
        # Get template if provided
        template_id = request.data.get('template_id')
        template = None
        if template_id:
            from irp.cases.models import CaseTemplate
            try:
                template = CaseTemplate.objects.get(pk=template_id)
            except CaseTemplate.DoesNotExist:
                return Response(
                    {"detail": f"Template with ID {template_id} not found"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
                
        # Get optional title and description
        case_title = request.data.get('title')
        case_description = request.data.get('description')
        
        # Use the service to create the case
        from .services import AlertService
        try:
            case = AlertService.escalate_to_case(
                alert=alert,
                user=request.user,
                template=template,
                case_title=case_title,
                case_description=case_description
            )
            
            # Notificar via WebSocket (tanto o alerta quanto o caso)
            WebSocketService.send_alert_update(
                alert_id=alert.alert_id,
                event_type='escalated',
                data={
                    'alert_id': str(alert.alert_id),
                    'case_id': str(case.case_id)
                }
            )
            
            WebSocketService.send_case_update(
                case_id=case.case_id,
                event_type='created_from_alert',
                data={
                    'case_id': str(case.case_id),
                    'alert_id': str(alert.alert_id)
                }
            )
            
            # Return the created case ID
            return Response({
                "detail": f"Alert escalated to case {case.case_id}",
                "case_id": case.case_id
            })
            
        except Exception as e:
            return Response(
                {"detail": f"Error escalating alert to case: {str(e)}"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    # Add the __name__ attribute to fix the problem
    escalate_to_case.__name__ = 'escalate_to_case'
    
    @action(detail=True, methods=['get'])
    def similar(self, request, pk=None):
        """
        Find alerts similar to the specified alert.
        """
        alert = self.get_object()
        
        # Get the max results parameter (default to 10 if not provided)
        max_results = int(request.query_params.get('max_results', 10))
        
        # Use the service to find similar alerts
        from .services import AlertService
        try:
            similar_alerts = AlertService.find_similar_alerts(
                alert=alert,
                max_results=max_results
            )
            
            # Serialize the results
            from .serializers import SimplifiedAlertSerializer
            results = []
            for item in similar_alerts:
                alert_data = SimplifiedAlertSerializer(item['alert']).data
                results.append({
                    'alert': alert_data,
                    'score': item['score'],
                    'match_reason': item['match_reason']
                })
                
            return Response({
                'count': len(results),
                'results': results
            })
            
        except Exception as e:
            return Response(
                {"detail": f"Error finding similar alerts: {str(e)}"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    # Add the __name__ attribute to fix the problem
    similar.__name__ = 'similar'


class AlertCommentViewSet(viewsets.ModelViewSet):
    queryset = AlertComment.objects.all()
    serializer_class = AlertCommentSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'alert:comment'
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            return AlertComment.objects.filter(
                alert__organization=user.profile.organization
            )
        return AlertComment.objects.none()
    
    @audit_action(entity_type='ALERT_COMMENT', action_type='CREATE')
    def perform_create(self, serializer):
        alert_id = self.request.data.get('alert')
        alert = get_object_or_404(Alert, pk=alert_id)
        
        # Check if user belongs to the same organization as the alert
        user = self.request.user
        if not hasattr(user, 'profile') or user.profile.organization != alert.organization:
            raise permissions.PermissionDenied("Usuário não tem permissão para comentar neste alerta")
        
        # Save the comment
        comment = serializer.save(alert=alert, user=self.request.user)
        
        # Extract observables from comment text
        if comment.comment_text and hasattr(user, 'profile'):
            auto_extract = self.request.data.get('auto_extract_observables', True)
            if auto_extract:
                # Extract and create observables
                observables = ObservableService.extract_and_create_observables_from_text(
                    comment.comment_text,
                    user,
                    user.profile.organization
                )
                
                # Link observables to the alert
                for observable in observables:
                    AlertObservable.objects.get_or_create(
                        alert=alert,
                        observable=observable.observable_id,
                        defaults={'sighted_at': timezone.now()}
                    )
        
        # Notificar via WebSocket
        WebSocketService.send_alert_update(
            alert_id=alert.alert_id,
            event_type='comment_added',
            data={
                'alert_id': str(alert.alert_id),
                'comment': AlertCommentSerializer(comment).data,
                'extracted_observables': len(observables)
            }
        )
        
        return comment
    
    @audit_action(entity_type='ALERT_COMMENT', action_type='UPDATE')
    def perform_update(self, serializer):
        comment = serializer.save()
        
        # Notificar via WebSocket
        WebSocketService.send_alert_update(
            alert_id=comment.alert.alert_id,
            event_type='comment_updated',
            data={
                'alert_id': str(comment.alert.alert_id),
                'comment': AlertCommentSerializer(comment).data
            }
        )
    
    @audit_action(entity_type='ALERT_COMMENT', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        comment = self.get_object()
        alert_id = comment.alert.alert_id
        comment_id = str(comment.comment_id)
        
        # Delete the comment
        response = super().destroy(request, *args, **kwargs)
        
        # Notificar via WebSocket
        WebSocketService.send_alert_update(
            alert_id=alert_id,
            event_type='comment_deleted',
            data={
                'alert_id': str(alert_id),
                'comment_id': comment_id
            }
        )
        
        return response


class AlertCustomFieldDefinitionViewSet(viewsets.ModelViewSet):
    queryset = AlertCustomFieldDefinition.objects.all()
    serializer_class = AlertCustomFieldDefinitionSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_alert_settings'
    
    def get_queryset(self):
        # Retorna definições globais (organization=None) ou específicas da organização
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            org_id = user.profile.organization.organization_id
            return AlertCustomFieldDefinition.objects.filter(organization__isnull=True) | AlertCustomFieldDefinition.objects.filter(organization_id=org_id)
        return AlertCustomFieldDefinition.objects.filter(organization__isnull=True)
    
    @audit_action(entity_type='ALERT_CUSTOM_FIELD_DEF', action_type='CREATE')
    def perform_create(self, serializer):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            serializer.save(organization=user.profile.organization)
        else:
            serializer.save()
    
    @audit_action(entity_type='ALERT_CUSTOM_FIELD_DEF', action_type='UPDATE')
    def perform_update(self, serializer):
        serializer.save()
    
    @audit_action(entity_type='ALERT_CUSTOM_FIELD_DEF', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)


class AlertCustomFieldValueViewSet(viewsets.ModelViewSet):
    queryset = AlertCustomFieldValue.objects.all()
    serializer_class = AlertCustomFieldValueSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'alert:edit'
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            return AlertCustomFieldValue.objects.filter(
                alert__organization=user.profile.organization
            )
        return AlertCustomFieldValue.objects.none()
    
    @audit_action(entity_type='ALERT_CUSTOM_FIELD_VALUE', action_type='CREATE')
    def perform_create(self, serializer):
        alert_id = self.request.data.get('alert')
        field_def_id = self.request.data.get('field_definition')
        
        alert = get_object_or_404(Alert, pk=alert_id)
        field_def = get_object_or_404(AlertCustomFieldDefinition, pk=field_def_id)
        
        # Check if user belongs to the same organization as the alert
        user = self.request.user
        if not hasattr(user, 'profile') or user.profile.organization != alert.organization:
            raise permissions.PermissionDenied("Usuário não tem permissão para editar este alerta")
            
        serializer.save(alert=alert, field_definition=field_def)
        
        # Notificar via WebSocket
        WebSocketService.send_alert_update(
            alert_id=alert.alert_id,
            event_type='custom_field_updated',
            data={
                'alert_id': str(alert.alert_id),
                'field_name': field_def.name,
                'field_id': str(field_def.id)
            }
        )
    
    @audit_action(entity_type='ALERT_CUSTOM_FIELD_VALUE', action_type='UPDATE')
    def perform_update(self, serializer):
        serializer.save()
    
    @audit_action(entity_type='ALERT_CUSTOM_FIELD_VALUE', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)


class AlertObservableViewSet(viewsets.ModelViewSet):
    queryset = AlertObservable.objects.all()
    serializer_class = AlertObservableSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'alert:edit'
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            return AlertObservable.objects.filter(
                alert__organization=user.profile.organization
            )
        return AlertObservable.objects.none()
    
    def perform_create(self, serializer):
        alert_id = self.request.data.get('alert')
        alert = get_object_or_404(Alert, pk=alert_id)
        
        # Check if user belongs to the same organization as the alert
        user = self.request.user
        if not hasattr(user, 'profile') or user.profile.organization != alert.organization:
            raise permissions.PermissionDenied("Usuário não tem permissão para editar este alerta")
        
        alert_observable = serializer.save(alert=alert)
        
        # Notificar via WebSocket
        WebSocketService.send_alert_update(
            alert_id=alert.alert_id,
            event_type='observable_added',
            data={
                'alert_id': str(alert.alert_id),
                'observable_id': str(alert_observable.observable)
            }
        )
    
    def perform_destroy(self, instance):
        alert_id = instance.alert.alert_id
        observable_id = instance.observable
        
        # Delete the alert observable
        instance.delete()
        
        # Notificar via WebSocket
        WebSocketService.send_alert_update(
            alert_id=alert_id,
            event_type='observable_removed',
            data={
                'alert_id': str(alert_id),
                'observable_id': str(observable_id)
            }
        )


# AlertMitreTechniqueViewSet foi movido para irp.mitre.views
