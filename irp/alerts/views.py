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
# AlertMitreTechnique foi movido para irp.mitre.models
from .serializers import (
    AlertSeveritySerializer, AlertStatusSerializer, AlertSerializer,
    AlertCommentSerializer, AlertCustomFieldDefinitionSerializer,
    AlertCustomFieldValueSerializer, AlertObservableSerializer
)
# AlertMitreTechniqueSerializer foi movido para irp.mitre.serializers
from irp.common.permissions import HasRolePermission

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
        
        return serializer.save(
            organization=user.profile.organization,
            severity=severity,
            status=status,
            first_seen_at=timezone.now()
        )
    
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
    
    @audit_action(entity_type='ALERT', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        alert = self.get_object()
        # Soft delete
        alert.is_deleted = True
        alert.save()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    @action(detail=True, methods=['post'])
    @audit_action(entity_type='ALERT', action_type='ESCALATE')
    def escalate_to_case(self, request, pk=None):
        # This will be implemented later when the cases module is migrated
        return Response({"detail": "Feature not yet implemented"}, status=status.HTTP_501_NOT_IMPLEMENTED)
    
    # Adicionar o atributo __name__ para corrigir o problema
    escalate_to_case.__name__ = 'escalate_to_case'


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
        
        serializer.save(alert=alert, user=self.request.user)
    
    @audit_action(entity_type='ALERT_COMMENT', action_type='UPDATE')
    def perform_update(self, serializer):
        serializer.save()
    
    @audit_action(entity_type='ALERT_COMMENT', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)


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
    required_permission = 'observable:view'
    
    def get_permissions(self):
        if self.action == 'create':
            self.required_permission = 'observable:create'
        elif self.action in ['update', 'partial_update']:
            self.required_permission = 'observable:edit'
        elif self.action == 'destroy':
            self.required_permission = 'observable:delete'
        return super().get_permissions()
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            return AlertObservable.objects.filter(
                alert__organization=user.profile.organization
            )
        return AlertObservable.objects.none()
    
    @audit_action(entity_type='ALERT_OBSERVABLE', action_type='CREATE')
    def perform_create(self, serializer):
        # Esta implementação é temporária e será atualizada quando o módulo observable for migrado
        # Por enquanto, assumimos que o observable_id é passado diretamente
        alert_id = self.request.data.get('alert')
        observable_id = self.request.data.get('observable')  # UUID como string
        
        if not alert_id or not observable_id:
            raise serializers.ValidationError("Tanto alert quanto observable são necessários")
        
        alert = get_object_or_404(Alert, pk=alert_id)
        
        # Check if user belongs to the same organization as the alert
        user = self.request.user
        if not hasattr(user, 'profile') or user.profile.organization != alert.organization:
            raise permissions.PermissionDenied("Usuário não tem permissão para adicionar observáveis a este alerta")
        
        # Converter observable_id para UUID
        try:
            observable_uuid = uuid.UUID(observable_id)
            serializer.save(alert=alert, observable=observable_uuid)
        except (ValueError, TypeError):
            raise serializers.ValidationError("ID de observable inválido")
    
    @audit_action(entity_type='ALERT_OBSERVABLE', action_type='UPDATE')
    def perform_update(self, serializer):
        serializer.save()
    
    @audit_action(entity_type='ALERT_OBSERVABLE', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)


# AlertMitreTechniqueViewSet foi movido para irp.mitre.views
