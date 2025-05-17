from rest_framework import viewsets, permissions, status
from rest_framework.response import Response
from rest_framework.decorators import action
from django.utils import timezone
from django.shortcuts import get_object_or_404
from django.db import transaction

from .models import ObservableType, TLPLevel, PAPLevel, Observable
from irp.cases.models import CaseObservable
from .serializers import (
    ObservableTypeSerializer, TLPLevelSerializer, 
    PAPLevelSerializer, ObservableSerializer
)
from irp.cases.serializers import CaseObservableSerializer
from irp.common.permissions import HasRolePermission
from irp.cases.models import Case
from irp.common.audit import audit_action
from .services import ObservableService

# This will be properly implemented in the audit module
from irp.common.audit import audit_action


class ObservableTypeViewSet(viewsets.ModelViewSet):
    queryset = ObservableType.objects.all()
    serializer_class = ObservableTypeSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_observable_settings'
    
    @audit_action(entity_type='OBSERVABLE_TYPE', action_type='CREATE')
    def perform_create(self, serializer):
        return super().perform_create(serializer)
        
    @audit_action(entity_type='OBSERVABLE_TYPE', action_type='UPDATE')
    def perform_update(self, serializer):
        return super().perform_update(serializer)
        
    @audit_action(entity_type='OBSERVABLE_TYPE', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)


class TLPLevelViewSet(viewsets.ModelViewSet):
    queryset = TLPLevel.objects.all()
    serializer_class = TLPLevelSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_observable_settings'
    
    @audit_action(entity_type='TLP_LEVEL', action_type='CREATE')
    def perform_create(self, serializer):
        return super().perform_create(serializer)
        
    @audit_action(entity_type='TLP_LEVEL', action_type='UPDATE')
    def perform_update(self, serializer):
        return super().perform_update(serializer)
        
    @audit_action(entity_type='TLP_LEVEL', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)


class PAPLevelViewSet(viewsets.ModelViewSet):
    queryset = PAPLevel.objects.all()
    serializer_class = PAPLevelSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_observable_settings'
    
    @audit_action(entity_type='PAP_LEVEL', action_type='CREATE')
    def perform_create(self, serializer):
        return super().perform_create(serializer)
        
    @audit_action(entity_type='PAP_LEVEL', action_type='UPDATE')
    def perform_update(self, serializer):
        return super().perform_update(serializer)
        
    @audit_action(entity_type='PAP_LEVEL', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)


class ObservableViewSet(viewsets.ModelViewSet):
    queryset = Observable.objects.all()
    serializer_class = ObservableSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'observable:view'
    
    def get_permissions(self):
        if self.action == 'create':
            self.required_permission = 'observable:create'
        elif self.action in ['update', 'partial_update']:
            self.required_permission = 'observable:edit'
        elif self.action == 'destroy':
            self.required_permission = 'observable:delete'
        elif self.action == 'extract_from_text':
            self.required_permission = 'observable:create'
        return super().get_permissions()
    
    def get_queryset(self):
        # Não há isolamento por organização para observáveis, já que eles são compartilhados.
        # No entanto, verificamos se o usuário tem permissão para ver observáveis em geral
        return Observable.objects.all()
    
    @audit_action(entity_type='OBSERVABLE', action_type='CREATE')
    def perform_create(self, serializer):
        user = self.request.user
        type_id = self.request.data.get('type')
        type_obj = get_object_or_404(ObservableType, pk=type_id)
        
        tlp_id = self.request.data.get('tlp_level')
        tlp_obj = get_object_or_404(TLPLevel, pk=tlp_id) if tlp_id else None
        
        pap_id = self.request.data.get('pap_level')
        pap_obj = get_object_or_404(PAPLevel, pk=pap_id) if pap_id else None
        
        serializer.save(
            type=type_obj,
            tlp_level=tlp_obj,
            pap_level=pap_obj,
            added_by=user
        )
    
    @audit_action(entity_type='OBSERVABLE', action_type='UPDATE')
    def perform_update(self, serializer):
        observable = self.get_object()
        serializer.save(updated_by=self.request.user)
    
    @audit_action(entity_type='OBSERVABLE', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)

    @audit_action(entity_type='OBSERVABLE', action_type='VIEW')
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

    @action(detail=False, methods=['post'])
    @audit_action(entity_type='OBSERVABLE', action_type='EXTRACT')
    def extract_from_text(self, request):
        """
        Extrai observáveis de um texto utilizando regex patterns.
        
        Payload:
        - text: Texto para extrair observáveis
        - create: Boolean indicando se deve criar os observáveis também (default: False)
        
        Returns:
        - Lista de observáveis extraídos, agrupados por tipo
        """
        text = request.data.get('text', '')
        create = request.data.get('create', False)
        
        if not text:
            return Response(
                {'detail': 'Texto não fornecido'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Extrair observáveis do texto
        extracted = ObservableService.extract_observables(text)
        
        if not extracted:
            return Response(
                {'detail': 'Nenhum observável encontrado no texto'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Se create=True, criar os observáveis no banco de dados
        if create and hasattr(request.user, 'profile') and request.user.profile.organization:
            observables = ObservableService.create_or_get_observables(
                extracted, 
                request.user, 
                request.user.profile.organization
            )
            
            # Serializar os observáveis criados
            serializer = ObservableSerializer(observables, many=True)
            
            return Response({
                'created': True,
                'count': len(observables),
                'observables': serializer.data
            })
        
        # Retornar apenas os observáveis extraídos sem criar
        return Response({
            'created': False,
            'extracted': extracted,
            'count': sum(len(values) for values in extracted.values())
        })


class CaseObservableViewSet(viewsets.ModelViewSet):
    queryset = CaseObservable.objects.all()
    serializer_class = CaseObservableSerializer
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
        # Se acessado por meio da rota aninhada de casos
        case_pk = self.kwargs.get('case_pk')
        if case_pk:
            user = self.request.user
            if hasattr(user, 'profile') and user.profile.organization:
                # Garantir que o caso pertence à organização do usuário
                case = get_object_or_404(
                    Case, 
                    case_id=case_pk, 
                    organization=user.profile.organization
                )
                return CaseObservable.objects.filter(case=case)
        
        # Caso contrário, lista geral filtrada por organização
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            return CaseObservable.objects.filter(case__organization=user.profile.organization)
        
        return CaseObservable.objects.none()
    
    @audit_action(entity_type='CASE_OBSERVABLE', action_type='CREATE')
    def perform_create(self, serializer):
        # Verificar se está sendo criado via rota aninhada
        case_pk = self.kwargs.get('case_pk')
        user = self.request.user
        
        # Obter o caso a partir do ID na URL ou nos dados
        if case_pk:
            case = get_object_or_404(Case, case_id=case_pk)
        else:
            case_id = self.request.data.get('case_id')
            case = get_object_or_404(Case, case_id=case_id)
        
        # Verificar se o usuário pertence à mesma organização do caso
        if (hasattr(user, 'profile') and user.profile.organization and 
            user.profile.organization == case.organization):
            
            # Salvar com o usuário atual como adicionado_por
            serializer.save(case=case, added_by=user)
            
            # Adicionar evento na timeline
            # Esta função será implementada no módulo timeline
            from irp.timeline.services import create_timeline_event
            create_timeline_event(
                case=case,
                organization=case.organization,
                event_type='OBSERVABLE_ADDED',
                description=f"Observável adicionado por {user.get_full_name() or user.username}",
                actor=user,
                target_entity_type='Observable',
                target_entity_id=str(serializer.instance.id),
                metadata={
                    'observable_value': serializer.instance.observable.value[:100],
                    'observable_type': serializer.instance.observable.type.name
                }
            )
            
        else:
            raise PermissionError("Usuário não pode adicionar observáveis a este caso")
    
    @audit_action(entity_type='CASE_OBSERVABLE', action_type='UPDATE')
    def perform_update(self, serializer):
        # Verificar se é o mesmo usuário que adicionou ou tem permissão especial
        case_observable = self.get_object()
        if case_observable.added_by != self.request.user and not self.request.user.has_perm('observable:edit_any'):
            raise PermissionError("Usuário não pode editar este observável")
        
        serializer.save()
    
    @audit_action(entity_type='CASE_OBSERVABLE', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        # Adicionar lógica para registrar na timeline antes de excluir
        case_observable = self.get_object()
        user = request.user
        case = case_observable.case
        
        # Adicionar evento na timeline
        from irp.timeline.services import create_timeline_event
        create_timeline_event(
            case=case,
            organization=case.organization,
            event_type='OBSERVABLE_REMOVED',
            description=f"Observável removido por {user.get_full_name() or user.username}",
            actor=user,
            target_entity_type='Observable',
            target_entity_id=str(case_observable.id),
            metadata={
                'observable_value': case_observable.observable.value[:100],
                'observable_type': case_observable.observable.type.name
            }
        )
        
        return super().destroy(request, *args, **kwargs)

    @audit_action(entity_type='CASE_OBSERVABLE', action_type='VIEW')
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)
