from django.shortcuts import render, get_object_or_404
from rest_framework import viewsets, permissions, status
from django.contrib.auth.models import User
from django.utils import timezone
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from .models import (
    Organization, Team, Profile, Role, Permission, UserRole, RolePermission,
    AlertSeverity, AlertStatus, Alert, AlertComment, AlertCustomFieldDefinition, AlertCustomFieldValue,
    CaseSeverity, CaseStatus, CaseTemplate, Case, CaseComment, CaseCustomFieldDefinition, CaseCustomFieldValue,
    TaskStatus, Task, ObservableType, TLPLevel, PAPLevel, Observable, CaseObservable, AlertObservable, AuditLog
)
from .serializers import (
    OrganizationSerializer, TeamSerializer, ProfileSerializer, RoleSerializer, PermissionSerializer,
    UserRoleSerializer, RolePermissionSerializer, UserSerializer,
    AlertSeveritySerializer, AlertStatusSerializer, AlertSerializer, AlertCommentSerializer,
    AlertCustomFieldDefinitionSerializer, AlertCustomFieldValueSerializer,
    CaseSeveritySerializer, CaseStatusSerializer, CaseTemplateSerializer, CaseSerializer, CaseCommentSerializer,
    CaseCustomFieldDefinitionSerializer, CaseCustomFieldValueSerializer,
    TaskStatusSerializer, TaskSerializer, ObservableTypeSerializer, TLPLevelSerializer, PAPLevelSerializer,
    ObservableSerializer, CaseObservableSerializer, AlertObservableSerializer, AuditLogSerializer
)
from .permissions import HasRolePermission
import functools
from django.db.models import Count, Q, F, Avg, Min, Max
from django.db.models.functions import TruncDay, TruncWeek, TruncMonth
from datetime import datetime, timedelta

# Decorator para auditoria de ações
def audit_action(entity_type, action_type, get_entity_id_func=None):
    """
    Decorator para registrar ações no log de auditoria.
    
    Args:
        entity_type (str): Tipo da entidade (ALERT, CASE, TASK, etc)
        action_type (str): Tipo da ação (CREATE, UPDATE, DELETE, etc)
        get_entity_id_func (callable, optional): Função para extrair o ID da entidade do resultado.
            Se não fornecido, tenta obter o ID do objeto retornado.
    """
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapper(self, request, *args, **kwargs):
            # Salvar estado antes da operação para comparação posterior
            details_before = None
            entity_id = None
            
            # Executar a view original
            result = view_func(self, request, *args, **kwargs)
            
            # Extrair ID da entidade
            if get_entity_id_func:
                entity_id = get_entity_id_func(result, self, request, *args, **kwargs)
            elif hasattr(self, 'get_object') and entity_type in ['ALERT', 'CASE', 'TASK', 'OBSERVABLE']:
                # Para ViewSets padrão, tenta obter o ID do objeto atual
                try:
                    obj = self.get_object()
                    entity_id = getattr(obj, f"{entity_type.lower()}_id", None)
                except:
                    pass
            
            # Se não conseguiu obter o ID ainda e a resposta tem dados, tenta extrair daí
            if not entity_id and hasattr(result, 'data') and isinstance(result.data, dict):
                id_key = f"{entity_type.lower()}_id"
                entity_id = result.data.get(id_key)
            
            # Registrar na auditoria apenas se conseguiu identificar a entidade
            if entity_id:
                # Obter organização do usuário
                user = request.user
                organization = None
                if hasattr(user, 'profile') and user.profile.organization:
                    organization = user.profile.organization
                
                # Dados após a operação
                details_after = None
                if hasattr(result, 'data'):
                    details_after = result.data
                
                # Criar entrada de auditoria
                if organization:
                    AuditLog.objects.create(
                        user=user,
                        organization=organization,
                        entity_type=entity_type,
                        entity_id=entity_id,
                        action_type=action_type,
                        details_before=details_before,
                        details_after=details_after
                    )
            
            return result
        return wrapper
    return decorator

# Create your views here.

class OrganizationViewSet(viewsets.ModelViewSet):
    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_organizations'

class TeamViewSet(viewsets.ModelViewSet):
    queryset = Team.objects.all()
    serializer_class = TeamSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_teams'

    def get_queryset(self):
        # Isolamento multi-tenant: só times da organização do usuário
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            return Team.objects.filter(organization=user.profile.organization)
        return Team.objects.none()

    def perform_create(self, serializer):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            serializer.save(organization=user.profile.organization)
        else:
            serializer.save()

class ProfileViewSet(viewsets.ModelViewSet):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

class RoleViewSet(viewsets.ModelViewSet):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_roles'

class PermissionViewSet(viewsets.ModelViewSet):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_permissions'

class UserRoleViewSet(viewsets.ModelViewSet):
    queryset = UserRole.objects.all()
    serializer_class = UserRoleSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'assign_roles'

class RolePermissionViewSet(viewsets.ModelViewSet):
    queryset = RolePermission.objects.all()
    serializer_class = RolePermissionSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'assign_permissions'

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        user = serializer.save()
        # Cria perfil automaticamente
        Profile.objects.create(user=user)

    def get_queryset(self):
        # Usuário só vê a si mesmo ou membros da sua organização
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            org = user.profile.organization
            return User.objects.filter(profile__organization=org)
        return User.objects.filter(id=user.id)

# Etapa 2 - Alert Management Views

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
    
    @action(detail=True, methods=['post'])
    def escalate_to_case(self, request, pk=None):
        alert = self.get_object()
        
        # Obter parâmetros para o novo caso
        title = request.data.get('title', alert.title)
        template_id = request.data.get('template_id')
        severity_id = request.data.get('severity_id')
        description = request.data.get('description', alert.description)
        
        # Verificar se há um status padrão para casos
        default_case_status = CaseStatus.objects.filter(
            organization=alert.organization,
            is_default_open_status=True
        ).first() or CaseStatus.objects.filter(
            organization__isnull=True,
            is_default_open_status=True
        ).first()
        
        if not default_case_status:
            return Response(
                {"detail": "Não foi possível encontrar um status padrão para casos."},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Buscar severidade (usar a mesma do alerta se não especificada)
        if not severity_id:
            # Mapeamento aproximado entre severidades de alerta e caso
            alert_severity_name = alert.severity.name
            case_severity = CaseSeverity.objects.filter(name=alert_severity_name).first()
        else:
            case_severity = get_object_or_404(CaseSeverity, pk=severity_id)
        
        # Buscar template se especificado
        template = None
        if template_id:
            template = get_object_or_404(CaseTemplate, pk=template_id)
        
        # Criar o caso
        case = Case.objects.create(
            title=title,
            description=description,
            severity=case_severity,
            status=default_case_status,
            organization=alert.organization,
            reporter=request.user,
            template=template
        )
        
        # Associar o alerta ao caso
        case.alerts.add(alert)
        
        # Atualizar status do alerta para indicar que foi escalado
        escalated_status = AlertStatus.objects.filter(
            organization=alert.organization,
            name__icontains='Escalated'
        ).first() or AlertStatus.objects.filter(
            organization__isnull=True,
            name__icontains='Escalated'
        ).first()
        
        if escalated_status:
            alert.status = escalated_status
            alert.save()
        
        # Se há um template, processar as tarefas predefinidas
        if template and template.predefined_tasks:
            task_status_todo = TaskStatus.objects.filter(name='ToDo').first()
            
            for task_def in template.predefined_tasks:
                Task.objects.create(
                    case=case,
                    title=task_def.get('title', ''),
                    description=task_def.get('description', ''),
                    status=task_status_todo,
                    order=task_def.get('order', 0)
                )
        
        # Registrar na auditoria
        AuditLog.objects.create(
            user=request.user,
            organization=alert.organization,
            entity_type='ALERT',
            entity_id=alert.alert_id,
            action_type='STATUS_CHANGE',
            details_before={'status': str(alert.status)},
            details_after={'status': str(escalated_status) if escalated_status else None, 'escalated_to_case': str(case.case_id)}
        )
        
        # Retornar detalhes do caso criado
        serializer = CaseSerializer(case)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    
    @action(detail=True, methods=['get'])
    def similar(self, request, pk=None):
        """
        Encontra alertas similares com base no título, descrição e observáveis em comum.
        Retorna uma lista de alertas ordenada por score de similaridade.
        """
        alert = self.get_object()
        organization_id = alert.organization.organization_id
        
        # Busca por título similar (exato ou parcial)
        title_matches = Alert.objects.filter(
            organization_id=organization_id,
            title__icontains=alert.title,
            is_deleted=False
        ).exclude(alert_id=alert.alert_id)
        
        # Busca por mesma fonte e ID externo
        source_matches = Alert.objects.filter(
            organization_id=organization_id,
            source_system=alert.source_system,
            external_alert_id=alert.external_alert_id,
            is_deleted=False
        ).exclude(alert_id=alert.alert_id)
        
        # Busca por observáveis em comum
        observable_ids = [ao.observable.observable_id for ao in alert.alert_observables.all()]
        if observable_ids:
            alerts_with_same_observables = AlertObservable.objects.filter(
                observable__observable_id__in=observable_ids,
                alert__organization_id=organization_id,
                alert__is_deleted=False
            ).exclude(alert__alert_id=alert.alert_id).values_list('alert__alert_id', flat=True)
            
            observable_matches = Alert.objects.filter(alert_id__in=alerts_with_same_observables)
        else:
            observable_matches = Alert.objects.none()
        
        # Combinar resultados e calcular scores
        similar_alerts = {}
        
        # Pontuação alta para alertas com a mesma origem e ID
        for a in source_matches:
            if a.alert_id not in similar_alerts:
                similar_alerts[a.alert_id] = {
                    'alert': a,
                    'score': 100,
                    'match_reason': 'Mesma fonte e ID externo'
                }
        
        # Pontuação média para títulos similares
        for a in title_matches:
            if a.alert_id not in similar_alerts:
                similar_alerts[a.alert_id] = {
                    'alert': a,
                    'score': 50,
                    'match_reason': 'Título similar'
                }
            else:
                similar_alerts[a.alert_id]['score'] += 30
                similar_alerts[a.alert_id]['match_reason'] += ', Título similar'
        
        # Pontuação baseada em observáveis comuns
        for a in observable_matches:
            if a.alert_id not in similar_alerts:
                similar_alerts[a.alert_id] = {
                    'alert': a,
                    'score': 40,
                    'match_reason': 'Observáveis em comum'
                }
            else:
                similar_alerts[a.alert_id]['score'] += 20
                similar_alerts[a.alert_id]['match_reason'] += ', Observáveis em comum'
        
        # Ordenar resultados por score
        results = sorted(similar_alerts.values(), key=lambda x: x['score'], reverse=True)
        
        # Serializar e retornar resultados
        serialized_results = []
        for item in results:
            alert_data = AlertSerializer(item['alert'], context={'request': request}).data
            serialized_results.append({
                'alert': alert_data,
                'similarity_score': item['score'],
                'match_reason': item['match_reason']
            })
        
        return Response(serialized_results)

    def destroy(self, request, *args, **kwargs):
        alert = self.get_object()
        # Soft delete
        alert.is_deleted = True
        alert.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

class AlertCommentViewSet(viewsets.ModelViewSet):
    queryset = AlertComment.objects.all()
    serializer_class = AlertCommentSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'alert:comment'
    
    def get_queryset(self):
        alert_id = self.kwargs.get('alert_pk')
        user = self.request.user
        
        if alert_id:
            if hasattr(user, 'profile') and user.profile.organization:
                org_id = user.profile.organization.organization_id
                return AlertComment.objects.filter(alert__alert_id=alert_id, alert__organization_id=org_id)
        return AlertComment.objects.none()
    
    def perform_create(self, serializer):
        alert_id = self.kwargs.get('alert_pk')
        alert = get_object_or_404(Alert, alert_id=alert_id)
        
        # Verificar se o usuário pertence à mesma organização do alerta
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization and user.profile.organization == alert.organization:
            serializer.save(alert=alert, user=user)
        else:
            raise PermissionError("Usuário não pode comentar neste alerta")

# Etapa 2 - Case Management Views

class CaseSeverityViewSet(viewsets.ModelViewSet):
    queryset = CaseSeverity.objects.all()
    serializer_class = CaseSeveritySerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_case_settings'

class CaseStatusViewSet(viewsets.ModelViewSet):
    queryset = CaseStatus.objects.all()
    serializer_class = CaseStatusSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_case_settings'
    
    def get_queryset(self):
        # Retorna status globais (organization=None) ou específicos da organização
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            org_id = user.profile.organization.organization_id
            return CaseStatus.objects.filter(organization__isnull=True) | CaseStatus.objects.filter(organization_id=org_id)
        return CaseStatus.objects.filter(organization__isnull=True)
    
    def perform_create(self, serializer):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            serializer.save(organization=user.profile.organization)
        else:
            serializer.save()

class CaseTemplateViewSet(viewsets.ModelViewSet):
    queryset = CaseTemplate.objects.all()
    serializer_class = CaseTemplateSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_case_templates'
    
    def get_queryset(self):
        # Retorna templates globais (organization=None) ou específicos da organização
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            org_id = user.profile.organization.organization_id
            return CaseTemplate.objects.filter(organization__isnull=True) | CaseTemplate.objects.filter(organization_id=org_id)
        return CaseTemplate.objects.filter(organization__isnull=True)
    
    def perform_create(self, serializer):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            serializer.save(organization=user.profile.organization)
        else:
            serializer.save()

class CaseViewSet(viewsets.ModelViewSet):
    queryset = Case.objects.all()
    serializer_class = CaseSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'case:view'
    
    def get_permissions(self):
        if self.action == 'create':
            self.required_permission = 'case:create'
        elif self.action in ['update', 'partial_update']:
            self.required_permission = 'case:edit'
        elif self.action == 'destroy':
            self.required_permission = 'case:delete'
        elif self.action == 'related':
            self.required_permission = 'case:view'
        return super().get_permissions()
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            org_id = user.profile.organization.organization_id
            return Case.objects.filter(organization_id=org_id)
        return Case.objects.none()
    
    @audit_action(entity_type='CASE', action_type='CREATE')
    def perform_create(self, serializer):
        user = self.request.user
        
        if not hasattr(user, 'profile') or not user.profile.organization:
            raise PermissionError("Usuário não possui organização")
        
        # Obter os valores necessários dos parâmetros
        severity_id = self.request.data.get('severity_id')
        status_id = self.request.data.get('status_id')
        template_id = self.request.data.get('template_id')
        
        # Verificar se há um status padrão, caso nenhum tenha sido fornecido
        if not status_id:
            default_status = CaseStatus.objects.filter(
                organization=user.profile.organization,
                is_default_open_status=True
            ).first() or CaseStatus.objects.filter(
                organization__isnull=True,
                is_default_open_status=True
            ).first()
            
            if default_status:
                status_id = default_status.id
        
        # Buscar os objetos relacionados
        severity = get_object_or_404(CaseSeverity, pk=severity_id) if severity_id else None
        status = get_object_or_404(CaseStatus, pk=status_id) if status_id else None
        template = get_object_or_404(CaseTemplate, pk=template_id) if template_id else None
        
        # Criar o caso
        case = serializer.save(
            organization=user.profile.organization,
            severity=severity,
            status=status,
            template=template,
            reporter=user
        )
        
        # Se há um template, processar as tarefas predefinidas
        if template and template.predefined_tasks:
            task_status_todo = TaskStatus.objects.filter(name='ToDo').first()
            
            for task_def in template.predefined_tasks:
                Task.objects.create(
                    case=case,
                    title=task_def.get('title', ''),
                    description=task_def.get('description', ''),
                    status=task_status_todo,
                    order=task_def.get('order', 0)
                )
        
        return case

    @action(detail=True, methods=['get'])
    def related(self, request, pk=None):
        """
        Encontra casos relacionados com base em observáveis comuns, alertas compartilhados,
        ou outros critérios de similaridade.
        """
        case = self.get_object()
        organization_id = case.organization.organization_id
        
        # Buscar casos com alertas em comum
        alert_ids = case.alerts.values_list('alert_id', flat=True)
        cases_with_same_alerts = Case.objects.filter(
            organization_id=organization_id,
            alerts__alert_id__in=alert_ids
        ).exclude(case_id=case.case_id).distinct()
        
        # Buscar casos com observáveis em comum
        observable_ids = [co.observable.observable_id for co in case.case_observables.all()]
        cases_with_same_observables = CaseObservable.objects.filter(
            observable__observable_id__in=observable_ids,
            case__organization_id=organization_id
        ).exclude(case__case_id=case.case_id).values_list('case__case_id', flat=True)
        
        cases_with_same_observables_qs = Case.objects.filter(case_id__in=cases_with_same_observables)
        
        # Combinar resultados e calcular scores
        related_cases = {}
        
        # Pontuação alta para casos com os mesmos alertas
        for c in cases_with_same_alerts:
            if c.case_id not in related_cases:
                related_cases[c.case_id] = {
                    'case': c,
                    'score': 80,
                    'relation_reason': 'Alertas em comum'
                }
        
        # Pontuação baseada em observáveis comuns
        for c in cases_with_same_observables_qs:
            if c.case_id not in related_cases:
                related_cases[c.case_id] = {
                    'case': c,
                    'score': 60,
                    'relation_reason': 'Observáveis em comum'
                }
            else:
                related_cases[c.case_id]['score'] += 30
                related_cases[c.case_id]['relation_reason'] += ', Observáveis em comum'
        
        # Ordenar resultados por score
        results = sorted(related_cases.values(), key=lambda x: x['score'], reverse=True)
        
        # Serializar e retornar resultados
        serialized_results = []
        for item in results:
            case_data = CaseSerializer(item['case'], context={'request': request}).data
            serialized_results.append({
                'case': case_data,
                'relation_score': item['score'],
                'relation_reason': item['relation_reason']
            })
        
        return Response(serialized_results)

class TaskStatusViewSet(viewsets.ModelViewSet):
    queryset = TaskStatus.objects.all()
    serializer_class = TaskStatusSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_case_settings'

class TaskViewSet(viewsets.ModelViewSet):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'task:view'
    
    def get_permissions(self):
        if self.action == 'create':
            self.required_permission = 'task:create'
        elif self.action in ['update', 'partial_update']:
            self.required_permission = 'task:edit'
        elif self.action == 'destroy':
            self.required_permission = 'task:delete'
        return super().get_permissions()
    
    def get_queryset(self):
        case_id = self.kwargs.get('case_pk')
        user = self.request.user
        
        if case_id:
            if hasattr(user, 'profile') and user.profile.organization:
                org_id = user.profile.organization.organization_id
                return Task.objects.filter(case__case_id=case_id, case__organization_id=org_id)
        return Task.objects.none()
    
    def perform_create(self, serializer):
        case_id = self.kwargs.get('case_pk')
        case = get_object_or_404(Case, case_id=case_id)
        
        # Verificar se o usuário pertence à mesma organização do caso
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization and user.profile.organization == case.organization:
            status_id = self.request.data.get('status_id')
            status = get_object_or_404(TaskStatus, pk=status_id) if status_id else TaskStatus.objects.filter(name='ToDo').first()
            
            serializer.save(case=case, status=status)
        else:
            raise PermissionError("Usuário não pode criar tarefas neste caso")

class CaseCommentViewSet(viewsets.ModelViewSet):
    queryset = CaseComment.objects.all()
    serializer_class = CaseCommentSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'case:comment'
    
    def get_queryset(self):
        case_id = self.kwargs.get('case_pk')
        user = self.request.user
        
        if case_id:
            if hasattr(user, 'profile') and user.profile.organization:
                org_id = user.profile.organization.organization_id
                return CaseComment.objects.filter(case__case_id=case_id, case__organization_id=org_id)
        return CaseComment.objects.none()
    
    def perform_create(self, serializer):
        case_id = self.kwargs.get('case_pk')
        case = get_object_or_404(Case, case_id=case_id)
        
        # Verificar se o usuário pertence à mesma organização do caso
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization and user.profile.organization == case.organization:
            serializer.save(case=case, user=user)
        else:
            raise PermissionError("Usuário não pode comentar neste caso")

# Observables Management Views

class ObservableTypeViewSet(viewsets.ModelViewSet):
    queryset = ObservableType.objects.all()
    serializer_class = ObservableTypeSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_case_settings'

class TLPLevelViewSet(viewsets.ModelViewSet):
    queryset = TLPLevel.objects.all()
    serializer_class = TLPLevelSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_case_settings'

class PAPLevelViewSet(viewsets.ModelViewSet):
    queryset = PAPLevel.objects.all()
    serializer_class = PAPLevelSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_case_settings'

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
        return super().get_permissions()

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
        case_id = self.kwargs.get('case_pk')
        user = self.request.user
        
        if case_id:
            if hasattr(user, 'profile') and user.profile.organization:
                org_id = user.profile.organization.organization_id
                return CaseObservable.objects.filter(case__case_id=case_id, case__organization_id=org_id)
        return CaseObservable.objects.none()
    
    def perform_create(self, serializer):
        case_id = self.kwargs.get('case_pk')
        case = get_object_or_404(Case, case_id=case_id)
        
        # Verificar se o usuário pertence à mesma organização do caso
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization and user.profile.organization == case.organization:
            # Processar os observáveis
            observable_data = self.request.data
            
            # Buscar ou criar o tipo de observável
            type_id = observable_data.get('type_id')
            type_obj = get_object_or_404(ObservableType, pk=type_id)
            
            # Buscar ou criar o observável
            value = observable_data.get('value')
            
            # Verificar se já existe um observável com este valor e tipo
            observable, created = Observable.objects.get_or_create(
                value=value,
                type=type_obj,
                defaults={
                    'description': observable_data.get('description', ''),
                    'tags': observable_data.get('tags', []),
                    'is_ioc': observable_data.get('is_ioc', False),
                    'added_by': user
                }
            )
            
            # TLP e PAP, se fornecidos
            tlp_id = observable_data.get('tlp_id')
            pap_id = observable_data.get('pap_id')
            
            if tlp_id:
                tlp = get_object_or_404(TLPLevel, pk=tlp_id)
                observable.tlp_level = tlp
            
            if pap_id:
                pap = get_object_or_404(PAPLevel, pk=pap_id)
                observable.pap_level = pap
            
            observable.save()
            
            # Associar o observável ao caso
            serializer.save(
                case=case,
                observable=observable,
                sighted_at=observable_data.get('sighted_at', timezone.now())
            )
        else:
            raise PermissionError("Usuário não pode adicionar observáveis a este caso")

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
        alert_id = self.kwargs.get('alert_pk')
        user = self.request.user
        
        if alert_id:
            if hasattr(user, 'profile') and user.profile.organization:
                org_id = user.profile.organization.organization_id
                return AlertObservable.objects.filter(alert__alert_id=alert_id, alert__organization_id=org_id)
        return AlertObservable.objects.none()
    
    def perform_create(self, serializer):
        alert_id = self.kwargs.get('alert_pk')
        alert = get_object_or_404(Alert, alert_id=alert_id)
        
        # Verificar se o usuário pertence à mesma organização do alerta
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization and user.profile.organization == alert.organization:
            # Processar os observáveis (similar ao CaseObservableViewSet)
            observable_data = self.request.data
            
            # Buscar ou criar o tipo de observável
            type_id = observable_data.get('type_id')
            type_obj = get_object_or_404(ObservableType, pk=type_id)
            
            # Buscar ou criar o observável
            value = observable_data.get('value')
            
            # Verificar se já existe um observável com este valor e tipo
            observable, created = Observable.objects.get_or_create(
                value=value,
                type=type_obj,
                defaults={
                    'description': observable_data.get('description', ''),
                    'tags': observable_data.get('tags', []),
                    'is_ioc': observable_data.get('is_ioc', False),
                    'added_by': user
                }
            )
            
            # TLP e PAP, se fornecidos
            tlp_id = observable_data.get('tlp_id')
            pap_id = observable_data.get('pap_id')
            
            if tlp_id:
                tlp = get_object_or_404(TLPLevel, pk=tlp_id)
                observable.tlp_level = tlp
            
            if pap_id:
                pap = get_object_or_404(PAPLevel, pk=pap_id)
                observable.pap_level = pap
            
            observable.save()
            
            # Associar o observável ao alerta
            serializer.save(
                alert=alert,
                observable=observable,
                sighted_at=observable_data.get('sighted_at', timezone.now())
            )
            
            # Incrementar contador de artefatos
            alert.artifact_count += 1
            alert.save()
        else:
            raise PermissionError("Usuário não pode adicionar observáveis a este alerta")

class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = AuditLog.objects.all()
    serializer_class = AuditLogSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_organizations'  # Permissão de alto nível
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            org_id = user.profile.organization.organization_id
            return AuditLog.objects.filter(organization_id=org_id)
        return AuditLog.objects.none()

class HelloWorldView(APIView):
    def get(self, request):
        return Response({'message': 'Hello, world!'}, status=status.HTTP_200_OK)

class LoginView(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        token = Token.objects.get(key=response.data['token'])
        return Response({'token': token.key, 'user_id': token.user_id})

class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request):
        request.user.auth_token.delete()
        return Response(status=status.HTTP_200_OK)

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
    
    def perform_create(self, serializer):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            serializer.save(organization=user.profile.organization)
        else:
            serializer.save()

class AlertCustomFieldValueViewSet(viewsets.ModelViewSet):
    queryset = AlertCustomFieldValue.objects.all()
    serializer_class = AlertCustomFieldValueSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'alert:edit'
    
    def get_queryset(self):
        alert_id = self.kwargs.get('alert_pk')
        user = self.request.user
        
        if alert_id:
            if hasattr(user, 'profile') and user.profile.organization:
                org_id = user.profile.organization.organization_id
                return AlertCustomFieldValue.objects.filter(alert__alert_id=alert_id, alert__organization_id=org_id)
        return AlertCustomFieldValue.objects.none()
    
    def perform_create(self, serializer):
        alert_id = self.kwargs.get('alert_pk')
        alert = get_object_or_404(Alert, alert_id=alert_id)
        
        # Verificar se o usuário pertence à mesma organização do alerta
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization and user.profile.organization == alert.organization:
            field_definition_id = self.request.data.get('field_definition_id')
            field_definition = get_object_or_404(AlertCustomFieldDefinition, pk=field_definition_id)
            
            serializer.save(
                alert=alert,
                field_definition=field_definition
            )
        else:
            raise PermissionError("Usuário não pode adicionar campos customizados a este alerta")

class CaseCustomFieldDefinitionViewSet(viewsets.ModelViewSet):
    queryset = CaseCustomFieldDefinition.objects.all()
    serializer_class = CaseCustomFieldDefinitionSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_case_settings'
    
    def get_queryset(self):
        # Retorna definições globais (organization=None) ou específicas da organização
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            org_id = user.profile.organization.organization_id
            return CaseCustomFieldDefinition.objects.filter(organization__isnull=True) | CaseCustomFieldDefinition.objects.filter(organization_id=org_id)
        return CaseCustomFieldDefinition.objects.filter(organization__isnull=True)
    
    def perform_create(self, serializer):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            serializer.save(organization=user.profile.organization)
        else:
            serializer.save()

class CaseCustomFieldValueViewSet(viewsets.ModelViewSet):
    queryset = CaseCustomFieldValue.objects.all()
    serializer_class = CaseCustomFieldValueSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'case:edit'
    
    def get_queryset(self):
        case_id = self.kwargs.get('case_pk')
        user = self.request.user
        
        if case_id:
            if hasattr(user, 'profile') and user.profile.organization:
                org_id = user.profile.organization.organization_id
                return CaseCustomFieldValue.objects.filter(case__case_id=case_id, case__organization_id=org_id)
        return CaseCustomFieldValue.objects.none()
    
    def perform_create(self, serializer):
        case_id = self.kwargs.get('case_pk')
        case = get_object_or_404(Case, case_id=case_id)
        
        # Verificar se o usuário pertence à mesma organização do caso
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization and user.profile.organization == case.organization:
            field_definition_id = self.request.data.get('field_definition_id')
            field_definition = get_object_or_404(CaseCustomFieldDefinition, pk=field_definition_id)
            
            serializer.save(
                case=case,
                field_definition=field_definition
            )
        else:
            raise PermissionError("Usuário não pode adicionar campos customizados a este caso")

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated, HasRolePermission])
def dashboard_stats(request):
    """Endpoint para fornecer estatísticas para o dashboard"""
    
    # Verificar permissão
    if not request.user.has_perm('view_dashboard'):
        return Response({"error": "Sem permissão para acessar o dashboard"}, status=status.HTTP_403_FORBIDDEN)
    
    # Obter organização do usuário
    user = request.user
    if not hasattr(user, 'profile') or not user.profile.organization:
        return Response({"error": "Usuário sem organização"}, status=status.HTTP_400_BAD_REQUEST)
    
    organization = user.profile.organization
    
    # Período para estatísticas (padrão: últimos 30 dias)
    days = int(request.query_params.get('days', 30))
    date_from = timezone.now() - timedelta(days=days)
    
    # Alertas por severidade
    alerts_by_severity = Alert.objects.filter(
        organization=organization,
        created_at__gte=date_from,
        is_deleted=False
    ).values('severity__name').annotate(count=Count('alert_id')).order_by('-count')
    
    # Casos por severidade
    cases_by_severity = Case.objects.filter(
        organization=organization,
        created_at__gte=date_from
    ).values('severity__name').annotate(count=Count('case_id')).order_by('-count')
    
    # Alertas por status
    alerts_by_status = Alert.objects.filter(
        organization=organization,
        created_at__gte=date_from,
        is_deleted=False
    ).values('status__name').annotate(count=Count('alert_id')).order_by('-count')
    
    # Casos por status
    cases_by_status = Case.objects.filter(
        organization=organization,
        created_at__gte=date_from
    ).values('status__name').annotate(count=Count('case_id')).order_by('-count')
    
    # Tendência de alertas por dia
    alert_trends = Alert.objects.filter(
        organization=organization,
        created_at__gte=date_from,
        is_deleted=False
    ).annotate(
        date=TruncDay('created_at')
    ).values('date').annotate(
        count=Count('alert_id')
    ).order_by('date')
    
    # Tempo médio de resolução de casos (casos fechados)
    avg_case_resolution = Case.objects.filter(
        organization=organization,
        created_at__gte=date_from,
        closed_at__isnull=False
    ).annotate(
        resolution_time=F('closed_at') - F('created_at')
    ).aggregate(
        avg_time=Avg('resolution_time')
    )
    
    # Estatísticas gerais
    stats = {
        'total_alerts': Alert.objects.filter(
            organization=organization,
            is_deleted=False
        ).count(),
        'total_cases': Case.objects.filter(
            organization=organization
        ).count(),
        'open_alerts': Alert.objects.filter(
            organization=organization,
            status__is_terminal_status=False,
            is_deleted=False
        ).count(),
        'open_cases': Case.objects.filter(
            organization=organization,
            status__is_terminal_status=False
        ).count(),
        'new_alerts_today': Alert.objects.filter(
            organization=organization,
            created_at__gte=timezone.now().replace(hour=0, minute=0, second=0),
            is_deleted=False
        ).count(),
        'closed_cases_today': Case.objects.filter(
            organization=organization,
            closed_at__gte=timezone.now().replace(hour=0, minute=0, second=0)
        ).count(),
    }
    
    return Response({
        'alerts_by_severity': alerts_by_severity,
        'cases_by_severity': cases_by_severity,
        'alerts_by_status': alerts_by_status,
        'cases_by_status': cases_by_status,
        'alert_trends': alert_trends,
        'avg_case_resolution': avg_case_resolution,
        'stats': stats,
        'period_days': days
    })

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated, HasRolePermission])
def reports(request, report_type=None):
    """Endpoint para gerar relatórios"""
    
    # Verificar permissão
    if not request.user.has_perm('generate_reports'):
        return Response({"error": "Sem permissão para gerar relatórios"}, status=status.HTTP_403_FORBIDDEN)
    
    # Obter organização do usuário
    user = request.user
    if not hasattr(user, 'profile') or not user.profile.organization:
        return Response({"error": "Usuário sem organização"}, status=status.HTTP_400_BAD_REQUEST)
    
    organization = user.profile.organization
    
    # Período para o relatório
    days = int(request.query_params.get('days', 30))
    date_from = timezone.now() - timedelta(days=days)
    
    if report_type == 'alerts':
        # Relatório de alertas
        alerts = Alert.objects.filter(
            organization=organization,
            created_at__gte=date_from,
            is_deleted=False
        )
        
        data = {
            'total_alerts': alerts.count(),
            'alerts_by_severity': alerts.values('severity__name').annotate(count=Count('alert_id')),
            'alerts_by_status': alerts.values('status__name').annotate(count=Count('alert_id')),
            'alerts_by_source': alerts.values('source_system').annotate(count=Count('alert_id')),
            'alerts_by_day': alerts.annotate(
                day=TruncDay('created_at')
            ).values('day').annotate(count=Count('alert_id')).order_by('day'),
            'alerts_by_assignee': alerts.values(
                'assignee__username',
                'assignee__first_name',
                'assignee__last_name'
            ).annotate(count=Count('alert_id')),
            'period': {
                'from': date_from,
                'to': timezone.now(),
                'days': days
            }
        }
    
    elif report_type == 'cases':
        # Relatório de casos
        cases = Case.objects.filter(
            organization=organization,
            created_at__gte=date_from
        )
        
        data = {
            'total_cases': cases.count(),
            'cases_by_severity': cases.values('severity__name').annotate(count=Count('case_id')),
            'cases_by_status': cases.values('status__name').annotate(count=Count('case_id')),
            'cases_by_day': cases.annotate(
                day=TruncDay('created_at')
            ).values('day').annotate(count=Count('case_id')).order_by('day'),
            'cases_by_assignee': cases.values(
                'assignee__username',
                'assignee__first_name',
                'assignee__last_name'
            ).annotate(count=Count('case_id')),
            'avg_resolution_time': cases.filter(
                closed_at__isnull=False
            ).annotate(
                resolution_time=F('closed_at') - F('created_at')
            ).aggregate(avg_time=Avg('resolution_time')),
            'period': {
                'from': date_from,
                'to': timezone.now(),
                'days': days
            }
        }
    
    elif report_type == 'observables':
        # Relatório de observáveis
        observables = Observable.objects.filter(
            added_at__gte=date_from,
            added_by__profile__organization=organization
        )
        
        data = {
            'total_observables': observables.count(),
            'observables_by_type': observables.values('type__name').annotate(count=Count('observable_id')),
            'iocs_count': observables.filter(is_ioc=True).count(),
            'tlp_distribution': observables.values('tlp_level__name').annotate(count=Count('observable_id')),
            'observables_by_day': observables.annotate(
                day=TruncDay('added_at')
            ).values('day').annotate(count=Count('observable_id')).order_by('day'),
            'top_observables': observables.values('type__name', 'value').annotate(
                count=Count('case_observables') + Count('alert_observables')
            ).order_by('-count')[:10],
            'period': {
                'from': date_from,
                'to': timezone.now(),
                'days': days
            }
        }
    
    else:
        # Lista de relatórios disponíveis
        data = {
            'available_reports': [
                {
                    'type': 'alerts',
                    'name': 'Relatório de Alertas',
                    'description': 'Estatísticas de alertas por severidade, status e fonte'
                },
                {
                    'type': 'cases',
                    'name': 'Relatório de Casos',
                    'description': 'Estatísticas de casos por severidade, status e tempo de resolução'
                },
                {
                    'type': 'observables',
                    'name': 'Relatório de Observáveis',
                    'description': 'Estatísticas de observáveis por tipo, TLP e frequência'
                }
            ]
        }
    
    return Response(data)
