from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.db.models import Q
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response

from .models import (
    CaseSeverity, CaseStatus, CaseTemplate, Case, CaseComment,
    CaseCustomFieldDefinition, CaseCustomFieldValue, Task,
    TaskStatus, CaseObservable, CaseMitreTechnique
)
from .serializers import (
    CaseSeveritySerializer, CaseStatusSerializer, CaseTemplateSerializer,
    CaseSerializer, CaseCommentSerializer, CaseCustomFieldDefinitionSerializer,
    CaseCustomFieldValueSerializer, TaskStatusSerializer, TaskSerializer,
    CaseObservableSerializer, CaseMitreTechniqueSerializer
)
from irp.common.permissions import HasRolePermission
from irp.common.audit import audit_action
from irp.timeline.services import create_timeline_event
from irp.audit.models import AuditLog

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
        
        # Adicionar evento na timeline
        create_timeline_event(
            case=case,
            organization=user.profile.organization,
            event_type='CASE_CREATED',
            description=f"Caso criado por {user.get_full_name() or user.username}",
            actor=user,
            metadata={
                'title': case.title,
                'severity': str(severity) if severity else None,
                'status': str(status) if status else None,
                'template': str(template) if template else None
            }
        )
        
        # Se há um template, processar as tarefas predefinidas
        if template and template.predefined_tasks:
            task_status_todo = TaskStatus.objects.filter(name='ToDo').first()
            
            for task_def in template.predefined_tasks:
                task = Task.objects.create(
                    case=case,
                    title=task_def.get('title', ''),
                    description=task_def.get('description', ''),
                    status=task_status_todo,
                    order=task_def.get('order', 0)
                )
                
                # Adicionar evento na timeline para cada tarefa criada
                create_timeline_event(
                    case=case,
                    organization=user.profile.organization,
                    event_type='TASK_CREATED',
                    description=f"Tarefa '{task.title}' criada automaticamente do template",
                    actor=user,
                    target_entity_type='Task',
                    target_entity_id=str(task.task_id)
                )
        
        return case

    @audit_action(entity_type='CASE', action_type='UPDATE')
    def perform_update(self, serializer):
        case = self.get_object()
        user = self.request.user
        
        # Capturar estado anterior para auditoria
        previous_status = case.status
        previous_assignee = case.assignee
        
        # Realizar a atualização normal
        serializer.save()
        
        # Se status mudou, registrar também como mudança de status
        if 'status' in serializer.validated_data and previous_status != case.status:
            # Se o status é terminal, registrar data de fechamento
            if case.status.is_terminal_status and not case.closed_at:
                case.closed_at = timezone.now()
                case.save(update_fields=['closed_at'])
            
            AuditLog.objects.create(
                user=self.request.user,
                organization=case.organization,
                entity_type='CASE',
                entity_id=case.case_id,
                action_type='STATUS_CHANGE',
                details_before={'status': str(previous_status)},
                details_after={'status': str(case.status)}
            )
            
            # Adicionar evento na timeline
            create_timeline_event(
                case=case,
                organization=case.organization,
                event_type='STATUS_CHANGED',
                description=f"Status alterado de '{previous_status}' para '{case.status}'",
                actor=user,
                metadata={
                    'old_status': str(previous_status),
                    'new_status': str(case.status)
                }
            )
        
        # Se assignee mudou, registrar também como atribuição
        if 'assignee' in serializer.validated_data and previous_assignee != case.assignee:
            AuditLog.objects.create(
                user=self.request.user,
                organization=case.organization,
                entity_type='CASE',
                entity_id=case.case_id,
                action_type='ASSIGN',
                details_before={'assignee': str(previous_assignee) if previous_assignee else None},
                details_after={'assignee': str(case.assignee) if case.assignee else None}
            )
            
            # Adicionar evento na timeline
            if case.assignee:
                description = f"Caso atribuído para {case.assignee.get_full_name() or case.assignee.username}"
            else:
                description = "Atribuição do caso removida"
                
            create_timeline_event(
                case=case,
                organization=case.organization,
                event_type='USER_ASSIGNED',
                description=description,
                actor=user,
                metadata={
                    'old_assignee': str(previous_assignee) if previous_assignee else None,
                    'new_assignee': str(case.assignee) if case.assignee else None
                }
            )
    
    @audit_action(entity_type='CASE', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)

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
    
    @audit_action(entity_type='TASK', action_type='CREATE')
    def perform_create(self, serializer):
        case_id = self.kwargs.get('case_pk')
        case = get_object_or_404(Case, case_id=case_id)
        user = self.request.user
        
        # Verificar se o usuário pertence à mesma organização do caso
        if hasattr(user, 'profile') and user.profile.organization and user.profile.organization == case.organization:
            status_id = self.request.data.get('status_id')
            status = get_object_or_404(TaskStatus, pk=status_id) if status_id else TaskStatus.objects.filter(name='ToDo').first()
            
            task = serializer.save(case=case, status=status)
            
            # Adicionar evento na timeline
            create_timeline_event(
                case=case,
                organization=case.organization,
                event_type='TASK_CREATED',
                description=f"Tarefa '{task.title}' criada por {user.get_full_name() or user.username}",
                actor=user,
                target_entity_type='Task',
                target_entity_id=str(task.task_id),
                metadata={
                    'task_title': task.title,
                    'task_description': task.description,
                    'task_status': str(task.status)
                }
            )
            
            return task
        else:
            raise PermissionError("Usuário não pode criar tarefas neste caso")

    @audit_action(entity_type='TASK', action_type='UPDATE')
    def perform_update(self, serializer):
        task = self.get_object()
        user = self.request.user
        
        # Capturar estado anterior para auditoria
        previous_status = task.status
        previous_assignee = task.assignee
        
        # Realizar a atualização normal
        serializer.save()
        
        # Se status mudou, registrar também como mudança de status
        if 'status' in serializer.validated_data and previous_status != task.status:
            AuditLog.objects.create(
                user=user,
                organization=task.case.organization,
                entity_type='TASK',
                entity_id=task.task_id,
                action_type='STATUS_CHANGE',
                details_before={'status': str(previous_status)},
                details_after={'status': str(task.status)}
            )
            
            # Adicionar evento na timeline
            event_type = 'TASK_STATUS_CHANGED'
            description = f"Status da tarefa '{task.title}' alterado de '{previous_status}' para '{task.status}'"
            
            # Se o status novo for completo/fechado, usar um evento de tarefa concluída
            if task.status.name.lower() in ['done', 'completed', 'finished', 'closed']:
                event_type = 'TASK_COMPLETED'
                description = f"Tarefa '{task.title}' concluída por {user.get_full_name() or user.username}"
            
            create_timeline_event(
                case=task.case,
                organization=task.case.organization,
                event_type=event_type,
                description=description,
                actor=user,
                target_entity_type='Task',
                target_entity_id=str(task.task_id),
                metadata={
                    'task_title': task.title,
                    'old_status': str(previous_status),
                    'new_status': str(task.status)
                }
            )
        
        # Se assignee mudou, registrar também como atribuição
        if 'assignee' in serializer.validated_data and previous_assignee != task.assignee:
            AuditLog.objects.create(
                user=user,
                organization=task.case.organization,
                entity_type='TASK',
                entity_id=task.task_id,
                action_type='ASSIGN',
                details_before={'assignee': str(previous_assignee) if previous_assignee else None},
                details_after={'assignee': str(task.assignee) if task.assignee else None}
            )
            
            # Adicionar evento na timeline
            if task.assignee:
                description = f"Tarefa '{task.title}' atribuída para {task.assignee.get_full_name() or task.assignee.username}"
            else:
                description = f"Atribuição da tarefa '{task.title}' removida"
                
            create_timeline_event(
                case=task.case,
                organization=task.case.organization,
                event_type='TASK_ASSIGNED',
                description=description,
                actor=user,
                target_entity_type='Task',
                target_entity_id=str(task.task_id),
                metadata={
                    'task_title': task.title,
                    'old_assignee': str(previous_assignee.id) if previous_assignee else None,
                    'new_assignee': str(task.assignee.id) if task.assignee else None
                }
            )
    
    @audit_action(entity_type='TASK', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        task = self.get_object()
        user = request.user
        
        # Adicionar evento na timeline antes de excluir
        create_timeline_event(
            case=task.case,
            organization=task.case.organization,
            event_type='TASK_DELETED',
            description=f"Tarefa '{task.title}' removida por {user.get_full_name() or user.username}",
            actor=user,
            target_entity_type='Task',
            target_entity_id=str(task.task_id),
            metadata={
                'task_title': task.title,
                'task_status': str(task.status)
            }
        )
        
        return super().destroy(request, *args, **kwargs)

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
    
    @audit_action(entity_type='CASE_COMMENT', action_type='CREATE')
    def perform_create(self, serializer):
        case_id = self.kwargs.get('case_pk')
        case = get_object_or_404(Case, case_id=case_id)
        user = self.request.user
        
        # Verificar se o usuário pertence à mesma organização do caso
        if hasattr(user, 'profile') and user.profile.organization and user.profile.organization == case.organization:
            comment = serializer.save(case=case, user=user)
            
            # Adicionar evento na timeline
            create_timeline_event(
                case=case,
                organization=case.organization,
                event_type='COMMENT_ADDED',
                description=f"Comentário adicionado por {user.get_full_name() or user.username}",
                actor=user,
                target_entity_type='Comment',
                target_entity_id=str(comment.id),
                metadata={
                    'comment_text': comment.text[:100] + ('...' if len(comment.text) > 100 else '')
                }
            )
            
            return comment
        else:
            raise PermissionError("Usuário não pode comentar neste caso")

    @audit_action(entity_type='CASE_COMMENT', action_type='UPDATE')
    def perform_update(self, serializer):
        comment = self.get_object()
        user = self.request.user
        case = comment.case
        
        # Verificar se é o autor do comentário ou tem permissão especial
        if comment.user != user and not user.has_perm('case:edit_any_comment'):
            raise PermissionError("Usuário não pode editar este comentário")
        
        updated_comment = serializer.save()
        
        # Adicionar evento na timeline
        create_timeline_event(
            case=case,
            organization=case.organization,
            event_type='COMMENT_UPDATED',
            description=f"Comentário editado por {user.get_full_name() or user.username}",
            actor=user,
            target_entity_type='Comment',
            target_entity_id=str(comment.id),
            metadata={
                'comment_text': updated_comment.text[:100] + ('...' if len(updated_comment.text) > 100 else '')
            }
        )
        
        return updated_comment
    
    @audit_action(entity_type='CASE_COMMENT', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        comment = self.get_object()
        user = request.user
        case = comment.case
        
        # Verificar se é o autor do comentário ou tem permissão especial
        if comment.user != user and not user.has_perm('case:delete_any_comment'):
            raise PermissionError("Usuário não pode excluir este comentário")
        
        # Adicionar evento na timeline
        create_timeline_event(
            case=case,
            organization=case.organization,
            event_type='COMMENT_DELETED',
            description=f"Comentário excluído por {user.get_full_name() or user.username}",
            actor=user,
            target_entity_type='Comment',
            target_entity_id=str(comment.id),
            metadata={
                'comment_text': comment.text[:100] + ('...' if len(comment.text) > 100 else '')
            }
        )
        
        return super().destroy(request, *args, **kwargs)

class CaseCustomFieldDefinitionViewSet(viewsets.ModelViewSet):
    queryset = CaseCustomFieldDefinition.objects.all()
    serializer_class = CaseCustomFieldDefinitionSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_case_settings'
    
    def get_queryset(self):
        # Retorna campos globais (organization=None) ou específicos da organização
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            org_id = user.profile.organization.organization_id
            return CaseCustomFieldDefinition.objects.filter(
                Q(organization__isnull=True) | Q(organization_id=org_id)
            )
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
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            case_id = self.request.query_params.get('case_id')
            org_id = user.profile.organization.organization_id
            
            # Filtrar por case_id se fornecido
            if case_id:
                return CaseCustomFieldValue.objects.filter(
                    case__case_id=case_id,
                    case__organization_id=org_id
                )
            
            # Caso contrário, retornar todos os valores de campos personalizados da organização
            return CaseCustomFieldValue.objects.filter(case__organization_id=org_id)
        
        return CaseCustomFieldValue.objects.none()
    
    def perform_create(self, serializer):
        # Verificar permissão para o caso específico
        case_id = self.request.data.get('case_id')
        case = get_object_or_404(Case, case_id=case_id)
        user = self.request.user
        
        # Apenas usuários da mesma organização podem adicionar campos
        if hasattr(user, 'profile') and user.profile.organization and user.profile.organization == case.organization:
            # Verificar se o campo personalizado é válido para esta organização
            field_def_id = self.request.data.get('field_definition_id')
            field_def = get_object_or_404(CaseCustomFieldDefinition, id=field_def_id)
            
            if field_def.organization is None or field_def.organization == user.profile.organization:
                # Salvar o valor do campo personalizado
                serializer.save(case=case)
            else:
                raise PermissionError("Definição de campo personalizado inválida")
        else:
            raise PermissionError("Usuário não pode adicionar campos personalizados a este caso")
