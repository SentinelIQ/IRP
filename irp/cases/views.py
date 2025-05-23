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
from irp.mitre.models import MitreTechnique
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
from irp.observables.services import ObservableService
from irp.common.websocket import WebSocketService

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
        
        # Obter técnicas MITRE opcionais
        mitre_technique_id = serializer.validated_data.pop('mitre_technique_id', None)
        mitre_subtechnique_id = serializer.validated_data.pop('mitre_subtechnique_id', None)
        
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
        
        # Associar técnicas MITRE, se fornecidas
        if mitre_technique_id and mitre_technique_id.strip():
            try:
                technique = MitreTechnique.objects.get(technique_id=mitre_technique_id)
                case_technique = CaseMitreTechnique.objects.create(
                    case=case,
                    technique=technique,
                    linked_by=user,
                    context_notes="Adicionado durante a criação do caso"
                )
                
                # Adicionar evento na timeline
                create_timeline_event(
                    case=case,
                    organization=user.profile.organization,
                    event_type='MITRE_TECHNIQUE_ADDED',
                    description=f"Técnica MITRE ATT&CK adicionada: {technique.technique_id} - {technique.name}",
                    actor=user,
                    target_entity_type='MitreTechnique',
                    target_entity_id=str(technique.technique_id),
                    metadata={
                        'technique_id': technique.technique_id,
                        'technique_name': technique.name
                    }
                )
            except MitreTechnique.DoesNotExist:
                # Log error but continue case creation
                pass
        
        # Associar subtécnica MITRE, se fornecida
        if mitre_subtechnique_id and mitre_subtechnique_id.strip():
            try:
                subtechnique = MitreTechnique.objects.get(technique_id=mitre_subtechnique_id)
                case_subtechnique = CaseMitreTechnique.objects.create(
                    case=case,
                    technique=subtechnique,
                    linked_by=user,
                    context_notes="Adicionado durante a criação do caso"
                )
                
                # Adicionar evento na timeline
                create_timeline_event(
                    case=case,
                    organization=user.profile.organization,
                    event_type='MITRE_TECHNIQUE_ADDED',
                    description=f"Subtécnica MITRE ATT&CK adicionada: {subtechnique.technique_id} - {subtechnique.name}",
                    actor=user,
                    target_entity_type='MitreTechnique',
                    target_entity_id=str(subtechnique.technique_id),
                    metadata={
                        'technique_id': subtechnique.technique_id,
                        'technique_name': subtechnique.name
                    }
                )
            except MitreTechnique.DoesNotExist:
                # Log error but continue case creation
                pass
        
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
        
        # Notificar via WebSocket
        WebSocketService.send_case_update(
            case_id=case.case_id,
            event_type='created',
            data={
                'case': CaseSerializer(case).data
            }
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
        
        # Notificar via WebSocket
        WebSocketService.send_case_update(
            case_id=case.case_id,
            event_type='updated',
            data={
                'case': CaseSerializer(case).data,
                'status_changed': previous_status != case.status,
                'assignee_changed': previous_assignee != case.assignee
            }
        )
    
    @audit_action(entity_type='CASE', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        case = self.get_object()
        case_id = str(case.case_id)
        
        response = super().destroy(request, *args, **kwargs)
        
        # Notificar via WebSocket
        WebSocketService.send_case_update(
            case_id=case_id,
            event_type='deleted',
            data={
                'case_id': case_id
            }
        )
        
        return response

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
            
            # Notificar via WebSocket
            WebSocketService.send_case_update(
                case_id=case.case_id,
                event_type='task_created',
                data={
                    'case_id': str(case.case_id),
                    'task': TaskSerializer(task).data
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
                    'old_assignee': str(previous_assignee) if previous_assignee else None,
                    'new_assignee': str(task.assignee) if task.assignee else None
                }
            )
        
        # Notificar via WebSocket
        WebSocketService.send_case_update(
            case_id=task.case.case_id,
            event_type='task_updated',
            data={
                'case_id': str(task.case.case_id),
                'task': TaskSerializer(task).data,
                'status_changed': previous_status != task.status,
                'assignee_changed': previous_assignee != task.assignee
            }
        )
    
    @audit_action(entity_type='TASK', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        task = self.get_object()
        case = task.case
        case_id = str(case.case_id)
        task_id = str(task.task_id)
        task_title = task.title
        
        # Adicionar evento na timeline antes de excluir
        user = request.user
        if hasattr(user, 'profile'):
            create_timeline_event(
                case=case,
                organization=user.profile.organization,
                event_type='TASK_DELETED',
                description=f"Tarefa '{task_title}' removida por {user.get_full_name() or user.username}",
                actor=user,
                metadata={
                    'task_title': task_title
                }
            )
        
        # Notificar via WebSocket
        WebSocketService.send_case_update(
            case_id=case_id,
            event_type='task_deleted',
            data={
                'case_id': case_id,
                'task_id': task_id
            }
        )
        
        return super().destroy(request, *args, **kwargs)

class CaseCommentViewSet(viewsets.ModelViewSet):
    queryset = CaseComment.objects.all()
    serializer_class = CaseCommentSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'case:comment'
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            return CaseComment.objects.filter(
                case__organization=user.profile.organization
            )
        return CaseComment.objects.none()
    
    @audit_action(entity_type='CASE_COMMENT', action_type='CREATE')
    def perform_create(self, serializer):
        case_id = self.request.data.get('case')
        case = get_object_or_404(Case, pk=case_id)
        
        # Check if user belongs to the same organization as the case
        user = self.request.user
        if not hasattr(user, 'profile') or user.profile.organization != case.organization:
            raise permissions.PermissionDenied("Usuário não tem permissão para comentar neste caso")
        
        # Save the comment
        comment = serializer.save(case=case, user=self.request.user)
        
        # Create timeline event
        create_timeline_event(
            case=case,
            organization=user.profile.organization,
            event_type='COMMENT_ADDED',
            description=f"Comentário adicionado por {user.get_full_name() or user.username}",
            actor=user,
            target_entity_type='CaseComment',
            target_entity_id=str(comment.comment_id),
            metadata={
                'comment_text': comment.comment_text[:100] + ('...' if len(comment.comment_text) > 100 else '')
            }
        )
        
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
                
                # Link observables to the case
                for observable in observables:
                    CaseObservable.objects.get_or_create(
                        case=case,
                        observable=observable,
                        defaults={'sighted_at': timezone.now()}
                    )
                    
                    # Create timeline event for each observable
                    create_timeline_event(
                        case=case,
                        organization=user.profile.organization,
                        event_type='OBSERVABLE_EXTRACTED',
                        description=f"Observável extraído automaticamente do comentário: {observable.value}",
                        actor=user,
                        target_entity_type='Observable',
                        target_entity_id=str(observable.observable_id),
                        metadata={
                            'observable_value': observable.value,
                            'observable_type': observable.type.name,
                            'source': 'comment'
                        }
                    )
        
        # Notificar via WebSocket
        WebSocketService.send_case_update(
            case_id=case.case_id,
            event_type='comment_added',
            data={
                'case_id': str(case.case_id),
                'comment': CaseCommentSerializer(comment).data
            }
        )
        
        return comment
    
    @audit_action(entity_type='CASE_COMMENT', action_type='UPDATE')
    def perform_update(self, serializer):
        comment = serializer.instance
        case = comment.case
        
        # Audit old value
        old_text = comment.comment_text
        
        # Update the comment
        serializer.save()
        
        # Create timeline event
        create_timeline_event(
            case=case,
            organization=self.request.user.profile.organization if hasattr(self.request.user, 'profile') else None,
            event_type='COMMENT_UPDATED',
            description=f"Comentário editado por {self.request.user.get_full_name() or self.request.user.username}",
            actor=self.request.user,
            target_entity_type='CaseComment',
            target_entity_id=str(comment.comment_id),
            metadata={
                'old_text': old_text[:100] + ('...' if len(old_text) > 100 else ''),
                'new_text': comment.comment_text[:100] + ('...' if len(comment.comment_text) > 100 else '')
            }
        )
        
        # Notificar via WebSocket
        WebSocketService.send_case_update(
            case_id=case.case_id,
            event_type='comment_updated',
            data={
                'case_id': str(case.case_id),
                'comment': CaseCommentSerializer(comment).data
            }
        )
    
    @audit_action(entity_type='CASE_COMMENT', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        comment = self.get_object()
        case = comment.case
        case_id = str(case.case_id)
        comment_id = str(comment.comment_id)
        
        # Create timeline event before deleting
        if hasattr(request.user, 'profile'):
            create_timeline_event(
                case=case,
                organization=request.user.profile.organization,
                event_type='COMMENT_DELETED',
                description=f"Comentário removido por {request.user.get_full_name() or request.user.username}",
                actor=request.user,
                metadata={
                    'comment_text': comment.comment_text[:100] + ('...' if len(comment.comment_text) > 100 else ''),
                    'created_by': comment.user.get_full_name() or comment.user.username
                }
            )
        
        # Notificar via WebSocket
        WebSocketService.send_case_update(
            case_id=case_id,
            event_type='comment_deleted',
            data={
                'case_id': case_id,
                'comment_id': comment_id
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
