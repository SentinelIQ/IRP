from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.utils import timezone

from .models import TimelineEvent, Case
from .serializers import TimelineEventSerializer
from .permissions import HasRolePermission
from .views import audit_action

class TimelineEventViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for retrieving timeline events for a specific case.
    Timeline events provide a chronological view of all activities related to a case.
    """
    queryset = TimelineEvent.objects.all()
    serializer_class = TimelineEventSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'case:view'
    
    def get_queryset(self):
        case_id = self.kwargs.get('case_pk')
        user = self.request.user
        
        if case_id:
            if hasattr(user, 'profile') and user.profile.organization:
                org_id = user.profile.organization.organization_id
                return TimelineEvent.objects.filter(
                    case__case_id=case_id, 
                    organization_id=org_id
                ).order_by('-occurred_at')
        return TimelineEvent.objects.none()
        
    @action(detail=False, methods=['post'])
    @audit_action(entity_type='TIMELINE_EVENT', action_type='CREATE')
    def create_event(self, request, case_pk=None):
        """
        Criar evento manualmente na timeline
        """
        case = get_object_or_404(Case, case_id=case_pk)
        user = request.user
        
        # Verificar se o usuário pertence à mesma organização do caso
        if not hasattr(user, 'profile') or not user.profile.organization or user.profile.organization != case.organization:
            raise PermissionError("Usuário não pode adicionar eventos a este caso")
        
        # Extrair dados do request
        event_type = request.data.get('event_type', 'MANUAL_EVENT')
        description = request.data.get('description')
        metadata = request.data.get('metadata', {})
        occurred_at = request.data.get('occurred_at')
        
        if not description:
            return Response(
                {"detail": "Descrição do evento é obrigatória"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Criar evento
        event = create_timeline_event(
            case=case,
            organization=case.organization,
            event_type=event_type,
            description=description,
            actor=user,
            metadata=metadata,
            occurred_at=occurred_at
        )
        
        # Serializar e retornar
        serializer = self.get_serializer(event)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

def create_timeline_event(case, organization, event_type, description, actor, 
                         target_entity_type=None, target_entity_id=None, metadata=None,
                         occurred_at=None):
    """
    Helper function to create timeline events.
    This should be called whenever a significant action happens in a case.
    """
    return TimelineEvent.objects.create(
        case=case,
        organization=organization,
        event_type=event_type,
        description=description,
        actor=actor,
        target_entity_type=target_entity_type,
        target_entity_id=target_entity_id,
        metadata=metadata or {},
        occurred_at=occurred_at or timezone.now()
    ) 