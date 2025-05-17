from rest_framework import viewsets, permissions, status, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.db.models import Q
from datetime import timedelta

from .models import TimelineEvent
from .serializers import TimelineEventSerializer, TimelineEventCreateSerializer
from .services import create_timeline_event, get_recent_events, EventType
from irp.common.permissions import HasRolePermission
from irp.common.audit import audit_action
from irp.common.websocket import WebSocketService

class TimelineEventViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for retrieving timeline events for a specific case.
    Timeline events provide a chronological view of all activities related to a case.
    """
    queryset = TimelineEvent.objects.all()
    serializer_class = TimelineEventSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'case:view'
    filter_backends = [filters.OrderingFilter, filters.SearchFilter]
    ordering_fields = ['occurred_at']
    ordering = ['-occurred_at']
    search_fields = ['description', 'event_type', 'metadata']
    
    def get_queryset(self):
        case_id = self.kwargs.get('case_pk')
        user = self.request.user
        
        if case_id:
            if hasattr(user, 'profile') and user.profile.organization:
                org_id = user.profile.organization.organization_id
                queryset = TimelineEvent.objects.filter(
                    case__case_id=case_id, 
                    organization_id=org_id
                ).order_by('-occurred_at')
                
                # Apply filters from query params
                return self.apply_filters(queryset)
        return TimelineEvent.objects.none()
    
    def apply_filters(self, queryset):
        # Get filter parameters from request
        event_type = self.request.query_params.get('event_type')
        since = self.request.query_params.get('since')
        until = self.request.query_params.get('until')
        is_important = self.request.query_params.get('is_important')
        actor_id = self.request.query_params.get('actor_id')
        entity_type = self.request.query_params.get('entity_type')
        entity_id = self.request.query_params.get('entity_id')
        
        # Apply filters if provided
        if event_type:
            event_types = event_type.split(',')
            queryset = queryset.filter(event_type__in=event_types)
        
        if since:
            try:
                since_date = timezone.datetime.fromisoformat(since)
                queryset = queryset.filter(occurred_at__gte=since_date)
            except (ValueError, TypeError):
                pass
        
        if until:
            try:
                until_date = timezone.datetime.fromisoformat(until)
                queryset = queryset.filter(occurred_at__lte=until_date)
            except (ValueError, TypeError):
                pass
        
        if is_important == 'true':
            queryset = queryset.filter(is_important=True)
        
        if actor_id:
            queryset = queryset.filter(actor_id=actor_id)
        
        if entity_type:
            queryset = queryset.filter(target_entity_type=entity_type)
        
        if entity_id:
            queryset = queryset.filter(target_entity_id=entity_id)
        
        return queryset
        
    @action(detail=False, methods=['post'])
    @audit_action(entity_type='TIMELINE_EVENT', action_type='CREATE')
    def create_event(self, request, case_pk=None):
        """
        Criar evento manualmente na timeline
        """
        from irp.cases.models import Case
        
        case = get_object_or_404(Case, case_id=case_pk)
        user = request.user
        
        # Verificar se o usuário pertence à mesma organização do caso
        if not hasattr(user, 'profile') or not user.profile.organization or user.profile.organization != case.organization:
            raise PermissionError("Usuário não pode adicionar eventos a este caso")
        
        # Validar os dados com o serializador
        serializer = TimelineEventCreateSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        # Extrair dados validados
        event_type = serializer.validated_data.get('event_type', 'MANUAL_EVENT')
        description = serializer.validated_data.get('description')
        metadata = serializer.validated_data.get('metadata', {})
        occurred_at = serializer.validated_data.get('occurred_at')
        is_important = serializer.validated_data.get('is_important', False)
        
        # Criar evento
        event = create_timeline_event(
            case=case,
            organization=case.organization,
            event_type=event_type,
            description=description,
            actor=user,
            metadata=metadata,
            occurred_at=occurred_at,
            is_important=is_important
        )
        
        # Serializar e retornar
        result_serializer = TimelineEventSerializer(event)
        return Response(result_serializer.data, status=status.HTTP_201_CREATED)
    
    @action(detail=False, methods=['get'])
    def summary(self, request, case_pk=None):
        """
        Obtém um resumo dos eventos da timeline, agrupados por tipo de evento
        """
        from irp.cases.models import Case
        
        case = get_object_or_404(Case, case_id=case_pk)
        user = request.user
        
        # Verificar se o usuário pertence à mesma organização do caso
        if not hasattr(user, 'profile') or not user.profile.organization or user.profile.organization != case.organization:
            raise PermissionError("Usuário não tem permissão para visualizar este caso")
        
        # Obter todos os eventos da timeline para este caso
        events = TimelineEvent.objects.filter(
            case=case,
            organization=user.profile.organization
        )
        
        # Agrupar por tipo de evento
        event_types = {}
        for event in events:
            if event.event_type not in event_types:
                event_types[event.event_type] = 0
            event_types[event.event_type] += 1
        
        # Obter os usuários mais ativos
        from django.db.models import Count
        active_users = events.values('actor').annotate(
            event_count=Count('actor')
        ).order_by('-event_count')[:5]
        
        # Obter dados para essas estatísticas
        from django.contrib.auth import get_user_model
        User = get_user_model()
        active_user_details = []
        
        for user_stat in active_users:
            if user_stat['actor']:
                try:
                    user_obj = User.objects.get(id=user_stat['actor'])
                    active_user_details.append({
                        'user_id': user_obj.id,
                        'username': user_obj.username,
                        'full_name': f"{user_obj.first_name} {user_obj.last_name}".strip() or user_obj.username,
                        'event_count': user_stat['event_count']
                    })
                except User.DoesNotExist:
                    pass
        
        # Calcular distribuição temporal de eventos (eventos por dia)
        from django.db.models.functions import TruncDate
        temporal_distribution = events.annotate(
            day=TruncDate('occurred_at')
        ).values('day').annotate(
            count=Count('event_id')
        ).order_by('day')
        
        # Obter o primeiro e último evento
        first_event = events.order_by('occurred_at').first()
        last_event = events.order_by('-occurred_at').first()
        
        # Construir o resumo
        summary = {
            'total_events': events.count(),
            'event_types': event_types,
            'active_users': active_user_details,
            'temporal_distribution': list(temporal_distribution),
            'first_event': TimelineEventSerializer(first_event).data if first_event else None,
            'last_event': TimelineEventSerializer(last_event).data if last_event else None,
            'important_events_count': events.filter(is_important=True).count()
        }
        
        return Response(summary)
    
    @action(detail=False, methods=['get'])
    def recent(self, request, case_pk=None):
        """
        Obtém os eventos mais recentes da timeline, filtrados por tipo
        """
        from irp.cases.models import Case
        
        case = get_object_or_404(Case, case_id=case_pk)
        user = request.user
        
        # Verificar se o usuário pertence à mesma organização do caso
        if not hasattr(user, 'profile') or not user.profile.organization or user.profile.organization != case.organization:
            raise PermissionError("Usuário não tem permissão para visualizar este caso")
        
        # Opções de filtragem
        limit = int(request.query_params.get('limit', 10))
        days = int(request.query_params.get('days', 7))
        event_type = request.query_params.get('event_type')
        
        # Calcular data de início
        since_date = timezone.now() - timedelta(days=days)
        
        # Filtrar eventos
        events = TimelineEvent.objects.filter(
            case=case,
            organization=user.profile.organization,
            occurred_at__gte=since_date
        )
        
        if event_type:
            event_types = event_type.split(',')
            events = events.filter(event_type__in=event_types)
        
        # Obter os eventos mais recentes
        recent_events = events.order_by('-occurred_at')[:limit]
        
        # Serializar e retornar
        serializer = TimelineEventSerializer(recent_events, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def important(self, request, case_pk=None):
        """
        Obtém eventos importantes da timeline
        """
        from irp.cases.models import Case
        
        case = get_object_or_404(Case, case_id=case_pk)
        user = request.user
        
        # Verificar se o usuário pertence à mesma organização do caso
        if not hasattr(user, 'profile') or not user.profile.organization or user.profile.organization != case.organization:
            raise PermissionError("Usuário não tem permissão para visualizar este caso")
        
        # Obter eventos importantes
        important_events = TimelineEvent.objects.filter(
            case=case,
            organization=user.profile.organization,
            is_important=True
        ).order_by('-occurred_at')
        
        # Serializar e retornar
        serializer = TimelineEventSerializer(important_events, many=True)
        return Response(serializer.data)
    
    @action(detail=True, methods=['post'])
    @audit_action(entity_type='TIMELINE_EVENT', action_type='MARK_IMPORTANT')
    def mark_important(self, request, case_pk=None, pk=None):
        """
        Marca um evento da timeline como importante
        """
        event = self.get_object()
        user = request.user
        
        # Verificar se o usuário pertence à mesma organização do evento
        if not hasattr(user, 'profile') or not user.profile.organization or user.profile.organization != event.organization:
            raise PermissionError("Usuário não tem permissão para modificar este evento")
        
        # Marcar como importante
        event.is_important = True
        event.save(update_fields=['is_important'])
        
        # Notificar via WebSocket
        WebSocketService.send_case_update(
            case_id=event.case.case_id,
            event_type='timeline_event_updated',
            data={
                'event_id': str(event.event_id),
                'is_important': True
            }
        )
        
        # Serializar e retornar
        serializer = TimelineEventSerializer(event)
        return Response(serializer.data)
