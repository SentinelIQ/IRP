from django.utils import timezone
from django.db.models import Q
from .models import TimelineEvent
from irp.common.websocket import WebSocketService

# Constantes para tipos de eventos da timeline
class EventType:
    # Eventos de Caso
    CASE_CREATED = "CASE_CREATED"
    CASE_UPDATED = "CASE_UPDATED"
    CASE_CLOSED = "CASE_CLOSED"
    STATUS_CHANGED = "STATUS_CHANGED"
    USER_ASSIGNED = "USER_ASSIGNED"
    
    # Eventos de Tarefa
    TASK_CREATED = "TASK_CREATED"
    TASK_UPDATED = "TASK_UPDATED"
    TASK_COMPLETED = "TASK_COMPLETED"
    TASK_STATUS_CHANGED = "TASK_STATUS_CHANGED"
    TASK_ASSIGNED = "TASK_ASSIGNED"
    TASK_DELETED = "TASK_DELETED"
    
    # Eventos de Comentários
    COMMENT_ADDED = "COMMENT_ADDED"
    COMMENT_UPDATED = "COMMENT_UPDATED"
    COMMENT_DELETED = "COMMENT_DELETED"
    
    # Eventos de Observáveis
    OBSERVABLE_ADDED = "OBSERVABLE_ADDED"
    OBSERVABLE_UPDATED = "OBSERVABLE_UPDATED"
    OBSERVABLE_REMOVED = "OBSERVABLE_REMOVED"
    OBSERVABLE_EXTRACTED = "OBSERVABLE_EXTRACTED"
    
    # Eventos de MITRE
    MITRE_TECHNIQUE_ADDED = "MITRE_TECHNIQUE_ADDED"
    MITRE_TECHNIQUE_REMOVED = "MITRE_TECHNIQUE_REMOVED"
    
    # Eventos de Alertas
    ALERT_ESCALATED = "ALERT_ESCALATED"
    ALERT_LINKED = "ALERT_LINKED"
    
    # Eventos de Relatórios
    REPORT_GENERATED = "REPORT_GENERATED"
    
    # Eventos manuais
    MANUAL_EVENT = "MANUAL_EVENT"
    IMPORTANT_UPDATE = "IMPORTANT_UPDATE"

def create_timeline_event(case, organization, event_type, description, actor, 
                         target_entity_type=None, target_entity_id=None, metadata=None,
                         occurred_at=None, is_important=False):
    """
    Helper function to create timeline events.
    This should be called whenever a significant action happens in a case.
    
    Args:
        case: Caso relacionado ao evento
        organization: Organização do caso
        event_type: Tipo de evento (use constants from EventType)
        description: Descrição textual do evento
        actor: Usuário que realizou a ação
        target_entity_type: Tipo da entidade relacionada (opcional)
        target_entity_id: ID da entidade relacionada (opcional)
        metadata: Dados adicionais específicos do evento (dict)
        occurred_at: Data/hora em que o evento ocorreu (default: now)
        is_important: Se o evento deve ser marcado como importante
        
    Returns:
        TimelineEvent: O evento criado
    """
    event = TimelineEvent.objects.create(
        case=case,
        organization=organization,
        event_type=event_type,
        description=description,
        actor=actor,
        target_entity_type=target_entity_type,
        target_entity_id=target_entity_id,
        metadata=metadata or {},
        occurred_at=occurred_at or timezone.now(),
        is_important=is_important
    )
    
    # Notificar via WebSocket
    WebSocketService.send_case_update(
        case_id=case.case_id,
        event_type='timeline_event_created',
        data={
            'case_id': str(case.case_id),
            'event_type': event_type,
            'description': description,
            'is_important': is_important
        }
    )
    
    return event

def get_recent_events(case=None, organization=None, limit=10, event_types=None, since=None, until=None, 
                     important_only=False, actor=None, entity_type=None, entity_id=None):
    """
    Obtém eventos recentes da timeline com base nos filtros fornecidos.
    
    Args:
        case: Filtrar por caso específico
        organization: Filtrar por organização
        limit: Número máximo de eventos a retornar
        event_types: Lista de tipos de evento para filtrar
        since: Data/hora inicial para filtro
        until: Data/hora final para filtro
        important_only: Se deve retornar apenas eventos marcados como importantes
        actor: Filtrar por usuário que realizou a ação
        entity_type: Filtrar por tipo de entidade relacionada
        entity_id: Filtrar por ID de entidade relacionada
        
    Returns:
        QuerySet: Eventos da timeline filtrados e ordenados
    """
    query = TimelineEvent.objects.all()
    
    if case:
        query = query.filter(case=case)
    
    if organization:
        query = query.filter(organization=organization)
    
    if event_types:
        query = query.filter(event_type__in=event_types)
    
    if since:
        query = query.filter(occurred_at__gte=since)
    
    if until:
        query = query.filter(occurred_at__lte=until)
    
    if important_only:
        query = query.filter(is_important=True)
    
    if actor:
        query = query.filter(actor=actor)
    
    if entity_type and entity_id:
        query = query.filter(target_entity_type=entity_type, target_entity_id=entity_id)
    elif entity_type:
        query = query.filter(target_entity_type=entity_type)
    elif entity_id:
        query = query.filter(target_entity_id=entity_id)
    
    return query.order_by('-occurred_at')[:limit]

def get_user_activity_summary(user, days=7):
    """
    Obtém um resumo das atividades recentes de um usuário.
    
    Args:
        user: Usuário para buscar atividades
        days: Número de dias anteriores para incluir
        
    Returns:
        dict: Resumo das atividades do usuário
    """
    since_date = timezone.now() - timezone.timedelta(days=days)
    
    # Obter eventos em que o usuário foi o ator
    user_events = TimelineEvent.objects.filter(
        actor=user,
        occurred_at__gte=since_date
    )
    
    # Contar por tipo de evento
    event_counts = user_events.values('event_type').annotate(
        count=models.Count('event_type')
    ).order_by('-count')
    
    # Casos em que o usuário esteve ativo
    active_cases = user_events.values(
        'case__case_id', 'case__title'
    ).distinct()
    
    return {
        'total_activities': user_events.count(),
        'event_type_summary': list(event_counts),
        'active_cases': list(active_cases),
        'first_activity': user_events.order_by('occurred_at').first(),
        'latest_activity': user_events.order_by('-occurred_at').first()
    }
