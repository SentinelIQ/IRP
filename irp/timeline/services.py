from django.utils import timezone
from .models import TimelineEvent

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
