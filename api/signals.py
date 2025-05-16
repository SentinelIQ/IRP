from django.db.models.signals import post_save, post_delete, m2m_changed
from django.dispatch import receiver
from django.contrib.auth.models import User
from django.utils import timezone

from .models import (
    Alert, Case, Task, CaseComment, AlertComment, 
    NotificationEvent
)
from .services import NotificationService

@receiver(post_save, sender=Alert)
def alert_notification(sender, instance, created, **kwargs):
    """
    Trigger notifications when an alert is created or updated
    """
    if instance.is_deleted:
        return  # Don't notify for deleted alerts
    
    if created:
        # Alert created event
        event_payload = {
            'alert_id': str(instance.alert_id),
            'title': instance.title,
            'description': instance.description,
            'severity': instance.severity.name if instance.severity else None,
            'status': instance.status.name if instance.status else None,
            'source_system': instance.source_system,
            'created_at': instance.created_at.isoformat() if instance.created_at else None,
            'organization_id': instance.organization.organization_id,
            'organization_name': instance.organization.name,
            'assignee': instance.assignee.username if instance.assignee else None
        }
        
        NotificationService.process_event(
            event_name='ALERT_CREATED',
            payload=event_payload,
            organization=instance.organization
        )
    else:
        # Alert updated event
        event_payload = {
            'alert_id': str(instance.alert_id),
            'title': instance.title,
            'severity': instance.severity.name if instance.severity else None,
            'status': instance.status.name if instance.status else None,
            'organization_id': instance.organization.organization_id,
            'organization_name': instance.organization.name,
            'updated_at': instance.updated_at.isoformat() if instance.updated_at else None,
            'assignee': instance.assignee.username if instance.assignee else None
        }
        
        NotificationService.process_event(
            event_name='ALERT_UPDATED',
            payload=event_payload,
            organization=instance.organization
        )

@receiver(post_save, sender=Case)
def case_notification(sender, instance, created, **kwargs):
    """
    Trigger notifications when a case is created or updated
    """
    if created:
        # Case created event
        event_payload = {
            'case_id': str(instance.case_id),
            'title': instance.title,
            'description': instance.description,
            'severity': instance.severity.name if instance.severity else None,
            'status': instance.status.name if instance.status else None,
            'created_at': instance.created_at.isoformat() if instance.created_at else None,
            'organization_id': instance.organization.organization_id,
            'organization_name': instance.organization.name,
            'assignee': instance.assignee.username if instance.assignee else None,
            'reporter': instance.reporter.username if instance.reporter else None,
        }
        
        NotificationService.process_event(
            event_name='CASE_CREATED',
            payload=event_payload,
            organization=instance.organization
        )
    else:
        # Check if the status has changed
        if hasattr(instance, '_status_changed') and instance._status_changed:
            # Case status changed event
            event_payload = {
                'case_id': str(instance.case_id),
                'title': instance.title,
                'severity': instance.severity.name if instance.severity else None,
                'previous_status': instance._previous_status.name if hasattr(instance, '_previous_status') else None,
                'new_status': instance.status.name if instance.status else None,
                'updated_at': instance.updated_at.isoformat() if instance.updated_at else None,
                'organization_id': instance.organization.organization_id,
                'organization_name': instance.organization.name,
                'closed_at': instance.closed_at.isoformat() if instance.closed_at else None,
                'assignee': instance.assignee.username if instance.assignee else None
            }
            
            NotificationService.process_event(
                event_name='CASE_STATUS_CHANGED',
                payload=event_payload,
                organization=instance.organization
            )
        else:
            # Generic case updated event
            event_payload = {
                'case_id': str(instance.case_id),
                'title': instance.title,
                'severity': instance.severity.name if instance.severity else None,
                'status': instance.status.name if instance.status else None,
                'updated_at': instance.updated_at.isoformat() if instance.updated_at else None,
                'organization_id': instance.organization.organization_id,
                'organization_name': instance.organization.name,
                'assignee': instance.assignee.username if instance.assignee else None
            }
            
            NotificationService.process_event(
                event_name='CASE_UPDATED',
                payload=event_payload,
                organization=instance.organization
            )

@receiver(post_save, sender=Task)
def task_notification(sender, instance, created, **kwargs):
    """
    Trigger notifications when a task is created or updated
    """
    if created:
        # Task created event
        event_payload = {
            'task_id': str(instance.task_id),
            'title': instance.title,
            'description': instance.description,
            'status': instance.status.name if instance.status else None,
            'created_at': instance.created_at.isoformat() if instance.created_at else None,
            'due_date': instance.due_date.isoformat() if instance.due_date else None,
            'case_id': str(instance.case.case_id),
            'case_title': instance.case.title,
            'organization_id': instance.case.organization.organization_id,
            'organization_name': instance.case.organization.name,
            'assignee': instance.assignee.username if instance.assignee else None
        }
        
        NotificationService.process_event(
            event_name='TASK_CREATED',
            payload=event_payload,
            organization=instance.case.organization
        )
    else:
        # Task updated event
        event_payload = {
            'task_id': str(instance.task_id),
            'title': instance.title,
            'status': instance.status.name if instance.status else None,
            'updated_at': instance.updated_at.isoformat() if instance.updated_at else None,
            'due_date': instance.due_date.isoformat() if instance.due_date else None,
            'case_id': str(instance.case.case_id),
            'case_title': instance.case.title,
            'organization_id': instance.case.organization.organization_id,
            'organization_name': instance.case.organization.name,
            'assignee': instance.assignee.username if instance.assignee else None
        }
        
        # If the assignee was changed, send a specific notification
        if hasattr(instance, '_assignee_changed') and instance._assignee_changed:
            event_payload['previous_assignee'] = instance._previous_assignee.username if hasattr(instance, '_previous_assignee') and instance._previous_assignee else None
            
            NotificationService.process_event(
                event_name='TASK_ASSIGNED',
                payload=event_payload,
                organization=instance.case.organization
            )
        else:
            NotificationService.process_event(
                event_name='TASK_UPDATED',
                payload=event_payload,
                organization=instance.case.organization
            )

@receiver(post_save, sender=CaseComment)
def case_comment_notification(sender, instance, created, **kwargs):
    """
    Trigger notifications when a comment is added to a case
    """
    if created:
        event_payload = {
            'comment_id': str(instance.comment_id),
            'comment_text': instance.comment_text,
            'created_at': instance.created_at.isoformat() if instance.created_at else None,
            'case_id': str(instance.case.case_id),
            'case_title': instance.case.title,
            'organization_id': instance.case.organization.organization_id,
            'organization_name': instance.case.organization.name,
            'user': instance.user.username if instance.user else None
        }
        
        NotificationService.process_event(
            event_name='COMMENT_ADDED_TO_CASE',
            payload=event_payload,
            organization=instance.case.organization
        )

@receiver(post_save, sender=AlertComment)
def alert_comment_notification(sender, instance, created, **kwargs):
    """
    Trigger notifications when a comment is added to an alert
    """
    if created:
        event_payload = {
            'comment_id': str(instance.comment_id),
            'comment_text': instance.comment_text,
            'created_at': instance.created_at.isoformat() if instance.created_at else None,
            'alert_id': str(instance.alert.alert_id),
            'alert_title': instance.alert.title,
            'organization_id': instance.alert.organization.organization_id,
            'organization_name': instance.alert.organization.name,
            'user': instance.user.username if instance.user else None
        }
        
        NotificationService.process_event(
            event_name='COMMENT_ADDED_TO_ALERT',
            payload=event_payload,
            organization=instance.alert.organization
        ) 