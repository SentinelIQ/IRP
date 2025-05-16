from django.core.management.base import BaseCommand
from api.models import NotificationEvent
import json

class Command(BaseCommand):
    help = 'Creates default notification events required by the platform'

    def handle(self, *args, **options):
        default_events = [
            {
                'event_name': 'ALERT_CREATED',
                'description': 'Triggered when a new alert is created in the system',
                'payload_schema': {
                    'type': 'object',
                    'properties': {
                        'alert_id': {'type': 'string'},
                        'title': {'type': 'string'},
                        'description': {'type': 'string'},
                        'severity': {'type': 'string'},
                        'status': {'type': 'string'},
                        'source_system': {'type': 'string'},
                        'created_at': {'type': 'string', 'format': 'date-time'},
                        'organization_id': {'type': 'integer'},
                        'organization_name': {'type': 'string'},
                        'assignee': {'type': ['string', 'null']}
                    }
                }
            },
            {
                'event_name': 'ALERT_UPDATED',
                'description': 'Triggered when an alert is updated',
                'payload_schema': {
                    'type': 'object',
                    'properties': {
                        'alert_id': {'type': 'string'},
                        'title': {'type': 'string'},
                        'severity': {'type': 'string'},
                        'status': {'type': 'string'},
                        'updated_at': {'type': 'string', 'format': 'date-time'},
                        'organization_id': {'type': 'integer'},
                        'organization_name': {'type': 'string'},
                        'assignee': {'type': ['string', 'null']}
                    }
                }
            },
            {
                'event_name': 'CASE_CREATED',
                'description': 'Triggered when a new case is created in the system',
                'payload_schema': {
                    'type': 'object',
                    'properties': {
                        'case_id': {'type': 'string'},
                        'title': {'type': 'string'},
                        'description': {'type': 'string'},
                        'severity': {'type': 'string'},
                        'status': {'type': 'string'},
                        'created_at': {'type': 'string', 'format': 'date-time'},
                        'organization_id': {'type': 'integer'},
                        'organization_name': {'type': 'string'},
                        'assignee': {'type': ['string', 'null']},
                        'reporter': {'type': ['string', 'null']}
                    }
                }
            },
            {
                'event_name': 'CASE_UPDATED',
                'description': 'Triggered when a case is updated',
                'payload_schema': {
                    'type': 'object',
                    'properties': {
                        'case_id': {'type': 'string'},
                        'title': {'type': 'string'},
                        'severity': {'type': 'string'},
                        'status': {'type': 'string'},
                        'updated_at': {'type': 'string', 'format': 'date-time'},
                        'organization_id': {'type': 'integer'},
                        'organization_name': {'type': 'string'},
                        'assignee': {'type': ['string', 'null']}
                    }
                }
            },
            {
                'event_name': 'CASE_STATUS_CHANGED',
                'description': 'Triggered when the status of a case changes',
                'payload_schema': {
                    'type': 'object',
                    'properties': {
                        'case_id': {'type': 'string'},
                        'title': {'type': 'string'},
                        'severity': {'type': 'string'},
                        'previous_status': {'type': ['string', 'null']},
                        'new_status': {'type': 'string'},
                        'updated_at': {'type': 'string', 'format': 'date-time'},
                        'organization_id': {'type': 'integer'},
                        'organization_name': {'type': 'string'},
                        'closed_at': {'type': ['string', 'null'], 'format': 'date-time'},
                        'assignee': {'type': ['string', 'null']}
                    }
                }
            },
            {
                'event_name': 'TASK_CREATED',
                'description': 'Triggered when a new task is created',
                'payload_schema': {
                    'type': 'object',
                    'properties': {
                        'task_id': {'type': 'string'},
                        'title': {'type': 'string'},
                        'description': {'type': 'string'},
                        'status': {'type': 'string'},
                        'created_at': {'type': 'string', 'format': 'date-time'},
                        'due_date': {'type': ['string', 'null'], 'format': 'date'},
                        'case_id': {'type': 'string'},
                        'case_title': {'type': 'string'},
                        'organization_id': {'type': 'integer'},
                        'organization_name': {'type': 'string'},
                        'assignee': {'type': ['string', 'null']}
                    }
                }
            },
            {
                'event_name': 'TASK_UPDATED',
                'description': 'Triggered when a task is updated',
                'payload_schema': {
                    'type': 'object',
                    'properties': {
                        'task_id': {'type': 'string'},
                        'title': {'type': 'string'},
                        'status': {'type': 'string'},
                        'updated_at': {'type': 'string', 'format': 'date-time'},
                        'due_date': {'type': ['string', 'null'], 'format': 'date'},
                        'case_id': {'type': 'string'},
                        'case_title': {'type': 'string'},
                        'organization_id': {'type': 'integer'},
                        'organization_name': {'type': 'string'},
                        'assignee': {'type': ['string', 'null']}
                    }
                }
            },
            {
                'event_name': 'TASK_ASSIGNED',
                'description': 'Triggered when a task is assigned to a user',
                'payload_schema': {
                    'type': 'object',
                    'properties': {
                        'task_id': {'type': 'string'},
                        'title': {'type': 'string'},
                        'status': {'type': 'string'},
                        'updated_at': {'type': 'string', 'format': 'date-time'},
                        'due_date': {'type': ['string', 'null'], 'format': 'date'},
                        'case_id': {'type': 'string'},
                        'case_title': {'type': 'string'},
                        'organization_id': {'type': 'integer'},
                        'organization_name': {'type': 'string'},
                        'previous_assignee': {'type': ['string', 'null']},
                        'assignee': {'type': ['string', 'null']}
                    }
                }
            },
            {
                'event_name': 'COMMENT_ADDED_TO_CASE',
                'description': 'Triggered when a comment is added to a case',
                'payload_schema': {
                    'type': 'object',
                    'properties': {
                        'comment_id': {'type': 'string'},
                        'comment_text': {'type': 'string'},
                        'created_at': {'type': 'string', 'format': 'date-time'},
                        'case_id': {'type': 'string'},
                        'case_title': {'type': 'string'},
                        'organization_id': {'type': 'integer'},
                        'organization_name': {'type': 'string'},
                        'user': {'type': ['string', 'null']}
                    }
                }
            },
            {
                'event_name': 'COMMENT_ADDED_TO_ALERT',
                'description': 'Triggered when a comment is added to an alert',
                'payload_schema': {
                    'type': 'object',
                    'properties': {
                        'comment_id': {'type': 'string'},
                        'comment_text': {'type': 'string'},
                        'created_at': {'type': 'string', 'format': 'date-time'},
                        'alert_id': {'type': 'string'},
                        'alert_title': {'type': 'string'},
                        'organization_id': {'type': 'integer'},
                        'organization_name': {'type': 'string'},
                        'user': {'type': ['string', 'null']}
                    }
                }
            }
        ]
        
        count_created = 0
        count_updated = 0
        
        for event_data in default_events:
            event_name = event_data['event_name']
            event, created = NotificationEvent.objects.update_or_create(
                event_name=event_name,
                defaults={
                    'description': event_data['description'],
                    'payload_schema': event_data['payload_schema']
                }
            )
            
            if created:
                count_created += 1
                self.stdout.write(self.style.SUCCESS(f'Created notification event: {event_name}'))
            else:
                count_updated += 1
                self.stdout.write(self.style.WARNING(f'Updated notification event: {event_name}'))
        
        if count_created > 0 or count_updated > 0:
            self.stdout.write(self.style.SUCCESS(
                f'Successfully created {count_created} and updated {count_updated} notification events'
            ))
        else:
            self.stdout.write(self.style.WARNING('No notification events created or updated')) 