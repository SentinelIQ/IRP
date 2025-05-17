"""
Celery Beat schedule configuration
"""
from celery.schedules import crontab

# Define the periodic tasks schedule
beat_schedule = {
    'check-scheduled-reports-every-15-minutes': {
        'task': 'irp.reports.tasks.generate_scheduled_reports',
        'schedule': crontab(minute='*/15'),  # Run every 15 minutes
        'args': (),
    },
    'check-ldap-sync-every-30-minutes': {
        'task': 'irp.accounts.tasks.schedule_ldap_sync',
        'schedule': crontab(minute='*/30'),  # Run every 30 minutes
        'args': (),
    },
} 