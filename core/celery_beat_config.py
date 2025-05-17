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
} 