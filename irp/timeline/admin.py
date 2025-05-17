from django.contrib import admin
from .models import TimelineEvent

@admin.register(TimelineEvent)
class TimelineEventAdmin(admin.ModelAdmin):
    list_display = ('event_id', 'event_type', 'description', 'case', 'organization', 'occurred_at')
    list_filter = ('event_type', 'organization')
    search_fields = ('description', 'case__title')
