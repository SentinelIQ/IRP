from django.contrib import admin
from .models import NotificationEvent, NotificationChannel, NotificationRule, NotificationLog


class NotificationEventAdmin(admin.ModelAdmin):
    list_display = ('event_name', 'description')
    search_fields = ('event_name', 'description')


class NotificationChannelAdmin(admin.ModelAdmin):
    list_display = ('name', 'channel_type', 'organization', 'is_active', 'created_at')
    list_filter = ('channel_type', 'is_active', 'organization')
    search_fields = ('name',)
    date_hierarchy = 'created_at'


class NotificationRuleAdmin(admin.ModelAdmin):
    list_display = ('name', 'event_type', 'channel', 'organization', 'is_active', 'created_at')
    list_filter = ('event_type', 'is_active', 'organization')
    search_fields = ('name',)
    date_hierarchy = 'created_at'


class NotificationLogAdmin(admin.ModelAdmin):
    list_display = ('rule', 'channel', 'organization', 'status', 'sent_at')
    list_filter = ('status', 'organization')
    date_hierarchy = 'sent_at'
    readonly_fields = ('log_id', 'rule', 'channel', 'organization', 'event_payload', 
                      'sent_at', 'status', 'response_details', 'retry_count')


admin.site.register(NotificationEvent, NotificationEventAdmin)
admin.site.register(NotificationChannel, NotificationChannelAdmin)
admin.site.register(NotificationRule, NotificationRuleAdmin)
admin.site.register(NotificationLog, NotificationLogAdmin) 