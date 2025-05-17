from django.contrib import admin
from .models import ReportTemplate, GeneratedReport, ScheduledReport


@admin.register(ReportTemplate)
class ReportTemplateAdmin(admin.ModelAdmin):
    list_display = ('name', 'organization', 'output_format', 'is_active', 'created_at', 'created_by')
    list_filter = ('output_format', 'is_active', 'organization')
    search_fields = ('name', 'description')
    date_hierarchy = 'created_at'


@admin.register(GeneratedReport)
class GeneratedReportAdmin(admin.ModelAdmin):
    list_display = ('report_id', 'case', 'template', 'output_format', 'status', 'created_at')
    list_filter = ('output_format', 'status')
    search_fields = ('case__title', 'template__name')
    date_hierarchy = 'created_at'
    readonly_fields = ('report_id', 'file_path', 'file_size', 'created_at', 'status', 'error_message')


@admin.register(ScheduledReport)
class ScheduledReportAdmin(admin.ModelAdmin):
    list_display = ('name', 'organization', 'frequency', 'is_active', 'last_run', 'next_run')
    list_filter = ('frequency', 'is_active', 'organization')
    search_fields = ('name', 'description')
    date_hierarchy = 'created_at'
    fieldsets = (
        ('Informações Básicas', {
            'fields': ('name', 'description', 'organization', 'created_by', 'is_active')
        }),
        ('Filtro de Casos', {
            'fields': ('case_filter',)
        }),
        ('Configurações do Relatório', {
            'fields': ('template', 'output_format', 'include_sections', 'include_attachments',
                      'custom_header', 'custom_footer')
        }),
        ('Agendamento', {
            'fields': ('frequency', 'day_of_week', 'day_of_month', 'hour', 'minute')
        }),
        ('Notificações', {
            'fields': ('notify_users', 'send_email')
        }),
        ('Status', {
            'fields': ('last_run', 'next_run'),
            'classes': ('collapse',)
        })
    )
    readonly_fields = ('last_run', 'next_run') 