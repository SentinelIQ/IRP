from django.contrib import admin
from .models import ReportTemplate, GeneratedReport


@admin.register(ReportTemplate)
class ReportTemplateAdmin(admin.ModelAdmin):
    list_display = ('name', 'organization', 'output_format', 'is_active', 'created_at', 'created_by')
    list_filter = ('organization', 'output_format', 'is_active')
    search_fields = ('name', 'description')
    readonly_fields = ('template_id', 'created_at', 'updated_at')


@admin.register(GeneratedReport)
class GeneratedReportAdmin(admin.ModelAdmin):
    list_display = ('case', 'template', 'output_format', 'status', 'generated_by', 'created_at')
    list_filter = ('status', 'output_format')
    search_fields = ('case__title', 'template__name')
    readonly_fields = ('report_id', 'file_path', 'file_size', 'created_at') 