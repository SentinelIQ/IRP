from django.contrib import admin
from .models import MISPInstance, MISPImport, MISPExport, ObservableMISPMapping

@admin.register(MISPInstance)
class MISPInstanceAdmin(admin.ModelAdmin):
    list_display = ('name', 'url', 'organization', 'is_active', 'last_import_timestamp')
    list_filter = ('is_active', 'organization')
    search_fields = ('name', 'url')
    readonly_fields = ('instance_id', 'created_at', 'updated_at')
    fieldsets = (
        ('Informações Básicas', {
            'fields': ('instance_id', 'name', 'organization', 'is_active')
        }),
        ('Conexão', {
            'fields': ('url', 'api_key', 'verify_ssl')
        }),
        ('Configurações de Exportação/Importação', {
            'fields': ('default_distribution', 'default_threat_level', 'default_analysis',
                       'import_filter_tags', 'export_default_tags')
        }),
        ('Metadados', {
            'fields': ('last_import_timestamp', 'created_at', 'updated_at')
        }),
    )


@admin.register(MISPImport)
class MISPImportAdmin(admin.ModelAdmin):
    list_display = ('misp_instance', 'organization', 'import_timestamp', 'status', 
                    'imported_events_count', 'created_alerts_count')
    list_filter = ('status', 'organization', 'misp_instance')
    search_fields = ('misp_instance__name', 'organization__name')
    readonly_fields = ('import_id', 'import_timestamp', 'imported_by',
                       'imported_events_count', 'imported_attributes_count',
                       'created_alerts_count', 'created_observables_count',
                       'updated_observables_count')
    fieldsets = (
        ('Informações Básicas', {
            'fields': ('import_id', 'misp_instance', 'organization', 'status')
        }),
        ('Resultado da Importação', {
            'fields': ('imported_events_count', 'imported_attributes_count',
                       'created_alerts_count', 'created_observables_count',
                       'updated_observables_count')
        }),
        ('Metadados', {
            'fields': ('import_timestamp', 'imported_by', 'error_message')
        }),
    )


@admin.register(MISPExport)
class MISPExportAdmin(admin.ModelAdmin):
    list_display = ('misp_instance', 'case', 'export_timestamp', 'status', 'exported_observables_count')
    list_filter = ('status', 'misp_instance')
    search_fields = ('misp_instance__name', 'case__title', 'misp_event_uuid')
    readonly_fields = ('export_id', 'export_timestamp', 'exported_by', 'misp_event_uuid',
                       'exported_observables_count')
    fieldsets = (
        ('Informações Básicas', {
            'fields': ('export_id', 'misp_instance', 'case', 'status')
        }),
        ('Dados do Evento MISP', {
            'fields': ('misp_event_uuid', 'exported_observables_count')
        }),
        ('Metadados', {
            'fields': ('export_timestamp', 'exported_by', 'error_message')
        }),
    )


@admin.register(ObservableMISPMapping)
class ObservableMISPMappingAdmin(admin.ModelAdmin):
    list_display = ('observable', 'misp_instance', 'misp_event_uuid', 'last_sync_timestamp')
    list_filter = ('misp_instance', 'last_sync_timestamp')
    search_fields = ('observable__value', 'misp_event_uuid', 'misp_attribute_uuid')
    readonly_fields = ('mapping_id', 'last_sync_timestamp')
    fieldsets = (
        ('Mapeamento', {
            'fields': ('mapping_id', 'observable', 'misp_instance')
        }),
        ('Referências MISP', {
            'fields': ('misp_event_uuid', 'misp_attribute_uuid')
        }),
        ('Metadados', {
            'fields': ('last_sync_timestamp',)
        }),
    ) 