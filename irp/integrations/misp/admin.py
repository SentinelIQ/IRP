from django.contrib import admin
from .models import (
    MISPInstance, MISPImport, MISPExport, ObservableMISPMapping,
    MISPTaxonomy, MISPTaxonomyEntry, CaseTaxonomyTag, AlertTaxonomyTag, ObservableTaxonomyTag
)

@admin.register(MISPInstance)
class MISPInstanceAdmin(admin.ModelAdmin):
    list_display = ('name', 'url', 'organization', 'is_active', 'last_import_timestamp', 'import_taxonomies', 'last_taxonomy_sync_timestamp')
    list_filter = ('is_active', 'organization', 'import_taxonomies')
    search_fields = ('name', 'url')
    readonly_fields = ('instance_id', 'created_at', 'updated_at', 'last_taxonomy_sync_timestamp')
    fieldsets = (
        ('Informações Básicas', {
            'fields': ('instance_id', 'name', 'organization', 'is_active')
        }),
        ('Conexão', {
            'fields': ('url', 'api_key', 'verify_ssl')
        }),
        ('Configurações de Exportação/Importação', {
            'fields': ('default_distribution', 'default_threat_level', 'default_analysis',
                       'import_filter_tags', 'export_default_tags', 'import_taxonomies')
        }),
        ('Metadados', {
            'fields': ('last_import_timestamp', 'last_taxonomy_sync_timestamp', 'created_at', 'updated_at')
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


@admin.register(MISPTaxonomy)
class MISPTaxonomyAdmin(admin.ModelAdmin):
    list_display = ('namespace', 'misp_instance', 'description', 'version', 'enabled_for_platform', 'synced_at')
    list_filter = ('misp_instance', 'enabled_for_platform')
    search_fields = ('namespace', 'description')
    readonly_fields = ('taxonomy_id', 'synced_at')
    actions = ['enable_taxonomies', 'disable_taxonomies']
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.select_related('misp_instance')
    
    def enable_taxonomies(self, request, queryset):
        queryset.update(enabled_for_platform=True)
        self.message_user(request, f"{queryset.count()} taxonomias habilitadas com sucesso.")
    enable_taxonomies.short_description = "Habilitar taxonomias selecionadas"
    
    def disable_taxonomies(self, request, queryset):
        queryset.update(enabled_for_platform=False)
        self.message_user(request, f"{queryset.count()} taxonomias desabilitadas com sucesso.")
    disable_taxonomies.short_description = "Desabilitar taxonomias selecionadas"


@admin.register(MISPTaxonomyEntry)
class MISPTaxonomyEntryAdmin(admin.ModelAdmin):
    list_display = ('tag_name', 'taxonomy', 'predicate', 'value', 'numerical_value')
    list_filter = ('taxonomy__namespace', 'taxonomy')
    search_fields = ('predicate', 'value', 'description_expanded')
    readonly_fields = ('entry_id',)
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.select_related('taxonomy')


class BaseTaxonomyTagAdmin(admin.ModelAdmin):
    """Base class for taxonomy tag admin"""
    readonly_fields = ('linked_at',)
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.select_related('taxonomy_entry', 'taxonomy_entry__taxonomy', 'linked_by')
    
    def tag_name(self, obj):
        return obj.taxonomy_entry.tag_name
    tag_name.short_description = "Tag"
    
    def taxonomy(self, obj):
        return obj.taxonomy_entry.taxonomy.namespace
    taxonomy.short_description = "Taxonomia"
    
    def linked_by_username(self, obj):
        return obj.linked_by.username if obj.linked_by else "-"
    linked_by_username.short_description = "Usuário"


@admin.register(CaseTaxonomyTag)
class CaseTaxonomyTagAdmin(BaseTaxonomyTagAdmin):
    list_display = ('tag_name', 'case', 'taxonomy', 'linked_by_username', 'linked_at')
    list_filter = ('taxonomy_entry__taxonomy__namespace', 'linked_at')
    search_fields = ('case__title', 'taxonomy_entry__predicate', 'taxonomy_entry__value')


@admin.register(AlertTaxonomyTag)
class AlertTaxonomyTagAdmin(BaseTaxonomyTagAdmin):
    list_display = ('tag_name', 'alert', 'taxonomy', 'linked_by_username', 'linked_at')
    list_filter = ('taxonomy_entry__taxonomy__namespace', 'linked_at')
    search_fields = ('alert__title', 'taxonomy_entry__predicate', 'taxonomy_entry__value')


@admin.register(ObservableTaxonomyTag)
class ObservableTaxonomyTagAdmin(BaseTaxonomyTagAdmin):
    list_display = ('tag_name', 'observable', 'taxonomy', 'linked_by_username', 'linked_at')
    list_filter = ('taxonomy_entry__taxonomy__namespace', 'linked_at')
    search_fields = ('observable__value', 'taxonomy_entry__predicate', 'taxonomy_entry__value') 