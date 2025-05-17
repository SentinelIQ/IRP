from rest_framework import serializers
from .models import (
    MISPInstance, MISPExport, MISPImport, ObservableMISPMapping,
    MISPTaxonomy, MISPTaxonomyEntry, CaseTaxonomyTag, AlertTaxonomyTag, ObservableTaxonomyTag
)


class MISPInstanceSerializer(serializers.ModelSerializer):
    """
    Serializador para instâncias MISP.
    """
    class Meta:
        model = MISPInstance
        fields = [
            'instance_id', 'name', 'url', 'api_key', 'verify_ssl', 
            'default_distribution', 'default_threat_level', 'default_analysis',
            'import_filter_tags', 'export_default_tags', 'is_active', 
            'last_import_timestamp', 'created_at', 'updated_at'
        ]
        extra_kwargs = {
            'api_key': {'write_only': True}  # Nunca retornar a API key nas responses
        }


class MISPImportSerializer(serializers.ModelSerializer):
    """
    Serializador para registros de importação MISP.
    """
    misp_instance_name = serializers.ReadOnlyField(source='misp_instance.name')
    imported_by_username = serializers.ReadOnlyField(source='imported_by.username')
    organization_name = serializers.ReadOnlyField(source='organization.name')
    
    class Meta:
        model = MISPImport
        fields = [
            'import_id', 'misp_instance', 'misp_instance_name', 'organization',
            'organization_name', 'import_timestamp', 'imported_by', 
            'imported_by_username', 'status', 'error_message',
            'imported_events_count', 'imported_attributes_count',
            'created_alerts_count', 'created_observables_count', 
            'updated_observables_count'
        ]
        read_only_fields = [
            'import_id', 'import_timestamp', 'status', 'error_message',
            'imported_events_count', 'imported_attributes_count',
            'created_alerts_count', 'created_observables_count',
            'updated_observables_count'
        ]


class MISPExportSerializer(serializers.ModelSerializer):
    """
    Serializador para registros de exportação MISP.
    """
    misp_instance_name = serializers.ReadOnlyField(source='misp_instance.name')
    exported_by_username = serializers.ReadOnlyField(source='exported_by.username')
    case_title = serializers.ReadOnlyField(source='case.title')
    
    class Meta:
        model = MISPExport
        fields = [
            'export_id', 'misp_instance', 'misp_instance_name', 'case', 'case_title',
            'misp_event_uuid', 'export_timestamp', 'exported_by', 
            'exported_by_username', 'status', 'error_message',
            'exported_observables_count'
        ]
        read_only_fields = [
            'export_id', 'misp_event_uuid', 'export_timestamp', 
            'status', 'error_message', 'exported_observables_count'
        ]


class ObservableMISPMappingSerializer(serializers.ModelSerializer):
    """
    Serializador para mapeamentos entre observáveis e atributos MISP.
    """
    observable_value = serializers.ReadOnlyField(source='observable.value')
    observable_type = serializers.ReadOnlyField(source='observable.type.name')
    misp_instance_name = serializers.ReadOnlyField(source='misp_instance.name')
    
    class Meta:
        model = ObservableMISPMapping
        fields = [
            'mapping_id', 'observable', 'observable_value', 'observable_type',
            'misp_instance', 'misp_instance_name', 'misp_event_uuid',
            'misp_attribute_uuid', 'last_sync_timestamp'
        ]
        read_only_fields = ['mapping_id', 'last_sync_timestamp']


class TriggerMISPImportSerializer(serializers.Serializer):
    """
    Serializador para disparar importação MISP sob demanda.
    """
    misp_instance_id = serializers.UUIDField()
    from_timestamp = serializers.DateTimeField(required=False)
    filter_tags = serializers.ListField(child=serializers.CharField(), required=False)
    create_alerts = serializers.BooleanField(default=True)


class ExportCaseToMISPSerializer(serializers.Serializer):
    """
    Serializador para exportar um caso para MISP.
    """
    misp_instance_id = serializers.UUIDField()
    include_observables = serializers.BooleanField(default=True)
    include_timeline = serializers.BooleanField(default=False)
    include_mitre_techniques = serializers.BooleanField(default=True)
    distribution = serializers.IntegerField(required=False)
    threat_level = serializers.IntegerField(required=False)
    analysis = serializers.IntegerField(required=False)
    additional_tags = serializers.ListField(child=serializers.CharField(), required=False)


class MISPTaxonomySerializer(serializers.ModelSerializer):
    misp_instance_name = serializers.ReadOnlyField(source='misp_instance.name')
    entries_count = serializers.SerializerMethodField()
    
    class Meta:
        model = MISPTaxonomy
        fields = ['taxonomy_id', 'misp_instance', 'misp_instance_name', 'namespace', 
                  'description', 'version', 'enabled_for_platform', 'synced_at', 'entries_count']
        read_only_fields = ['taxonomy_id', 'misp_instance', 'namespace', 'version', 'synced_at']
    
    def get_entries_count(self, obj):
        return obj.entries.count()


class MISPTaxonomyEntrySerializer(serializers.ModelSerializer):
    taxonomy_namespace = serializers.ReadOnlyField(source='taxonomy.namespace')
    tag_name = serializers.ReadOnlyField()
    
    class Meta:
        model = MISPTaxonomyEntry
        fields = ['entry_id', 'taxonomy', 'taxonomy_namespace', 'predicate', 
                  'value', 'description_expanded', 'numerical_value', 'tag_name']
        read_only_fields = ['entry_id', 'taxonomy', 'predicate', 'value']


class CaseTaxonomyTagSerializer(serializers.ModelSerializer):
    taxonomy_namespace = serializers.ReadOnlyField(source='taxonomy_entry.taxonomy.namespace')
    predicate = serializers.ReadOnlyField(source='taxonomy_entry.predicate')
    value = serializers.ReadOnlyField(source='taxonomy_entry.value')
    tag_name = serializers.ReadOnlyField(source='taxonomy_entry.tag_name')
    linked_by_username = serializers.ReadOnlyField(source='linked_by.username')
    
    class Meta:
        model = CaseTaxonomyTag
        fields = ['case', 'taxonomy_entry', 'taxonomy_namespace', 'predicate', 
                  'value', 'tag_name', 'linked_by', 'linked_by_username', 'linked_at']
        read_only_fields = ['linked_at']


class AlertTaxonomyTagSerializer(serializers.ModelSerializer):
    taxonomy_namespace = serializers.ReadOnlyField(source='taxonomy_entry.taxonomy.namespace')
    predicate = serializers.ReadOnlyField(source='taxonomy_entry.predicate')
    value = serializers.ReadOnlyField(source='taxonomy_entry.value')
    tag_name = serializers.ReadOnlyField(source='taxonomy_entry.tag_name')
    linked_by_username = serializers.ReadOnlyField(source='linked_by.username')
    
    class Meta:
        model = AlertTaxonomyTag
        fields = ['alert', 'taxonomy_entry', 'taxonomy_namespace', 'predicate', 
                  'value', 'tag_name', 'linked_by', 'linked_by_username', 'linked_at']
        read_only_fields = ['linked_at']


class ObservableTaxonomyTagSerializer(serializers.ModelSerializer):
    taxonomy_namespace = serializers.ReadOnlyField(source='taxonomy_entry.taxonomy.namespace')
    predicate = serializers.ReadOnlyField(source='taxonomy_entry.predicate')
    value = serializers.ReadOnlyField(source='taxonomy_entry.value')
    tag_name = serializers.ReadOnlyField(source='taxonomy_entry.tag_name')
    linked_by_username = serializers.ReadOnlyField(source='linked_by.username')
    
    class Meta:
        model = ObservableTaxonomyTag
        fields = ['observable', 'taxonomy_entry', 'taxonomy_namespace', 'predicate', 
                  'value', 'tag_name', 'linked_by', 'linked_by_username', 'linked_at']
        read_only_fields = ['linked_at']


# Serializer para usar ao adicionar tags de taxonomia a casos/alertas/observáveis
class TaxonomyTagInputSerializer(serializers.Serializer):
    taxonomy_namespace = serializers.CharField(required=True)
    predicate = serializers.CharField(required=True)
    value = serializers.CharField(required=False, allow_blank=True)
    
    def validate(self, data):
        namespace = data.get('taxonomy_namespace')
        predicate = data.get('predicate')
        value = data.get('value', '')
        
        # Verificar se a taxonomia existe e está habilitada
        try:
            taxonomy = MISPTaxonomy.objects.get(namespace=namespace, enabled_for_platform=True)
        except MISPTaxonomy.DoesNotExist:
            raise serializers.ValidationError(f"Taxonomia '{namespace}' não encontrada ou desabilitada")
        
        # Verificar se a entrada da taxonomia existe
        try:
            entry = MISPTaxonomyEntry.objects.get(
                taxonomy=taxonomy, 
                predicate=predicate,
                value=value
            )
            data['taxonomy_entry_id'] = entry.entry_id
        except MISPTaxonomyEntry.DoesNotExist:
            raise serializers.ValidationError(f"Entrada de taxonomia '{namespace}:{predicate}' não encontrada")
            
        return data 