from rest_framework import serializers
from .models import MISPInstance, MISPImport, MISPExport, ObservableMISPMapping


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