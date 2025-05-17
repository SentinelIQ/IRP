from rest_framework import serializers

from .models import ReportTemplate, GeneratedReport


class ReportTemplateSerializer(serializers.ModelSerializer):
    created_by_username = serializers.ReadOnlyField(source='created_by.username')
    organization_name = serializers.ReadOnlyField(source='organization.name')
    
    class Meta:
        model = ReportTemplate
        fields = ['template_id', 'organization', 'organization_name', 'name', 
                  'description', 'output_format', 'template_content', 
                  'default_sections', 'is_active', 'created_at', 'updated_at',
                  'created_by', 'created_by_username']


class GeneratedReportSerializer(serializers.ModelSerializer):
    case_title = serializers.ReadOnlyField(source='case.title')
    template_name = serializers.ReadOnlyField(source='template.name')
    generated_by_username = serializers.ReadOnlyField(source='generated_by.username')
    
    class Meta:
        model = GeneratedReport
        fields = ['report_id', 'case', 'case_title', 'template', 'template_name',
                  'generated_by', 'generated_by_username', 'output_format',
                  'file_path', 'file_size', 'created_at', 'status',
                  'error_message', 'included_sections']
        read_only_fields = ['report_id', 'file_path', 'file_size', 'created_at',
                           'status', 'error_message']


class GenerateReportSerializer(serializers.Serializer):
    template_id = serializers.UUIDField(required=False)
    output_format = serializers.CharField(required=False)
    sections = serializers.ListField(child=serializers.CharField(), required=False)
    include_attachments = serializers.BooleanField(default=False)
    custom_header = serializers.CharField(required=False)
    custom_footer = serializers.CharField(required=False) 