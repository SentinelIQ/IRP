from rest_framework import serializers

from .models import ReportTemplate, GeneratedReport, ScheduledReport


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


class ScheduledReportSerializer(serializers.ModelSerializer):
    created_by_username = serializers.ReadOnlyField(source='created_by.username')
    organization_name = serializers.ReadOnlyField(source='organization.name')
    template_name = serializers.ReadOnlyField(source='template.name')
    notify_users_info = serializers.SerializerMethodField()
    
    class Meta:
        model = ScheduledReport
        fields = ['schedule_id', 'name', 'description', 'organization', 'organization_name',
                  'created_by', 'created_by_username', 'case_filter',
                  'template', 'template_name', 'output_format',
                  'include_sections', 'include_attachments',
                  'custom_header', 'custom_footer',
                  'frequency', 'day_of_week', 'day_of_month', 'hour', 'minute',
                  'notify_users', 'notify_users_info', 'send_email',
                  'is_active', 'created_at', 'updated_at', 'last_run', 'next_run']
        read_only_fields = ['schedule_id', 'created_at', 'updated_at', 
                           'last_run', 'next_run']
    
    def get_notify_users_info(self, obj):
        """Retorna informações dos usuários a serem notificados"""
        return [
            {
                'id': user.id,
                'username': user.username,
                'full_name': f"{user.first_name} {user.last_name}".strip() or user.username
            }
            for user in obj.notify_users.all()
        ]
    
    def validate(self, data):
        """Validação adicional para os campos de agendamento"""
        frequency = data.get('frequency')
        day_of_week = data.get('day_of_week')
        day_of_month = data.get('day_of_month')
        
        if frequency == 'WEEKLY' and (day_of_week is None or day_of_week < 0 or day_of_week > 6):
            raise serializers.ValidationError(
                {'day_of_week': 'Para frequência semanal, informe um dia da semana válido (0-6)'}
            )
            
        if frequency in ['MONTHLY', 'QUARTERLY'] and (day_of_month is None or day_of_month < 1 or day_of_month > 31):
            raise serializers.ValidationError(
                {'day_of_month': 'Para frequência mensal/trimestral, informe um dia do mês válido (1-31)'}
            )
            
        return data 