from rest_framework import serializers
from .models import Metric, MetricSnapshot, Dashboard, DashboardWidget


class MetricSerializer(serializers.ModelSerializer):
    class Meta:
        model = Metric
        fields = '__all__'


class MetricSnapshotSerializer(serializers.ModelSerializer):
    metric_name = serializers.SerializerMethodField()
    organization_name = serializers.SerializerMethodField()
    
    class Meta:
        model = MetricSnapshot
        fields = ['snapshot_id', 'metric', 'metric_name', 'organization', 
                 'organization_name', 'date', 'granularity', 'dimensions', 'value']
        read_only_fields = ['snapshot_id']
    
    def get_metric_name(self, obj):
        return obj.metric.display_name if obj.metric else None
    
    def get_organization_name(self, obj):
        return obj.organization.name if obj.organization else None


class DashboardWidgetSerializer(serializers.ModelSerializer):
    metric_name = serializers.SerializerMethodField()
    
    class Meta:
        model = DashboardWidget
        fields = ['widget_id', 'dashboard', 'title', 'widget_type', 
                 'metric', 'metric_name', 'config', 'position']
        read_only_fields = ['widget_id']
    
    def get_metric_name(self, obj):
        return obj.metric.display_name if obj.metric else None


class DashboardSerializer(serializers.ModelSerializer):
    widgets = DashboardWidgetSerializer(many=True, read_only=True)
    organization_name = serializers.SerializerMethodField()
    created_by_name = serializers.SerializerMethodField()
    
    class Meta:
        model = Dashboard
        fields = ['dashboard_id', 'name', 'description', 'organization', 
                 'organization_name', 'is_system', 'layout', 'created_by', 
                 'created_by_name', 'created_at', 'updated_at', 'widgets']
        read_only_fields = ['dashboard_id', 'created_at', 'updated_at']
    
    def get_organization_name(self, obj):
        return obj.organization.name if obj.organization else None
    
    def get_created_by_name(self, obj):
        if obj.created_by:
            return f"{obj.created_by.first_name} {obj.created_by.last_name}".strip() or obj.created_by.username
        return None 