from rest_framework import serializers
from .models import NotificationEvent, NotificationChannel, NotificationRule, NotificationLog


class NotificationEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = NotificationEvent
        fields = '__all__'


class NotificationChannelSerializer(serializers.ModelSerializer):
    organization_name = serializers.SerializerMethodField()
    
    class Meta:
        model = NotificationChannel
        fields = ['channel_id', 'organization', 'organization_name', 'channel_type', 
                 'name', 'configuration', 'is_active', 'created_at', 'updated_at']
        read_only_fields = ['channel_id', 'organization', 'created_at', 'updated_at']
    
    def get_organization_name(self, obj):
        return obj.organization.name if obj.organization else None


class NotificationRuleSerializer(serializers.ModelSerializer):
    event_name = serializers.SerializerMethodField()
    channel_name = serializers.SerializerMethodField()
    organization_name = serializers.SerializerMethodField()
    
    class Meta:
        model = NotificationRule
        fields = ['rule_id', 'organization', 'organization_name', 'name', 
                 'event_type', 'event_name', 'channel', 'channel_name', 
                 'conditions', 'message_template', 'is_active', 
                 'created_at', 'updated_at']
        read_only_fields = ['rule_id', 'organization', 'created_at', 'updated_at']
    
    def get_event_name(self, obj):
        return obj.event_type.event_name if obj.event_type else None
    
    def get_channel_name(self, obj):
        return obj.channel.name if obj.channel else None
    
    def get_organization_name(self, obj):
        return obj.organization.name if obj.organization else None


class NotificationLogSerializer(serializers.ModelSerializer):
    rule_name = serializers.SerializerMethodField()
    channel_name = serializers.SerializerMethodField()
    organization_name = serializers.SerializerMethodField()
    
    class Meta:
        model = NotificationLog
        fields = ['log_id', 'rule', 'rule_name', 'channel', 'channel_name', 
                 'organization', 'organization_name', 'event_payload', 
                 'sent_at', 'status', 'response_details', 'retry_count']
        read_only_fields = ['log_id', 'sent_at']
    
    def get_rule_name(self, obj):
        return obj.rule.name if obj.rule else None
    
    def get_channel_name(self, obj):
        return obj.channel.name if obj.channel else None
    
    def get_organization_name(self, obj):
        return obj.organization.name if obj.organization else None 