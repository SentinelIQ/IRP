from rest_framework import serializers
from django.contrib.auth.models import User

from .models import (
    AlertSeverity, AlertStatus, Alert, AlertComment,
    AlertCustomFieldDefinition, AlertCustomFieldValue,
    AlertObservable
)
# AlertMitreTechniqueSerializer foi movido para irp.mitre.serializers

from irp.accounts.serializers import UserSerializer, OrganizationSerializer


class AlertSeveritySerializer(serializers.ModelSerializer):
    class Meta:
        model = AlertSeverity
        fields = '__all__'


class AlertStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = AlertStatus
        fields = '__all__'


class AlertCommentSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = AlertComment
        fields = '__all__'
        read_only_fields = ['comment_id', 'alert', 'user', 'created_at']


class AlertCustomFieldDefinitionSerializer(serializers.ModelSerializer):
    class Meta:
        model = AlertCustomFieldDefinition
        fields = '__all__'


class AlertCustomFieldValueSerializer(serializers.ModelSerializer):
    field_definition = AlertCustomFieldDefinitionSerializer(read_only=True)
    
    class Meta:
        model = AlertCustomFieldValue
        fields = '__all__'


class AlertSerializer(serializers.ModelSerializer):
    severity = AlertSeveritySerializer(read_only=True)
    status = AlertStatusSerializer(read_only=True)
    organization = OrganizationSerializer(read_only=True)
    assignee = UserSerializer(read_only=True)
    comments = AlertCommentSerializer(many=True, read_only=True)
    custom_field_values = AlertCustomFieldValueSerializer(many=True, read_only=True)
    
    class Meta:
        model = Alert
        fields = '__all__'
        read_only_fields = ['alert_id', 'created_at', 'updated_at']


class SimplifiedAlertSerializer(serializers.ModelSerializer):
    severity = AlertSeveritySerializer(read_only=True)
    status = AlertStatusSerializer(read_only=True)
    
    class Meta:
        model = Alert
        fields = ['alert_id', 'title', 'severity', 'status', 'created_at']


class AlertObservableSerializer(serializers.ModelSerializer):
    # This will be updated once the Observable model is migrated
    # observable = ObservableSerializer(read_only=True)
    
    class Meta:
        model = AlertObservable
        fields = '__all__'
        read_only_fields = ['alert']


# AlertMitreTechniqueSerializer foi movido para irp.mitre.serializers
