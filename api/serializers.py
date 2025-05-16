from rest_framework import serializers
from django.contrib.auth.models import User
from .models import (
    Organization, Team, Profile, Role, Permission, UserRole, RolePermission,
    AlertSeverity, AlertStatus, Alert, AlertComment, AlertCustomFieldDefinition, AlertCustomFieldValue,
    CaseSeverity, CaseStatus, CaseTemplate, Case, CaseComment, CaseCustomFieldDefinition, CaseCustomFieldValue,
    TaskStatus, Task, ObservableType, TLPLevel, PAPLevel, Observable, CaseObservable, AlertObservable, AuditLog
)

class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = '__all__'

class TeamSerializer(serializers.ModelSerializer):
    organization = OrganizationSerializer(read_only=True)
    members = serializers.PrimaryKeyRelatedField(many=True, queryset=User.objects.all())
    class Meta:
        model = Team
        fields = '__all__'

class ProfileSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField(read_only=True)
    organization = OrganizationSerializer(read_only=True)
    class Meta:
        model = Profile
        fields = '__all__'

class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = '__all__'

class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = '__all__'

class UserRoleSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField(read_only=True)
    role = RoleSerializer(read_only=True)
    organization = OrganizationSerializer(read_only=True)
    class Meta:
        model = UserRole
        fields = '__all__'

class RolePermissionSerializer(serializers.ModelSerializer):
    role = RoleSerializer(read_only=True)
    permission = PermissionSerializer(read_only=True)
    class Meta:
        model = RolePermission
        fields = '__all__'

class UserSerializer(serializers.ModelSerializer):
    profile = ProfileSerializer(read_only=True)
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'profile']

# Alert Management Serializers

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

# Case Management Serializers

class CaseSeveritySerializer(serializers.ModelSerializer):
    class Meta:
        model = CaseSeverity
        fields = '__all__'

class CaseStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = CaseStatus
        fields = '__all__'

class CaseTemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = CaseTemplate
        fields = '__all__'

class TaskStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = TaskStatus
        fields = '__all__'

class TaskSerializer(serializers.ModelSerializer):
    status = TaskStatusSerializer(read_only=True)
    assignee = UserSerializer(read_only=True)
    
    class Meta:
        model = Task
        fields = '__all__'
        read_only_fields = ['task_id', 'case', 'created_at', 'updated_at']

class CaseCommentSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = CaseComment
        fields = '__all__'
        read_only_fields = ['comment_id', 'case', 'user', 'created_at']

class CaseCustomFieldDefinitionSerializer(serializers.ModelSerializer):
    class Meta:
        model = CaseCustomFieldDefinition
        fields = '__all__'

class CaseCustomFieldValueSerializer(serializers.ModelSerializer):
    field_definition = CaseCustomFieldDefinitionSerializer(read_only=True)
    
    class Meta:
        model = CaseCustomFieldValue
        fields = '__all__'

class ObservableTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = ObservableType
        fields = '__all__'

class TLPLevelSerializer(serializers.ModelSerializer):
    class Meta:
        model = TLPLevel
        fields = '__all__'

class PAPLevelSerializer(serializers.ModelSerializer):
    class Meta:
        model = PAPLevel
        fields = '__all__'

class ObservableSerializer(serializers.ModelSerializer):
    type = ObservableTypeSerializer(read_only=True)
    tlp_level = TLPLevelSerializer(read_only=True)
    pap_level = PAPLevelSerializer(read_only=True)
    added_by = UserSerializer(read_only=True)
    
    class Meta:
        model = Observable
        fields = '__all__'
        read_only_fields = ['observable_id', 'added_at']

class CaseObservableSerializer(serializers.ModelSerializer):
    observable = ObservableSerializer(read_only=True)
    
    class Meta:
        model = CaseObservable
        fields = '__all__'
        read_only_fields = ['case']

class AlertObservableSerializer(serializers.ModelSerializer):
    observable = ObservableSerializer(read_only=True)
    
    class Meta:
        model = AlertObservable
        fields = '__all__'
        read_only_fields = ['alert']

class SimplifiedAlertSerializer(serializers.ModelSerializer):
    severity = AlertSeveritySerializer(read_only=True)
    status = AlertStatusSerializer(read_only=True)
    
    class Meta:
        model = Alert
        fields = ['alert_id', 'title', 'severity', 'status', 'created_at']

class CaseSerializer(serializers.ModelSerializer):
    severity = CaseSeveritySerializer(read_only=True)
    status = CaseStatusSerializer(read_only=True)
    organization = OrganizationSerializer(read_only=True)
    assignee = UserSerializer(read_only=True)
    reporter = UserSerializer(read_only=True)
    template = CaseTemplateSerializer(read_only=True)
    comments = CaseCommentSerializer(many=True, read_only=True)
    tasks = TaskSerializer(many=True, read_only=True)
    case_observables = CaseObservableSerializer(many=True, read_only=True)
    alerts = SimplifiedAlertSerializer(many=True, read_only=True)
    custom_field_values = CaseCustomFieldValueSerializer(many=True, read_only=True)
    
    class Meta:
        model = Case
        fields = '__all__'
        read_only_fields = ['case_id', 'created_at', 'updated_at']

class AuditLogSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    organization = OrganizationSerializer(read_only=True)
    
    class Meta:
        model = AuditLog
        fields = '__all__'
        read_only_fields = ['log_id', 'timestamp'] 