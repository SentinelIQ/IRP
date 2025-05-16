from rest_framework import serializers
from django.contrib.auth.models import User
from .models import (
    Organization, Team, Profile, Role, Permission, UserRole, RolePermission,
    AlertSeverity, AlertStatus, Alert, AlertComment, AlertCustomFieldDefinition, AlertCustomFieldValue,
    CaseSeverity, CaseStatus, CaseTemplate, Case, CaseComment, CaseCustomFieldDefinition, CaseCustomFieldValue,
    TaskStatus, Task, ObservableType, TLPLevel, PAPLevel, Observable, CaseObservable, AlertObservable, AuditLog,
    TimelineEvent, MitreTactic, MitreTechnique, CaseMitreTechnique, AlertMitreTechnique, KBCategory, KBArticleVersion, KBArticle,
    NotificationEvent, NotificationChannel, NotificationRule, NotificationLog, Metric, MetricSnapshot, DashboardWidget, Dashboard
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

# Timeline serializers
class TimelineEventSerializer(serializers.ModelSerializer):
    actor_name = serializers.SerializerMethodField()
    
    class Meta:
        model = TimelineEvent
        fields = '__all__'
    
    def get_actor_name(self, obj):
        if obj.actor:
            return f"{obj.actor.first_name} {obj.actor.last_name}".strip() or obj.actor.username
        return None

# MITRE ATT&CK serializers
class MitreTacticSerializer(serializers.ModelSerializer):
    class Meta:
        model = MitreTactic
        fields = '__all__'

class MitreTechniqueSerializer(serializers.ModelSerializer):
    tactics = MitreTacticSerializer(many=True, read_only=True)
    parent_technique_name = serializers.SerializerMethodField()
    
    class Meta:
        model = MitreTechnique
        fields = '__all__'
    
    def get_parent_technique_name(self, obj):
        if obj.parent_technique:
            return obj.parent_technique.name
        return None

class CaseMitreTechniqueSerializer(serializers.ModelSerializer):
    technique = MitreTechniqueSerializer(read_only=True)
    technique_id = serializers.CharField(write_only=True)
    linked_by_name = serializers.SerializerMethodField()
    
    class Meta:
        model = CaseMitreTechnique
        fields = ['technique', 'technique_id', 'linked_by', 'linked_by_name', 'linked_at', 'context_notes']
    
    def get_linked_by_name(self, obj):
        if obj.linked_by:
            return f"{obj.linked_by.first_name} {obj.linked_by.last_name}".strip() or obj.linked_by.username
        return None

class AlertMitreTechniqueSerializer(serializers.ModelSerializer):
    technique = MitreTechniqueSerializer(read_only=True)
    technique_id = serializers.CharField(write_only=True)
    linked_by_name = serializers.SerializerMethodField()
    
    class Meta:
        model = AlertMitreTechnique
        fields = ['technique', 'technique_id', 'linked_by', 'linked_by_name', 'linked_at', 'context_notes']
    
    def get_linked_by_name(self, obj):
        if obj.linked_by:
            return f"{obj.linked_by.first_name} {obj.linked_by.last_name}".strip() or obj.linked_by.username
        return None

# Knowledge Base serializers
class KBCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = KBCategory
        fields = '__all__'

class KBArticleVersionSerializer(serializers.ModelSerializer):
    author_name = serializers.SerializerMethodField()
    
    class Meta:
        model = KBArticleVersion
        fields = ['version_id', 'article', 'version_number', 'title', 
                 'content', 'author', 'author_name', 'changed_at']
    
    def get_author_name(self, obj):
        if obj.author:
            return f"{obj.author.first_name} {obj.author.last_name}".strip() or obj.author.username
        return None

class KBArticleSerializer(serializers.ModelSerializer):
    author_name = serializers.SerializerMethodField()
    category_name = serializers.SerializerMethodField()
    
    class Meta:
        model = KBArticle
        fields = ['article_id', 'title', 'slug', 'content', 'category', 
                 'category_name', 'organization', 'author', 'author_name',
                 'version', 'status', 'tags', 'created_at', 'updated_at', 
                 'published_at']
        read_only_fields = ['article_id', 'created_at', 'updated_at', 'published_at']
    
    def get_author_name(self, obj):
        if obj.author:
            return f"{obj.author.first_name} {obj.author.last_name}".strip() or obj.author.username
        return None
    
    def get_category_name(self, obj):
        if obj.category:
            return obj.category.name
        return None

# Notification Framework serializers
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

# Metrics and Dashboards serializers
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