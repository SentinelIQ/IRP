from rest_framework import serializers
from django.contrib.auth.models import User

from .models import (
    CaseSeverity, CaseStatus, CaseTemplate, Case, CaseComment, 
    CaseCustomFieldDefinition, CaseCustomFieldValue, Task, 
    TaskStatus, CaseObservable, CaseMitreTechnique
)
from irp.accounts.serializers import UserSerializer, OrganizationSerializer
from irp.observables.serializers import ObservableSerializer
from irp.alerts.serializers import SimplifiedAlertSerializer
from irp.mitre.serializers import MitreTechniqueSerializer

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

class CaseCustomFieldDefinitionSerializer(serializers.ModelSerializer):
    class Meta:
        model = CaseCustomFieldDefinition
        fields = '__all__'

class CaseCustomFieldValueSerializer(serializers.ModelSerializer):
    field_definition = CaseCustomFieldDefinitionSerializer(read_only=True)
    
    class Meta:
        model = CaseCustomFieldValue
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

class CaseObservableSerializer(serializers.ModelSerializer):
    observable = ObservableSerializer(read_only=True)
    
    class Meta:
        model = CaseObservable
        fields = '__all__'
        read_only_fields = ['case']

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