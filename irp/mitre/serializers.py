from rest_framework import serializers
from .models import MitreTactic, MitreTechnique, TechniqueTactic, CaseMitreTechnique, AlertMitreTechnique

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

# Serializadores para relações com casos
class CaseMitreTechniqueSerializer(serializers.ModelSerializer):
    technique = MitreTechniqueSerializer(read_only=True)
    technique_id = serializers.CharField(write_only=True)
    added_by_name = serializers.SerializerMethodField()
    
    class Meta:
        model = CaseMitreTechnique
        fields = ['id', 'case', 'technique', 'technique_id', 'added_by', 'added_by_name', 'added_at', 'notes']
        read_only_fields = ['id', 'case', 'added_by', 'added_at']
    
    def get_added_by_name(self, obj):
        if obj.added_by:
            return f"{obj.added_by.first_name} {obj.added_by.last_name}".strip() or obj.added_by.username
        return None

# Serializador para relações com alertas
class AlertMitreTechniqueSerializer(serializers.ModelSerializer):
    technique = MitreTechniqueSerializer(read_only=True)
    technique_id = serializers.CharField(write_only=True)
    added_by_name = serializers.SerializerMethodField()
    
    class Meta:
        model = AlertMitreTechnique
        fields = ['id', 'alert', 'technique', 'technique_id', 'added_by', 'added_by_name', 'added_at', 'notes']
        read_only_fields = ['id', 'alert', 'added_by', 'added_at']
    
    def get_added_by_name(self, obj):
        if obj.added_by:
            return f"{obj.added_by.first_name} {obj.added_by.last_name}".strip() or obj.added_by.username
        return None
