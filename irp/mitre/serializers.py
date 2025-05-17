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
    tactic_names = serializers.SerializerMethodField()
    case_id = serializers.CharField(write_only=True, required=False, allow_null=True)
    alert_id = serializers.CharField(write_only=True, required=False, allow_null=True)
    case_title = serializers.SerializerMethodField()
    alert_title = serializers.SerializerMethodField()
    
    class Meta:
        model = CaseMitreTechnique
        fields = [
            'id', 'case', 'case_id', 'case_title', 'alert', 'alert_id', 'alert_title',
            'technique', 'technique_id', 'added_by', 'added_by_name', 'added_at', 
            'notes', 'kill_chain_phase', 'confidence_score', 'detection_method', 
            'artifacts', 'impact_level', 'mitigation_status', 'first_observed',
            'last_observed', 'tactic_names'
        ]
        read_only_fields = ['id', 'added_by', 'added_at']
    
    def get_added_by_name(self, obj):
        if obj.added_by:
            return f"{obj.added_by.first_name} {obj.added_by.last_name}".strip() or obj.added_by.username
        return None
    
    def get_tactic_names(self, obj):
        """Retorna os nomes das táticas associadas à técnica"""
        return [
            {'id': tactic.tactic_id, 'name': tactic.name, 'short_name': tactic.short_name}
            for tactic in obj.technique.tactics.all()
        ]
        
    def get_case_title(self, obj):
        """Retorna o título do caso, se existir"""
        if obj.case:
            return obj.case.title
        return None
        
    def get_alert_title(self, obj):
        """Retorna o título do alerta, se existir"""
        if obj.alert:
            return obj.alert.title
        return None
        
    def validate(self, data):
        """Validar que pelo menos um caso ou um alerta está presente"""
        if self.instance:  # Na atualização, não exigir
            return data
            
        # Na criação, verificar se tem case_id ou alert_id
        if 'case_id' not in data and 'alert_id' not in data:
            raise serializers.ValidationError(
                "É necessário fornecer pelo menos um caso (case_id) ou um alerta (alert_id)."
            )
        return data

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
