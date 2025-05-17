import json
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from django.utils import timezone
from django.db import transaction
from django.shortcuts import get_object_or_404

from .models import MitreTactic, MitreTechnique, TechniqueTactic, CaseMitreTechnique, AlertMitreTechnique
from .serializers import (
    MitreTacticSerializer, MitreTechniqueSerializer, 
    CaseMitreTechniqueSerializer, AlertMitreTechniqueSerializer
)
from irp.common.permissions import HasRolePermission
from irp.cases.models import Case
from irp.alerts.models import Alert

from irp.common.audit import audit_action

class MitreTacticViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint para visualizar táticas MITRE ATT&CK.
    """
    queryset = MitreTactic.objects.all().order_by('tactic_id')
    serializer_class = MitreTacticSerializer
    permission_classes = [permissions.IsAuthenticated]

class MitreTechniqueViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint para visualizar técnicas MITRE ATT&CK.
    """
    queryset = MitreTechnique.objects.all().order_by('technique_id')
    serializer_class = MitreTechniqueSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """
        Opcionalmente filtra o conjunto de resultados com base nos parâmetros da consulta.
        """
        queryset = super().get_queryset()
        
        # Filtrar por tática
        tactic_id = self.request.query_params.get('tactic', None)
        if tactic_id:
            queryset = queryset.filter(tactics__tactic_id=tactic_id)
        
        # Filtrar por subtécnicas
        include_subtechniques = self.request.query_params.get('include_subtechniques', 'true').lower() == 'true'
        if not include_subtechniques:
            queryset = queryset.filter(is_subtechnique=False)
            
        return queryset

class CaseMitreTechniqueViewSet(viewsets.ModelViewSet):
    """
    API endpoint para gerenciar técnicas MITRE ATT&CK associadas a casos.
    """
    queryset = CaseMitreTechnique.objects.all()
    serializer_class = CaseMitreTechniqueSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'case:edit'
    
    def get_queryset(self):
        case_pk = self.kwargs.get('case_pk')
        user = self.request.user
        
        if case_pk:
            if hasattr(user, 'profile') and user.profile.organization:
                # Garantir que o caso pertence à organização do usuário
                case = get_object_or_404(
                    Case, 
                    case_id=case_pk, 
                    organization=user.profile.organization
                )
                return CaseMitreTechnique.objects.filter(case=case)
        
        return CaseMitreTechnique.objects.none()
    
    @audit_action(entity_type='CASE_MITRE_TECHNIQUE', action_type='CREATE')
    def perform_create(self, serializer):
        case_pk = self.kwargs.get('case_pk')
        user = self.request.user
        
        # Obter o caso a partir do ID na URL ou nos dados
        if case_pk:
            case = get_object_or_404(Case, case_id=case_pk)
        else:
            case_id = self.request.data.get('case_id')
            case = get_object_or_404(Case, case_id=case_id)
        
        # Verificar se o usuário pertence à mesma organização do caso
        if (hasattr(user, 'profile') and user.profile.organization and 
            user.profile.organization == case.organization):
            
            # Obter a técnica MITRE
            technique_id = self.request.data.get('technique_id')
            technique = get_object_or_404(MitreTechnique, pk=technique_id)
            
            # Salvar a associação
            case_technique = serializer.save(
                case=case, 
                technique=technique,
                added_by=user
            )
            
            # Adicionar evento na timeline
            from irp.timeline.services import create_timeline_event
            create_timeline_event(
                case=case,
                organization=case.organization,
                event_type='MITRE_TECHNIQUE_ADDED',
                description=f"Técnica MITRE ATT&CK adicionada: {technique.technique_id} - {technique.name}",
                actor=user,
                target_entity_type='MitreTechnique',
                target_entity_id=str(technique.id),
                metadata={
                    'technique_id': technique.technique_id,
                    'technique_name': technique.name
                }
            )
            
            return case_technique
        else:
            raise PermissionError("Usuário não pode adicionar técnicas MITRE a este caso")
    
    @audit_action(entity_type='CASE_MITRE_TECHNIQUE', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        # Registrar na timeline antes de excluir
        case_technique = self.get_object()
        user = request.user
        case = case_technique.case
        technique = case_technique.technique
        
        # Adicionar evento na timeline
        from irp.timeline.services import create_timeline_event
        create_timeline_event(
            case=case,
            organization=case.organization,
            event_type='MITRE_TECHNIQUE_REMOVED',
            description=f"Técnica MITRE ATT&CK removida: {technique.technique_id} - {technique.name}",
            actor=user,
            target_entity_type='MitreTechnique',
            target_entity_id=str(technique.id),
            metadata={
                'technique_id': technique.technique_id,
                'technique_name': technique.name
            }
        )
        
        return super().destroy(request, *args, **kwargs)

class AlertMitreTechniqueViewSet(viewsets.ModelViewSet):
    """
    API endpoint para gerenciar técnicas MITRE ATT&CK associadas a alertas.
    """
    queryset = AlertMitreTechnique.objects.all()
    serializer_class = AlertMitreTechniqueSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'alert:edit'
    
    def get_queryset(self):
        alert_pk = self.kwargs.get('alert_pk')
        user = self.request.user
        
        if alert_pk:
            if hasattr(user, 'profile') and user.profile.organization:
                # Garantir que o alerta pertence à organização do usuário
                alert = get_object_or_404(
                    Alert, 
                    alert_id=alert_pk, 
                    organization=user.profile.organization
                )
                return AlertMitreTechnique.objects.filter(alert=alert)
        
        return AlertMitreTechnique.objects.none()
    
    @audit_action(entity_type='ALERT_MITRE_TECHNIQUE', action_type='CREATE')
    def perform_create(self, serializer):
        alert_pk = self.kwargs.get('alert_pk')
        user = self.request.user
        
        # Obter o alerta a partir do ID na URL ou nos dados
        if alert_pk:
            alert = get_object_or_404(Alert, alert_id=alert_pk)
        else:
            alert_id = self.request.data.get('alert_id')
            alert = get_object_or_404(Alert, alert_id=alert_id)
        
        # Verificar se o usuário pertence à mesma organização do alerta
        if (hasattr(user, 'profile') and user.profile.organization and 
            user.profile.organization == alert.organization):
            
            # Obter a técnica MITRE
            technique_id = self.request.data.get('technique_id')
            technique = get_object_or_404(MitreTechnique, pk=technique_id)
            
            # Salvar a associação
            alert_technique = serializer.save(
                alert=alert, 
                technique=technique,
                added_by=user
            )
            
            # Registrar auditoria - integrar com audit module quando disponível
            # AuditLog.objects.create(
            #     user=user,
            #     organization=alert.organization,
            #     entity_type='ALERT_MITRE_TECHNIQUE',
            #     entity_id=alert.alert_id,
            #     action_type='ADD',
            #     details={'technique_id': technique.technique_id, 'technique_name': technique.name}
            # )
            
            return alert_technique
        else:
            raise PermissionError("Usuário não pode adicionar técnicas MITRE a este alerta")
    
    @audit_action(entity_type='ALERT_MITRE_TECHNIQUE', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        # Registrar auditoria antes de excluir
        alert_technique = self.get_object()
        user = request.user
        alert = alert_technique.alert
        technique = alert_technique.technique
        
        # Registrar auditoria - integrar com audit module quando disponível
        # AuditLog.objects.create(
        #     user=user,
        #     organization=alert.organization,
        #     entity_type='ALERT_MITRE_TECHNIQUE',
        #     entity_id=alert.alert_id,
        #     action_type='REMOVE',
        #     details={'technique_id': technique.technique_id, 'technique_name': technique.name}
        # )
        
        return super().destroy(request, *args, **kwargs)

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated, HasRolePermission])
def import_mitre_attack(request):
    """
    Endpoint para importar dados MITRE ATT&CK de um arquivo JSON enviado pelo cliente.
    """
    if 'file' not in request.FILES:
        return Response({'error': 'Nenhum arquivo enviado.'}, status=status.HTTP_400_BAD_REQUEST)
    
    file = request.FILES['file']
    try:
        data = json.load(file)
    except json.JSONDecodeError:
        return Response({'error': 'O arquivo enviado não é um JSON válido.'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        import_count = process_mitre_data(data)
        return Response({
            'message': 'Importação concluída com sucesso',
            'imported': import_count
        })
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def process_mitre_data(data):
    """
    Processa os dados MITRE ATT&CK importados.
    """
    if not isinstance(data, dict) or 'objects' not in data:
        raise ValueError("Estrutura de dados MITRE ATT&CK inválida")
    
    tactics_count = 0
    techniques_count = 0
    version = data.get('version', 'unknown')
    
    with transaction.atomic():
        # Processar táticas
        tactics = {}
        for obj in data['objects']:
            if obj.get('type') == 'x-mitre-tactic':
                tactic_id = obj.get('external_references', [{}])[0].get('external_id', '')
                if not tactic_id:
                    continue
                
                name = obj.get('name', '')
                description = obj.get('description', '')
                url = next((ref.get('url', '') for ref in obj.get('external_references', []) if 'url' in ref), '')
                
                tactic, created = MitreTactic.objects.update_or_create(
                    tactic_id=tactic_id,
                    defaults={
                        'name': name,
                        'description': description,
                        'url': url,
                        'version': version
                    }
                )
                tactics[obj.get('id')] = tactic
                if created:
                    tactics_count += 1
        
        # Processar técnicas
        for obj in data['objects']:
            if obj.get('type') == 'attack-pattern':
                technique_id = next((ref.get('external_id', '') for ref in obj.get('external_references', []) 
                                    if ref.get('source_name') == 'mitre-attack'), '')
                if not technique_id:
                    continue
                
                name = obj.get('name', '')
                description = obj.get('description', '')
                url = next((ref.get('url', '') for ref in obj.get('external_references', []) 
                           if 'url' in ref), '')
                
                is_subtechnique = '.' in technique_id
                parent_technique_id = None
                
                if is_subtechnique:
                    parent_id = technique_id.split('.')[0]
                    try:
                        parent_technique = MitreTechnique.objects.get(technique_id=parent_id)
                        parent_technique_id = parent_technique.pk
                    except MitreTechnique.DoesNotExist:
                        pass
                
                technique, created = MitreTechnique.objects.update_or_create(
                    technique_id=technique_id,
                    defaults={
                        'name': name,
                        'description': description,
                        'url': url,
                        'is_subtechnique': is_subtechnique,
                        'parent_technique_id': parent_technique_id,
                        'version': version
                    }
                )
                
                # Associar táticas
                if 'kill_chain_phases' in obj:
                    for phase in obj['kill_chain_phases']:
                        if phase.get('kill_chain_name') == 'mitre-attack':
                            phase_name = phase.get('phase_name')
                            for tactic_id, tactic in tactics.items():
                                if tactic_id.endswith(phase_name):
                                    TechniqueTactic.objects.get_or_create(
                                        technique=technique,
                                        tactic=tactic
                                    )
                
                if created:
                    techniques_count += 1
    
    return {
        'tactics': tactics_count,
        'techniques': techniques_count
    }
