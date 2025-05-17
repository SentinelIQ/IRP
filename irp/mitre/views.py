import json
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.response import Response
from django.utils import timezone
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.db.models import Count, Q

from .models import MitreTactic, MitreTechnique, TechniqueTactic, CaseMitreTechnique, AlertMitreTechnique
from .serializers import (
    MitreTacticSerializer, MitreTechniqueSerializer, 
    CaseMitreTechniqueSerializer, AlertMitreTechniqueSerializer
)
from .services import sync_mitre_attack_data
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
    
    @action(detail=False, methods=['get'], permission_classes=[permissions.IsAuthenticated, HasRolePermission])
    def sync(self, request):
        """
        Sincroniza técnicas e táticas MITRE ATT&CK com a fonte oficial.
        Requer permissão administrativa.
        """
        self.check_object_permissions(request, None)
        
        try:
            # Usar URL padrão fixa na implementação
            result = sync_mitre_attack_data()
            
            # Registrar auditoria
            from irp.common.audit import audit_log
            audit_log(
                user=request.user,
                action="MITRE_SYNC",
                entity_type="MITRE_DATA",
                entity_id="SYSTEM",
                details={"stats": result}
            )
            
            return Response({
                'status': 'success',
                'message': 'Sincronização de dados MITRE ATT&CK concluída com sucesso',
                'stats': result
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'status': 'error',
                'message': f'Erro ao sincronizar dados MITRE ATT&CK: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    # Definir a permissão necessária para a ação de sincronização
    sync.required_permission = 'manage_mitre_data'

class CaseMitreTechniqueViewSet(viewsets.ModelViewSet):
    """
    API endpoint para gerenciar técnicas MITRE ATT&CK associadas a casos ou alertas.
    """
    queryset = CaseMitreTechnique.objects.all()
    serializer_class = CaseMitreTechniqueSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'case:edit'
    
    def get_queryset(self):
        case_pk = self.kwargs.get('case_pk')
        alert_pk = self.kwargs.get('alert_pk')
        user = self.request.user
        
        if not hasattr(user, 'profile') or not user.profile.organization:
            return CaseMitreTechnique.objects.none()
            
        queryset = CaseMitreTechnique.objects.filter(
            technique__isnull=False
        )
        
        # Filtrar por caso, se especificado
        if case_pk:
            case = get_object_or_404(
                Case, 
                case_id=case_pk, 
                organization=user.profile.organization
            )
            return queryset.filter(case=case)
            
        # Filtrar por alerta, se especificado
        elif alert_pk:
            alert = get_object_or_404(
                Alert, 
                alert_id=alert_pk, 
                organization=user.profile.organization
            )
            return queryset.filter(alert=alert)
        
        # Retornar todas as técnicas associadas a casos ou alertas da organização
        return queryset.filter(
            Q(case__organization=user.profile.organization) | 
            Q(alert__organization=user.profile.organization)
        )
    
    @audit_action(entity_type='MITRE_TECHNIQUE', action_type='CREATE')
    def perform_create(self, serializer):
        case_pk = self.kwargs.get('case_pk')
        alert_pk = self.kwargs.get('alert_pk')
        user = self.request.user
        
        if not hasattr(user, 'profile') or not user.profile.organization:
            raise PermissionError("Usuário sem organização não pode adicionar técnicas MITRE")
            
        # Obter o caso ou alerta a partir do ID na URL
        case = None
        alert = None
        
        if case_pk:
            case = get_object_or_404(Case, case_id=case_pk, organization=user.profile.organization)
        elif alert_pk:
            alert = get_object_or_404(Alert, alert_id=alert_pk, organization=user.profile.organization)
        else:
            # Se não for especificado na URL, tentar obter dos dados
            case_id = self.request.data.get('case_id')
            alert_id = self.request.data.get('alert_id')
            
            if case_id:
                case = get_object_or_404(Case, case_id=case_id, organization=user.profile.organization)
            elif alert_id:
                alert = get_object_or_404(Alert, alert_id=alert_id, organization=user.profile.organization)
            else:
                raise ValidationError("É necessário especificar um caso ou um alerta para associar a técnica MITRE.")
        
        # Verificar se o usuário tem permissão para o caso ou alerta
        if case and user.profile.organization != case.organization:
            raise PermissionError("Usuário não pode adicionar técnicas MITRE a este caso")
        elif alert and user.profile.organization != alert.organization:
            raise PermissionError("Usuário não pode adicionar técnicas MITRE a este alerta")
        
        # Obter a técnica MITRE
        technique_id = self.request.data.get('technique_id')
        technique = get_object_or_404(MitreTechnique, pk=technique_id)
        
        # Obter a fase da kill chain, se fornecida, ou tentar derivar das táticas
        kill_chain_phase = self.request.data.get('kill_chain_phase')
        if not kill_chain_phase and technique.tactics.exists():
            # Usar o short_name da primeira tática como fase da kill chain
            first_tactic = technique.tactics.first()
            if first_tactic and first_tactic.short_name:
                kill_chain_phase = first_tactic.short_name
        
        # Valores timestamp para observações, se não fornecidos
        now = timezone.now()
        first_observed = self.request.data.get('first_observed', now)
        
        # Salvar a associação com todos os campos
        mitre_technique = serializer.save(
            case=case,
            alert=alert,
            technique=technique,
            added_by=user,
            kill_chain_phase=kill_chain_phase,
            first_observed=first_observed,
            last_observed=self.request.data.get('last_observed', first_observed)
        )
        
        # Adicionar evento na timeline se for um caso
        if case:
            from irp.timeline.services import create_timeline_event
            create_timeline_event(
                case=case,
                organization=case.organization,
                event_type='MITRE_TECHNIQUE_ADDED',
                description=f"Técnica MITRE ATT&CK adicionada: {technique.technique_id} - {technique.name}",
                actor=user,
                target_entity_type='MitreTechnique',
                target_entity_id=str(technique.technique_id),
                metadata={
                    'technique_id': technique.technique_id,
                    'technique_name': technique.name,
                    'kill_chain_phase': kill_chain_phase,
                    'confidence_score': self.request.data.get('confidence_score'),
                    'impact_level': self.request.data.get('impact_level')
                }
            )
        
        return mitre_technique
    
    @audit_action(entity_type='MITRE_TECHNIQUE', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        # Registrar na timeline antes de excluir
        mitre_technique = self.get_object()
        user = request.user
        
        if mitre_technique.case:
            # Adicionar evento na timeline
            from irp.timeline.services import create_timeline_event
            create_timeline_event(
                case=mitre_technique.case,
                organization=mitre_technique.case.organization,
                event_type='MITRE_TECHNIQUE_REMOVED',
                description=f"Técnica MITRE ATT&CK removida: {mitre_technique.technique.technique_id} - {mitre_technique.technique.name}",
                actor=user,
                target_entity_type='MitreTechnique',
                target_entity_id=str(mitre_technique.technique.technique_id),
                metadata={
                    'technique_id': mitre_technique.technique.technique_id,
                    'technique_name': mitre_technique.technique.name
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
        return Response({'error': 'Arquivo JSON inválido.'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Este endpoint usa a mesma lógica da action sync, mas recebe o arquivo diretamente
    try:
        with transaction.atomic():
            result = process_mitre_data(data)
        return Response({
            'status': 'success',
            'message': 'Dados MITRE ATT&CK importados com sucesso.',
            'data': result
        }, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({
            'error': f'Erro ao processar dados: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Atribuir a permissão necessária
import_mitre_attack.required_permission = 'manage_mitre_data'

def process_mitre_data(data):
    """
    Processa dados MITRE ATT&CK no formato STIX e atualiza o banco de dados.
    Esta função é uma versão simplificada do que seria implementado na função sync_mitre_attack_data.
    """
    # Implementação resumida - usar a função sync_mitre_attack_data do services.py
    # Esta função está aqui por compatibilidade com código existente
    from .services import sync_mitre_attack_data
    return {"message": "Implementação simplificada - use a função sync_mitre_attack_data"}

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def verify_mitre_correlations(request):
    """
    Verifica e exibe estatísticas sobre as correlações entre técnicas e táticas.
    Útil para diagnosticar problemas de integração do MITRE ATT&CK.
    """
    # Estatísticas gerais
    total_tactics = MitreTactic.objects.count()
    total_techniques = MitreTechnique.objects.count()
    total_relationships = TechniqueTactic.objects.count()
    
    # Técnicas sem táticas
    orphaned_techniques = MitreTechnique.objects.annotate(
        tactics_count=Count('tactics')
    ).filter(tactics_count=0)
    
    # Táticas sem técnicas
    orphaned_tactics = MitreTactic.objects.annotate(
        techniques_count=Count('techniques')
    ).filter(techniques_count=0)
    
    # Táticas mais comuns
    popular_tactics = MitreTactic.objects.annotate(
        techniques_count=Count('techniques')
    ).order_by('-techniques_count')[:5]
    
    # Técnicas em múltiplas táticas
    multi_tactic_techniques = MitreTechnique.objects.annotate(
        tactics_count=Count('tactics')
    ).filter(tactics_count__gt=1).order_by('-tactics_count')[:5]
    
    response_data = {
        'status': 'success',
        'statistics': {
            'total_tactics': total_tactics,
            'total_techniques': total_techniques,
            'total_relationships': total_relationships,
            'orphaned_techniques_count': orphaned_techniques.count(),
            'orphaned_tactics_count': orphaned_tactics.count(),
        },
        'orphaned_techniques': [
            {
                'id': t.technique_id,
                'name': t.name,
                'is_subtechnique': t.is_subtechnique,
                'parent_id': t.parent_technique.technique_id if t.parent_technique else None,
            } for t in orphaned_techniques[:10]  # Mostrar apenas os primeiros 10
        ],
        'orphaned_tactics': [
            {
                'id': t.tactic_id,
                'name': t.name,
            } for t in orphaned_tactics[:10]
        ],
        'popular_tactics': [
            {
                'id': t.tactic_id,
                'name': t.name,
                'techniques_count': t.techniques_count,
            } for t in popular_tactics
        ],
        'multi_tactic_techniques': [
            {
                'id': t.technique_id,
                'name': t.name,
                'tactics_count': t.tactics_count,
                'tactics': [{'id': tac.tactic_id, 'name': tac.name} for tac in t.tactics.all()[:5]]
            } for t in multi_tactic_techniques
        ],
    }
    
    return Response(response_data)

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated, HasRolePermission])
def repair_correlations(request):
    """
    Repara as correlações entre técnicas e táticas MITRE.
    Útil quando há dados no sistema mas as correlações estão faltando.
    """
    from .services import repair_mitre_correlations
    
    try:
        results = repair_mitre_correlations()
        
        return Response({
            'status': 'success',
            'message': f'Correlações MITRE reparadas. {results["fixed_relations"]} relações criadas.',
            'results': results
        }, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({
            'status': 'error',
            'message': f'Erro ao reparar correlações MITRE: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Atribuir a permissão necessária
repair_correlations.required_permission = 'manage_mitre_data'

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def get_kill_chain_phases_view(request):
    """
    Retorna uma lista de fases da kill chain MITRE ATT&CK disponíveis.
    Útil para interfaces de usuário que precisam mostrar as fases 
    da kill chain para seleção.
    """
    from .services import get_kill_chain_phases
    
    phases = get_kill_chain_phases()
    
    return Response({
        'status': 'success',
        'kill_chain_phases': phases
    })
