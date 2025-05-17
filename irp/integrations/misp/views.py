from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from django.db import models
import logging

from irp.integrations.misp.models import (
    MISPInstance, MISPImport, MISPExport, MISPTaxonomy, MISPTaxonomyEntry,
    CaseTaxonomyTag, AlertTaxonomyTag, ObservableTaxonomyTag
)
from irp.integrations.misp.serializers import (
    MISPInstanceSerializer, MISPImportSerializer, MISPExportSerializer,
    TriggerMISPImportSerializer, ExportCaseToMISPSerializer,
    MISPTaxonomySerializer, MISPTaxonomyEntrySerializer,
    CaseTaxonomyTagSerializer, AlertTaxonomyTagSerializer, ObservableTaxonomyTagSerializer,
    TaxonomyTagInputSerializer
)
from irp.cases.models import Case
from irp.alerts.models import Alert
from irp.observables.models import Observable
from irp.common.permissions import HasRolePermission, has_permission
from irp.audit.services import AuditService

logger = logging.getLogger(__name__)

class MISPInstanceViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing MISP instances
    """
    queryset = MISPInstance.objects.all()
    serializer_class = MISPInstanceSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_organizations'  # Permissão de alto nível para configurar integrações
    
    def get_queryset(self):
        # Isolamento multi-tenant: só instâncias da organização do usuário
        if not self.request.user.is_authenticated:
            return MISPInstance.objects.none()
            
        if self.request.user.is_superuser or getattr(self.request.user.profile, 'is_system_admin', False):
            return MISPInstance.objects.all()
            
        # Usuário comum só vê instâncias da própria organização
        if hasattr(self.request.user, 'profile') and self.request.user.profile.organization:
            return MISPInstance.objects.filter(
                models.Q(organization=self.request.user.profile.organization) | 
                models.Q(organization=None)
            )
        return MISPInstance.objects.none()
    
    def perform_create(self, serializer):
        # Associar à organização do usuário
        organization = None
        if hasattr(self.request.user, 'profile'):
            organization = self.request.user.profile.organization
        instance = serializer.save(organization=organization)
        
        # Registrar auditoria
        AuditService.log(
            user=self.request.user,
            organization=organization,
            entity_type='MISP_INSTANCE',
            entity_id=instance.instance_id,
            action_type='CREATE',
            details_after=serializer.data
        )
    
    def perform_update(self, serializer):
        instance = self.get_object()
        
        # Dados antes da atualização
        previous_data = MISPInstanceSerializer(instance).data
        
        # Atualizar
        updated_instance = serializer.save()
        
        # Registrar auditoria
        AuditService.log(
            user=self.request.user,
            organization=updated_instance.organization,
            entity_type='MISP_INSTANCE',
            entity_id=updated_instance.instance_id,
            action_type='UPDATE',
            details_before=previous_data,
            details_after=serializer.data
        )
    
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        
        # Dados antes da exclusão
        previous_data = MISPInstanceSerializer(instance).data
        organization = instance.organization
        instance_id = instance.instance_id
        
        # Excluir
        response = super().destroy(request, *args, **kwargs)
        
        # Registrar auditoria
        AuditService.log(
            user=request.user,
            organization=organization,
            entity_type='MISP_INSTANCE',
            entity_id=instance_id,
            action_type='DELETE',
            details_before=previous_data
        )
        
        return response
    
    @action(detail=True, methods=['post'])
    def test_connection(self, request, pk=None):
        """
        Testa a conexão com uma instância MISP
        """
        instance = self.get_object()
        from irp.integrations.misp.services import MISPService
        
        try:
            success, message = MISPService.test_connection(instance)
            
            # Registrar auditoria
            AuditService.log(
                user=request.user,
                organization=instance.organization,
                entity_type='MISP_INSTANCE',
                entity_id=instance.instance_id,
                action_type='TEST_CONNECTION',
                details_after={'success': success, 'message': message}
            )
            
            return Response({
                'success': success,
                'message': message
            })
        except Exception as e:
            return Response({
                'success': False,
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class MISPImportViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for viewing MISP import logs (readonly)
    """
    queryset = MISPImport.objects.all()
    serializer_class = MISPImportSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'observable:view'  # Mesmo permissão para visualizar observáveis
    
    def get_queryset(self):
        # Isolamento multi-tenant: só importações da organização do usuário
        if not self.request.user.is_authenticated:
            return MISPImport.objects.none()
            
        if self.request.user.is_superuser or getattr(self.request.user.profile, 'is_system_admin', False):
            return MISPImport.objects.all().order_by('-import_timestamp')
            
        # Usuário comum só vê importações da própria organização
        if hasattr(self.request.user, 'profile') and self.request.user.profile.organization:
            return MISPImport.objects.filter(
                organization=self.request.user.profile.organization
            ).order_by('-import_timestamp')
        return MISPImport.objects.none()


class MISPExportViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for viewing MISP export logs (readonly)
    """
    queryset = MISPExport.objects.all()
    serializer_class = MISPExportSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'case:view'  # Mesmo permissão para visualizar casos
    
    def get_queryset(self):
        # Isolamento multi-tenant: só exportações da organização do usuário através de casos
        if not self.request.user.is_authenticated:
            return MISPExport.objects.none()
            
        if self.request.user.is_superuser or getattr(self.request.user.profile, 'is_system_admin', False):
            return MISPExport.objects.all().order_by('-export_timestamp')
            
        # Usuário comum só vê exportações relacionadas a casos da própria organização
        if hasattr(self.request.user, 'profile') and self.request.user.profile.organization:
            organization = self.request.user.profile.organization
            return MISPExport.objects.filter(
                case__organization=organization
            ).order_by('-export_timestamp')
        return MISPExport.objects.none()


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated, HasRolePermission])
def trigger_misp_import(request):
    """
    Endpoint para disparar importação manual do MISP
    """
    serializer = TriggerMISPImportSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    # Verificar permissão específica
    if not has_permission(request.user, 'observable:create'):
        return Response(
            {"detail": "Você não tem permissão para importar do MISP"},
            status=status.HTTP_403_FORBIDDEN
        )
    
    # Obter parâmetros da requisição
    misp_instance_id = serializer.validated_data['misp_instance_id']
    from_timestamp = serializer.validated_data.get('from_timestamp')
    filter_tags = serializer.validated_data.get('filter_tags')
    create_alerts = serializer.validated_data.get('create_alerts', True)
    
    try:
        # Obter instância MISP
        misp_instance = MISPInstance.objects.get(instance_id=misp_instance_id)
        
        # Verificar se o usuário tem acesso à instância (multi-tenant)
        if (not request.user.is_superuser 
            and not getattr(request.user.profile, 'is_system_admin', False)
            and misp_instance.organization 
            and misp_instance.organization != request.user.profile.organization):
            return Response(
                {"detail": "Você não tem acesso a esta instância MISP"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Obter organização do usuário
        organization = None
        if hasattr(request.user, 'profile'):
            organization = request.user.profile.organization
        
        if not organization and not request.user.is_superuser:
            return Response(
                {"detail": "Usuário não está associado a uma organização"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Importar
        from irp.integrations.misp.services import MISPService
        misp_import = MISPService.import_from_misp(
            misp_instance=misp_instance,
            organization=organization or misp_instance.organization,
            from_timestamp=from_timestamp,
            filter_tags=filter_tags,
            create_alerts=create_alerts,
            imported_by=request.user
        )
        
        # Registrar auditoria após importação bem-sucedida
        if organization:
            AuditService.log(
                user=request.user,
                organization=organization,
                entity_type='MISP_INSTANCE',
                entity_id=misp_instance.instance_id,
                action_type='IMPORT',
                details_after={
                    'misp_import_id': str(misp_import.import_id),
                    'from_timestamp': str(from_timestamp) if from_timestamp else None,
                    'filter_tags': filter_tags or [],
                    'create_alerts': create_alerts
                }
            )
        
        # Retornar o resultado
        return Response({
            "status": "success",
            "message": f"Importação do MISP iniciada. ID: {misp_import.import_id}",
            "import_id": misp_import.import_id
        })
        
    except MISPInstance.DoesNotExist:
        return Response(
            {"detail": "Instância MISP não encontrada"},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        return Response(
            {"detail": f"Erro ao importar do MISP: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated, HasRolePermission])
def export_case_to_misp(request, case_id):
    """
    Endpoint para exportar um caso para o MISP
    """
    serializer = ExportCaseToMISPSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    # Verificar permissão específica
    if not has_permission(request.user, 'case:edit'):
        return Response(
            {"detail": "Você não tem permissão para exportar para o MISP"},
            status=status.HTTP_403_FORBIDDEN
        )
    
    # Obter parâmetros da requisição
    misp_instance_id = serializer.validated_data['misp_instance_id']
    include_observables = serializer.validated_data.get('include_observables', True)
    include_timeline = serializer.validated_data.get('include_timeline', False)
    include_mitre_techniques = serializer.validated_data.get('include_mitre_techniques', True)
    distribution = serializer.validated_data.get('distribution')
    threat_level = serializer.validated_data.get('threat_level')
    analysis = serializer.validated_data.get('analysis')
    additional_tags = serializer.validated_data.get('additional_tags')
    
    try:
        # Obter caso
        case = Case.objects.get(case_id=case_id)
        
        # Verificar acesso ao caso (multi-tenant)
        if (not request.user.is_superuser 
            and not getattr(request.user.profile, 'is_system_admin', False)
            and case.organization != request.user.profile.organization):
            return Response(
                {"detail": "Você não tem acesso a este caso"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Obter instância MISP
        misp_instance = MISPInstance.objects.get(instance_id=misp_instance_id)
        
        # Executar exportação
        from irp.integrations.misp.services import MISPService
        misp_export = MISPService.export_case_to_misp(
            case=case,
            misp_instance=misp_instance,
            include_observables=include_observables,
            include_timeline=include_timeline,
            include_mitre_techniques=include_mitre_techniques,
            distribution=distribution,
            threat_level=threat_level,
            analysis=analysis,
            additional_tags=additional_tags,
            exported_by=request.user
        )
        
        # Registrar auditoria
        AuditService.log(
            user=request.user,
            organization=case.organization,
            entity_type='CASE',
            entity_id=case.case_id,
            action_type='EXPORT_TO_MISP',
            details_after={
                'misp_export_id': str(misp_export.export_id),
                'misp_instance_id': str(misp_instance.instance_id),
                'misp_instance_name': misp_instance.name,
                'status': misp_export.status,
                'exported_observables_count': misp_export.exported_observables_count
            }
        )
        
        # Retornar resultado
        if misp_export.status == 'SUCCESS':
            return Response({
                "status": "success",
                "message": f"Caso exportado com sucesso para MISP {misp_instance.name}.",
                "export_id": misp_export.export_id,
                "misp_event_uuid": misp_export.misp_event_uuid,
                "exported_observables_count": misp_export.exported_observables_count
            })
        else:
            return Response({
                "status": "error",
                "message": f"Erro ao exportar caso para MISP: {misp_export.error_message}",
                "export_id": misp_export.export_id
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
    except Case.DoesNotExist:
        return Response(
            {"detail": "Caso não encontrado"},
            status=status.HTTP_404_NOT_FOUND
        )
    except MISPInstance.DoesNotExist:
        return Response(
            {"detail": "Instância MISP não encontrada"},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        return Response(
            {"detail": f"Erro ao exportar para MISP: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated, HasRolePermission])
def sync_taxonomies(request, instance_id):
    """
    Endpoint para sincronizar taxonomias de uma instância MISP
    """
    # Verificar permissão específica
    if not has_permission(request.user, 'manage_organizations'):
        return Response(
            {"detail": "Você não tem permissão para sincronizar taxonomias"},
            status=status.HTTP_403_FORBIDDEN
        )
    
    force_update = request.data.get('force_update', False)
    
    try:
        # Obter instância MISP
        misp_instance = MISPInstance.objects.get(instance_id=instance_id)
        
        # Verificar se o usuário tem acesso à instância (multi-tenant)
        if (not request.user.is_superuser 
            and not getattr(request.user.profile, 'is_system_admin', False)
            and misp_instance.organization 
            and misp_instance.organization != request.user.profile.organization):
            return Response(
                {"detail": "Você não tem acesso a esta instância MISP"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Sincronizar taxonomias
        from irp.integrations.misp.services import MISPService
        result = MISPService.sync_taxonomies(misp_instance, force_update=force_update)
        
        # Registrar auditoria
        AuditService.log(
            user=request.user,
            organization=misp_instance.organization,
            entity_type='MISP_INSTANCE',
            entity_id=misp_instance.instance_id,
            action_type='SYNC_TAXONOMIES',
            details_after=result
        )
        
        return Response(result)
        
    except MISPInstance.DoesNotExist:
        return Response(
            {"detail": "Instância MISP não encontrada"},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        return Response(
            {"detail": f"Erro ao sincronizar taxonomias: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


class MISPTaxonomyViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint para visualizar taxonomias MISP
    """
    queryset = MISPTaxonomy.objects.all()
    serializer_class = MISPTaxonomySerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'observable:view'  # Mesma permissão para visualizar observáveis
    
    def get_queryset(self):
        # Isolamento multi-tenant: só taxonomias da organização do usuário
        if not self.request.user.is_authenticated:
            return MISPTaxonomy.objects.none()
            
        if self.request.user.is_superuser or getattr(self.request.user.profile, 'is_system_admin', False):
            return MISPTaxonomy.objects.all().order_by('namespace')
            
        # Usuário comum só vê taxonomias de instâncias MISP da própria organização
        if hasattr(self.request.user, 'profile') and self.request.user.profile.organization:
            organization = self.request.user.profile.organization
            return MISPTaxonomy.objects.filter(
                misp_instance__organization=organization,
                enabled_for_platform=True
            ).order_by('namespace')
        return MISPTaxonomy.objects.none()
    
    @action(detail=True, methods=['get'])
    def entries(self, request, pk=None):
        """
        Retorna as entradas de uma taxonomia específica
        """
        taxonomy = self.get_object()
        entries = MISPTaxonomyEntry.objects.filter(taxonomy=taxonomy).order_by('predicate', 'value')
        serializer = MISPTaxonomyEntrySerializer(entries, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def search(self, request):
        """
        Busca taxonomias e entradas por termo de pesquisa
        """
        query = request.query_params.get('q', '')
        if len(query) < 2:
            return Response({"detail": "Termo de pesquisa muito curto"}, status=status.HTTP_400_BAD_REQUEST)
        
        queryset = self.get_queryset()
        
        # Buscar taxonomias pelo namespace ou descrição
        taxonomy_results = queryset.filter(
            models.Q(namespace__icontains=query) | 
            models.Q(description__icontains=query)
        )
        
        # Buscar entradas pelo predicado ou valor
        entry_results = MISPTaxonomyEntry.objects.filter(
            models.Q(predicate__icontains=query) | 
            models.Q(value__icontains=query) |
            models.Q(description_expanded__icontains=query),
            taxonomy__in=queryset
        )
        
        # Serializar resultados
        taxonomy_serializer = MISPTaxonomySerializer(taxonomy_results, many=True)
        entry_serializer = MISPTaxonomyEntrySerializer(entry_results, many=True)
        
        return Response({
            "taxonomies": taxonomy_serializer.data,
            "entries": entry_serializer.data
        })


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated, HasRolePermission])
def add_taxonomy_tag_to_case(request, case_id):
    """
    Adiciona uma tag de taxonomia a um caso
    """
    # Verificar permissão
    if not has_permission(request.user, 'case:edit'):
        return Response(
            {"detail": "Você não tem permissão para editar casos"},
            status=status.HTTP_403_FORBIDDEN
        )
    
    # Validar tag de entrada
    serializer = TaxonomyTagInputSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # Obter caso
        case = Case.objects.get(case_id=case_id)
        
        # Verificar acesso ao caso (multi-tenant)
        if (not request.user.is_superuser 
            and not getattr(request.user.profile, 'is_system_admin', False)
            and case.organization != request.user.profile.organization):
            return Response(
                {"detail": "Você não tem acesso a este caso"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Obter entrada de taxonomia
        taxonomy_entry = MISPTaxonomyEntry.objects.get(entry_id=serializer.validated_data['taxonomy_entry_id'])
        
        # Adicionar tag ao caso
        tag, created = CaseTaxonomyTag.objects.get_or_create(
            case=case,
            taxonomy_entry=taxonomy_entry,
            defaults={'linked_by': request.user}
        )
        
        # Registrar auditoria
        AuditService.log(
            user=request.user,
            organization=case.organization,
            entity_type='CASE',
            entity_id=case.case_id,
            action_type='ADD_TAXONOMY_TAG',
            details_after={
                'taxonomy_namespace': taxonomy_entry.taxonomy.namespace,
                'predicate': taxonomy_entry.predicate,
                'value': taxonomy_entry.value,
                'tag_name': taxonomy_entry.tag_name
            }
        )
        
        return Response({
            "status": "success",
            "message": f"Tag '{taxonomy_entry.tag_name}' adicionada ao caso",
            "created": created
        })
        
    except Case.DoesNotExist:
        return Response(
            {"detail": "Caso não encontrado"},
            status=status.HTTP_404_NOT_FOUND
        )
    except MISPTaxonomyEntry.DoesNotExist:
        return Response(
            {"detail": "Entrada de taxonomia não encontrada"},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        return Response(
            {"detail": f"Erro ao adicionar tag: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['DELETE'])
@permission_classes([permissions.IsAuthenticated, HasRolePermission])
def remove_taxonomy_tag_from_case(request, case_id, tag_id):
    """
    Remove uma tag de taxonomia de um caso
    """
    # Verificar permissão
    if not has_permission(request.user, 'case:edit'):
        return Response(
            {"detail": "Você não tem permissão para editar casos"},
            status=status.HTTP_403_FORBIDDEN
        )
    
    try:
        # Obter caso
        case = Case.objects.get(case_id=case_id)
        
        # Verificar acesso ao caso (multi-tenant)
        if (not request.user.is_superuser 
            and not getattr(request.user.profile, 'is_system_admin', False)
            and case.organization != request.user.profile.organization):
            return Response(
                {"detail": "Você não tem acesso a este caso"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Obter tag
        tag = CaseTaxonomyTag.objects.get(
            case=case,
            taxonomy_entry__entry_id=tag_id
        )
        
        # Salvar informações para auditoria
        taxonomy_entry = tag.taxonomy_entry
        tag_info = {
            'taxonomy_namespace': taxonomy_entry.taxonomy.namespace,
            'predicate': taxonomy_entry.predicate,
            'value': taxonomy_entry.value,
            'tag_name': taxonomy_entry.tag_name
        }
        
        # Remover tag
        tag.delete()
        
        # Registrar auditoria
        AuditService.log(
            user=request.user,
            organization=case.organization,
            entity_type='CASE',
            entity_id=case.case_id,
            action_type='REMOVE_TAXONOMY_TAG',
            details_before=tag_info
        )
        
        return Response({
            "status": "success",
            "message": f"Tag '{tag_info['tag_name']}' removida do caso"
        })
        
    except Case.DoesNotExist:
        return Response(
            {"detail": "Caso não encontrado"},
            status=status.HTTP_404_NOT_FOUND
        )
    except CaseTaxonomyTag.DoesNotExist:
        return Response(
            {"detail": "Tag não encontrada para este caso"},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        return Response(
            {"detail": f"Erro ao remover tag: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated, HasRolePermission])
def add_taxonomy_tag_to_alert(request, alert_id):
    """
    Adiciona uma tag de taxonomia a um alerta
    """
    # Verificar permissão
    if not has_permission(request.user, 'alert:edit'):
        return Response(
            {"detail": "Você não tem permissão para editar alertas"},
            status=status.HTTP_403_FORBIDDEN
        )
    
    # Validar tag de entrada
    serializer = TaxonomyTagInputSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # Obter alerta
        alert = Alert.objects.get(alert_id=alert_id)
        
        # Verificar acesso ao alerta (multi-tenant)
        if (not request.user.is_superuser 
            and not getattr(request.user.profile, 'is_system_admin', False)
            and alert.organization != request.user.profile.organization):
            return Response(
                {"detail": "Você não tem acesso a este alerta"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Obter entrada de taxonomia
        taxonomy_entry = MISPTaxonomyEntry.objects.get(entry_id=serializer.validated_data['taxonomy_entry_id'])
        
        # Adicionar tag ao alerta
        tag, created = AlertTaxonomyTag.objects.get_or_create(
            alert=alert,
            taxonomy_entry=taxonomy_entry,
            defaults={'linked_by': request.user}
        )
        
        # Registrar auditoria
        AuditService.log(
            user=request.user,
            organization=alert.organization,
            entity_type='ALERT',
            entity_id=alert.alert_id,
            action_type='ADD_TAXONOMY_TAG',
            details_after={
                'taxonomy_namespace': taxonomy_entry.taxonomy.namespace,
                'predicate': taxonomy_entry.predicate,
                'value': taxonomy_entry.value,
                'tag_name': taxonomy_entry.tag_name
            }
        )
        
        return Response({
            "status": "success",
            "message": f"Tag '{taxonomy_entry.tag_name}' adicionada ao alerta",
            "created": created
        })
        
    except Alert.DoesNotExist:
        return Response(
            {"detail": "Alerta não encontrado"},
            status=status.HTTP_404_NOT_FOUND
        )
    except MISPTaxonomyEntry.DoesNotExist:
        return Response(
            {"detail": "Entrada de taxonomia não encontrada"},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        return Response(
            {"detail": f"Erro ao adicionar tag: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['DELETE'])
@permission_classes([permissions.IsAuthenticated, HasRolePermission])
def remove_taxonomy_tag_from_alert(request, alert_id, tag_id):
    """
    Remove uma tag de taxonomia de um alerta
    """
    # Verificar permissão
    if not has_permission(request.user, 'alert:edit'):
        return Response(
            {"detail": "Você não tem permissão para editar alertas"},
            status=status.HTTP_403_FORBIDDEN
        )
    
    try:
        # Obter alerta
        alert = Alert.objects.get(alert_id=alert_id)
        
        # Verificar acesso ao alerta (multi-tenant)
        if (not request.user.is_superuser 
            and not getattr(request.user.profile, 'is_system_admin', False)
            and alert.organization != request.user.profile.organization):
            return Response(
                {"detail": "Você não tem acesso a este alerta"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Obter tag
        tag = AlertTaxonomyTag.objects.get(
            alert=alert,
            taxonomy_entry__entry_id=tag_id
        )
        
        # Salvar informações para auditoria
        taxonomy_entry = tag.taxonomy_entry
        tag_info = {
            'taxonomy_namespace': taxonomy_entry.taxonomy.namespace,
            'predicate': taxonomy_entry.predicate,
            'value': taxonomy_entry.value,
            'tag_name': taxonomy_entry.tag_name
        }
        
        # Remover tag
        tag.delete()
        
        # Registrar auditoria
        AuditService.log(
            user=request.user,
            organization=alert.organization,
            entity_type='ALERT',
            entity_id=alert.alert_id,
            action_type='REMOVE_TAXONOMY_TAG',
            details_before=tag_info
        )
        
        return Response({
            "status": "success",
            "message": f"Tag '{tag_info['tag_name']}' removida do alerta"
        })
        
    except Alert.DoesNotExist:
        return Response(
            {"detail": "Alerta não encontrado"},
            status=status.HTTP_404_NOT_FOUND
        )
    except AlertTaxonomyTag.DoesNotExist:
        return Response(
            {"detail": "Tag não encontrada para este alerta"},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        return Response(
            {"detail": f"Erro ao remover tag: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated, HasRolePermission])
def add_taxonomy_tag_to_observable(request, observable_id):
    """
    Adiciona uma tag de taxonomia a um observável
    """
    # Verificar permissão
    if not has_permission(request.user, 'observable:edit'):
        return Response(
            {"detail": "Você não tem permissão para editar observáveis"},
            status=status.HTTP_403_FORBIDDEN
        )
    
    # Validar tag de entrada
    serializer = TaxonomyTagInputSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # Obter observável
        observable = Observable.objects.get(observable_id=observable_id)
        
        # Verificar acesso ao observável (multi-tenant)
        if (not request.user.is_superuser 
            and not getattr(request.user.profile, 'is_system_admin', False)
            and observable.organization != request.user.profile.organization):
            return Response(
                {"detail": "Você não tem acesso a este observável"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Obter entrada de taxonomia
        taxonomy_entry = MISPTaxonomyEntry.objects.get(entry_id=serializer.validated_data['taxonomy_entry_id'])
        
        # Adicionar tag ao observável
        tag, created = ObservableTaxonomyTag.objects.get_or_create(
            observable=observable,
            taxonomy_entry=taxonomy_entry,
            defaults={'linked_by': request.user}
        )
        
        # Registrar auditoria
        AuditService.log(
            user=request.user,
            organization=observable.organization,
            entity_type='OBSERVABLE',
            entity_id=observable.observable_id,
            action_type='ADD_TAXONOMY_TAG',
            details_after={
                'taxonomy_namespace': taxonomy_entry.taxonomy.namespace,
                'predicate': taxonomy_entry.predicate,
                'value': taxonomy_entry.value,
                'tag_name': taxonomy_entry.tag_name
            }
        )
        
        return Response({
            "status": "success",
            "message": f"Tag '{taxonomy_entry.tag_name}' adicionada ao observável",
            "created": created
        })
        
    except Observable.DoesNotExist:
        return Response(
            {"detail": "Observável não encontrado"},
            status=status.HTTP_404_NOT_FOUND
        )
    except MISPTaxonomyEntry.DoesNotExist:
        return Response(
            {"detail": "Entrada de taxonomia não encontrada"},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        return Response(
            {"detail": f"Erro ao adicionar tag: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['DELETE'])
@permission_classes([permissions.IsAuthenticated, HasRolePermission])
def remove_taxonomy_tag_from_observable(request, observable_id, tag_id):
    """
    Remove uma tag de taxonomia de um observável
    """
    # Verificar permissão
    if not has_permission(request.user, 'observable:edit'):
        return Response(
            {"detail": "Você não tem permissão para editar observáveis"},
            status=status.HTTP_403_FORBIDDEN
        )
    
    try:
        # Obter observável
        observable = Observable.objects.get(observable_id=observable_id)
        
        # Verificar acesso ao observável (multi-tenant)
        if (not request.user.is_superuser 
            and not getattr(request.user.profile, 'is_system_admin', False)
            and observable.organization != request.user.profile.organization):
            return Response(
                {"detail": "Você não tem acesso a este observável"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Obter tag
        tag = ObservableTaxonomyTag.objects.get(
            observable=observable,
            taxonomy_entry__entry_id=tag_id
        )
        
        # Salvar informações para auditoria
        taxonomy_entry = tag.taxonomy_entry
        tag_info = {
            'taxonomy_namespace': taxonomy_entry.taxonomy.namespace,
            'predicate': taxonomy_entry.predicate,
            'value': taxonomy_entry.value,
            'tag_name': taxonomy_entry.tag_name
        }
        
        # Remover tag
        tag.delete()
        
        # Registrar auditoria
        AuditService.log(
            user=request.user,
            organization=observable.organization,
            entity_type='OBSERVABLE',
            entity_id=observable.observable_id,
            action_type='REMOVE_TAXONOMY_TAG',
            details_before=tag_info
        )
        
        return Response({
            "status": "success",
            "message": f"Tag '{tag_info['tag_name']}' removida do observável"
        })
        
    except Observable.DoesNotExist:
        return Response(
            {"detail": "Observável não encontrado"},
            status=status.HTTP_404_NOT_FOUND
        )
    except ObservableTaxonomyTag.DoesNotExist:
        return Response(
            {"detail": "Tag não encontrada para este observável"},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        return Response(
            {"detail": f"Erro ao remover tag: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        ) 