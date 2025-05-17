from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from django.db import models
import logging

from irp.integrations.misp.models import MISPInstance, MISPImport, MISPExport
from irp.integrations.misp.serializers import (
    MISPInstanceSerializer, MISPImportSerializer, MISPExportSerializer,
    TriggerMISPImportSerializer, ExportCaseToMISPSerializer
)
from irp.cases.models import Case
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