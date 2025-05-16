from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response
from django.db import models
import logging
import functools

from .models import (
    MISPInstance, MISPImport, MISPExport, Case, ReportTemplate, GeneratedReport, AuditLog
)
from .serializers import (
    MISPInstanceSerializer, MISPImportSerializer, MISPExportSerializer, 
    ReportTemplateSerializer, GeneratedReportSerializer,
    TriggerMISPImportSerializer, ExportCaseToMISPSerializer, GenerateReportSerializer
)
from .permissions import HasRolePermission, has_permission
from .views import audit_action

logger = logging.getLogger(__name__)

# MISP Integration ViewSets
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
    
    @audit_action(entity_type='MISP_INSTANCE', action_type='CREATE')
    def perform_create(self, serializer):
        # Associar à organização do usuário
        organization = None
        if hasattr(self.request.user, 'profile'):
            organization = self.request.user.profile.organization
        serializer.save(organization=organization)
    
    @audit_action(entity_type='MISP_INSTANCE', action_type='UPDATE')
    def perform_update(self, serializer):
        serializer.save()
    
    @audit_action(entity_type='MISP_INSTANCE', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)
    
    @action(detail=True, methods=['post'])
    @audit_action(entity_type='MISP_INSTANCE', action_type='TEST_CONNECTION')
    def test_connection(self, request, pk=None):
        """
        Testa a conexão com uma instância MISP
        """
        instance = self.get_object()
        from .services.misp_service import MISPService
        
        try:
            success, message = MISPService.test_connection(instance)
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
        
        # Importar imediatamente ou agendar a tarefa
        from .services.misp_service import MISPService
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
            AuditLog.objects.create(
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
        from .services.misp_service import MISPService
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
        
        # Registrar auditoria após exportação bem-sucedida
        if case.organization:
            AuditLog.objects.create(
                user=request.user,
                organization=case.organization,
                entity_type='CASE',
                entity_id=case.case_id,
                action_type='MISP_EXPORT',
                details_after={
                    'misp_export_id': str(misp_export.export_id),
                    'misp_instance': str(misp_instance.instance_id),
                    'misp_event_uuid': str(misp_export.misp_event_uuid),
                    'include_observables': include_observables,
                    'include_timeline': include_timeline,
                    'include_mitre_techniques': include_mitre_techniques,
                    'exported_observables_count': misp_export.exported_observables_count,
                }
            )
        
        # Retornar o resultado
        return Response({
            "status": "success",
            "message": f"Caso exportado com sucesso para o MISP. ID do evento: {misp_export.misp_event_uuid}",
            "misp_event_uuid": misp_export.misp_event_uuid,
            "export_id": misp_export.export_id
        })
        
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
            {"detail": f"Erro ao exportar para o MISP: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


# Report Generation ViewSets
class ReportTemplateViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing report templates
    """
    queryset = ReportTemplate.objects.all()
    serializer_class = ReportTemplateSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'case:view'
    
    def get_queryset(self):
        # Isolamento multi-tenant: só templates da organização do usuário ou globais
        if not self.request.user.is_authenticated:
            return ReportTemplate.objects.none()
            
        if self.request.user.is_superuser or getattr(self.request.user.profile, 'is_system_admin', False):
            return ReportTemplate.objects.all()
            
        # Usuário comum só vê templates da própria organização ou globais
        if hasattr(self.request.user, 'profile') and self.request.user.profile.organization:
            return ReportTemplate.objects.filter(
                models.Q(organization=self.request.user.profile.organization) | 
                models.Q(organization=None)
            )
        return ReportTemplate.objects.none()
    
    def get_permissions(self):
        # Para visualização, basta permissão de visualizar casos
        if self.action == 'retrieve' or self.action == 'list':
            return [permissions.IsAuthenticated(), HasRolePermission()]
        
        # Para operações de escrita, exigir permissão de editar casos
        self.required_permission = 'case:edit'
        return super().get_permissions()
    
    @audit_action(entity_type='REPORT_TEMPLATE', action_type='CREATE')
    def perform_create(self, serializer):
        # Associar à organização do usuário
        organization = None
        if hasattr(self.request.user, 'profile'):
            organization = self.request.user.profile.organization
        serializer.save(
            organization=organization,
            created_by=self.request.user
        )
    
    @audit_action(entity_type='REPORT_TEMPLATE', action_type='UPDATE')
    def perform_update(self, serializer):
        serializer.save()
        
    @audit_action(entity_type='REPORT_TEMPLATE', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)


class GeneratedReportViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for viewing generated reports (readonly)
    """
    queryset = GeneratedReport.objects.all()
    serializer_class = GeneratedReportSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'case:view'
    
    def get_queryset(self):
        # Isolamento multi-tenant: só relatórios de casos da organização do usuário
        if not self.request.user.is_authenticated:
            return GeneratedReport.objects.none()
            
        if self.request.user.is_superuser or getattr(self.request.user.profile, 'is_system_admin', False):
            return GeneratedReport.objects.all().order_by('-created_at')
            
        # Usuário comum só vê relatórios de casos da própria organização
        if hasattr(self.request.user, 'profile') and self.request.user.profile.organization:
            organization = self.request.user.profile.organization
            return GeneratedReport.objects.filter(
                case__organization=organization
            ).order_by('-created_at')
        return GeneratedReport.objects.none()


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated, HasRolePermission])
def generate_case_report(request, case_id):
    """
    Endpoint para gerar relatório de caso
    """
    serializer = GenerateReportSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    # Verificar permissão específica
    if not has_permission(request.user, 'case:view'):
        return Response(
            {"detail": "Você não tem permissão para gerar relatórios"},
            status=status.HTTP_403_FORBIDDEN
        )
    
    # Obter parâmetros da requisição
    template_id = serializer.validated_data.get('template_id')
    output_format = serializer.validated_data.get('output_format')
    included_sections = serializer.validated_data.get('included_sections', [])
    
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
        
        # Obter template, se especificado
        template = None
        if template_id:
            try:
                template = ReportTemplate.objects.get(template_id=template_id)
                
                # Verificar acesso ao template (multi-tenant)
                if (template.organization 
                    and not request.user.is_superuser 
                    and not getattr(request.user.profile, 'is_system_admin', False)
                    and template.organization != request.user.profile.organization):
                    return Response(
                        {"detail": "Você não tem acesso a este template"},
                        status=status.HTTP_403_FORBIDDEN
                    )
                    
                if not output_format:
                    output_format = template.output_format
            except ReportTemplate.DoesNotExist:
                return Response(
                    {"detail": "Template não encontrado"},
                    status=status.HTTP_404_NOT_FOUND
                )
        
        # Se não foi especificado um formato, usar MARKDOWN por padrão
        if not output_format:
            output_format = 'MARKDOWN'
        
        # Normalizar o formato
        output_format = output_format.upper()
        
        # Gerar o relatório
        from .services.report_service import ReportService
        generated_report = ReportService.generate_report(
            case=case,
            output_format=output_format,
            template=template,
            included_sections=included_sections,
            generated_by=request.user
        )
        
        # Registrar auditoria após geração bem-sucedida
        if case.organization:
            AuditLog.objects.create(
                user=request.user,
                organization=case.organization,
                entity_type='CASE',
                entity_id=case.case_id,
                action_type='GENERATE_REPORT',
                details_after={
                    'report_id': str(generated_report.report_id),
                    'template_id': str(template.template_id) if template else None,
                    'output_format': output_format,
                    'included_sections': included_sections
                }
            )
        
        if generated_report:
            return Response({
                "status": "success",
                "message": "Geração de relatório iniciada",
                "report_id": generated_report.report_id
            })
        else:
            return Response(
                {"detail": "Erro ao iniciar geração do relatório"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
    except Case.DoesNotExist:
        return Response(
            {"detail": "Caso não encontrado"},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        return Response(
            {"detail": f"Erro ao gerar relatório: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


# Function for the calculate_metrics endpoint
@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated, HasRolePermission])
def calculate_metrics(request):
    """
    Endpoint para calcular métricas sob demanda
    """
    # Verificar permissão específica
    if not has_permission(request.user, 'metrics:view'):
        return Response(
            {"detail": "Você não tem permissão para calcular métricas"},
            status=status.HTTP_403_FORBIDDEN
        )
    
    try:
        # Obter organização do usuário
        organization = None
        if hasattr(request.user, 'profile'):
            organization = request.user.profile.organization
        
        if not organization and not request.user.is_superuser:
            return Response(
                {"detail": "Usuário não está associado a uma organização"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Obter parâmetros da requisição
        from .models import Metric
        metric_id = request.data.get('metric_id')
        granularity = request.data.get('granularity', 'daily')
        
        if metric_id:
            # Calcular métrica específica
            try:
                metric = Metric.objects.get(metric_id=metric_id)
                
                # Usar serviço de métricas para o cálculo
                from .services import MetricsService
                result = MetricsService.calculate_metric_on_demand(
                    metric=metric,
                    organization=organization,
                    granularity=granularity
                )
                
                return Response({
                    "status": "success",
                    "metric": metric.name,
                    "result": result
                })
                
            except Metric.DoesNotExist:
                return Response(
                    {"detail": "Métrica não encontrada"},
                    status=status.HTTP_404_NOT_FOUND
                )
        else:
            # Calcular todas as métricas
            # Disparar tarefa assíncrona
            from .tasks import calculate_daily_metrics, calculate_weekly_metrics, calculate_monthly_metrics
            
            if granularity.lower() == 'daily':
                calculate_daily_metrics.delay()
            elif granularity.lower() == 'weekly':
                calculate_weekly_metrics.delay()
            elif granularity.lower() == 'monthly':
                calculate_monthly_metrics.delay()
            else:
                return Response(
                    {"detail": f"Granularidade inválida: {granularity}"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            return Response({
                "status": "success",
                "message": f"Cálculo de métricas {granularity} iniciado em segundo plano"
            })
    
    except Exception as e:
        return Response(
            {"detail": f"Erro ao calcular métricas: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        ) 