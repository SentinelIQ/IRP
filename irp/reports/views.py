from django.db import models
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.db.models import Count, F, Avg
from datetime import timedelta

from rest_framework import viewsets, permissions, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response

from .models import ReportTemplate, GeneratedReport
from .serializers import ReportTemplateSerializer, GeneratedReportSerializer, GenerateReportSerializer
from .services import ReportService
from irp.cases.models import Case
from irp.audit.models import AuditLog
from irp.alerts.models import Alert
from irp.common.permissions import HasRolePermission
from irp.common.utils import has_permission


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
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            return ReportTemplate.objects.filter(
                models.Q(organization=user.profile.organization) | 
                models.Q(organization__isnull=True)
            )
        return ReportTemplate.objects.filter(organization__isnull=True)
    
    def get_permissions(self):
        # Para visualização, basta permissão de visualizar casos
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            self.required_permission = 'manage_case_settings'
        return super().get_permissions()
    
    def perform_create(self, serializer):
        # Associar à organização do usuário
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            serializer.save(created_by=user, organization=user.profile.organization)
        else:
            serializer.save(created_by=user)
    
    def perform_update(self, serializer):
        serializer.save()
    
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
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            return GeneratedReport.objects.filter(
                case__organization=user.profile.organization
            )
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
    included_sections = serializer.validated_data.get('sections', [])
    
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
        generated_report = ReportService.generate_report(
            case=case,
            output_format=output_format,
            template=template,
            sections=included_sections,
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


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated, HasRolePermission])
def reports(request, report_type=None):
    """Endpoint para gerar relatórios"""
    
    # Verificar permissão
    if not has_permission(request.user, 'generate_reports'):
        return Response({"error": "Sem permissão para gerar relatórios"}, status=status.HTTP_403_FORBIDDEN)
    
    # Obter organização do usuário
    user = request.user
    if not hasattr(user, 'profile') or not user.profile.organization:
        return Response({"error": "Usuário sem organização"}, status=status.HTTP_400_BAD_REQUEST)
    
    organization = user.profile.organization
    
    # Período para o relatório
    days = int(request.query_params.get('days', 30))
    date_from = timezone.now() - timedelta(days=days)
    
    if report_type == 'alerts':
        # Relatório de alertas
        alerts = Alert.objects.filter(
            organization=organization,
            created_at__gte=date_from,
            is_deleted=False
        )
        
        data = {
            'total_alerts': alerts.count(),
            'alerts_by_severity': alerts.values('severity__name').annotate(count=Count('alert_id')),
            'alerts_by_status': alerts.values('status__name').annotate(count=Count('alert_id')),
            'alerts_by_source': alerts.values('source_system').annotate(count=Count('alert_id')),
            'alerts_by_day': alerts.annotate(
                day=models.functions.TruncDay('created_at')
            ).values('day').annotate(count=Count('alert_id')).order_by('day'),
            'alerts_by_assignee': alerts.values(
                'assignee__username',
                'assignee__first_name',
                'assignee__last_name'
            ).annotate(count=Count('alert_id')),
            'period': {
                'from': date_from,
                'to': timezone.now(),
                'days': days
            }
        }
    
    elif report_type == 'cases':
        # Relatório de casos
        cases = Case.objects.filter(
            organization=organization,
            created_at__gte=date_from
        )
        
        data = {
            'total_cases': cases.count(),
            'cases_by_severity': cases.values('severity__name').annotate(count=Count('case_id')),
            'cases_by_status': cases.values('status__name').annotate(count=Count('case_id')),
            'cases_by_day': cases.annotate(
                day=models.functions.TruncDay('created_at')
            ).values('day').annotate(count=Count('case_id')).order_by('day'),
            'cases_by_assignee': cases.values(
                'assignee__username',
                'assignee__first_name',
                'assignee__last_name'
            ).annotate(count=Count('case_id')),
            'avg_resolution_time': cases.filter(
                closed_at__isnull=False
            ).annotate(
                resolution_time=F('closed_at') - F('created_at')
            ).aggregate(avg_time=Avg('resolution_time')),
            'period': {
                'from': date_from,
                'to': timezone.now(),
                'days': days
            }
        }
    
    elif report_type == 'observables':
        # Relatório de observáveis
        from irp.observables.models import Observable
        
        observables = Observable.objects.filter(
            added_at__gte=date_from,
            added_by__profile__organization=organization
        )
        
        data = {
            'total_observables': observables.count(),
            'observables_by_type': observables.values('type__name').annotate(count=Count('observable_id')),
            'iocs_count': observables.filter(is_ioc=True).count(),
            'tlp_distribution': observables.values('tlp_level__name').annotate(count=Count('observable_id')),
            'observables_by_day': observables.annotate(
                day=models.functions.TruncDay('added_at')
            ).values('day').annotate(count=Count('observable_id')).order_by('day'),
            'top_observables': observables.values('type__name', 'value').annotate(
                count=Count('caseobservable') + Count('alertobservable')
            ).order_by('-count')[:10],
            'period': {
                'from': date_from,
                'to': timezone.now(),
                'days': days
            }
        }
    
    else:
        # Lista de relatórios disponíveis
        data = {
            'available_reports': [
                {
                    'type': 'alerts',
                    'name': 'Relatório de Alertas',
                    'description': 'Estatísticas de alertas por severidade, status e fonte'
                },
                {
                    'type': 'cases',
                    'name': 'Relatório de Casos',
                    'description': 'Estatísticas de casos por severidade, status e tempo de resolução'
                },
                {
                    'type': 'observables',
                    'name': 'Relatório de Observáveis',
                    'description': 'Estatísticas de observáveis por tipo, TLP e frequência'
                }
            ]
        }
    
    return Response(data) 