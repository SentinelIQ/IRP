from django.db import models
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.db.models import Count, F, Avg
from datetime import timedelta
from django.http import FileResponse, Http404
import jinja2

from rest_framework import viewsets, permissions, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response

from .models import ReportTemplate, GeneratedReport, ScheduledReport
from .serializers import (
    ReportTemplateSerializer, GeneratedReportSerializer, GenerateReportSerializer,
    ScheduledReportSerializer
)
from .services import ReportService
from irp.cases.models import Case
from irp.audit.models import AuditLog
from irp.alerts.models import Alert
from irp.common.permissions import HasRolePermission
from irp.common.utils import has_permission
from irp.common.audit import audit_action


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
    
    @audit_action(entity_type='REPORT_TEMPLATE', action_type='CREATE')
    def perform_create(self, serializer):
        # Associar à organização do usuário
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            serializer.save(created_by=user, organization=user.profile.organization)
        else:
            serializer.save(created_by=user)
    
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
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            return GeneratedReport.objects.filter(
                case__organization=user.profile.organization
            )
        return GeneratedReport.objects.none()

    @audit_action(entity_type='GENERATED_REPORT', action_type='VIEW')
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated, HasRolePermission])
@audit_action(entity_type='REPORT', action_type='GENERATE')
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
@audit_action(entity_type='REPORT', action_type='LIST')
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


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated, HasRolePermission])
@audit_action(entity_type='REPORT', action_type='DOWNLOAD')
def download_report(request, report_id):
    """
    Endpoint para download de relatório gerado
    """
    # Verificar permissão específica
    if not has_permission(request.user, 'case:view'):
        return Response(
            {"detail": "Você não tem permissão para baixar relatórios"},
            status=status.HTTP_403_FORBIDDEN
        )
    
    try:
        # Obter o relatório gerado
        report = get_object_or_404(GeneratedReport, report_id=report_id)
        
        # Verificar acesso multi-tenant ao relatório
        if (not request.user.is_superuser 
            and not getattr(request.user.profile, 'is_system_admin', False)
            and report.case.organization != request.user.profile.organization):
            return Response(
                {"detail": "Você não tem acesso a este relatório"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Verificar se o relatório foi gerado com sucesso
        if report.status != 'COMPLETED':
            return Response(
                {"detail": f"O relatório não está disponível para download (Status: {report.status})"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Verificar se o arquivo existe
        import os
        if not os.path.exists(report.file_path):
            return Response(
                {"detail": "Arquivo de relatório não encontrado"},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Definir o tipo MIME com base no formato do relatório
        content_type = {
            'MARKDOWN': 'text/markdown',
            'DOCX': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'PDF': 'application/pdf'
        }.get(report.output_format, 'application/octet-stream')
        
        # Definir o nome do arquivo para download
        filename = os.path.basename(report.file_path)
        
        # Registrar auditoria de download
        if report.case.organization:
            AuditLog.objects.create(
                user=request.user,
                organization=report.case.organization,
                entity_type='CASE',
                entity_id=report.case.case_id,
                action_type='DOWNLOAD_REPORT',
                details_after={
                    'report_id': str(report.report_id),
                    'filename': filename,
                    'format': report.output_format
                }
            )
        
        # Retornar o arquivo como resposta
        return FileResponse(
            open(report.file_path, 'rb'),
            as_attachment=True,
            filename=filename,
            content_type=content_type
        )
    
    except Exception as e:
        return Response(
            {"detail": f"Erro ao baixar relatório: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated, HasRolePermission])
@audit_action(entity_type='REPORT', action_type='PREVIEW')
def preview_report(request, case_id):
    """
    Endpoint para pré-visualizar relatório de caso sem salvar
    """
    serializer = GenerateReportSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    # Verificar permissão específica
    if not has_permission(request.user, 'case:view'):
        return Response(
            {"detail": "Você não tem permissão para visualizar relatórios"},
            status=status.HTTP_403_FORBIDDEN
        )
    
    # Obter parâmetros da requisição
    template_id = serializer.validated_data.get('template_id')
    output_format = serializer.validated_data.get('output_format')
    included_sections = serializer.validated_data.get('sections', [])
    include_attachments = serializer.validated_data.get('include_attachments', False)
    custom_header = serializer.validated_data.get('custom_header')
    custom_footer = serializer.validated_data.get('custom_footer')
    
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
        
        # Adicionar 'attachments' às seções se include_attachments for True
        if include_attachments and included_sections and 'attachments' not in included_sections:
            included_sections.append('attachments')
        elif include_attachments and not included_sections:
            included_sections = ['attachments']
        
        # Coletar dados do caso
        case_data = ReportService._collect_case_data(case, included_sections)
        
        # Determinar conteúdo do template
        if template and template.template_content:
            template_content = template.template_content
        else:
            template_content = ReportService._get_default_markdown_template(case_data)
            
        # Adicionar cabeçalho e rodapé personalizados
        if custom_header:
            template_content = f"{custom_header}\n\n{template_content}"
            
        if custom_footer:
            template_content = f"{template_content}\n\n{custom_footer}"
            
        # Renderizar template usando Jinja2
        env = jinja2.Environment()
        template_obj = env.from_string(template_content)
        rendered_content = template_obj.render(**case_data)
        
        # Retornar uma amostra do conteúdo renderizado
        # Para Markdown, retornamos o markdown diretamente
        # Para DOCX e PDF retornamos apenas uma parte do markdown como representação
        preview_content = rendered_content
        if len(preview_content) > 5000:  # Limitar tamanho da preview
            preview_content = preview_content[:5000] + "...\n\n(Preview truncada)"
            
        return Response({
            "status": "success",
            "preview_format": "MARKDOWN",  # Sempre retorna markdown para preview
            "preview_content": preview_content,
            "message": f"Preview do relatório em formato {output_format} gerada com sucesso"
        })
            
    except Case.DoesNotExist:
        return Response(
            {"detail": "Caso não encontrado"},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        return Response(
            {"detail": f"Erro ao gerar preview do relatório: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


class ScheduledReportViewSet(viewsets.ModelViewSet):
    """
    API endpoint para gerenciar relatórios agendados
    """
    queryset = ScheduledReport.objects.all()
    serializer_class = ScheduledReportSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'case:view'
    
    def get_queryset(self):
        # Isolamento multi-tenant: só relatórios da organização do usuário
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            return ScheduledReport.objects.filter(
                organization=user.profile.organization
            )
        return ScheduledReport.objects.none()
    
    def get_permissions(self):
        # Para visualização, basta permissão de visualizar casos
        # Para criar/atualizar/excluir, é necessário permissão de gerenciar configurações
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            self.required_permission = 'manage_case_settings'
        return super().get_permissions()
    
    @audit_action(entity_type='SCHEDULED_REPORT', action_type='CREATE')
    def perform_create(self, serializer):
        # Associar à organização do usuário
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            serializer.save(created_by=user, organization=user.profile.organization)
        else:
            # Se não tiver organização, não deve conseguir criar
            raise serializers.ValidationError({'organization': 'Usuário não está associado a uma organização'})
    
    @audit_action(entity_type='SCHEDULED_REPORT', action_type='UPDATE')
    def perform_update(self, serializer):
        serializer.save()
        
    @audit_action(entity_type='SCHEDULED_REPORT', action_type='DELETE')
    def perform_destroy(self, instance):
        # Soft-delete: apenas desativar
        instance.is_active = False
        instance.save()
        
    @audit_action(entity_type='SCHEDULED_REPORT', action_type='VIEW')
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated, HasRolePermission])
@audit_action(entity_type='SCHEDULED_REPORT', action_type='RUN')
def run_scheduled_report_now(request, schedule_id):
    """
    Endpoint para executar um relatório agendado imediatamente
    """
    # Verificar permissão específica
    if not has_permission(request.user, 'manage_case_settings'):
        return Response(
            {"detail": "Você não tem permissão para executar relatórios agendados manualmente"},
            status=status.HTTP_403_FORBIDDEN
        )
    
    try:
        # Obter o agendamento
        schedule = get_object_or_404(ScheduledReport, schedule_id=schedule_id)
        
        # Verificar acesso multi-tenant
        if (not request.user.is_superuser 
            and not getattr(request.user.profile, 'is_system_admin', False)
            and schedule.organization != request.user.profile.organization):
            return Response(
                {"detail": "Você não tem acesso a este agendamento"},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Registrar auditoria de execução manual
        AuditLog.objects.create(
            user=request.user,
            organization=schedule.organization,
            entity_type='SCHEDULED_REPORT',
            entity_id=schedule.schedule_id,
            action_type='MANUAL_RUN',
            details_after={
                'name': schedule.name,
                'run_at': timezone.now().isoformat()
            }
        )
        
        # Construir filtro de casos
        from django.db.models import Q
        case_query = Q(organization=schedule.organization)
        
        # Adicionar filtros adicionais
        filters = schedule.case_filter
        if filters:
            if filters.get('status'):
                case_query &= Q(status__name__in=filters.get('status'))
            if filters.get('severity'):
                case_query &= Q(severity__name__in=filters.get('severity'))
            if filters.get('tags'):
                # Para cada tag no filtro, exigir que esteja presente no caso
                for tag in filters.get('tags'):
                    case_query &= Q(tags__contains=[tag])
        
        # Filtrar casos de acordo com os critérios
        cases = Case.objects.filter(case_query)
        
        # Contar casos e iniciar geração assíncrona
        case_count = cases.count()
        
        # Iniciar tarefa assíncrona para gerar os relatórios
        from .tasks import generate_scheduled_reports
        generate_scheduled_reports.delay()
        
        return Response({
            "status": "success",
            "message": f"Execução do relatório agendado iniciada. {case_count} casos serão processados.",
            "case_count": case_count
        })
        
    except Exception as e:
        return Response(
            {"detail": f"Erro ao executar relatório agendado: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        ) 