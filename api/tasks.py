from celery import shared_task
from django.utils import timezone
from datetime import datetime, timedelta
from .models import Metric, Organization, NotificationEvent
from .services import MetricsService, NotificationService
import logging

logger = logging.getLogger(__name__)

@shared_task
def calculate_daily_metrics():
    """
    Tarefa para calcular as métricas diárias para todas as organizações
    Esta tarefa deve ser executada uma vez por dia
    """
    logger.info("Iniciando cálculo diário de métricas")
    
    yesterday = (timezone.now() - timedelta(days=1)).date()
    organizations = Organization.objects.filter(is_active=True)
    metrics = Metric.objects.filter(enabled=True)
    
    success_count = 0
    error_count = 0
    
    for org in organizations:
        for metric in metrics:
            try:
                logger.debug(f"Calculando métrica {metric.name} para {org.name}")
                
                # Cálculo da métrica
                metric_value = MetricsService.calculate_metric(
                    metric,
                    org,
                    yesterday,
                    yesterday + timedelta(days=1),
                    'DAILY'
                )
                
                if metric_value is not None:
                    # Armazenar o snapshot
                    MetricsService.store_metric_snapshot(
                        metric,
                        org,
                        yesterday,
                        metric_value,
                        'DAILY'
                    )
                    
                    success_count += 1
                    
            except Exception as e:
                logger.exception(f"Erro ao calcular métrica {metric.metric_id} para {org.name}: {str(e)}")
                error_count += 1
    
    logger.info(f"Cálculo diário de métricas concluído. Sucesso: {success_count}, Erros: {error_count}")
    return {'success': success_count, 'errors': error_count}

@shared_task
def calculate_weekly_metrics():
    """
    Tarefa para calcular as métricas semanais para todas as organizações
    Esta tarefa deve ser executada uma vez por semana (domingo ou segunda)
    """
    logger.info("Iniciando cálculo semanal de métricas")
    
    # Determinar o início da semana anterior
    today = timezone.now().date()
    start_of_week = today - timedelta(days=today.weekday() + 7)  # Segunda-feira da semana passada
    end_of_week = start_of_week + timedelta(days=7)  # Domingo da semana passada
    
    organizations = Organization.objects.filter(is_active=True)
    metrics = Metric.objects.filter(enabled=True)
    
    success_count = 0
    error_count = 0
    
    for org in organizations:
        for metric in metrics:
            try:
                logger.debug(f"Calculando métrica semanal {metric.name} para {org.name}")
                
                # Cálculo da métrica
                metric_value = MetricsService.calculate_metric(
                    metric,
                    org,
                    start_of_week,
                    end_of_week,
                    'WEEKLY'
                )
                
                if metric_value is not None:
                    # Armazenar o snapshot
                    MetricsService.store_metric_snapshot(
                        metric,
                        org,
                        start_of_week,
                        metric_value,
                        'WEEKLY'
                    )
                    
                    success_count += 1
                    
            except Exception as e:
                logger.exception(f"Erro ao calcular métrica semanal {metric.metric_id} para {org.name}: {str(e)}")
                error_count += 1
    
    logger.info(f"Cálculo semanal de métricas concluído. Sucesso: {success_count}, Erros: {error_count}")
    return {'success': success_count, 'errors': error_count}

@shared_task
def calculate_monthly_metrics():
    """
    Tarefa para calcular as métricas mensais para todas as organizações
    Esta tarefa deve ser executada uma vez por mês (1º dia do mês)
    """
    logger.info("Iniciando cálculo mensal de métricas")
    
    # Determinar o mês anterior
    today = timezone.now().date()
    if today.month == 1:
        previous_month = 12
        previous_year = today.year - 1
    else:
        previous_month = today.month - 1
        previous_year = today.year
    
    # Primeiro dia do mês anterior
    start_of_month = datetime(previous_year, previous_month, 1).date()
    
    # Primeiro dia do mês atual
    if previous_month == 12:
        end_of_month = datetime(today.year, 1, 1).date()
    else:
        end_of_month = datetime(today.year, previous_month + 1, 1).date()
    
    organizations = Organization.objects.filter(is_active=True)
    metrics = Metric.objects.filter(enabled=True)
    
    success_count = 0
    error_count = 0
    
    for org in organizations:
        for metric in metrics:
            try:
                logger.debug(f"Calculando métrica mensal {metric.name} para {org.name}")
                
                # Cálculo da métrica
                metric_value = MetricsService.calculate_metric(
                    metric,
                    org,
                    start_of_month,
                    end_of_month,
                    'MONTHLY'
                )
                
                if metric_value is not None:
                    # Armazenar o snapshot
                    MetricsService.store_metric_snapshot(
                        metric,
                        org,
                        start_of_month,
                        metric_value,
                        'MONTHLY'
                    )
                    
                    success_count += 1
                    
            except Exception as e:
                logger.exception(f"Erro ao calcular métrica mensal {metric.metric_id} para {org.name}: {str(e)}")
                error_count += 1
    
    logger.info(f"Cálculo mensal de métricas concluído. Sucesso: {success_count}, Erros: {error_count}")
    return {'success': success_count, 'errors': error_count}

@shared_task
def cleanup_notification_logs(days=30):
    """
    Tarefa para limpar logs de notificação antigos.
    Por padrão, remove logs com mais de 30 dias.
    """
    logger.info(f"Iniciando limpeza de logs de notificação mais antigos que {days} dias")
    
    cutoff_date = timezone.now() - timedelta(days=days)
    from .models import NotificationLog
    
    count, _ = NotificationLog.objects.filter(sent_at__lt=cutoff_date).delete()
    
    logger.info(f"Limpeza de logs de notificação concluída. {count} logs removidos.")
    return {'deleted_count': count}

@shared_task
def process_scheduled_notifications():
    """
    Tarefa para processar notificações agendadas.
    Processa eventos que devem ser enviados periodicamente.
    """
    logger.info("Iniciando processamento de notificações agendadas")
    
    # Obtém todas as organizações ativas
    organizations = Organization.objects.filter(is_active=True)
    
    notification_count = 0
    
    # Para cada organização, processa as notificações agendadas
    for org in organizations:
        try:
            # Gerar notificações para eventos periódicos, como resumos diários
            
            # Exemplo: Resumo diário de alertas novos
            from .models import Alert
            
            # Alertas criados nas últimas 24 horas
            yesterday = timezone.now() - timedelta(days=1)
            new_alerts = Alert.objects.filter(
                organization=org,
                created_at__gte=yesterday,
                is_deleted=False
            ).count()
            
            # Casos abertos
            from .models import Case, CaseStatus
            open_cases = Case.objects.filter(
                organization=org,
                status__is_terminal_status=False
            ).count()
            
            # Criar payload para evento DAILY_SUMMARY
            payload = {
                'organization_id': str(org.organization_id),
                'organization_name': org.name,
                'timestamp': timezone.now().isoformat(),
                'summary_date': timezone.now().date().isoformat(),
                'new_alerts_count': new_alerts,
                'open_cases_count': open_cases,
            }
            
            # Processar o evento
            notification_logs = NotificationService.process_event(
                event_name='DAILY_SUMMARY',
                payload=payload,
                organization=org
            )
            
            notification_count += len(notification_logs)
            
        except Exception as e:
            logger.exception(f"Erro ao processar notificações agendadas para {org.name}: {str(e)}")
    
    logger.info(f"Processamento de notificações agendadas concluído. {notification_count} notificações enviadas.")
    return {'notifications_sent': notification_count}

# Tarefas para integração MISP

@shared_task
def auto_import_from_misp():
    """
    Tarefa para importar automaticamente eventos do MISP
    """
    from .models import MISPInstance, Organization
    from .services.misp_service import MISPService
    
    logger.info("Iniciando importação automática do MISP")
    
    # Obter todas as instâncias MISP ativas
    misp_instances = MISPInstance.objects.filter(is_active=True)
    
    if not misp_instances.exists():
        logger.info("Nenhuma instância MISP ativa encontrada")
        return
    
    results = {
        'total_instances': misp_instances.count(),
        'successful_imports': 0,
        'failed_imports': 0,
        'total_events_imported': 0,
        'total_attributes_imported': 0,
        'total_alerts_created': 0
    }
    
    for instance in misp_instances:
        try:
            # Determinar a organização para importação
            organization = instance.organization
            
            # Se a instância não está associada a uma organização específica,
            # importar para todas as organizações
            if not organization:
                organizations = Organization.objects.all()
                for org in organizations:
                    try:
                        misp_import = MISPService.import_from_misp(
                            misp_instance=instance,
                            organization=org,
                            create_alerts=True
                        )
                        
                        if misp_import.status == 'COMPLETED':
                            results['successful_imports'] += 1
                            results['total_events_imported'] += misp_import.imported_events_count
                            results['total_attributes_imported'] += misp_import.imported_attributes_count
                            results['total_alerts_created'] += misp_import.created_alerts_count
                        else:
                            results['failed_imports'] += 1
                    except Exception as e:
                        logger.error(f"Erro ao importar do MISP para organização {org.name}: {str(e)}")
                        results['failed_imports'] += 1
            else:
                # Importar apenas para a organização associada
                misp_import = MISPService.import_from_misp(
                    misp_instance=instance,
                    organization=organization,
                    create_alerts=True
                )
                
                if misp_import.status == 'COMPLETED':
                    results['successful_imports'] += 1
                    results['total_events_imported'] += misp_import.imported_events_count
                    results['total_attributes_imported'] += misp_import.imported_attributes_count
                    results['total_alerts_created'] += misp_import.created_alerts_count
                else:
                    results['failed_imports'] += 1
        
        except Exception as e:
            logger.error(f"Erro ao importar do MISP {instance.name}: {str(e)}")
            results['failed_imports'] += 1
    
    # Registrar resultados
    logger.info(f"Importação automática do MISP concluída: {results}")
    
    # Atualizar métricas
    update_misp_metrics()
    
    return results


@shared_task
def update_misp_metrics():
    """
    Atualiza as métricas relacionadas ao MISP
    """
    from .models import Metric, MetricSnapshot, MISPImport, MISPExport
    from django.utils import timezone
    from django.db.models import Count, Sum, Avg
    from datetime import timedelta
    
    try:
        # Definir período para métricas (últimos 30 dias)
        end_date = timezone.now()
        start_date = end_date - timedelta(days=30)
        
        # Obter ou criar métrica para importações MISP
        misp_import_metric, _ = Metric.objects.get_or_create(
            name='misp_import_stats',
            defaults={
                'display_name': 'Estatísticas de Importação MISP',
                'description': 'Estatísticas de importações do MISP',
                'metric_type': 'COUNT',
                'entity_type': 'MISP_IMPORT'
            }
        )
        
        # Calcular estatísticas de importação
        import_stats = MISPImport.objects.filter(
            import_timestamp__gte=start_date,
            import_timestamp__lte=end_date
        ).aggregate(
            total_imports=Count('import_id'),
            total_events=Sum('imported_events_count'),
            total_attributes=Sum('imported_attributes_count'),
            total_alerts=Sum('created_alerts_count'),
            avg_events_per_import=Avg('imported_events_count'),
            avg_attributes_per_import=Avg('imported_attributes_count')
        )
        
        # Criar snapshot para importações
        MetricSnapshot.objects.create(
            metric=misp_import_metric,
            timestamp=end_date,
            value_json={
                'total_imports': import_stats['total_imports'] or 0,
                'total_events': import_stats['total_events'] or 0,
                'total_attributes': import_stats['total_attributes'] or 0,
                'total_alerts': import_stats['total_alerts'] or 0,
                'avg_events_per_import': float(import_stats['avg_events_per_import'] or 0),
                'avg_attributes_per_import': float(import_stats['avg_attributes_per_import'] or 0),
                'period_start': start_date.isoformat(),
                'period_end': end_date.isoformat()
            }
        )
        
        # Obter ou criar métrica para exportações MISP
        misp_export_metric, _ = Metric.objects.get_or_create(
            name='misp_export_stats',
            defaults={
                'display_name': 'Estatísticas de Exportação MISP',
                'description': 'Estatísticas de exportações para MISP',
                'metric_type': 'COUNT',
                'entity_type': 'MISP_EXPORT'
            }
        )
        
        # Calcular estatísticas de exportação
        export_stats = MISPExport.objects.filter(
            export_timestamp__gte=start_date,
            export_timestamp__lte=end_date
        ).aggregate(
            total_exports=Count('export_id'),
            total_observables=Sum('exported_observables_count'),
            avg_observables_per_export=Avg('exported_observables_count')
        )
        
        # Criar snapshot para exportações
        MetricSnapshot.objects.create(
            metric=misp_export_metric,
            timestamp=end_date,
            value_json={
                'total_exports': export_stats['total_exports'] or 0,
                'total_observables': export_stats['total_observables'] or 0,
                'avg_observables_per_export': float(export_stats['avg_observables_per_export'] or 0),
                'period_start': start_date.isoformat(),
                'period_end': end_date.isoformat()
            }
        )
        
        logger.info("Métricas do MISP atualizadas com sucesso")
        
    except Exception as e:
        logger.error(f"Erro ao atualizar métricas do MISP: {str(e)}")


@shared_task
def generate_report_for_case(case_id, template_id=None, output_format=None, sections=None):
    """
    Gera um relatório para um caso específico de forma assíncrona
    
    Args:
        case_id: ID do caso
        template_id: ID do template a ser usado (opcional)
        output_format: Formato de saída (MARKDOWN, DOCX, PDF)
        sections: Lista de seções a incluir no relatório
    """
    from .models import Case, ReportTemplate
    from .services.report_service import ReportService
    from django.contrib.auth.models import User
    
    try:
        # Obter o caso
        case = Case.objects.get(case_id=case_id)
        
        # Obter o template se especificado
        template = None
        if template_id:
            try:
                template = ReportTemplate.objects.get(template_id=template_id)
            except ReportTemplate.DoesNotExist:
                logger.error(f"Template {template_id} não encontrado")
                return {"error": f"Template {template_id} não encontrado"}
        
        # Gerar o relatório
        report = ReportService.generate_report(
            case=case,
            template=template,
            output_format=output_format,
            sections=sections
        )
        
        if report.status == 'COMPLETED':
            logger.info(f"Relatório {report.report_id} gerado com sucesso para o caso {case_id}")
            
            # Criar notificação sobre o relatório gerado
            from .services import NotificationService
            
            try:
                NotificationService.create_notification(
                    event_name='REPORT_GENERATED',
                    entity_id=str(report.report_id),
                    entity_type='REPORT',
                    title=f"Relatório gerado para o caso: {case.title}",
                    message=f"Um relatório foi gerado no formato {report.output_format}.",
                    organization=case.organization,
                    related_object_id=str(case.case_id),
                    related_object_type='CASE'
                )
            except Exception as e:
                logger.error(f"Erro ao criar notificação para relatório gerado: {str(e)}")
            
            return {
                "report_id": str(report.report_id),
                "status": report.status,
                "file_path": report.file_path
            }
        else:
            logger.error(f"Erro ao gerar relatório para caso {case_id}: {report.error_message}")
            return {
                "report_id": str(report.report_id),
                "status": report.status,
                "error": report.error_message
            }
    
    except Case.DoesNotExist:
        logger.error(f"Caso {case_id} não encontrado")
        return {"error": f"Caso {case_id} não encontrado"}
    
    except Exception as e:
        logger.error(f"Erro ao gerar relatório para caso {case_id}: {str(e)}")
        return {"error": str(e)} 