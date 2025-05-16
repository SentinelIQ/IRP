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