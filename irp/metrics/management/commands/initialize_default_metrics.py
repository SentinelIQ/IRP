from django.core.management.base import BaseCommand
from irp.metrics.models import Metric

class Command(BaseCommand):
    help = 'Inicializa as métricas padrão no sistema'

    def handle(self, *args, **options):
        # Lista de métricas padrão do sistema
        default_metrics = [
            # Métricas de Alerta
            {
                'name': 'alerts_created_daily',
                'display_name': 'Alerts Created Daily',
                'description': 'Number of alerts created per day',
                'metric_type': 'COUNT',
                'entity_type': 'ALERT',
            },
            {
                'name': 'alerts_by_severity',
                'display_name': 'Alerts by Severity',
                'description': 'Distribution of alerts by severity',
                'metric_type': 'COUNT',
                'entity_type': 'ALERT',
            },
            {
                'name': 'alerts_by_status',
                'display_name': 'Alerts by Status',
                'description': 'Distribution of alerts by status',
                'metric_type': 'COUNT',
                'entity_type': 'ALERT',
            },
            {
                'name': 'alerts_triage_time_avg',
                'display_name': 'Average Alert Triage Time (minutes)',
                'description': 'Average time for alerts to be triaged (minutes)',
                'metric_type': 'AVERAGE',
                'entity_type': 'ALERT',
            },
            
            # Métricas de Caso
            {
                'name': 'cases_created_daily',
                'display_name': 'Cases Created Daily',
                'description': 'Number of cases created per day',
                'metric_type': 'COUNT',
                'entity_type': 'CASE',
            },
            {
                'name': 'cases_closed_daily',
                'display_name': 'Cases Closed Daily',
                'description': 'Number of cases closed per day',
                'metric_type': 'COUNT',
                'entity_type': 'CASE',
            },
            {
                'name': 'cases_by_severity',
                'display_name': 'Cases by Severity',
                'description': 'Distribution of cases by severity',
                'metric_type': 'COUNT',
                'entity_type': 'CASE',
            },
            {
                'name': 'cases_by_status',
                'display_name': 'Cases by Status',
                'description': 'Distribution of cases by status',
                'metric_type': 'COUNT',
                'entity_type': 'CASE',
            },
            {
                'name': 'cases_resolution_time_avg',
                'display_name': 'Average Case Resolution Time (hours)',
                'description': 'Average time for cases to be resolved (hours)',
                'metric_type': 'AVERAGE',
                'entity_type': 'CASE',
            },
            
            # Métricas de Tarefa
            {
                'name': 'tasks_created_daily',
                'display_name': 'Tasks Created Daily',
                'description': 'Number of tasks created per day',
                'metric_type': 'COUNT',
                'entity_type': 'TASK',
            },
            {
                'name': 'tasks_completed_daily',
                'display_name': 'Tasks Completed Daily',
                'description': 'Number of tasks completed per day',
                'metric_type': 'COUNT',
                'entity_type': 'TASK',
            },
            {
                'name': 'tasks_by_status',
                'display_name': 'Tasks by Status',
                'description': 'Distribution of tasks by status',
                'metric_type': 'COUNT',
                'entity_type': 'TASK',
            },
            {
                'name': 'tasks_overdue',
                'display_name': 'Overdue Tasks',
                'description': 'Number of tasks that are past their due date',
                'metric_type': 'COUNT',
                'entity_type': 'TASK',
            },
            
            # Métricas de Observáveis
            {
                'name': 'observables_added_daily',
                'display_name': 'Observables Added Daily',
                'description': 'Number of observables added per day',
                'metric_type': 'COUNT',
                'entity_type': 'OBSERVABLE',
            },
            {
                'name': 'observables_by_type',
                'display_name': 'Observables by Type',
                'description': 'Distribution of observables by type',
                'metric_type': 'COUNT',
                'entity_type': 'OBSERVABLE',
            },
        ]
        
        # Contador de métricas criadas/atualizadas
        created_count = 0
        updated_count = 0
        
        # Processar cada métrica na lista
        for metric_data in default_metrics:
            metric, created = Metric.objects.update_or_create(
                name=metric_data['name'],
                defaults={
                    'display_name': metric_data['display_name'],
                    'description': metric_data['description'],
                    'metric_type': metric_data['metric_type'],
                    'entity_type': metric_data['entity_type'],
                    'calculation_query': metric_data.get('calculation_query', ''),
                }
            )
            
            if created:
                created_count += 1
            else:
                updated_count += 1
        
        self.stdout.write(self.style.SUCCESS(
            f'Inicialização concluída: {created_count} métricas criadas, {updated_count} métricas atualizadas'
        )) 