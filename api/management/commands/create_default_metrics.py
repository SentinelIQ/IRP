from django.core.management.base import BaseCommand
from api.models import Metric

class Command(BaseCommand):
    help = 'Creates default metrics required by the platform'

    def handle(self, *args, **options):
        default_metrics = [
            {
                'name': 'alert_count',
                'display_name': 'Alert Count',
                'description': 'The number of alerts created in a time period',
                'metric_type': 'COUNT',
                'entity_type': 'ALERT',
                'calculation_query': 'SELECT COUNT(*) FROM api_alert WHERE organization_id = :org_id AND created_at >= :start_date AND created_at < :end_date AND is_deleted = FALSE'
            },
            {
                'name': 'alert_severity_distribution',
                'display_name': 'Alert Severity Distribution',
                'description': 'Distribution of alerts by severity level',
                'metric_type': 'COUNT',
                'entity_type': 'ALERT',
                'calculation_query': 'SELECT severity_id, COUNT(*) FROM api_alert WHERE organization_id = :org_id AND created_at >= :start_date AND created_at < :end_date AND is_deleted = FALSE GROUP BY severity_id'
            },
            {
                'name': 'case_count',
                'display_name': 'Case Count',
                'description': 'The number of cases created in a time period',
                'metric_type': 'COUNT',
                'entity_type': 'CASE',
                'calculation_query': 'SELECT COUNT(*) FROM api_case WHERE organization_id = :org_id AND created_at >= :start_date AND created_at < :end_date'
            },
            {
                'name': 'case_severity_distribution',
                'display_name': 'Case Severity Distribution',
                'description': 'Distribution of cases by severity level',
                'metric_type': 'COUNT',
                'entity_type': 'CASE',
                'calculation_query': 'SELECT severity_id, COUNT(*) FROM api_case WHERE organization_id = :org_id AND created_at >= :start_date AND created_at < :end_date GROUP BY severity_id'
            },
            {
                'name': 'case_status_distribution',
                'display_name': 'Case Status Distribution',
                'description': 'Distribution of cases by status',
                'metric_type': 'COUNT',
                'entity_type': 'CASE',
                'calculation_query': 'SELECT status_id, COUNT(*) FROM api_case WHERE organization_id = :org_id AND created_at >= :start_date AND created_at < :end_date GROUP BY status_id'
            },
            {
                'name': 'case_resolution_time',
                'display_name': 'Case Resolution Time',
                'description': 'Average time to resolve cases (in hours)',
                'metric_type': 'AVERAGE',
                'entity_type': 'CASE',
                'calculation_query': 'SELECT AVG(EXTRACT(EPOCH FROM (closed_at - created_at))/3600) FROM api_case WHERE organization_id = :org_id AND closed_at IS NOT NULL AND closed_at >= :start_date AND closed_at < :end_date'
            },
            {
                'name': 'task_completion_rate',
                'display_name': 'Task Completion Rate',
                'description': 'Percentage of tasks completed vs total tasks',
                'metric_type': 'PERCENTAGE',
                'entity_type': 'TASK',
                'calculation_query': 'SELECT (COUNT(*) FILTER (WHERE t.status_id = (SELECT id FROM api_taskstatus WHERE name = \'Completed\')) * 100.0 / NULLIF(COUNT(*), 0)) FROM api_task t JOIN api_case c ON t.case_id = c.case_id WHERE c.organization_id = :org_id AND t.created_at >= :start_date AND t.created_at < :end_date'
            },
            {
                'name': 'assignee_workload',
                'display_name': 'Assignee Workload',
                'description': 'Number of open cases per assignee',
                'metric_type': 'COUNT',
                'entity_type': 'CASE',
                'calculation_query': 'SELECT assignee_id, COUNT(*) FROM api_case WHERE organization_id = :org_id AND status_id NOT IN (SELECT id FROM api_casestatus WHERE is_terminal_status = TRUE) GROUP BY assignee_id'
            },
            {
                'name': 'mitre_technique_frequency',
                'display_name': 'MITRE Technique Frequency',
                'description': 'Most commonly observed MITRE ATT&CK techniques',
                'metric_type': 'COUNT',
                'entity_type': 'CASE',
                'calculation_query': 'SELECT technique_id, COUNT(*) FROM api_casemitretechnique JOIN api_case ON api_casemitretechnique.case_id = api_case.case_id WHERE api_case.organization_id = :org_id AND api_casemitretechnique.linked_at >= :start_date AND api_casemitretechnique.linked_at < :end_date GROUP BY technique_id ORDER BY COUNT(*) DESC LIMIT 10'
            },
            {
                'name': 'observable_type_distribution',
                'display_name': 'Observable Type Distribution',
                'description': 'Distribution of observables by type',
                'metric_type': 'COUNT',
                'entity_type': 'OBSERVABLE',
                'calculation_query': 'SELECT type_id, COUNT(*) FROM api_observable JOIN api_caseobservable ON api_observable.observable_id = api_caseobservable.observable_id JOIN api_case ON api_caseobservable.case_id = api_case.case_id WHERE api_case.organization_id = :org_id AND api_caseobservable.sighted_at >= :start_date AND api_caseobservable.sighted_at < :end_date GROUP BY type_id'
            }
        ]
        
        count_created = 0
        count_updated = 0
        
        for metric_data in default_metrics:
            metric_name = metric_data['name']
            metric, created = Metric.objects.update_or_create(
                name=metric_name,
                defaults={
                    'display_name': metric_data['display_name'],
                    'description': metric_data['description'],
                    'metric_type': metric_data['metric_type'],
                    'entity_type': metric_data['entity_type'],
                    'calculation_query': metric_data['calculation_query']
                }
            )
            
            if created:
                count_created += 1
                self.stdout.write(self.style.SUCCESS(f'Created metric: {metric_name}'))
            else:
                count_updated += 1
                self.stdout.write(self.style.WARNING(f'Updated metric: {metric_name}'))
        
        if count_created > 0 or count_updated > 0:
            self.stdout.write(self.style.SUCCESS(
                f'Successfully created {count_created} and updated {count_updated} metrics'
            ))
        else:
            self.stdout.write(self.style.WARNING('No metrics created or updated')) 