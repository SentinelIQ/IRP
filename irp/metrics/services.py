from django.db.models import Count, Avg, Sum, Q, F
from django.utils import timezone
from datetime import timedelta
from .models import Metric, MetricSnapshot
from datetime import datetime
from decimal import Decimal

from .models import Dashboard, DashboardWidget
from irp.alerts.models import Alert, AlertStatus, AlertSeverity
from irp.cases.models import Case, CaseStatus, CaseSeverity, Task, TaskStatus
from irp.observables.models import Observable, ObservableType
from irp.timeline.models import TimelineEvent


class MetricsService:
    """
    Service class for metric operations.
    """
    
    @staticmethod
    def get_metric_data(metric, organization, start_date, end_date, granularity='DAILY', dimensions=None):
        """
        Get metric data, either from snapshots or calculated on-the-fly.
        
        Args:
            metric: Metric object
            organization: Organization object
            start_date: Date to start from
            end_date: Date to end at
            granularity: 'DAILY', 'WEEKLY', or 'MONTHLY'
            dimensions: Dictionary of dimension filters
            
        Returns:
            Dictionary with metric data
        """
        # Try to get data from snapshots first
        snapshots = MetricSnapshot.objects.filter(
            metric=metric,
            organization=organization,
            date__gte=start_date,
            date__lte=end_date,
            granularity=granularity
        )
        
        # Apply dimension filters if provided
        if dimensions:
            for key, value in dimensions.items():
                snapshots = snapshots.filter(dimensions__contains={key: value})
        
        # If we have snapshots, return them
        if snapshots.exists():
            result = {
                'metric_id': metric.metric_id,
                'metric_name': metric.display_name,
                'description': metric.description,
                'type': metric.metric_type,
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat(),
                'granularity': granularity,
                'data_points': []
            }
            
            for snapshot in snapshots:
                result['data_points'].append({
                    'date': snapshot.date.isoformat(),
                    'value': float(snapshot.value),
                    'dimensions': snapshot.dimensions
                })
            
            return result
        
        # Otherwise, calculate on the fly
        return MetricsService._calculate_metric_data(
            metric=metric,
            organization=organization,
            start_date=start_date,
            end_date=end_date,
            granularity=granularity,
            dimensions=dimensions
        )
    
    @staticmethod
    def _calculate_metric_data(metric, organization, start_date, end_date, granularity, dimensions):
        """
        Calculate metric data on-the-fly.
        """
        result = {
            'metric_id': metric.metric_id,
            'metric_name': metric.display_name,
            'description': metric.description,
            'type': metric.metric_type,
            'start_date': start_date.isoformat(),
            'end_date': end_date.isoformat(),
            'granularity': granularity,
            'data_points': []
        }
        
        # Implement calculation logic based on metric entity_type
        # This is a simplified implementation
        if metric.entity_type == 'ALERT':
            from irp.alerts.models import Alert
            
            alerts = Alert.objects.filter(
                organization=organization,
                created_at__date__gte=start_date,
                created_at__date__lte=end_date
            )
            
            # If we're counting alerts by severity
            if metric.name == 'alerts_by_severity':
                data = alerts.values('severity__name').annotate(count=Count('alert_id'))
                for item in data:
                    result['data_points'].append({
                        'dimension': item['severity__name'],
                        'value': item['count']
                    })
            
            # Or alerts over time
            elif metric.name == 'alerts_created_over_time':
                # Group by day/week/month based on granularity
                if granularity == 'DAILY':
                    data = alerts.values('created_at__date').annotate(count=Count('alert_id'))
                    for item in data:
                        result['data_points'].append({
                            'date': item['created_at__date'].isoformat(),
                            'value': item['count']
                        })
                elif granularity == 'WEEKLY':
                    # Implementation would depend on DB backend
                    pass
                elif granularity == 'MONTHLY':
                    # Implementation would depend on DB backend
                    pass
        
        elif metric.entity_type == 'CASE':
            from irp.cases.models import Case
            
            cases = Case.objects.filter(
                organization=organization,
                created_at__date__gte=start_date,
                created_at__date__lte=end_date
            )
            
            # Similar logic for cases as for alerts
            if metric.name == 'cases_by_severity':
                data = cases.values('severity__name').annotate(count=Count('case_id'))
                for item in data:
                    result['data_points'].append({
                        'dimension': item['severity__name'],
                        'value': item['count']
                    })
        
        # Add more entity_types and metrics as needed
        
        return result
    
    @staticmethod
    def calculate_and_save_metrics(organization, period_type='daily'):
        """
        Calculate and save metrics for the specified period.
        
        Args:
            organization: Organization to calculate metrics for
            period_type: 'daily', 'weekly', or 'monthly'
        """
        today = timezone.now().date()
        
        if period_type == 'daily':
            start_date = today - timedelta(days=1)
            granularity = 'DAILY'
        elif period_type == 'weekly':
            start_date = today - timedelta(days=7)
            granularity = 'WEEKLY'
        elif period_type == 'monthly':
            start_date = today - timedelta(days=30)
            granularity = 'MONTHLY'
        else:
            raise ValueError(f"Invalid period_type: {period_type}")
        
        # Get all metrics
        metrics = Metric.objects.all()
        
        for metric in metrics:
            # Calculate metric data
            metric_data = MetricsService._calculate_metric_data(
                metric=metric,
                organization=organization,
                start_date=start_date,
                end_date=today,
                granularity=granularity,
                dimensions=None
            )
            
            # Save snapshot for each data point
            for data_point in metric_data['data_points']:
                MetricSnapshot.objects.create(
                    metric=metric,
                    organization=organization,
                    date=today,
                    granularity=granularity,
                    dimensions=data_point.get('dimensions', {}),
                    value=data_point['value']
                ) 

    @classmethod
    def collect_metrics(cls, organization, date=None, recalculate=False):
        """
        Coleta métricas para a organização especificada e data.
        
        Args:
            organization: Organização para coletar métricas
            date: Data para coletar métricas (padrão: hoje)
            recalculate: Se deve recalcular métricas mesmo se já existirem
            
        Returns:
            dict: Resumo das métricas coletadas
        """
        if date is None:
            date = timezone.now().date()
            
        metrics = Metric.objects.all()
        summary = {
            'organization': organization.name,
            'date': date,
            'metrics_collected': 0,
            'metrics_updated': 0,
            'metric_details': []
        }
        
        for metric in metrics:
            collected = cls._collect_metric(metric, organization, date, recalculate)
            
            if collected:
                summary['metrics_collected'] += len(collected.get('created', []))
                summary['metrics_updated'] += len(collected.get('updated', []))
                summary['metric_details'].append({
                    'metric_name': metric.name,
                    'values_created': len(collected.get('created', [])),
                    'values_updated': len(collected.get('updated', []))
                })
                
        return summary
    
    @classmethod
    def _collect_metric(cls, metric, organization, date, recalculate=False):
        """
        Coleta uma métrica específica para a organização e data.
        
        Args:
            metric: Objeto Metric para coletar
            organization: Organização para coletar métricas
            date: Data para coletar métricas
            recalculate: Se deve recalcular métricas mesmo se já existirem
            
        Returns:
            dict: Detalhes das métricas coletadas
        """
        # Verificar se já existe snapshot para esta data e métrica
        existing = MetricSnapshot.objects.filter(
            metric=metric,
            organization=organization,
            date=date,
            granularity='DAILY'
        )
        
        if existing.exists() and not recalculate:
            return {'message': 'Snapshots already exist', 'created': [], 'updated': []}
        
        # Calcular métricas com base no tipo de entidade
        created = []
        updated = []
        
        if metric.entity_type == 'ALERT':
            metrics_data = cls._calculate_alert_metrics(metric, organization, date)
        elif metric.entity_type == 'CASE':
            metrics_data = cls._calculate_case_metrics(metric, organization, date)
        elif metric.entity_type == 'TASK':
            metrics_data = cls._calculate_task_metrics(metric, organization, date)
        elif metric.entity_type == 'OBSERVABLE':
            metrics_data = cls._calculate_observable_metrics(metric, organization, date)
        else:
            metrics_data = []
            
        # Salvar snapshots
        for data in metrics_data:
            dimensions = data.get('dimensions', {})
            value = data.get('value', 0)
            
            snapshot, created_new = MetricSnapshot.objects.update_or_create(
                metric=metric,
                organization=organization,
                date=date,
                granularity='DAILY',
                dimensions=dimensions,
                defaults={'value': value}
            )
            
            if created_new:
                created.append(snapshot.snapshot_id)
            else:
                updated.append(snapshot.snapshot_id)
                
        return {
            'created': created,
            'updated': updated
        }
    
    @classmethod
    def _calculate_alert_metrics(cls, metric, organization, date):
        """Calcula métricas relacionadas a alertas"""
        metrics_data = []
        
        # Data range para métricas diárias
        start_date = datetime.combine(date, datetime.min.time())
        end_date = datetime.combine(date, datetime.max.time())
        
        if metric.name == 'alerts_created_daily':
            # Total de alertas criados no dia
            count = Alert.objects.filter(
                organization=organization,
                created_at__gte=start_date,
                created_at__lte=end_date
            ).count()
            
            metrics_data.append({
                'dimensions': {},
                'value': count
            })
            
        elif metric.name == 'alerts_by_severity':
            # Alertas por severidade
            severities = AlertSeverity.objects.all()
            
            for severity in severities:
                count = Alert.objects.filter(
                    organization=organization,
                    severity=severity,
                    created_at__gte=start_date,
                    created_at__lte=end_date
                ).count()
                
                metrics_data.append({
                    'dimensions': {'severity': severity.name},
                    'value': count
                })
                
        elif metric.name == 'alerts_by_status':
            # Alertas por status
            statuses = AlertStatus.objects.all()
            
            for status in statuses:
                count = Alert.objects.filter(
                    organization=organization,
                    status=status,
                    created_at__gte=start_date,
                    created_at__lte=end_date
                ).count()
                
                metrics_data.append({
                    'dimensions': {'status': status.name},
                    'value': count
                })
                
        elif metric.name == 'alerts_triage_time_avg':
            # Tempo médio de triagem (de New para Acknowledged ou Escalated)
            from django.db.models.functions import Extract
            from django.db.models import ExpressionWrapper, DurationField, F
            
            alerts_with_status_change = Alert.objects.filter(
                organization=organization,
                created_at__gte=start_date,
                created_at__lte=end_date,
                status__name__in=['Acknowledged', 'Escalated']
            ).annotate(
                triage_time=ExpressionWrapper(
                    F('updated_at') - F('created_at'),
                    output_field=DurationField()
                )
            )
            
            # Converter para minutos
            if alerts_with_status_change.exists():
                avg_minutes = alerts_with_status_change.aggregate(
                    avg_triage_minutes=Avg(Extract('triage_time', 'epoch') / 60)
                )['avg_triage_minutes'] or 0
                
                metrics_data.append({
                    'dimensions': {},
                    'value': round(Decimal(avg_minutes), 2)
                })
            else:
                metrics_data.append({
                    'dimensions': {},
                    'value': 0
                })
                
        return metrics_data
    
    @classmethod
    def _calculate_case_metrics(cls, metric, organization, date):
        """Calcula métricas relacionadas a casos"""
        metrics_data = []
        
        # Data range para métricas diárias
        start_date = datetime.combine(date, datetime.min.time())
        end_date = datetime.combine(date, datetime.max.time())
        
        if metric.name == 'cases_created_daily':
            # Total de casos criados no dia
            count = Case.objects.filter(
                organization=organization,
                created_at__gte=start_date,
                created_at__lte=end_date
            ).count()
            
            metrics_data.append({
                'dimensions': {},
                'value': count
            })
            
        elif metric.name == 'cases_closed_daily':
            # Total de casos fechados no dia
            closed_status = CaseStatus.objects.filter(name__in=['Closed', 'Resolved']).values_list('id', flat=True)
            
            count = Case.objects.filter(
                organization=organization,
                status_id__in=closed_status,
                updated_at__gte=start_date,
                updated_at__lte=end_date
            ).count()
            
            metrics_data.append({
                'dimensions': {},
                'value': count
            })
            
        elif metric.name == 'cases_by_severity':
            # Casos por severidade
            severities = CaseSeverity.objects.all()
            
            for severity in severities:
                count = Case.objects.filter(
                    organization=organization,
                    severity=severity,
                    created_at__lte=end_date  # Todos os casos até a data atual com esta severidade
                ).count()
                
                metrics_data.append({
                    'dimensions': {'severity': severity.name},
                    'value': count
                })
                
        elif metric.name == 'cases_by_status':
            # Casos por status
            statuses = CaseStatus.objects.all()
            
            for status in statuses:
                count = Case.objects.filter(
                    organization=organization,
                    status=status,
                    created_at__lte=end_date  # Todos os casos até a data atual com este status
                ).count()
                
                metrics_data.append({
                    'dimensions': {'status': status.name},
                    'value': count
                })
                
        elif metric.name == 'cases_resolution_time_avg':
            # Tempo médio de resolução para casos fechados no período
            from django.db.models.functions import Extract
            from django.db.models import ExpressionWrapper, DurationField, F
            
            closed_status = CaseStatus.objects.filter(name__in=['Closed', 'Resolved']).values_list('id', flat=True)
            
            closed_cases = Case.objects.filter(
                organization=organization,
                status_id__in=closed_status,
                updated_at__gte=start_date,
                updated_at__lte=end_date
            ).annotate(
                resolution_time=ExpressionWrapper(
                    F('updated_at') - F('created_at'),
                    output_field=DurationField()
                )
            )
            
            # Converter para horas
            if closed_cases.exists():
                avg_hours = closed_cases.aggregate(
                    avg_hours=Avg(Extract('resolution_time', 'epoch') / 3600)
                )['avg_hours'] or 0
                
                metrics_data.append({
                    'dimensions': {},
                    'value': round(Decimal(avg_hours), 2)
                })
            else:
                metrics_data.append({
                    'dimensions': {},
                    'value': 0
                })
                
        return metrics_data
    
    @classmethod
    def _calculate_task_metrics(cls, metric, organization, date):
        """Calcula métricas relacionadas a tarefas"""
        metrics_data = []
        
        # Data range para métricas diárias
        start_date = datetime.combine(date, datetime.min.time())
        end_date = datetime.combine(date, datetime.max.time())
        
        if metric.name == 'tasks_created_daily':
            # Total de tarefas criadas no dia
            count = Task.objects.filter(
                case__organization=organization,
                created_at__gte=start_date,
                created_at__lte=end_date
            ).count()
            
            metrics_data.append({
                'dimensions': {},
                'value': count
            })
            
        elif metric.name == 'tasks_completed_daily':
            # Total de tarefas completadas no dia
            completed_status = TaskStatus.objects.filter(name__in=['Done', 'Completed']).values_list('id', flat=True)
            
            count = Task.objects.filter(
                case__organization=organization,
                status_id__in=completed_status,
                updated_at__gte=start_date,
                updated_at__lte=end_date
            ).count()
            
            metrics_data.append({
                'dimensions': {},
                'value': count
            })
            
        elif metric.name == 'tasks_by_status':
            # Tarefas por status
            statuses = TaskStatus.objects.all()
            
            for status in statuses:
                count = Task.objects.filter(
                    case__organization=organization,
                    status=status,
                    created_at__lte=end_date  # Todas as tarefas até a data atual com este status
                ).count()
                
                metrics_data.append({
                    'dimensions': {'status': status.name},
                    'value': count
                })
                
        elif metric.name == 'tasks_overdue':
            # Tarefas atrasadas
            today = timezone.now().date()
            
            not_completed_status = TaskStatus.objects.exclude(
                name__in=['Done', 'Completed']
            ).values_list('id', flat=True)
            
            count = Task.objects.filter(
                case__organization=organization,
                status_id__in=not_completed_status,
                due_date__lt=today
            ).count()
            
            metrics_data.append({
                'dimensions': {},
                'value': count
            })
                
        return metrics_data
    
    @classmethod
    def _calculate_observable_metrics(cls, metric, organization, date):
        """Calcula métricas relacionadas a observáveis"""
        metrics_data = []
        
        # Data range para métricas diárias
        start_date = datetime.combine(date, datetime.min.time())
        end_date = datetime.combine(date, datetime.max.time())
        
        if metric.name == 'observables_added_daily':
            # Total de observáveis adicionados no dia
            count = Observable.objects.filter(
                case__organization=organization,
                created_at__gte=start_date,
                created_at__lte=end_date
            ).count()
            
            metrics_data.append({
                'dimensions': {},
                'value': count
            })
            
        elif metric.name == 'observables_by_type':
            # Observáveis por tipo
            observable_types = ObservableType.objects.all()
            
            for obs_type in observable_types:
                count = Observable.objects.filter(
                    case__organization=organization,
                    type=obs_type,
                    created_at__lte=end_date  # Todos os observáveis até a data atual com este tipo
                ).count()
                
                metrics_data.append({
                    'dimensions': {'type': obs_type.name},
                    'value': count
                })
                
        return metrics_data
    
    @classmethod
    def get_dashboard_data(cls, dashboard, organization, start_date=None, end_date=None):
        """
        Recupera dados para um dashboard específico.
        
        Args:
            dashboard: Dashboard para recuperar dados
            organization: Organização para filtrar dados
            start_date: Data inicial para filtro (opcional)
            end_date: Data final para filtro (opcional)
            
        Returns:
            dict: Dados do dashboard com valores para cada widget
        """
        if start_date is None:
            start_date = (timezone.now() - timedelta(days=30)).date()
            
        if end_date is None:
            end_date = timezone.now().date()
            
        widgets = DashboardWidget.objects.filter(dashboard=dashboard)
        widget_data = []
        
        for widget in widgets:
            metric = widget.metric
            
            # Buscar snapshots da métrica
            snapshots = MetricSnapshot.objects.filter(
                metric=metric,
                organization=organization,
                date__gte=start_date,
                date__lte=end_date
            ).order_by('date')
            
            # Formatar dados de acordo com o tipo de widget
            if widget.widget_type in ['LINE_CHART', 'BAR_CHART']:
                # Para gráficos de linha ou barra, agrupar por dimensão
                data_by_dimension = {}
                
                for snapshot in snapshots:
                    key = tuple(sorted(snapshot.dimensions.items())) if snapshot.dimensions else ('default',)
                    
                    if key not in data_by_dimension:
                        label = ", ".join([f"{k}: {v}" for k, v in key]) if key != ('default',) else 'Total'
                        data_by_dimension[key] = {
                            'label': label,
                            'data': []
                        }
                        
                    data_by_dimension[key]['data'].append({
                        'x': snapshot.date.isoformat(),
                        'y': float(snapshot.value)
                    })
                
                widget_data.append({
                    'widget_id': str(widget.widget_id),
                    'title': widget.title,
                    'type': widget.widget_type,
                    'config': widget.config,
                    'position': widget.position,
                    'series': list(data_by_dimension.values())
                })
                
            elif widget.widget_type in ['PIE_CHART']:
                # Para gráficos de pizza, pegar o snapshot mais recente e agrupar por dimensão
                latest_date = snapshots.values('date').order_by('-date').first()
                
                if latest_date:
                    latest_snapshots = snapshots.filter(date=latest_date['date'])
                    pie_data = []
                    
                    for snapshot in latest_snapshots:
                        label = ", ".join([f"{k}: {v}" for k, v in snapshot.dimensions.items()]) if snapshot.dimensions else 'Total'
                        pie_data.append({
                            'label': label,
                            'value': float(snapshot.value)
                        })
                    
                    widget_data.append({
                        'widget_id': str(widget.widget_id),
                        'title': widget.title,
                        'type': widget.widget_type,
                        'config': widget.config,
                        'position': widget.position,
                        'data': pie_data
                    })
                    
            elif widget.widget_type in ['KPI_CARD', 'COUNTER', 'GAUGE']:
                # Para cartões KPI, contadores e medidores, pegar o valor mais recente
                latest_snapshot = snapshots.order_by('-date').first()
                
                if latest_snapshot:
                    widget_data.append({
                        'widget_id': str(widget.widget_id),
                        'title': widget.title,
                        'type': widget.widget_type,
                        'config': widget.config,
                        'position': widget.position,
                        'value': float(latest_snapshot.value),
                        'date': latest_snapshot.date.isoformat()
                    })
                    
            elif widget.widget_type in ['TABLE']:
                # Para tabelas, agrupar por data e dimensão
                table_data = []
                
                for snapshot in snapshots:
                    row = {'date': snapshot.date.isoformat(), 'value': float(snapshot.value)}
                    row.update(snapshot.dimensions)
                    table_data.append(row)
                
                widget_data.append({
                    'widget_id': str(widget.widget_id),
                    'title': widget.title,
                    'type': widget.widget_type,
                    'config': widget.config,
                    'position': widget.position,
                    'data': table_data
                })
        
        return {
            'dashboard_id': str(dashboard.dashboard_id),
            'name': dashboard.name,
            'description': dashboard.description,
            'widgets': widget_data,
            'date_range': {
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat()
            }
        }
    
    @classmethod
    def generate_default_dashboards(cls, organization):
        """
        Gera dashboards padrão para a organização.
        
        Args:
            organization: Organização para criar dashboards
            
        Returns:
            list: Dashboards criados
        """
        # Verificar se já existem dashboards para a organização
        existing_dashboards = Dashboard.objects.filter(organization=organization)
        
        if existing_dashboards.exists():
            return list(existing_dashboards)
            
        # Criar dashboard de alertas
        alerts_dashboard = Dashboard.objects.create(
            name="Alert Metrics",
            description="Dashboard showing metrics about alerts and alert processing",
            organization=organization,
            layout={
                'columns': 24,
                'rowHeight': 50
            }
        )
        
        # Criar dashboard de casos
        cases_dashboard = Dashboard.objects.create(
            name="Case Metrics",
            description="Dashboard showing metrics about cases and case management",
            organization=organization,
            layout={
                'columns': 24,
                'rowHeight': 50
            }
        )
        
        # Criar dashboard geral (overview)
        overview_dashboard = Dashboard.objects.create(
            name="IR Platform Overview",
            description="Overview dashboard showing key metrics across the platform",
            organization=organization,
            layout={
                'columns': 24,
                'rowHeight': 50
            }
        )
        
        # Adicionar widgets aos dashboards
        cls._add_default_widgets(alerts_dashboard, organization)
        cls._add_default_widgets(cases_dashboard, organization)
        cls._add_default_widgets(overview_dashboard, organization)
        
        return [alerts_dashboard, cases_dashboard, overview_dashboard]
    
    @classmethod
    def _add_default_widgets(cls, dashboard, organization):
        """Adiciona widgets padrão ao dashboard"""
        # Implementar de acordo com as métricas e dashboards desejados
        pass 