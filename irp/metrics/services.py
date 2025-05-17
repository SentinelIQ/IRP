from django.db.models import Count, Avg, Sum, Q, F
from django.utils import timezone
from datetime import timedelta
from .models import Metric, MetricSnapshot


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