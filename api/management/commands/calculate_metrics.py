from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import datetime, timedelta
from api.models import Metric, Organization
from api.services import MetricsService
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Calculates and stores snapshots for all metrics'

    def add_arguments(self, parser):
        parser.add_argument(
            '--date',
            type=str,
            help='Target date (YYYY-MM-DD). Defaults to yesterday.'
        )
        parser.add_argument(
            '--granularity',
            type=str,
            choices=['DAILY', 'WEEKLY', 'MONTHLY'],
            default='DAILY',
            help='Granularity of the metrics calculation.'
        )
        parser.add_argument(
            '--metric-id',
            type=int,
            help='Calculate only a specific metric by ID.'
        )
        parser.add_argument(
            '--organization-id',
            type=int,
            help='Calculate for a specific organization by ID.'
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force recalculation even if snapshots already exist.'
        )

    def handle(self, *args, **options):
        # Determine target date (default to yesterday)
        if options['date']:
            try:
                target_date = datetime.strptime(options['date'], '%Y-%m-%d').date()
            except ValueError:
                self.stderr.write(self.style.ERROR('Invalid date format. Use YYYY-MM-DD.'))
                return
        else:
            # Default to yesterday
            target_date = (timezone.now() - timedelta(days=1)).date()
        
        granularity = options['granularity']
        force = options['force']
        
        # Set end date based on granularity
        if granularity == 'DAILY':
            end_date = target_date + timedelta(days=1)
        elif granularity == 'WEEKLY':
            # End of week (target_date should be the start of the week)
            end_date = target_date + timedelta(days=7)
        elif granularity == 'MONTHLY':
            # End of month (target_date should be the start of the month)
            if target_date.month == 12:
                end_date = target_date.replace(year=target_date.year + 1, month=1, day=1)
            else:
                end_date = target_date.replace(month=target_date.month + 1, day=1)
        
        # Get metrics to calculate
        if options['metric_id']:
            metrics = Metric.objects.filter(metric_id=options['metric_id'])
            if not metrics.exists():
                self.stderr.write(self.style.ERROR(f'Metric with ID {options["metric_id"]} not found.'))
                return
        else:
            metrics = Metric.objects.all()
        
        # Get organizations
        if options['organization_id']:
            organizations = Organization.objects.filter(organization_id=options['organization_id'])
            if not organizations.exists():
                self.stderr.write(self.style.ERROR(f'Organization with ID {options["organization_id"]} not found.'))
                return
        else:
            organizations = Organization.objects.filter(is_active=True)
        
        metrics_count = metrics.count()
        orgs_count = organizations.count()
        self.stdout.write(self.style.SUCCESS(
            f'Starting metric calculation for {metrics_count} metrics across {orgs_count} organizations'
        ))
        self.stdout.write(f'Date: {target_date}, Granularity: {granularity}')
        
        # Track stats
        success_count = 0
        error_count = 0
        
        # Calculate for each organization and metric
        for org in organizations:
            for metric in metrics:
                try:
                    self.stdout.write(f'Calculating metric {metric.name} for {org.name}...')
                    
                    # Calculate the metric
                    metric_value = MetricsService.calculate_metric(
                        metric,
                        org,
                        target_date,
                        end_date,
                        granularity
                    )
                    
                    if metric_value is not None:
                        # Store the snapshot
                        MetricsService.store_metric_snapshot(
                            metric,
                            org,
                            target_date,
                            metric_value,
                            granularity
                        )
                        
                        success_count += 1
                        self.stdout.write(self.style.SUCCESS(
                            f'Successfully calculated {metric.name} for {org.name}: {metric_value}'
                        ))
                    else:
                        self.stdout.write(self.style.WARNING(
                            f'No value calculated for {metric.name} for {org.name}'
                        ))
                        error_count += 1
                        
                except Exception as e:
                    self.stderr.write(self.style.ERROR(
                        f'Error calculating {metric.name} for {org.name}: {str(e)}'
                    ))
                    logger.exception(f'Error calculating metric {metric.metric_id}')
                    error_count += 1
        
        # Summary
        self.stdout.write(self.style.SUCCESS(
            f'Finished metric calculation. Success: {success_count}, Errors: {error_count}'
        )) 