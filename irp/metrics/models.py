import uuid
from django.db import models
from django.contrib.auth.models import User


class Metric(models.Model):
    """
    Define métricas disponíveis para visualização em dashboards.
    """
    METRIC_TYPES = [
        ('COUNT', 'Count'),
        ('AVERAGE', 'Average'),
        ('SUM', 'Sum'),
        ('PERCENTAGE', 'Percentage'),
        ('CUSTOM', 'Custom'),
    ]
    
    metric_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100, unique=True)
    display_name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    metric_type = models.CharField(max_length=20, choices=METRIC_TYPES)
    entity_type = models.CharField(max_length=50)  # 'ALERT', 'CASE', 'TASK', etc.
    calculation_query = models.TextField(blank=True)  # SQL or query reference
    
    def __str__(self):
        return self.display_name


class MetricSnapshot(models.Model):
    """
    Armazena snapshots periódicos de métricas para visualização rápida.
    """
    snapshot_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    metric = models.ForeignKey(Metric, related_name='snapshots', on_delete=models.CASCADE)
    organization = models.ForeignKey('accounts.Organization', related_name='metric_snapshots', on_delete=models.CASCADE)
    date = models.DateField()
    granularity = models.CharField(max_length=10)  # 'DAILY', 'WEEKLY', 'MONTHLY'
    dimensions = models.JSONField(default=dict, blank=True)  # Dimension values for the metric
    value = models.DecimalField(max_digits=15, decimal_places=2)
    
    class Meta:
        indexes = [
            models.Index(fields=['metric', 'organization', 'date']),
            models.Index(fields=['date']),
            models.Index(fields=['organization']),
        ]


class Dashboard(models.Model):
    """
    Define dashboards que podem ser visualizados pelos usuários.
    """
    dashboard_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    organization = models.ForeignKey('accounts.Organization', related_name='dashboards', 
                                    on_delete=models.CASCADE, null=True, blank=True)
    is_system = models.BooleanField(default=False)  # System dashboards cannot be deleted
    layout = models.JSONField(default=dict, blank=True)  # Layout configuration
    created_by = models.ForeignKey(User, related_name='created_dashboards', 
                                 on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name
    
    class Meta:
        unique_together = ('name', 'organization')
        indexes = [
            models.Index(fields=['organization']),
            models.Index(fields=['is_system']),
        ]


class DashboardWidget(models.Model):
    """
    Define widgets que compõem um dashboard.
    """
    WIDGET_TYPES = [
        ('LINE_CHART', 'Line Chart'),
        ('BAR_CHART', 'Bar Chart'),
        ('PIE_CHART', 'Pie Chart'),
        ('TABLE', 'Table'),
        ('KPI_CARD', 'KPI Card'),
        ('COUNTER', 'Counter'),
        ('GAUGE', 'Gauge'),
    ]
    
    widget_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    dashboard = models.ForeignKey(Dashboard, related_name='widgets', on_delete=models.CASCADE)
    title = models.CharField(max_length=100)
    widget_type = models.CharField(max_length=20, choices=WIDGET_TYPES)
    metric = models.ForeignKey(Metric, related_name='widgets', on_delete=models.CASCADE)
    config = models.JSONField(default=dict)  # Widget-specific configuration
    position = models.JSONField(default=dict)  # Position in the dashboard grid
    
    def __str__(self):
        return f"{self.title} ({self.get_widget_type_display()})" 