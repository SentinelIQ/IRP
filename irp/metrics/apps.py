from django.apps import AppConfig


class MetricsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'irp.metrics'
    verbose_name = 'Métricas e Dashboards' 