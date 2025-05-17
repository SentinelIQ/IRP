from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    MetricViewSet, MetricSnapshotViewSet,
    DashboardViewSet, DashboardWidgetViewSet,
    calculate_metrics, dashboard_stats
)

router = DefaultRouter()
router.register(r'metrics', MetricViewSet)
router.register(r'metric-snapshots', MetricSnapshotViewSet, basename='metric-snapshot')
router.register(r'dashboards', DashboardViewSet, basename='dashboard')
router.register(r'dashboard-widgets', DashboardWidgetViewSet, basename='dashboard-widget')

urlpatterns = [
    path('', include(router.urls)),
    path('calculate/', calculate_metrics, name='calculate_metrics'),
    path('dashboard-stats/', dashboard_stats, name='dashboard-stats'),
] 