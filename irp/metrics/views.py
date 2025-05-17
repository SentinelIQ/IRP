from django.db import models
from rest_framework import viewsets, permissions, status, exceptions
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.response import Response

from .models import Metric, MetricSnapshot, Dashboard, DashboardWidget
from .serializers import (
    MetricSerializer, MetricSnapshotSerializer,
    DashboardSerializer, DashboardWidgetSerializer
)
from irp.common.permissions import HasRolePermission, has_permission

from django.shortcuts import render, get_object_or_404
from django.db.models import Count, Avg, Sum, F, Q
from django.utils import timezone
from datetime import timedelta

from irp.cases.models import Case
from irp.alerts.models import Alert
from irp.observables.models import Observable

from irp.common.audit import audit_action


class MetricViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for listing and retrieving metrics.
    Metrics are system-defined and cannot be modified via API.
    """
    queryset = Metric.objects.all()
    serializer_class = MetricSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    @audit_action(entity_type='METRIC', action_type='VIEW')
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

    @action(detail=True, methods=['get'])
    @audit_action(entity_type='METRIC', action_type='GET_DATA')
    def data(self, request, pk=None):
        """
        Get data for a specific metric over a time period.
        """
        metric = self.get_object()
        
        # Get parameters
        organization = request.user.profile.organization
        if not organization:
            return Response(
                {"error": "User not associated with an organization"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Parse date parameters
            end_date = request.query_params.get('end_date')
            if not end_date:
                end_date = timezone.now().date()
            else:
                end_date = timezone.datetime.strptime(end_date, '%Y-%m-%d').date()
            
            start_date = request.query_params.get('start_date')
            if not start_date:
                # Default to 30 days before end_date
                start_date = end_date - timedelta(days=30)
            else:
                start_date = timezone.datetime.strptime(start_date, '%Y-%m-%d').date()
            
            # Get granularity (daily, weekly, monthly)
            granularity = request.query_params.get('granularity', 'DAILY')
            if granularity not in ['DAILY', 'WEEKLY', 'MONTHLY']:
                granularity = 'DAILY'
            
            # Parse dimensions
            dimensions = {}
            for key, value in request.query_params.items():
                if key.startswith('dim_'):
                    dimension_name = key[4:]  # Remove 'dim_' prefix
                    dimensions[dimension_name] = value
            
            # Get metric data
            metric_data = MetricsService.get_metric_data(
                metric=metric,
                organization=organization,
                start_date=start_date,
                end_date=end_date,
                granularity=granularity,
                dimensions=dimensions
            )
            
            return Response(metric_data)
            
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class MetricSnapshotViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for retrieving metric snapshots
    """
    serializer_class = MetricSnapshotSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    @audit_action(entity_type='METRIC_SNAPSHOT', action_type='VIEW')
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

    def get_queryset(self):
        user = self.request.user
        if not hasattr(user, 'profile') or not user.profile.organization:
            return MetricSnapshot.objects.none()
        
        organization = user.profile.organization
        
        # Filter parameters
        metric_id = self.request.query_params.get('metric_id')
        date_from = self.request.query_params.get('date_from')
        date_to = self.request.query_params.get('date_to')
        granularity = self.request.query_params.get('granularity')
        
        queryset = MetricSnapshot.objects.filter(organization=organization)
        
        if metric_id:
            queryset = queryset.filter(metric_id=metric_id)
        
        if date_from:
            try:
                date_from = timezone.datetime.strptime(date_from, '%Y-%m-%d').date()
                queryset = queryset.filter(date__gte=date_from)
            except ValueError:
                pass
        
        if date_to:
            try:
                date_to = timezone.datetime.strptime(date_to, '%Y-%m-%d').date()
                queryset = queryset.filter(date__lte=date_to)
            except ValueError:
                pass
        
        if granularity:
            queryset = queryset.filter(granularity=granularity)
        
        return queryset.order_by('-date')


class DashboardViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing dashboards
    """
    serializer_class = DashboardSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    @audit_action(entity_type='DASHBOARD', action_type='CREATE')
    def perform_create(self, serializer):
        user = self.request.user
        serializer.save(
            organization=user.profile.organization,
            created_by=user
        )
    
    @audit_action(entity_type='DASHBOARD', action_type='UPDATE')
    def perform_update(self, serializer):
        serializer.save()
    
    @audit_action(entity_type='DASHBOARD', action_type='DELETE')
    def perform_destroy(self, instance):
        # Prevent deleting system dashboards
        if instance.is_system:
            raise exceptions.PermissionDenied("Cannot delete system dashboards")
        instance.delete()
    
    @audit_action(entity_type='DASHBOARD', action_type='VIEW')
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

    def get_queryset(self):
        user = self.request.user
        if not hasattr(user, 'profile') or not user.profile.organization:
            return Dashboard.objects.none()
        
        organization = user.profile.organization
        
        # Return dashboards for the user's organization and system dashboards
        return Dashboard.objects.filter(
            models.Q(organization=organization) | 
            models.Q(is_system=True)
        )


class DashboardWidgetViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing dashboard widgets
    """
    serializer_class = DashboardWidgetSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    @audit_action(entity_type='DASHBOARD_WIDGET', action_type='CREATE')
    def perform_create(self, serializer):
        dashboard = serializer.validated_data.get('dashboard')
        user = self.request.user
        organization = user.profile.organization
        
        # Verify user has access to the dashboard
        if not dashboard.is_system and dashboard.organization != organization:
            raise exceptions.PermissionDenied(
                "You don't have permission to modify this dashboard"
            )
        
        serializer.save()
    
    @audit_action(entity_type='DASHBOARD_WIDGET', action_type='UPDATE')
    def perform_update(self, serializer):
        serializer.save()
    
    @audit_action(entity_type='DASHBOARD_WIDGET', action_type='DELETE')
    def perform_destroy(self, instance):
        # Prevent deleting widgets from system dashboards
        if instance.dashboard.is_system:
            raise exceptions.PermissionDenied("Cannot modify system dashboards")
        instance.delete()
    
    @audit_action(entity_type='DASHBOARD_WIDGET', action_type='VIEW')
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

    def get_queryset(self):
        user = self.request.user
        if not hasattr(user, 'profile') or not user.profile.organization:
            return DashboardWidget.objects.none()
        
        organization = user.profile.organization
        
        # Return widgets from the user's dashboards and system dashboards
        return DashboardWidget.objects.filter(
            models.Q(dashboard__organization=organization) | 
            models.Q(dashboard__is_system=True)
        )


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated, HasRolePermission])
@audit_action(entity_type='DASHBOARD', action_type='GET_STATS')
def dashboard_stats(request):
    """
    Endpoint para fornecer estatísticas do dashboard
    """
    if not has_permission(request.user, 'view_dashboard'):
        return Response(
            {"detail": "Permissão negada para visualizar o dashboard"},
            status=status.HTTP_403_FORBIDDEN
        )

    # Obtém a organização do usuário
    organization = None
    if hasattr(request.user, 'profile') and request.user.profile.organization:
        organization = request.user.profile.organization
    
    if not organization:
        return Response(
            {"detail": "Usuário sem organização"},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Define períodos para as estatísticas
    today = timezone.now()
    last_week = today - timedelta(days=7)
    last_month = today - timedelta(days=30)
    
    # Filtros base para organização do usuário
    case_base_filter = Q(organization=organization)
    alert_base_filter = Q(organization=organization)
    observable_base_filter = Q(added_by__profile__organization=organization)
    
    # Obtém estatísticas de casos
    cases_total = Case.objects.filter(case_base_filter).count()
    cases_month = Case.objects.filter(case_base_filter, created_at__gte=last_month).count()
    cases_week = Case.objects.filter(case_base_filter, created_at__gte=last_week).count()
    
    cases_by_status = list(Case.objects.filter(case_base_filter)
                          .values('status__name')
                          .annotate(count=Count('case_id'))
                          .order_by('status__name'))
    
    cases_by_severity = list(Case.objects.filter(case_base_filter)
                            .values('severity__name')
                            .annotate(count=Count('case_id'))
                            .order_by('severity__name'))
    
    # Obtém estatísticas de alertas
    alerts_total = Alert.objects.filter(alert_base_filter).count()
    alerts_month = Alert.objects.filter(alert_base_filter, created_at__gte=last_month).count()
    alerts_week = Alert.objects.filter(alert_base_filter, created_at__gte=last_week).count()
    
    alerts_by_status = list(Alert.objects.filter(alert_base_filter)
                           .values('status__name')
                           .annotate(count=Count('alert_id'))
                           .order_by('status__name'))
    
    alerts_by_severity = list(Alert.objects.filter(alert_base_filter)
                             .values('severity__name')
                             .annotate(count=Count('alert_id'))
                             .order_by('severity__name'))
    
    # Obtém estatísticas de observáveis
    observables_total = Observable.objects.filter(observable_base_filter).count()
    observables_month = Observable.objects.filter(observable_base_filter, added_at__gte=last_month).count()
    observables_week = Observable.objects.filter(observable_base_filter, added_at__gte=last_week).count()
    
    observables_by_type = list(Observable.objects.filter(observable_base_filter)
                              .values('type__name')
                              .annotate(count=Count('observable_id'))
                              .order_by('-count')[:10])
    
    # Combine tudo em um único objeto de resposta
    response_data = {
        'cases': {
            'total': cases_total,
            'month': cases_month,
            'week': cases_week,
            'by_status': cases_by_status,
            'by_severity': cases_by_severity
        },
        'alerts': {
            'total': alerts_total,
            'month': alerts_month,
            'week': alerts_week,
            'by_status': alerts_by_status,
            'by_severity': alerts_by_severity
        },
        'observables': {
            'total': observables_total,
            'month': observables_month,
            'week': observables_week,
            'by_type': observables_by_type
        }
    }
    
    return Response(response_data)

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated, HasRolePermission])
@audit_action(entity_type='METRIC', action_type='CALCULATE')
def calculate_metrics(request):
    """
    Endpoint para calcular métricas e salvar snapshots
    """
    if not has_permission(request.user, 'manage_metrics'):
        return Response(
            {"detail": "Permissão negada para calcular métricas"},
            status=status.HTTP_403_FORBIDDEN
        )
    
    # Implementação do cálculo de métricas
    # ... implementação ...
    
    return Response({"status": "Cálculo de métricas iniciado"}) 