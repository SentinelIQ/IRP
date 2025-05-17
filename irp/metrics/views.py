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

from django.shortcuts import render
from django.db.models import Count, Avg, Sum, F, Q
from django.utils import timezone
from datetime import timedelta

from irp.cases.models import Case
from irp.alerts.models import Alert
from irp.observables.models import Observable


class MetricViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for listing and retrieving metrics.
    Metrics are system-defined and cannot be modified via API.
    """
    queryset = Metric.objects.all()
    serializer_class = MetricSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    @action(detail=True, methods=['get'])
    def data(self, request, pk=None):
        """
        Get metric data for a specific period
        """
        metric = self.get_object()
        user = request.user
        
        if not hasattr(user, 'profile') or not user.profile.organization:
            return Response(
                {'detail': 'User not associated with an organization'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Parse query parameters
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')
        granularity = request.query_params.get('granularity', 'DAILY')
        
        # Parse dimensions from query params
        dimensions = {}
        for key, value in request.query_params.items():
            if key.startswith('dimension_'):
                dimension_name = key[10:]  # Remove 'dimension_' prefix
                dimensions[dimension_name] = value
        
        # Validate required parameters
        if not start_date or not end_date:
            return Response(
                {'detail': 'start_date and end_date are required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Convert string dates to datetime
            from django.utils.dateparse import parse_date
            start_date = parse_date(start_date)
            end_date = parse_date(end_date)
            
            if not start_date or not end_date:
                raise ValueError("Invalid date format")
            
            # Get metric data from service
            # Note: This requires implementing MetricsService which should be imported
            from .services import MetricsService
            data = MetricsService.get_metric_data(
                metric=metric,
                organization=user.profile.organization,
                start_date=start_date,
                end_date=end_date,
                granularity=granularity,
                dimensions=dimensions
            )
            
            return Response(data)
            
        except Exception as e:
            return Response(
                {'detail': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class MetricSnapshotViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for retrieving metric snapshots
    """
    serializer_class = MetricSnapshotSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            queryset = MetricSnapshot.objects.filter(organization=user.profile.organization)
            
            # Filter by metric if provided
            metric_id = self.request.query_params.get('metric_id')
            if metric_id:
                queryset = queryset.filter(metric__metric_id=metric_id)
            
            # Filter by date range if provided
            start_date = self.request.query_params.get('start_date')
            end_date = self.request.query_params.get('end_date')
            if start_date:
                queryset = queryset.filter(date__gte=start_date)
            if end_date:
                queryset = queryset.filter(date__lte=end_date)
            
            # Filter by granularity if provided
            granularity = self.request.query_params.get('granularity')
            if granularity:
                queryset = queryset.filter(granularity=granularity)
            
            return queryset
        return MetricSnapshot.objects.none()


class DashboardViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing dashboards
    """
    serializer_class = DashboardSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            return Dashboard.objects.filter(
                models.Q(organization=user.profile.organization) | 
                models.Q(is_system=True)
            )
        return Dashboard.objects.filter(is_system=True)  # Only system dashboards for users without org
    
    def perform_create(self, serializer):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            serializer.save(
                organization=user.profile.organization,
                created_by=user
            )
        else:
            raise exceptions.PermissionDenied("User must belong to an organization to create dashboards")
    
    def perform_update(self, serializer):
        dashboard = self.get_object()
        
        # Prevent updating system dashboards unless user is a system admin
        if dashboard.is_system and not self.request.user.profile.is_system_admin:
            raise exceptions.PermissionDenied("Cannot modify system dashboards")
        
        serializer.save()
    
    def perform_destroy(self, instance):
        # Prevent deleting system dashboards
        if instance.is_system:
            raise exceptions.PermissionDenied("Cannot delete system dashboards")
        
        instance.delete()


class DashboardWidgetViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing dashboard widgets
    """
    serializer_class = DashboardWidgetSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            # Get dashboards this user has access to
            accessible_dashboards = Dashboard.objects.filter(
                models.Q(organization=user.profile.organization) | 
                models.Q(is_system=True)
            ).values_list('dashboard_id', flat=True)
            
            return DashboardWidget.objects.filter(dashboard__dashboard_id__in=accessible_dashboards)
        
        # User without org can only see widgets from system dashboards
        system_dashboards = Dashboard.objects.filter(is_system=True).values_list('dashboard_id', flat=True)
        return DashboardWidget.objects.filter(dashboard__dashboard_id__in=system_dashboards)
    
    def perform_create(self, serializer):
        dashboard = serializer.validated_data.get('dashboard')
        
        # Check if user has permission to modify this dashboard
        user = self.request.user
        if dashboard.is_system and not user.profile.is_system_admin:
            raise exceptions.PermissionDenied("Cannot add widgets to system dashboards")
        
        if dashboard.organization and (
            not hasattr(user, 'profile') or 
            not user.profile.organization or 
            user.profile.organization.id != dashboard.organization.id
        ):
            raise exceptions.PermissionDenied("Cannot add widgets to dashboards from other organizations")
        
        serializer.save()
    
    def perform_update(self, serializer):
        widget = self.get_object()
        
        # Prevent updating widgets in system dashboards
        if widget.dashboard.is_system and not self.request.user.profile.is_system_admin:
            raise exceptions.PermissionDenied("Cannot modify widgets in system dashboards")
        
        serializer.save()
    
    def perform_destroy(self, instance):
        # Prevent deleting widgets from system dashboards
        if instance.dashboard.is_system and not self.request.user.profile.is_system_admin:
            raise exceptions.PermissionDenied("Cannot delete widgets from system dashboards")
        
        instance.delete()


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated, HasRolePermission])
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