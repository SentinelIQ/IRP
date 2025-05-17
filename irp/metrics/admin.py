from django.contrib import admin
from .models import Metric, MetricSnapshot, Dashboard, DashboardWidget


@admin.register(Metric)
class MetricAdmin(admin.ModelAdmin):
    list_display = ('name', 'display_name', 'metric_type', 'entity_type')
    search_fields = ('name', 'display_name', 'description')
    list_filter = ('metric_type', 'entity_type')


@admin.register(MetricSnapshot)
class MetricSnapshotAdmin(admin.ModelAdmin):
    list_display = ('metric', 'organization', 'date', 'granularity', 'value')
    search_fields = ('metric__name', 'organization__name')
    list_filter = ('granularity', 'date', 'metric')
    date_hierarchy = 'date'


class DashboardWidgetInline(admin.TabularInline):
    model = DashboardWidget
    extra = 0


@admin.register(Dashboard)
class DashboardAdmin(admin.ModelAdmin):
    list_display = ('name', 'organization', 'is_system', 'created_by', 'created_at')
    search_fields = ('name', 'description', 'organization__name')
    list_filter = ('is_system', 'created_at')
    inlines = [DashboardWidgetInline]
    date_hierarchy = 'created_at'


@admin.register(DashboardWidget)
class DashboardWidgetAdmin(admin.ModelAdmin):
    list_display = ('title', 'dashboard', 'widget_type', 'metric')
    search_fields = ('title', 'dashboard__name', 'metric__name')
    list_filter = ('widget_type', 'dashboard') 