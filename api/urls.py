from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_nested.routers import NestedSimpleRouter
from rest_framework.authtoken.views import obtain_auth_token
from .views import (
    OrganizationViewSet, TeamViewSet, ProfileViewSet, RoleViewSet, PermissionViewSet,
    UserRoleViewSet, RolePermissionViewSet, UserViewSet, 
    AlertSeverityViewSet, AlertStatusViewSet, AlertViewSet, AlertCommentViewSet,
    AlertCustomFieldDefinitionViewSet, AlertCustomFieldValueViewSet,
    CaseSeverityViewSet, CaseStatusViewSet, CaseTemplateViewSet, CaseViewSet, CaseCommentViewSet,
    CaseCustomFieldDefinitionViewSet, CaseCustomFieldValueViewSet,
    TaskStatusViewSet, TaskViewSet, ObservableTypeViewSet, TLPLevelViewSet, PAPLevelViewSet,
    ObservableViewSet, CaseObservableViewSet, AlertObservableViewSet,
    MitreTacticViewSet, MitreTechniqueViewSet,
    CaseMitreTechniqueViewSet, AlertMitreTechniqueViewSet,
    KBCategoryViewSet, KBArticleViewSet,
    HelloWorldView, LoginView, LogoutView, dashboard_stats, reports,
    import_mitre_attack, kb_search, kb_related_articles,
    NotificationEventViewSet, NotificationChannelViewSet, NotificationRuleViewSet,
    NotificationLogViewSet, NotificationViewSet, MetricViewSet, MetricSnapshotViewSet,
    DashboardViewSet, DashboardWidgetViewSet
)
from .misp_views import (
    MISPInstanceViewSet, MISPImportViewSet, MISPExportViewSet,
    ReportTemplateViewSet, GeneratedReportViewSet,
    calculate_metrics, trigger_misp_import, export_case_to_misp, generate_case_report
)
from .audit_views import AuditLogViewSet
from .timeline_views import TimelineEventViewSet, create_timeline_event

router = DefaultRouter()

# Organization and User Management
router.register(r'organizations', OrganizationViewSet)
router.register(r'teams', TeamViewSet)
router.register(r'profiles', ProfileViewSet)
router.register(r'roles', RoleViewSet)
router.register(r'permissions', PermissionViewSet)
router.register(r'user-roles', UserRoleViewSet)
router.register(r'role-permissions', RolePermissionViewSet)
router.register(r'users', UserViewSet)

# Alert Management
router.register(r'alert-severities', AlertSeverityViewSet)
router.register(r'alert-statuses', AlertStatusViewSet)
router.register(r'alerts', AlertViewSet)
router.register(r'alert-comments', AlertCommentViewSet)
router.register(r'alert-custom-field-definitions', AlertCustomFieldDefinitionViewSet)
router.register(r'alert-custom-field-values', AlertCustomFieldValueViewSet)

# Case Management
router.register(r'case-severities', CaseSeverityViewSet)
router.register(r'case-statuses', CaseStatusViewSet)
router.register(r'case-templates', CaseTemplateViewSet)
router.register(r'cases', CaseViewSet)
router.register(r'case-comments', CaseCommentViewSet)
router.register(r'case-custom-field-definitions', CaseCustomFieldDefinitionViewSet)
router.register(r'case-custom-field-values', CaseCustomFieldValueViewSet)
router.register(r'tasks', TaskViewSet)
router.register(r'task-statuses', TaskStatusViewSet)

# Observable Management
router.register(r'observable-types', ObservableTypeViewSet)
router.register(r'tlp-levels', TLPLevelViewSet)
router.register(r'pap-levels', PAPLevelViewSet)
router.register(r'observables', ObservableViewSet)
router.register(r'case-observables', CaseObservableViewSet)
router.register(r'alert-observables', AlertObservableViewSet)

# Audit
router.register(r'audit-logs', AuditLogViewSet)

# MITRE ATT&CK Framework
router.register(r'mitre-tactics', MitreTacticViewSet)
router.register(r'mitre-techniques', MitreTechniqueViewSet)

# Knowledge Base
router.register(r'kb-categories', KBCategoryViewSet)
router.register(r'kb-articles', KBArticleViewSet)

# Notification routes
router.register(r'notification-events', NotificationEventViewSet)
router.register(r'notification-channels', NotificationChannelViewSet, basename='notification-channel')
router.register(r'notification-rules', NotificationRuleViewSet, basename='notification-rule')
router.register(r'notification-logs', NotificationLogViewSet, basename='notification-log')
router.register(r'notifications', NotificationViewSet, basename='notification')

# Metrics and Dashboards routes
router.register(r'metrics', MetricViewSet)
router.register(r'metric-snapshots', MetricSnapshotViewSet, basename='metric-snapshot')
router.register(r'dashboards', DashboardViewSet, basename='dashboard')
router.register(r'dashboard-widgets', DashboardWidgetViewSet, basename='dashboard-widget')

# MISP Integration routes
router.register(r'misp-instances', MISPInstanceViewSet)
router.register(r'misp-imports', MISPImportViewSet)
router.register(r'misp-exports', MISPExportViewSet)

# Report Generation routes
router.register(r'report-templates', ReportTemplateViewSet)
router.register(r'generated-reports', GeneratedReportViewSet)

# Create nested routers for entity-specific routes
alerts_router = NestedSimpleRouter(router, r'alerts', lookup='alert')
alerts_router.register(r'comments', AlertCommentViewSet, basename='alert-comments')
alerts_router.register(r'observables', AlertObservableViewSet, basename='alert-observables')
alerts_router.register(r'mitre-techniques', AlertMitreTechniqueViewSet, basename='alert-mitre-techniques')

cases_router = NestedSimpleRouter(router, r'cases', lookup='case')
cases_router.register(r'comments', CaseCommentViewSet, basename='case-comments')
cases_router.register(r'tasks', TaskViewSet, basename='case-tasks')
cases_router.register(r'observables', CaseObservableViewSet, basename='case-observables')
cases_router.register(r'mitre-techniques', CaseMitreTechniqueViewSet, basename='case-mitre-techniques')
cases_router.register(r'timeline', TimelineEventViewSet, basename='case-timeline')

urlpatterns = [
    path('', include(router.urls)),
    path('', include(alerts_router.urls)),
    path('', include(cases_router.urls)),
    path('auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('token-auth/', obtain_auth_token, name='token_auth'),
    path('metrics/calculate/', calculate_metrics, name='calculate_metrics'),
    
    # MISP Integration Endpoints
    path('misp/trigger-import/', trigger_misp_import, name='trigger_misp_import'),
    path('cases/<uuid:case_id>/export-to-misp/', export_case_to_misp, name='export_case_to_misp'),
    
    # Report Generation Endpoints
    path('cases/<uuid:case_id>/generate-report/', generate_case_report, name='generate_case_report'),
    
    # Authentication
    path('hello/', HelloWorldView.as_view(), name='hello'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    
    # Dashboard and reports
    path('dashboard/', dashboard_stats, name='dashboard'),
    path('reports/', reports, name='reports-list'),
    path('reports/<str:report_type>/', reports, name='reports-detail'),
    
    # MITRE ATT&CK import
    path('mitre/import/', import_mitre_attack, name='mitre-import'),
    
    # Knowledge Base search
    path('kb/search/', kb_search, name='kb-search'),
    path('kb/related/<str:entity_type>/<str:entity_id>/', kb_related_articles, name='kb-related-articles'),
] 