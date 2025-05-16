from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_nested.routers import NestedSimpleRouter
from .views import (
    OrganizationViewSet, TeamViewSet, ProfileViewSet, RoleViewSet, PermissionViewSet,
    UserRoleViewSet, RolePermissionViewSet, UserViewSet, 
    AlertSeverityViewSet, AlertStatusViewSet, AlertViewSet, AlertCommentViewSet,
    AlertCustomFieldDefinitionViewSet, AlertCustomFieldValueViewSet,
    CaseSeverityViewSet, CaseStatusViewSet, CaseTemplateViewSet, CaseViewSet, CaseCommentViewSet,
    CaseCustomFieldDefinitionViewSet, CaseCustomFieldValueViewSet,
    TaskStatusViewSet, TaskViewSet, ObservableTypeViewSet, TLPLevelViewSet, PAPLevelViewSet,
    ObservableViewSet, CaseObservableViewSet, AlertObservableViewSet, AuditLogViewSet,
    TimelineEventViewSet, MitreTacticViewSet, MitreTechniqueViewSet,
    CaseMitreTechniqueViewSet, AlertMitreTechniqueViewSet,
    KBCategoryViewSet, KBArticleViewSet,
    HelloWorldView, LoginView, LogoutView, dashboard_stats, reports,
    import_mitre_attack, kb_search, kb_related_articles
)

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
router.register(r'alert-custom-field-definitions', AlertCustomFieldDefinitionViewSet)

# Case Management
router.register(r'case-severities', CaseSeverityViewSet)
router.register(r'case-statuses', CaseStatusViewSet)
router.register(r'case-templates', CaseTemplateViewSet)
router.register(r'cases', CaseViewSet)
router.register(r'case-custom-field-definitions', CaseCustomFieldDefinitionViewSet)
router.register(r'task-statuses', TaskStatusViewSet)

# Observable Management
router.register(r'observable-types', ObservableTypeViewSet)
router.register(r'tlp-levels', TLPLevelViewSet)
router.register(r'pap-levels', PAPLevelViewSet)
router.register(r'observables', ObservableViewSet)

# Audit
router.register(r'audit-logs', AuditLogViewSet)

# MITRE ATT&CK Framework
router.register(r'mitre/tactics', MitreTacticViewSet)
router.register(r'mitre/techniques', MitreTechniqueViewSet)

# Knowledge Base
router.register(r'kb/categories', KBCategoryViewSet)
router.register(r'kb/articles', KBArticleViewSet, basename='kb-article')

# Nested Routers
alerts_router = NestedSimpleRouter(router, r'alerts', lookup='alert')
alerts_router.register(r'comments', AlertCommentViewSet, basename='alert-comments')
alerts_router.register(r'custom-fields', AlertCustomFieldValueViewSet, basename='alert-custom-fields')
alerts_router.register(r'observables', AlertObservableViewSet, basename='alert-observables')
alerts_router.register(r'mitre-techniques', AlertMitreTechniqueViewSet, basename='alert-mitre-techniques')

cases_router = NestedSimpleRouter(router, r'cases', lookup='case')
cases_router.register(r'comments', CaseCommentViewSet, basename='case-comments')
cases_router.register(r'tasks', TaskViewSet, basename='case-tasks')
cases_router.register(r'custom-fields', CaseCustomFieldValueViewSet, basename='case-custom-fields')
cases_router.register(r'observables', CaseObservableViewSet, basename='case-observables')
cases_router.register(r'timeline', TimelineEventViewSet, basename='case-timeline')
cases_router.register(r'mitre-techniques', CaseMitreTechniqueViewSet, basename='case-mitre-techniques')

urlpatterns = [
    path('', include(router.urls)),
    path('', include(alerts_router.urls)),
    path('', include(cases_router.urls)),
    
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