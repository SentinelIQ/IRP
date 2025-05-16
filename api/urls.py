from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_nested import routers
from .views import (
    HelloWorldView, OrganizationViewSet, TeamViewSet, ProfileViewSet, RoleViewSet, PermissionViewSet,
    UserRoleViewSet, RolePermissionViewSet, UserViewSet, LoginView, LogoutView,
    AlertSeverityViewSet, AlertStatusViewSet, AlertViewSet, AlertCommentViewSet,
    AlertCustomFieldDefinitionViewSet, AlertCustomFieldValueViewSet,
    CaseSeverityViewSet, CaseStatusViewSet, CaseTemplateViewSet, CaseViewSet, CaseCommentViewSet,
    CaseCustomFieldDefinitionViewSet, CaseCustomFieldValueViewSet,
    TaskStatusViewSet, TaskViewSet, ObservableTypeViewSet, TLPLevelViewSet, PAPLevelViewSet,
    ObservableViewSet, CaseObservableViewSet, AlertObservableViewSet, AuditLogViewSet,
    dashboard_stats, reports
)

# Roteador principal
router = DefaultRouter()
router.register(r'organizations', OrganizationViewSet)
router.register(r'teams', TeamViewSet)
router.register(r'profiles', ProfileViewSet)
router.register(r'roles', RoleViewSet)
router.register(r'permissions', PermissionViewSet)
router.register(r'user-roles', UserRoleViewSet)
router.register(r'role-permissions', RolePermissionViewSet)
router.register(r'users', UserViewSet)

# Roteadores para Etapa 2 - Alertas e Casos
router.register(r'alert-severities', AlertSeverityViewSet)
router.register(r'alert-statuses', AlertStatusViewSet)
router.register(r'alert-custom-fields', AlertCustomFieldDefinitionViewSet)
router.register(r'alerts', AlertViewSet)
router.register(r'case-severities', CaseSeverityViewSet)
router.register(r'case-statuses', CaseStatusViewSet)
router.register(r'case-templates', CaseTemplateViewSet)
router.register(r'case-custom-fields', CaseCustomFieldDefinitionViewSet)
router.register(r'cases', CaseViewSet)
router.register(r'task-statuses', TaskStatusViewSet)
router.register(r'observable-types', ObservableTypeViewSet)
router.register(r'tlp-levels', TLPLevelViewSet)
router.register(r'pap-levels', PAPLevelViewSet)
router.register(r'observables', ObservableViewSet)
router.register(r'audit-logs', AuditLogViewSet)

# Roteadores para recursos aninhados
alert_router = routers.NestedSimpleRouter(router, r'alerts', lookup='alert')
alert_router.register(r'comments', AlertCommentViewSet, basename='alert-comments')
alert_router.register(r'observables', AlertObservableViewSet, basename='alert-observables')
alert_router.register(r'custom-fields', AlertCustomFieldValueViewSet, basename='alert-custom-fields')

case_router = routers.NestedSimpleRouter(router, r'cases', lookup='case')
case_router.register(r'comments', CaseCommentViewSet, basename='case-comments')
case_router.register(r'tasks', TaskViewSet, basename='case-tasks')
case_router.register(r'observables', CaseObservableViewSet, basename='case-observables')
case_router.register(r'custom-fields', CaseCustomFieldValueViewSet, basename='case-custom-fields')

urlpatterns = [
    path('hello/', HelloWorldView.as_view(), name='hello'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('dashboard/', dashboard_stats, name='dashboard'),
    path('reports/', reports, name='reports-list'),
    path('reports/<str:report_type>/', reports, name='reports-detail'),
    path('', include(router.urls)),
    path('', include(alert_router.urls)),
    path('', include(case_router.urls)),
] 