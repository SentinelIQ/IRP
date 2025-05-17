from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_nested import routers

from .views import (
    CaseSeverityViewSet, CaseStatusViewSet, CaseTemplateViewSet, 
    CaseViewSet, CaseCommentViewSet, TaskStatusViewSet, TaskViewSet,
    CaseCustomFieldDefinitionViewSet, CaseCustomFieldValueViewSet
)

# Main router
router = DefaultRouter()
router.register(r'severities', CaseSeverityViewSet, basename='case-severity')
router.register(r'statuses', CaseStatusViewSet, basename='case-status')
router.register(r'templates', CaseTemplateViewSet, basename='case-template')
router.register(r'task-statuses', TaskStatusViewSet, basename='task-status')
router.register(r'cases', CaseViewSet, basename='case')
router.register(r'custom-field-definitions', CaseCustomFieldDefinitionViewSet, basename='case-custom-field-definition')
router.register(r'custom-field-values', CaseCustomFieldValueViewSet, basename='case-custom-field-value')

# Nested routes for case-related resources
cases_router = routers.NestedSimpleRouter(router, r'cases', lookup='case')
cases_router.register(r'comments', CaseCommentViewSet, basename='case-comment')
cases_router.register(r'tasks', TaskViewSet, basename='task')

urlpatterns = [
    path('', include(router.urls)),
    path('', include(cases_router.urls)),
] 