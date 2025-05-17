from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    AlertSeverityViewSet, AlertStatusViewSet, AlertViewSet,
    AlertCommentViewSet, AlertCustomFieldDefinitionViewSet,
    AlertCustomFieldValueViewSet, AlertObservableViewSet
)
# AlertMitreTechniqueViewSet foi movido para irp.mitre.views

router = DefaultRouter()

# Alert Management
router.register(r'alert-severities', AlertSeverityViewSet, basename='alert-severity')
router.register(r'alert-statuses', AlertStatusViewSet, basename='alert-status')
router.register(r'alerts', AlertViewSet)
router.register(r'alert-comments', AlertCommentViewSet)
router.register(r'alert-custom-field-definitions', AlertCustomFieldDefinitionViewSet)
router.register(r'alert-custom-field-values', AlertCustomFieldValueViewSet)
router.register(r'alert-observables', AlertObservableViewSet)
# alert-mitre-techniques rota foi movida para mitre.urls

urlpatterns = [
    path('', include(router.urls)),
]
