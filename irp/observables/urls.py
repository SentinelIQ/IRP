from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    ObservableTypeViewSet, TLPLevelViewSet,
    PAPLevelViewSet, ObservableViewSet
)

router = DefaultRouter()

# Observable Management
router.register(r'observable-types', ObservableTypeViewSet)
router.register(r'tlp-levels', TLPLevelViewSet)
router.register(r'pap-levels', PAPLevelViewSet)
router.register(r'observables', ObservableViewSet)

urlpatterns = [
    path('', include(router.urls)),
]
