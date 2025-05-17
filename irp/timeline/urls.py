from django.urls import path, include
from rest_framework_nested import routers
from .views import TimelineEventViewSet
from irp.cases.views import CaseViewSet

router = routers.SimpleRouter()

# Define a parent router for cases
parent_router = routers.SimpleRouter()
parent_router.register(r'cases', CaseViewSet, basename='case')

# Create a nested router for timeline events under cases
case_timeline_router = routers.NestedSimpleRouter(parent_router, r'cases', lookup='case')
case_timeline_router.register(r'timeline', TimelineEventViewSet, basename='case-timeline')

urlpatterns = [
    path('', include(case_timeline_router.urls)),
]

# Para ser usado em irp/cases/urls.py como:
# from irp.timeline.urls import case_timeline_router
# urlpatterns = [
#     ...
#     path('', include(case_timeline_router.urls)),
# ]
