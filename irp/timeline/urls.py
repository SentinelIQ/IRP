from django.urls import path, include
from rest_framework_nested import routers
from .views import TimelineEventViewSet

# Define a parent router for cases
parent_router = routers.SimpleRouter()
parent_router.register(r'cases', 'irp.cases.views.CaseViewSet', basename='case')

# Create a nested router for timeline events under cases
case_timeline_router = routers.NestedSimpleRouter(parent_router, r'cases', lookup='case')
case_timeline_router.register(r'timeline', TimelineEventViewSet, basename='case-timeline')

# Add specific endpoints for timeline features
timeline_urls = [
    # Estas rotas são acessadas via /timeline/cases/{case_id}/timeline/
    path('cases/<uuid:case_pk>/timeline/summary/', TimelineEventViewSet.as_view({'get': 'summary'}), name='timeline-summary'),
    path('cases/<uuid:case_pk>/timeline/recent/', TimelineEventViewSet.as_view({'get': 'recent'}), name='timeline-recent'),
    path('cases/<uuid:case_pk>/timeline/important/', TimelineEventViewSet.as_view({'get': 'important'}), name='timeline-important'),
]

urlpatterns = [
    path('', include(case_timeline_router.urls)),
    # URLs adicionais específicas da timeline
    *timeline_urls,
]

# Para ser usado em irp/cases/urls.py como:
# from irp.timeline.urls import case_timeline_router
# urlpatterns = [
#     ...
#     path('', include(case_timeline_router.urls)),
# ]
