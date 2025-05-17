from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register(r'templates', views.ReportTemplateViewSet)
router.register(r'generated', views.GeneratedReportViewSet)

app_name = 'reports'

urlpatterns = [
    path('', include(router.urls)),
    path('cases/<uuid:case_id>/generate/', views.generate_case_report, name='generate_case_report'),
    path('', views.reports, name='reports'),
    path('<str:report_type>/', views.reports, name='reports_by_type'),
] 