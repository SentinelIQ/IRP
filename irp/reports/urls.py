from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register(r'templates', views.ReportTemplateViewSet)
router.register(r'generated', views.GeneratedReportViewSet)
router.register(r'scheduled', views.ScheduledReportViewSet)

app_name = 'reports'

urlpatterns = [
    path('', include(router.urls)),
    path('cases/<uuid:case_id>/generate/', views.generate_case_report, name='generate_case_report'),
    path('cases/<uuid:case_id>/preview/', views.preview_report, name='preview_report'),
    path('download/<uuid:report_id>/', views.download_report, name='download_report'),
    path('scheduled/<uuid:schedule_id>/run/', views.run_scheduled_report_now, name='run_scheduled_report_now'),
    path('', views.reports, name='reports'),
    path('<str:report_type>/', views.reports, name='reports_by_type'),
] 