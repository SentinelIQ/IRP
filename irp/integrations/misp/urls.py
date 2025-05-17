from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register('instances', views.MISPInstanceViewSet)
router.register('imports', views.MISPImportViewSet)
router.register('exports', views.MISPExportViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('trigger-import/', views.trigger_misp_import, name='misp-trigger-import'),
    path('export-case/<uuid:case_id>/', views.export_case_to_misp, name='misp-export-case'),
] 