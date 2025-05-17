from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register('instances', views.MISPInstanceViewSet)
router.register('imports', views.MISPImportViewSet)
router.register('exports', views.MISPExportViewSet)
router.register('taxonomies', views.MISPTaxonomyViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('trigger-import/', views.trigger_misp_import, name='misp-trigger-import'),
    path('export-case/<uuid:case_id>/', views.export_case_to_misp, name='misp-export-case'),
    
    # Taxonomy synchronization
    path('instances/<uuid:instance_id>/sync-taxonomies/', views.sync_taxonomies, name='misp-sync-taxonomies'),
    
    # Taxonomy tag management for cases
    path('cases/<uuid:case_id>/add-taxonomy-tag/', views.add_taxonomy_tag_to_case, name='add-taxonomy-tag-to-case'),
    path('cases/<uuid:case_id>/remove-taxonomy-tag/<uuid:tag_id>/', views.remove_taxonomy_tag_from_case, name='remove-taxonomy-tag-from-case'),
    
    # Taxonomy tag management for alerts
    path('alerts/<uuid:alert_id>/add-taxonomy-tag/', views.add_taxonomy_tag_to_alert, name='add-taxonomy-tag-to-alert'),
    path('alerts/<uuid:alert_id>/remove-taxonomy-tag/<uuid:tag_id>/', views.remove_taxonomy_tag_from_alert, name='remove-taxonomy-tag-from-alert'),
    
    # Taxonomy tag management for observables
    path('observables/<uuid:observable_id>/add-taxonomy-tag/', views.add_taxonomy_tag_to_observable, name='add-taxonomy-tag-to-observable'),
    path('observables/<uuid:observable_id>/remove-taxonomy-tag/<uuid:tag_id>/', views.remove_taxonomy_tag_from_observable, name='remove-taxonomy-tag-from-observable'),
] 