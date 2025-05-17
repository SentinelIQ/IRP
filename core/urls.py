"""
URL configuration for core project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView
from rest_framework_nested import routers

# Para rotas aninhadas de MITRE
from irp.mitre.views import CaseMitreTechniqueViewSet, AlertMitreTechniqueViewSet
from irp.cases.views import CaseViewSet
from irp.alerts.views import AlertViewSet
from irp.metrics.views import dashboard_stats

# Configurar routers aninhados para MITRE
cases_router = routers.SimpleRouter()
cases_router.register(r'cases', CaseViewSet, basename='case')

alerts_router = routers.SimpleRouter()
alerts_router.register(r'alerts', AlertViewSet, basename='alert')

# Routers aninhados para caso-mitre e alerta-mitre
case_mitre_router = routers.NestedSimpleRouter(cases_router, r'cases', lookup='case')
case_mitre_router.register(r'mitre-techniques', CaseMitreTechniqueViewSet, basename='case-mitre-technique')

alert_mitre_router = routers.NestedSimpleRouter(alerts_router, r'alerts', lookup='alert')
alert_mitre_router.register(r'mitre-techniques', AlertMitreTechniqueViewSet, basename='alert-mitre-technique')

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # Módulos modularizados na API v2
    path('api/v2/', include('irp.accounts.urls')),  # Alterado para incluir na raiz da API v2
    path('api/v2/alerts/', include('irp.alerts.urls')),
    path('api/v2/observables/', include('irp.observables.urls')),
    path('api/v2/timeline/', include('irp.timeline.urls')),
    path('api/v2/mitre/', include('irp.mitre.urls')),
    path('api/v2/metrics/', include('irp.metrics.urls')),
    path('api/v2/knowledge-base/', include('irp.knowledge_base.urls')),
    path('api/v2/notifications/', include('irp.notifications.urls')),
    path('api/v2/audit/', include('irp.audit.urls')),
    path('api/v2/integrations/misp/', include('irp.integrations.misp.urls')),
    # Temporarily disabled due to weasyprint dependency issue
    # path('api/v2/reports/', include('irp.reports.urls')),
    # Dashboard principal
    path('api/v2/dashboard/', dashboard_stats, name='dashboard'),
    
    # Rotas aninhadas para MITRE
    path('api/v2/', include(case_mitre_router.urls)),
    path('api/v2/', include(alert_mitre_router.urls)),
    
    # API Documentation
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
]

# Serve static files in development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
