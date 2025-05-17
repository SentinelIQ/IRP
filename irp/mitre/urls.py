from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_nested import routers
from .views import MitreTacticViewSet, MitreTechniqueViewSet, CaseMitreTechniqueViewSet, AlertMitreTechniqueViewSet, import_mitre_attack

router = DefaultRouter()
router.register(r'tactics', MitreTacticViewSet)
router.register(r'techniques', MitreTechniqueViewSet)

# Não é necessário registrar o CaseMitreTechniqueViewSet e AlertMitreTechniqueViewSet no router principal
# pois eles serão acessados via rotas aninhadas (caso e alerta, respectivamente)

# Observe: estas rotas aninhadas devem ser incluídas no URLconf principal do projeto
# para acessar as técnicas MITRE por meio de cases/:case_id/mitre-techniques/
# e alerts/:alert_id/mitre-techniques/

urlpatterns = [
    path('', include(router.urls)),
    path('import/', import_mitre_attack, name='mitre-import'),
]
