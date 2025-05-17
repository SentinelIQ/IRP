from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import KBCategoryViewSet, KBArticleViewSet, KBArticleVersionViewSet, kb_search, kb_related_articles

router = DefaultRouter()
router.register(r'categories', KBCategoryViewSet)
router.register(r'articles', KBArticleViewSet)
router.register(r'article-versions', KBArticleVersionViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('search/', kb_search, name='kb-search'),
    path('related/<str:entity_type>/<str:entity_id>/', kb_related_articles, name='kb-related-articles'),
] 