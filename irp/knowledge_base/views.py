from rest_framework import viewsets, permissions, status
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.response import Response
from django.db.models import Q
from django.shortcuts import get_object_or_404
from django.utils import timezone
from irp.common.permissions import HasRolePermission
from irp.common.audit import audit_action
from .models import KBCategory, KBArticle, KBArticleVersion
from .serializers import KBCategorySerializer, KBArticleSerializer, KBArticleVersionSerializer
from irp.cases.models import Case
from irp.alerts.models import Alert

class KBCategoryViewSet(viewsets.ModelViewSet):
    queryset = KBCategory.objects.all()
    serializer_class = KBCategorySerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_kb'
    
    @audit_action(entity_type='KB_CATEGORY', action_type='CREATE')
    def perform_create(self, serializer):
        return super().perform_create(serializer)
        
    @audit_action(entity_type='KB_CATEGORY', action_type='UPDATE')
    def perform_update(self, serializer):
        return super().perform_update(serializer)
        
    @audit_action(entity_type='KB_CATEGORY', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)

class KBArticleViewSet(viewsets.ModelViewSet):
    queryset = KBArticle.objects.all()
    serializer_class = KBArticleSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_kb'
    
    @audit_action(entity_type='KB_ARTICLE', action_type='CREATE')
    def perform_create(self, serializer):
        serializer.save(author=self.request.user)
        
    @audit_action(entity_type='KB_ARTICLE', action_type='UPDATE')
    def perform_update(self, serializer):
        # Criar uma nova versão do artigo
        article = self.get_object()
        version = article.version + 1
        
        # Salvar a versão anterior
        KBArticleVersion.objects.create(
            article=article,
            version_number=article.version,
            title=article.title,
            content=article.content,
            author=article.author,
            changed_at=article.updated_at
        )
        
        # Atualizar o artigo
        serializer.save(version=version)
        
    @audit_action(entity_type='KB_ARTICLE', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)
        
    @audit_action(entity_type='KB_ARTICLE', action_type='VIEW')
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

class KBArticleVersionViewSet(viewsets.ModelViewSet):
    queryset = KBArticleVersion.objects.all()
    serializer_class = KBArticleVersionSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_kb'
    
    @audit_action(entity_type='KB_ARTICLE_VERSION', action_type='VIEW')
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
@audit_action(entity_type='KNOWLEDGE_BASE', action_type='SEARCH')
def kb_search(request):
    """
    Endpoint para busca avançada na base de conhecimento.
    """
    user = request.user
    search_term = request.query_params.get('q', '')
    
    if not search_term:
        return Response({"detail": "Parâmetro de busca 'q' é obrigatório"}, 
                       status=status.HTTP_400_BAD_REQUEST)
    
    # Buscar artigos visíveis para o usuário
    if hasattr(user, 'profile') and user.profile.organization:
        org_id = user.profile.organization.organization_id
        queryset = KBArticle.objects.filter(
            Q(organization__isnull=True) | Q(organization_id=org_id),
            status='PUBLISHED'
        )
    else:
        queryset = KBArticle.objects.filter(
            organization__isnull=True,
            status='PUBLISHED'
        )
    
    # Busca em título, conteúdo e tags
    results = queryset.filter(
        Q(title__icontains=search_term) | 
        Q(content__icontains=search_term) |
        Q(tags__contains=[search_term])
    ).order_by('-updated_at')
    
    # Limitar resultados
    limit = int(request.query_params.get('limit', 20))
    results = results[:limit]
    
    # Serializar resultados
    serializer = KBArticleSerializer(results, many=True)
    
    return Response({
        'count': len(results),
        'results': serializer.data
    })

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
@audit_action(entity_type='KNOWLEDGE_BASE', action_type='VIEW_RELATED')
def kb_related_articles(request, entity_type, entity_id):
    """
    Endpoint para sugerir artigos da base de conhecimento relacionados 
    a um caso, alerta ou outro objeto com base em palavras-chave.
    """
    user = request.user
    
    # Obter o objeto relacionado
    if entity_type.lower() == 'case':
        try:
            entity = Case.objects.get(case_id=entity_id)
            keywords = []
            
            # Extrair palavras-chave do título e descrição
            if entity.title:
                keywords.extend(entity.title.lower().split())
            if entity.description:
                keywords.extend(entity.description.lower().split())
                
            # Adicionar outros termos relevantes como severidade, status, etc.
            if entity.severity:
                keywords.append(entity.severity.name.lower())
            if entity.status:
                keywords.append(entity.status.name.lower())
                
        except Case.DoesNotExist:
            return Response({"detail": "Caso não encontrado"}, 
                           status=status.HTTP_404_NOT_FOUND)
    
    elif entity_type.lower() == 'alert':
        try:
            entity = Alert.objects.get(alert_id=entity_id)
            keywords = []
            
            # Extrair palavras-chave do título e descrição
            if entity.title:
                keywords.extend(entity.title.lower().split())
            if entity.description:
                keywords.extend(entity.description.lower().split())
                
            # Adicionar outros termos relevantes
            if entity.severity:
                keywords.append(entity.severity.name.lower())
            if entity.status:
                keywords.append(entity.status.name.lower())
            if entity.source_system:
                keywords.append(entity.source_system.lower())
                
        except Alert.DoesNotExist:
            return Response({"detail": "Alerta não encontrado"}, 
                           status=status.HTTP_404_NOT_FOUND)
    else:
        return Response({"detail": "Tipo de entidade não suportado"}, 
                       status=status.HTTP_400_BAD_REQUEST)
    
    # Filtrar palavras-chave (remover preposições, artigos, etc.)
    stopwords = ['a', 'o', 'e', 'de', 'do', 'da', 'em', 'no', 'na', 'para', 'com', 'por']
    keywords = [k for k in keywords if len(k) > 3 and k not in stopwords]
    
    # Limite de palavras-chave
    keywords = keywords[:10]
    
    # Buscar artigos visíveis para o usuário
    if hasattr(user, 'profile') and user.profile.organization:
        org_id = user.profile.organization.organization_id
        queryset = KBArticle.objects.filter(
            Q(organization__isnull=True) | Q(organization_id=org_id),
            status='PUBLISHED'
        )
    else:
        queryset = KBArticle.objects.filter(
            organization__isnull=True,
            status='PUBLISHED'
        )
    
    # Buscar artigos relacionados com as palavras-chave
    results = []
    for keyword in keywords:
        articles = queryset.filter(
            Q(title__icontains=keyword) | 
            Q(content__icontains=keyword) |
            Q(tags__contains=[keyword])
        )
        
        for article in articles:
            # Adicionar score de relevância baseado no número de keywords encontradas
            score = 0
            for k in keywords:
                if k in article.title.lower():
                    score += 3  # Peso maior para matches no título
                if k in article.content.lower():
                    score += 1  # Peso menor para matches no conteúdo
                if article.tags and k in [t.lower() for t in article.tags]:
                    score += 2  # Peso médio para matches nas tags
            
            # Adicionar à lista de resultados se tiver score mínimo
            if score > 0:
                result = {
                    'article': article,
                    'score': score
                }
                
                # Verificar se já está nos resultados
                existing = next((r for r in results if r['article'].article_id == article.article_id), None)
                if existing:
                    # Atualizar score se for maior
                    if score > existing['score']:
                        existing['score'] = score
                else:
                    results.append(result)
    
    # Ordenar por score e limitar resultados
    results = sorted(results, key=lambda x: x['score'], reverse=True)[:5]
    
    # Serializar resultados
    serialized_results = []
    for result in results:
        article_data = KBArticleSerializer(result['article']).data
        serialized_results.append({
            'article': article_data,
            'relevance_score': result['score']
        })
    
    return Response({
        'count': len(serialized_results),
        'keywords_used': keywords,
        'results': serialized_results
    }) 