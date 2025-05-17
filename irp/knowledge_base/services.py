# Serviços para o módulo Knowledge Base

# Exemplo de função utilitária (pode ser expandido futuramente)
def get_published_articles():
    from .models import KBArticle
    return KBArticle.objects.filter(status='PUBLISHED') 