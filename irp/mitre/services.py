from django.db.models import Q
from .models import MitreTactic, MitreTechnique

def get_techniques_by_tactic(tactic_id):
    """
    Retorna todas as técnicas associadas a uma determinada tática.
    
    Args:
        tactic_id: O ID da tática para filtrar
    
    Returns:
        Queryset com as técnicas associadas
    """
    try:
        tactic = MitreTactic.objects.get(tactic_id=tactic_id)
        return tactic.techniques.all().order_by('technique_id')
    except MitreTactic.DoesNotExist:
        return MitreTechnique.objects.none()

def search_techniques(query):
    """
    Busca técnicas MITRE pelo nome, ID ou descrição.
    
    Args:
        query: String de busca
    
    Returns:
        Queryset com as técnicas correspondentes
    """
    if not query:
        return MitreTechnique.objects.none()
    
    return MitreTechnique.objects.filter(
        Q(name__icontains=query) | 
        Q(technique_id__icontains=query) | 
        Q(description__icontains=query)
    ).order_by('technique_id')[:50]  # Limitar a 50 resultados

def get_technique_details(technique_id):
    """
    Obtém detalhes completos de uma técnica, incluindo táticas associadas
    e técnicas relacionadas (subtécnicas ou técnica pai).
    
    Args:
        technique_id: ID da técnica
    
    Returns:
        Dicionário com detalhes da técnica ou None se não existir
    """
    try:
        technique = MitreTechnique.objects.get(technique_id=technique_id)
        
        # Obter táticas
        tactics = technique.tactics.all()
        
        # Obter subtécnicas ou técnica pai
        related_techniques = []
        if technique.is_subtechnique and technique.parent_technique:
            related_techniques.append({
                'id': technique.parent_technique.technique_id,
                'name': technique.parent_technique.name,
                'relationship': 'parent'
            })
        else:
            subtechniques = technique.subtechniques.all()
            for st in subtechniques:
                related_techniques.append({
                    'id': st.technique_id,
                    'name': st.name,
                    'relationship': 'subtechnique'
                })
        
        return {
            'id': technique.technique_id,
            'name': technique.name,
            'description': technique.description,
            'url': technique.url,
            'is_subtechnique': technique.is_subtechnique,
            'version': technique.version,
            'tactics': [{'id': t.tactic_id, 'name': t.name} for t in tactics],
            'related_techniques': related_techniques
        }
    except MitreTechnique.DoesNotExist:
        return None
