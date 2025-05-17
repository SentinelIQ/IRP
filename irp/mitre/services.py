from django.db.models import Q
from .models import MitreTactic, MitreTechnique, TechniqueTactic
import requests
import json
from django.db import transaction
from django.db.models import Count

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

def fetch_mitre_data(url):
    """
    Baixa os dados MITRE ATT&CK da URL fornecida
    """
    response = requests.get(url)
    response.raise_for_status()  # Raise an exception for HTTP errors
    return response.json()

# Função para verificar e criar relações técnica-tática
def ensure_technique_tactic_relations():
    """
    Verifica e repara relações entre técnicas e táticas, garantindo
    que todas as técnicas tenham ao menos uma tática associada quando possível.
    
    Esta função é útil para corrigir possíveis falhas na sincronização.
    """
    print("Verificando relações entre técnicas e táticas...")
    
    # Encontrar técnicas sem táticas
    orphaned_techniques = MitreTechnique.objects.annotate(
        tactics_count=Count('tactics')
    ).filter(tactics_count=0)
    
    count_fixed = 0
    
    for technique in orphaned_techniques:
        # Para subtécnicas, tentar usar as mesmas táticas da técnica pai
        if technique.is_subtechnique and technique.parent_technique:
            parent_tactics = technique.parent_technique.tactics.all()
            for tactic in parent_tactics:
                TechniqueTactic.objects.get_or_create(technique=technique, tactic=tactic)
                count_fixed += 1
                print(f"Técnica {technique.technique_id} associada à tática {tactic.tactic_id} (herdada do pai)")
    
    print(f"Reparadas {count_fixed} relações")
    return count_fixed

@transaction.atomic
def sync_mitre_attack_data(url="https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"):
    """
    Sincroniza dados MITRE ATT&CK do repositório oficial usando a abordagem de kill_chain_phases
    """
    print("Iniciando sincronização do MITRE ATT&CK...")
    data = fetch_mitre_data(url)
    
    # Primeiro, extrair as táticas existentes
    taticas = {}
    tecnicas_por_id = {}
    subtecnicas_por_pai = {}
    
    # Extrair primeiro as táticas
    for obj in data.get("objects", []):
        if obj.get("type") == "x-mitre-tactic":
            tactic_id = obj.get("external_references", [])[0].get("external_id")
            name = obj.get("name")
            short_name = obj.get("x_mitre_shortname")
            description = obj.get("description", "")
            url_ref = next((ref.get("url", "") for ref in obj.get("external_references", []) 
                  if ref.get("source_name") == "mitre-attack"), "")
            
            if tactic_id:
                taticas[short_name] = {
                    'tactic_id': tactic_id,
                    'name': name,
                    'short_name': short_name,
                    'description': description,
                    'url': url_ref
                }
                
    print(f"Extraídas {len(taticas)} táticas")
    
    # Processar técnicas e subtécnicas
    for obj in data.get("objects", []):
        if obj.get("type") == "attack-pattern" and "kill_chain_phases" in obj:
            external_refs = obj.get("external_references", [])
            mitre_ref = next((ref for ref in external_refs if ref.get("source_name") == "mitre-attack"), {})
            tecnica_id = mitre_ref.get("external_id", "")
            nome = obj.get("name", "")
            description = obj.get("description", "")
            url = mitre_ref.get("url", "")
            version = obj.get("x_mitre_version", "")
            kill_phases = [k["phase_name"] for k in obj.get("kill_chain_phases", [])]
            
            if not tecnica_id:
                continue
                
            tecnica = {
                "id": tecnica_id,
                "nome": nome,
                "description": description,
                "url": url,
                "version": version,
                "kill_chain_phases": kill_phases,
                "is_subtechnique": "." in tecnica_id,
                "parent_id": tecnica_id.split(".")[0] if "." in tecnica_id else None
            }
            
            if tecnica["is_subtechnique"]:
                subtecnicas_por_pai.setdefault(tecnica["parent_id"], []).append(tecnica)
            else:
                tecnicas_por_id[tecnica_id] = tecnica
    
    print(f"Extraídas {len(tecnicas_por_id)} técnicas e {sum(len(subs) for subs in subtecnicas_por_pai.values())} subtécnicas")
    
    # Persistir táticas no banco de dados
    for tactic_name, tactic_data in taticas.items():
        MitreTactic.objects.update_or_create(
            tactic_id=tactic_data['tactic_id'],
            defaults={
                'name': tactic_data['name'],
                'short_name': tactic_data['short_name'],
                'description': tactic_data['description'],
                'url': tactic_data['url'],
                'version': version
            }
        )
    
    # Persistir técnicas (primeiro as técnicas pai)
    parent_techniques = {}
    for technique_id, technique_data in tecnicas_por_id.items():
        technique_obj, created = MitreTechnique.objects.update_or_create(
            technique_id=technique_data['id'],
            defaults={
                'name': technique_data['nome'],
                'description': technique_data['description'],
                'url': technique_data['url'],
                'is_subtechnique': False,
                'parent_technique': None,
                'version': technique_data['version']
            }
        )
        parent_techniques[technique_id] = technique_obj
    
    # Persistir subtécnicas
    for parent_id, subtechniques in subtecnicas_por_pai.items():
        parent = parent_techniques.get(parent_id)
        if not parent:
            print(f"Técnica pai {parent_id} não encontrada para suas subtécnicas")
            continue
            
        for sub_data in subtechniques:
            MitreTechnique.objects.update_or_create(
                technique_id=sub_data['id'],
                defaults={
                    'name': sub_data['nome'],
                    'description': sub_data['description'],
                    'url': sub_data['url'],
                    'is_subtechnique': True,
                    'parent_technique': parent,
                    'version': sub_data['version']
                }
            )
    
    # Limpar relações existentes e recriar
    print("Removendo relações tática-técnica existentes...")
    TechniqueTactic.objects.all().delete()
    
    relationships_count = 0
    
    # Criar relações entre táticas e técnicas baseadas nas kill_chain_phases
    for technique_id, technique_data in tecnicas_por_id.items():
        technique = MitreTechnique.objects.filter(technique_id=technique_id).first()
        if not technique:
            print(f"Técnica {technique_id} não encontrada")
            continue
            
        for phase_name in technique_data["kill_chain_phases"]:
            tactic_data = taticas.get(phase_name)
            if not tactic_data:
                print(f"Tática {phase_name} não encontrada")
                continue
                
            tactic = MitreTactic.objects.filter(tactic_id=tactic_data["tactic_id"]).first()
            if not tactic:
                print(f"Tática {tactic_data['tactic_id']} não encontrada no banco de dados")
                continue
                
            # Criar relação técnica-tática
            TechniqueTactic.objects.create(technique=technique, tactic=tactic)
            relationships_count += 1
            print(f"Técnica {technique.technique_id} associada à tática {tactic.tactic_id}")
    
    # Associar subtécnicas às mesmas táticas de suas técnicas pai
    for parent_id, subtechniques in subtecnicas_por_pai.items():
        parent = MitreTechnique.objects.filter(technique_id=parent_id).first()
        if not parent:
            continue
            
        parent_tactics = parent.tactics.all()
        
        for sub_data in subtechniques:
            subtechnique = MitreTechnique.objects.filter(technique_id=sub_data['id']).first()
            if not subtechnique:
                continue
                
            # Associar subtécnica às mesmas táticas da técnica pai
            for tactic in parent_tactics:
                TechniqueTactic.objects.get_or_create(technique=subtechnique, tactic=tactic)
                relationships_count += 1
                print(f"Subtécnica {subtechnique.technique_id} associada à tática {tactic.tactic_id} (herdada do pai)")
                
            # Verificar se a subtécnica tem táticas específicas diferentes do pai
            for phase_name in sub_data["kill_chain_phases"]:
                tactic_data = taticas.get(phase_name)
                if not tactic_data:
                    continue
                    
                tactic = MitreTactic.objects.filter(tactic_id=tactic_data["tactic_id"]).first()
                if not tactic:
                    continue
                    
                # Verificar se já existe esta relação (para evitar duplicação)
                if not TechniqueTactic.objects.filter(technique=subtechnique, tactic=tactic).exists():
                    TechniqueTactic.objects.create(technique=subtechnique, tactic=tactic)
                    relationships_count += 1
                    print(f"Subtécnica {subtechnique.technique_id} associada à tática específica {tactic.tactic_id}")
    
    print("Sincronização concluída!")
    
    # Retornar estatísticas
    return {
        'tactics_count': len(taticas),
        'techniques_count': len(tecnicas_por_id),
        'subtechniques_count': sum(len(subs) for subs in subtecnicas_por_pai.values()),
        'relationships_count': relationships_count,
        'version': version if 'version' in locals() else 'desconhecida'
    }

def repair_mitre_correlations():
    """
    Repara correlações entre táticas e técnicas MITRE ATT&CK.
    Esta função tenta consertar problemas de correlação sem precisar de uma sincronização completa.
    
    Útil quando existe dados no banco, mas as correlações estão faltando.
    
    Returns:
        dict: Estatísticas sobre as correções realizadas
    """
    from django.db.models import Count
    
    # Estatísticas para retornar
    stats = {
        'orphaned_techniques_before': 0,
        'fixed_relations': 0,
        'orphaned_techniques_after': 0
    }
    
    # 1. Encontrar técnicas sem táticas
    orphaned_techniques = MitreTechnique.objects.annotate(
        tactics_count=Count('tactics')
    ).filter(tactics_count=0)
    
    stats['orphaned_techniques_before'] = orphaned_techniques.count()
    print(f"Encontradas {stats['orphaned_techniques_before']} técnicas sem táticas.")
    
    # 2. Para técnicas sem táticas, tentar aplicar a mesma lógica de correlação
    for technique in orphaned_techniques:
        fixed = False
        
        # 2.1 Para subtécnicas, herdar táticas do pai
        if technique.is_subtechnique and technique.parent_technique:
            parent_tactics = technique.parent_technique.tactics.all()
            for tactic in parent_tactics:
                TechniqueTactic.objects.get_or_create(technique=technique, tactic=tactic)
                stats['fixed_relations'] += 1
                fixed = True
                print(f"Técnica {technique.technique_id} associada à tática {tactic.tactic_id} (herdada do pai)")
        
        # 2.2 Para técnicas normais, tentar inferir pela ID ou nome
        if not fixed:
            # Tentar inferir táticas por padrões comuns nas IDs ou nomes
            # Exemplo: muitas técnicas de "Initial Access" começam com T1190-T1199
            tactic_patterns = {
                'TA0001': ['initial access', 'T119'],  # Initial Access
                'TA0002': ['execution', 'T105'], # Execution
                'TA0003': ['persistence', 'T112'], # Persistence
                'TA0004': ['privilege escalation', 'T113'], # Privilege Escalation
                'TA0005': ['defense evasion', 'T111'], # Defense Evasion
                'TA0006': ['credential access', 'T110'], # Credential Access
                'TA0007': ['discovery', 'T101'], # Discovery
                'TA0008': ['lateral movement', 'T108'], # Lateral Movement
                'TA0009': ['collection', 'T111'], # Collection
                'TA0011': ['command and control', 'T109'], # Command and Control
                'TA0010': ['exfiltration', 'T114'], # Exfiltration
                'TA0040': ['impact', 'T104'], # Impact
            }
            
            tech_id_name = f"{technique.technique_id} {technique.name}".lower()
            
            for tactic_id, patterns in tactic_patterns.items():
                if any(pattern.lower() in tech_id_name for pattern in patterns):
                    try:
                        tactic = MitreTactic.objects.get(tactic_id=tactic_id)
                        TechniqueTactic.objects.get_or_create(technique=technique, tactic=tactic)
                        stats['fixed_relations'] += 1
                        fixed = True
                        print(f"Técnica {technique.technique_id} associada à tática {tactic_id} (inferida por padrão)")
                    except MitreTactic.DoesNotExist:
                        continue
    
    # 3. Verificar quantas técnicas ainda estão sem táticas
    orphaned_after = MitreTechnique.objects.annotate(
        tactics_count=Count('tactics')
    ).filter(tactics_count=0).count()
    
    stats['orphaned_techniques_after'] = orphaned_after
    print(f"Corrigidas {stats['fixed_relations']} relações")
    print(f"Ainda restam {stats['orphaned_techniques_after']} técnicas sem táticas")
    
    return stats

def get_kill_chain_phases():
    """
    Retorna uma lista de fases da kill chain MITRE ATT&CK,
    baseada nas táticas disponíveis no banco de dados.
    
    Returns:
        list: Lista de dicionários com informações sobre as fases da kill chain
    """
    phases = []
    try:
        # Obter todas as táticas e usar seus short_names como fases da kill chain
        tactics = MitreTactic.objects.all().order_by('tactic_id')
        for tactic in tactics:
            if tactic.short_name:
                phases.append({
                    'tactic_id': tactic.tactic_id,
                    'name': tactic.name,
                    'phase_name': tactic.short_name
                })
    except Exception as e:
        print(f"Erro ao obter fases da kill chain: {e}")
    
    return phases

def get_technique_by_kill_chain_phase(phase_name):
    """
    Retorna técnicas associadas a uma determinada fase da kill chain.
    
    Args:
        phase_name: Nome da fase da kill chain (ex: "initial-access")
        
    Returns:
        Queryset com técnicas associadas à fase da kill chain
    """
    try:
        tactic = MitreTactic.objects.filter(short_name=phase_name).first()
        if tactic:
            return tactic.techniques.all().order_by('technique_id')
        return MitreTechnique.objects.none()
    except Exception as e:
        print(f"Erro ao buscar técnicas por fase da kill chain: {e}")
        return MitreTechnique.objects.none()
