#!/usr/bin/env python
"""
Script para testar a consulta de dados MITRE ATT&CK.
"""

import requests
import sys
import json

# Configurações
BASE_URL = "http://localhost:8000/api/v2"

def get_auth_token(username="gfds", password="password123"):
    """Obtém um token de autenticação para uso nas requisições subsequentes."""
    url = f"{BASE_URL}/token-auth/"  
    print(f"Obtendo token de autenticação para {username}...")
    
    try:
        response = requests.post(url, data={"username": username, "password": password})
        if response.status_code == 200:
            token = response.json().get('token')
            if token:
                print(f"✓ Token obtido com sucesso!")
                return token
            else:
                print(f"✗ Falha ao extrair token da resposta: {response.text}")
        else:
            print(f"✗ Falha na autenticação. Status: {response.status_code}")
            print(f"Resposta: {response.text[:200]}...")
        return None
    except Exception as e:
        print(f"✗ Erro na autenticação: {str(e)}")
        return None

def query_mitre_data(token=None):
    """Consulta táticas e técnicas MITRE ATT&CK."""
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = f'Token {token}'
    
    print("Consultando táticas MITRE ATT&CK...")
    try:
        response = requests.get(f"{BASE_URL}/mitre/tactics/", headers=headers)
        if response.status_code == 200:
            data = response.json()
            total_tactics = data.get('count', 0)
            tactics = data.get('results', [])
            
            print(f"✓ Encontradas {total_tactics} táticas!")
            
            if tactics:
                print(f"\nPrimeiras táticas:")
                for i, tactic in enumerate(tactics[:3]):
                    print(f"{i+1}. {tactic['tactic_id']} - {tactic['name']}")
            else:
                print("Nenhuma tática encontrada. A sincronização pode não ter importado táticas.")
        else:
            print(f"✗ Falha! Status: {response.status_code}")
            print(f"Resposta: {response.text[:200]}...")
    except Exception as e:
        print(f"✗ Erro ao consultar táticas: {str(e)}")
    
    print("\nConsultando técnicas MITRE ATT&CK...")
    try:
        response = requests.get(f"{BASE_URL}/mitre/techniques/", headers=headers)
        if response.status_code == 200:
            data = response.json()
            total_techniques = data.get('count', 0)
            techniques = data.get('results', [])
            
            print(f"✓ Encontradas {total_techniques} técnicas no total!")
            
            # Contar subtécnicas na primeira página
            subtechniques = [t for t in techniques if t.get('is_subtechnique')]
            
            if techniques:
                print(f"\nPrimeiras técnicas principais:")
                main_techniques = [t for t in techniques if not t.get('is_subtechnique')]
                for i, technique in enumerate(main_techniques[:3]):
                    print(f"{i+1}. {technique['technique_id']} - {technique['name']}")
                    # Mostrar táticas associadas a esta técnica
                    if 'tactics' in technique and technique['tactics']:
                        print("   Táticas associadas:")
                        for tactic in technique['tactics']:
                            print(f"   - {tactic['tactic_id']}: {tactic['name']}")
                    else:
                        print("   Sem táticas associadas!")
                
                if subtechniques:
                    print(f"\nPrimeiras subtécnicas:")
                    for i, subtechnique in enumerate(subtechniques[:3]):
                        print(f"{i+1}. {subtechnique['technique_id']} - {subtechnique['name']}")
                        # Mostrar táticas associadas a esta subtécnica
                        if 'tactics' in subtechnique and subtechnique['tactics']:
                            print("   Táticas associadas:")
                            for tactic in subtechnique['tactics']:
                                print(f"   - {tactic['tactic_id']}: {tactic['name']}")
                        else:
                            print("   Sem táticas associadas!")
            else:
                print("Nenhuma técnica encontrada na primeira página.")
        else:
            print(f"✗ Falha! Status: {response.status_code}")
            print(f"Resposta: {response.text[:200]}...")
    except Exception as e:
        print(f"✗ Erro ao consultar técnicas: {str(e)}")
    
def main():
    """Função principal."""
    print("=" * 50)
    print("TESTE DE CONSULTA MITRE ATT&CK")
    print("=" * 50)
    
    # Obter token de autenticação
    token = get_auth_token()
    if not token:
        print("Não foi possível obter token. Tentando sem autenticação...")
    
    # Consultar dados
    query_mitre_data(token)
    
    print("\n" + "=" * 50)
    print("TESTE CONCLUÍDO")
    print("=" * 50)

if __name__ == "__main__":
    main() 