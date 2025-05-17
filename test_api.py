#!/usr/bin/env python
"""
Script para testar os endpoints da API modernizada.
Executa testes básicos verificando que os endpoints estão respondendo corretamente.
"""

import requests
import sys
import json
from time import sleep

BASE_URL = "http://localhost:8000/api/v2"

def get_auth_token(username="gfds", password="password123"):
    """Obtém um token de autenticação para uso nas requisições subsequentes."""
    url = f"{BASE_URL}/token-auth/"  # Usando o endpoint de token-auth em vez de login
    print(f"\nObtendo token de autenticação para {username}...")
    
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

def test_endpoint(endpoint, description=None, method="GET", expected_status=200, data=None, token=None):
    """Testa um endpoint específico da API."""
    url = f"{BASE_URL}/{endpoint.lstrip('/')}"
    print(f"\nTestando: {url} ({'GET' if method == 'GET' else 'POST'}) - {description or endpoint}")
    
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = f'Token {token}'
    
    try:
        if method == "GET":
            response = requests.get(url, headers=headers)
        else:
            response = requests.post(url, json=data, headers=headers)
        
        if response.status_code == expected_status:
            print(f"✓ Sucesso! Status: {response.status_code}")
            return response.json()
        else:
            print(f"✗ Falha! Status esperado: {expected_status}, recebido: {response.status_code}")
            print(f"Resposta: {response.text[:200]}...")
            return None
    except Exception as e:
        print(f"✗ Erro: {str(e)}")
        return None

def main():
    """Função principal que executa todos os testes."""
    print("=" * 50)
    print("TESTANDO API v2")
    print("=" * 50)
    
    # Obter token de autenticação
    token = get_auth_token()
    if not token:
        print("Não foi possível obter token. Continuando testes sem autenticação...")
    
    # Teste básico de status da API
    test_endpoint("test-status/", "Verificação de status da API", token=token)
    sleep(0.5)
    
    # Módulo accounts
    test_endpoint("organizations/", "Lista de organizações", token=token)
    test_endpoint("users/", "Lista de usuários", token=token)
    test_endpoint("roles/", "Lista de papéis", token=token)
    sleep(0.5)
    
    # Módulo alerts (caminhos corretos baseados no arquivo urls.py)
    test_endpoint("alerts/", "Lista de alertas", token=token)
    test_endpoint("alert-statuses/", "Lista de status de alertas", token=token)
    test_endpoint("alert-severities/", "Lista de severidades de alertas", token=token)
    sleep(0.5)
    
    # Módulo cases (caminhos corretos baseados no arquivo urls.py)
    test_endpoint("cases/", "Lista de casos", token=token)
    test_endpoint("severities/", "Lista de severidades de casos", token=token)
    test_endpoint("statuses/", "Lista de status de casos", token=token)
    sleep(0.5)
    
    # Módulo mitre
    test_endpoint("mitre/tactics/", "Lista de táticas MITRE", token=token)
    test_endpoint("mitre/techniques/", "Lista de técnicas MITRE", token=token)
    sleep(0.5)
    
    # Módulo observables
    test_endpoint("observables/", "Lista de observáveis", token=token)
    test_endpoint("observables/observable-types/", "Lista de tipos de observáveis", token=token)
    sleep(0.5)
    
    # Módulo knowledge-base
    test_endpoint("knowledge-base/articles/", "Lista de artigos da base de conhecimento", token=token)
    test_endpoint("knowledge-base/categories/", "Lista de categorias da base de conhecimento", token=token)
    sleep(0.5)
    
    # Módulo audit
    test_endpoint("audit/logs/", "Lista de logs de auditoria", token=token)
    sleep(0.5)
    
    # Módulo notifications
    test_endpoint("notifications/", "Lista de notificações", token=token)
    
    print("\n" + "=" * 50)
    print("TESTES CONCLUÍDOS")
    print("=" * 50)

if __name__ == "__main__":
    main() 