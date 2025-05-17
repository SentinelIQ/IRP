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
    
    # Teste básico de status da API
    test_endpoint("test-status/", "Verificação de status da API")
    sleep(0.5)
    
    # Módulo accounts
    test_endpoint("organizations/", "Lista de organizações")
    test_endpoint("users/", "Lista de usuários")
    test_endpoint("roles/", "Lista de papéis")
    sleep(0.5)
    
    # Módulo alerts
    test_endpoint("alerts/", "Lista de alertas")
    test_endpoint("alerts/statuses/", "Lista de status de alertas")
    test_endpoint("alerts/severities/", "Lista de severidades de alertas")
    sleep(0.5)
    
    # Módulo cases
    test_endpoint("cases/", "Lista de casos")
    test_endpoint("cases/statuses/", "Lista de status de casos")
    test_endpoint("cases/severities/", "Lista de severidades de casos")
    sleep(0.5)
    
    # Módulo mitre
    test_endpoint("mitre/tactics/", "Lista de táticas MITRE")
    test_endpoint("mitre/techniques/", "Lista de técnicas MITRE")
    sleep(0.5)
    
    # Módulo observables
    test_endpoint("observables/", "Lista de observáveis")
    test_endpoint("observables/types/", "Lista de tipos de observáveis")
    sleep(0.5)
    
    # Módulo knowledge-base
    test_endpoint("knowledge-base/articles/", "Lista de artigos da base de conhecimento")
    test_endpoint("knowledge-base/categories/", "Lista de categorias da base de conhecimento")
    sleep(0.5)
    
    # Módulo audit
    test_endpoint("audit/logs/", "Lista de logs de auditoria")
    sleep(0.5)
    
    # Módulo notifications
    test_endpoint("notifications/", "Lista de notificações")
    
    print("\n" + "=" * 50)
    print("TESTES CONCLUÍDOS")
    print("=" * 50)

if __name__ == "__main__":
    main() 