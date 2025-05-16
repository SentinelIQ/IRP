# Plataforma de Resposta a Incidentes

## Visão Geral

Esta é uma plataforma de resposta a incidentes baseada em Django e Django REST Framework. Ela fornece uma API completa para gerenciar alertas, casos, observáveis, tarefas e muito mais.

## Funcionalidades Principais

### Etapa 1: Estrutura Base e Multi-tenancy
- Sistema multi-tenant com isolamento por organização
- Gerenciamento de usuários, equipes e permissões
- API RESTful com autenticação e autorização

### Etapa 2: Gerenciamento de Alertas e Casos
- Criação e gerenciamento de alertas de segurança
- Gerenciamento de casos de incidentes
- Campos customizáveis para alertas e casos
- Sistema de comentários e histórico de atividades

### Etapa 3: Observáveis, Timeline e MITRE ATT&CK
- Gerenciamento de observáveis (IOCs) com suporte a múltiplos tipos
- Sistema de timeline para documentar eventos de incidentes
- Integração com framework MITRE ATT&CK
- Base de conhecimento para documentação e procedimentos

### Etapa 4: Comunicação, Automação e Visibilidade
- Sistema de notificações configurável
- Automação de tarefas com Celery
- Métricas e dashboards para visibilidade
- Agendamento de tarefas periódicas

### Etapa 5: Integrações Externas e Finalização
- Integração bidirecional com MISP (Malware Information Sharing Platform)
- Sistema de geração de relatórios em múltiplos formatos (Markdown, DOCX, PDF)
- Personalização de templates de relatórios
- Importação/exportação de indicadores de ameaças

## Tecnologias Utilizadas

- Django 5.2+
- Django REST Framework 3.16+
- PostgreSQL (banco de dados)
- Celery (processamento assíncrono)
- Redis (message broker e cache)
- MISP API (integração com threat intelligence)
- WeasyPrint e python-docx (geração de relatórios)

## Configuração

### Requisitos
- Python 3.11+
- PostgreSQL 13+
- Redis 6+

### Instalação

1. Clone o repositório
2. Instale as dependências:
```
pip install uv
uv venv
uv pip sync
```

3. Configure as variáveis de ambiente (veja `.env.example`)
4. Execute as migrações:
```
python manage.py migrate
```

5. Inicialize os dados padrão:
```
python manage.py shell -c "from api.admin import create_default_data; create_default_data()"
```

6. Execute o servidor:
```
python manage.py runserver
```

### Docker

Também é possível executar a aplicação com Docker:

```
docker-compose up -d
```

## Serviços

A plataforma consiste em vários serviços:

- **API**: Serviço principal que fornece a API REST
- **Celery Worker**: Processa tarefas assíncronas
- **Celery Beat**: Agenda tarefas periódicas
- **Redis**: Message broker e cache
- **PostgreSQL**: Banco de dados
- **Nginx**: Servidor web (em produção)

## Integração MISP

A plataforma suporta integração bidirecional com MISP:

### Importação do MISP
- Configuração de múltiplas instâncias MISP
- Importação manual ou automática de eventos
- Filtragem por tags, data, etc.
- Conversão automática de atributos MISP para observáveis

### Exportação para MISP
- Exportação de casos para eventos MISP
- Configuração de níveis de distribuição, ameaça e análise
- Adição automática de tags

## Sistema de Relatórios

A plataforma inclui um sistema flexível de geração de relatórios:

- Múltiplos formatos (Markdown, DOCX, PDF)
- Templates personalizáveis
- Inclusão seletiva de seções (observáveis, timeline, tarefas, etc.)
- Geração assíncrona via API

## API

A documentação da API está disponível em `/api/schema/swagger-ui/` quando o servidor está em execução.

## Licença

Este projeto é privado e não possui licença de código aberto. 