# Multi-Tenant Platform API

API de gerenciamento para plataforma multi-tenant com controle avançado de usuários, times e organizações.

## Etapa 1: Fundação - Estrutura e Acesso Básico

### Funcionalidades Implementadas

#### Multi-Tenant Environments
- ✅ Modelagem de Dados para Organizações
- ✅ Backend - API para Gerenciamento de Organizações
- ✅ Modelagem de Dados para Times
- ✅ Backend - API para Gerenciamento de Times
- ✅ Lógica de Isolamento de Dados (Initial)

#### Advanced User Management
- ✅ Modelagem de Dados para Perfis de Usuário
- ✅ Backend - API para Gerenciamento de Usuários
- ✅ Associação de Usuários a Organizações e Times
- ✅ Sistema Básico de Autenticação (Token-based)
- ✅ Modelagem de Dados para Permissões e Papéis
- ✅ Backend - API para Gerenciamento de Papéis e Atribuição de Permissões
- ✅ Lógica de Autorização Baseada em Papéis

### Funcionalidades Pendentes
- ❌ Frontend - UI para Gerenciamento de Organizações
- ❌ Frontend - UI para Gerenciamento de Times
- ❌ Frontend - UI para Gerenciamento de Usuários
- ❌ Frontend - UI para Gerenciamento de Papéis e Permissões
- ❌ Sincronização de Usuários via LDAP/AD

## Etapa 2: Alerta e Gerenciamento de Casos

## Etapa 3: Enriquecimento e Contexto

## Etapa 4: Comunicação, Automação e Visibilidade

### Funcionalidades Implementadas

#### Notification Framework (Estrutura de Notificações)
- ✅ Modelagem de Dados para Notificações (Events, Channels, Rules, Logs)
- ✅ API para Gerenciamento de Canais de Notificação
- ✅ API para Gerenciamento de Regras de Notificação
- ✅ Sistema de Dispatch de Notificações com Condições
- ✅ Conectores para Múltiplos Canais (Email, Webhook, Slack, Custom HTTP)
- ✅ Templates para Formatação de Mensagens
- ✅ Registro de Eventos para Notificações (Case/Alert criação, mudanças de status, etc.)
- ✅ Teste e Validação de Regras de Notificação

#### Comprehensive APIs (APIs Abrangentes)
- ✅ API RESTful para Todas as Funcionalidades da Plataforma
- ✅ Documentação OpenAPI/Swagger
- ✅ Versionamento de API (/api/v1/...)
- ✅ Paginação, Filtragem e Ordenação Padrão
- ✅ Segurança Multi-Tenant Integrada
- ✅ Consistência em Endpoints e Responses
- ✅ Suporte a Autenticação por Token

#### Metrics and Dashboards (Métricas e Dashboards)
- ✅ Modelagem de Dados para Métricas e Snapshots
- ✅ Modelagem de Dados para Dashboards e Widgets
- ✅ API para Acesso a Métricas
- ✅ API para Gerenciamento de Dashboards e Widgets
- ✅ Sistema de Cálculo Periódico de Métricas
- ✅ Métricas Padrão para KPIs de Segurança
- ✅ Serviço para Cálculo de Métricas Customizadas

#### Task Scheduling (Agendamento de Tarefas) com Celery
- ✅ Processamento Assíncrono de Tarefas
- ✅ Cálculo Automático de Métricas (Diário, Semanal e Mensal)
- ✅ Envio Agendado de Notificações de Resumo
- ✅ Limpeza Automática de Logs Antigos
- ✅ Dashboard de Administração das Tarefas Agendadas

### Eventos de Notificação Disponíveis
- `ALERT_CREATED` - Quando um alerta é criado
- `ALERT_UPDATED` - Quando um alerta é atualizado
- `CASE_CREATED` - Quando um caso é criado
- `CASE_UPDATED` - Quando um caso é atualizado
- `CASE_STATUS_CHANGED` - Quando o status de um caso muda
- `TASK_CREATED` - Quando uma tarefa é criada
- `TASK_UPDATED` - Quando uma tarefa é atualizada
- `TASK_ASSIGNED` - Quando uma tarefa é atribuída a um usuário
- `COMMENT_ADDED_TO_CASE` - Quando um comentário é adicionado a um caso
- `COMMENT_ADDED_TO_ALERT` - Quando um comentário é adicionado a um alerta
- `DAILY_SUMMARY` - Resumo diário enviado automaticamente

### Tarefas Agendadas
- **Daily Metrics Calculation** - Cálculo diário de métricas (Executa às 01:00 AM)
- **Weekly Metrics Calculation** - Cálculo semanal de métricas (Executa aos Domingos às 02:00 AM)
- **Monthly Metrics Calculation** - Cálculo mensal de métricas (Executa no 1º dia do mês às 03:00 AM)
- **Daily Summary Notification** - Envio de resumo diário (Executa às 01:00 AM)
- **Clean Old Notification Logs** - Limpeza de logs antigos (Executa a cada 30 dias às 04:00 AM)

### Canais de Notificação Suportados
- **Webhook** - Envio de notificações para endpoints HTTP externos
- **Email** - Envio de notificações por email com suporte a templates HTML
- **Slack** - Envio de notificações para canais do Slack via Incoming Webhooks
- **Custom HTTP** - Requisições HTTP personalizadas para integrações específicas

### Métricas Padrão Disponíveis
- **Alert Count** - Número de alertas criados em um período
- **Alert Severity Distribution** - Distribuição de alertas por severidade
- **Case Count** - Número de casos criados em um período
- **Case Severity Distribution** - Distribuição de casos por severidade
- **Case Status Distribution** - Distribuição de casos por status
- **Case Resolution Time** - Tempo médio para resolução de casos (em horas)
- **Task Completion Rate** - Percentual de tarefas concluídas vs. total
- **Assignee Workload** - Número de casos abertos por responsável
- **MITRE Technique Frequency** - Técnicas MITRE ATT&CK mais observadas
- **Observable Type Distribution** - Distribuição de observáveis por tipo

### API de Notificações
- `GET /api/v1/notification-events/` - Listar eventos de notificação disponíveis
- `GET /api/v1/notification-channels/` - Listar canais de notificação
- `POST /api/v1/notification-channels/` - Criar canal de notificação
- `GET /api/v1/notification-rules/` - Listar regras de notificação
- `POST /api/v1/notification-rules/` - Criar regra de notificação
- `POST /api/v1/notifications/trigger-event/` - Disparar evento de notificação manualmente
- `GET /api/v1/notification-logs/` - Listar logs de notificação

### API de Métricas e Dashboards
- `GET /api/v1/metrics/` - Listar métricas disponíveis
- `GET /api/v1/metrics/{id}/data/` - Obter dados de uma métrica específica
- `GET /api/v1/metric-snapshots/` - Listar snapshots de métricas
- `GET /api/v1/dashboards/` - Listar dashboards
- `POST /api/v1/dashboards/` - Criar dashboard
- `GET /api/v1/dashboard-widgets/` - Listar widgets de dashboard
- `POST /api/v1/dashboard-widgets/` - Criar widget de dashboard

### Comandos de Gerenciamento
- `python manage.py create_default_notification_events` - Cria eventos de notificação padrão
- `python manage.py create_default_metrics` - Cria métricas padrão
- `python manage.py calculate_metrics [--date YYYY-MM-DD] [--granularity DAILY|WEEKLY|MONTHLY]` - Calcula snapshots de métricas
- `python manage.py create_default_celery_schedules` - Configura tarefas periódicas padrão do Celery Beat

## Configuração

### Requisitos
- Python 3.11+
- Django 5.2.1
- Django REST Framework 3.16.0
- PostgreSQL (opcional - SQLite disponível)
- Redis (para Celery)
- Celery 5.5.2

### Instalação

1. Clone o repositório e entre na pasta do projeto
```
git clone <url-do-repositorio>
cd projeto
```

2. Crie e ative um ambiente virtual
```
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/Mac
source .venv/bin/activate
```

3. Instale as dependências
```
pip install -r requirements.txt
```

4. Configure o banco de dados no arquivo .env
```
# Para usar SQLite
USE_SQLITE=1

# Para usar PostgreSQL
USE_SQLITE=0
POSTGRES_DB=postgres
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
```

5. Execute as migrações
```
python manage.py migrate
```

6. Crie um superusuário
```
python manage.py createsuperuser
```

7. Execute o servidor de desenvolvimento
```
python manage.py runserver
```

8. Para inicializar os dados padrão
```
bash init_data.sh
```

9. Para executar o Celery worker
```
celery -A core worker -l INFO
```

10. Para executar o Celery Beat
```
celery -A core beat -l INFO --scheduler django_celery_beat.schedulers:DatabaseScheduler
```

11. Acesse o admin em http://localhost:8000/admin/

## Development with uv

This project uses [uv](https://github.com/astral-sh/uv) as the Python package manager.

### Prerequisites

- Python 3.11+
- uv

### Installing uv

```bash
# On macOS and Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# On Windows
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### Setting up the project

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd <project-directory>
   ```

2. Create a virtual environment and install dependencies:
   ```bash
   uv venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   uv pip install -e .
   ```

3. Run migrations:
   ```bash
   python manage.py migrate
   ```

4. Initialize default data:
   ```bash
   bash init_data.sh
   ```

5. Run the development server:
   ```bash
   python manage.py runserver
   ```

### Docker Deployment

The project includes Docker configuration for easy deployment:

```bash
docker-compose up -d
```

This will start the following services:
- **web**: Django application with Gunicorn
- **db**: PostgreSQL database
- **redis**: Redis for Celery broker
- **celery_worker**: Celery worker for processing tasks
- **celery_beat**: Celery beat for scheduling tasks
- **nginx**: Nginx for serving static files

## API Documentation

API documentation is available at:
- `/api/docs/` - Swagger UI
- `/api/redoc/` - ReDoc interface
- `/api/schema/` - Raw OpenAPI schema 