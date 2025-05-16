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

## Configuração

### Requisitos
- Python 3.8+
- Django 5.2.1
- Django REST Framework 3.16.0
- PostgreSQL (opcional - SQLite disponível)

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

8. Acesse o admin em http://localhost:8000/admin/

## API Endpoints

### Autenticação
- `POST /api/login/` - Obter token de autenticação
- `POST /api/logout/` - Invalidar token atual

### Organizações
- `GET /api/organizations/` - Listar organizações
- `POST /api/organizations/` - Criar organização
- `GET /api/organizations/{id}/` - Detalhes de uma organização
- `PUT /api/organizations/{id}/` - Atualizar organização
- `DELETE /api/organizations/{id}/` - Excluir organização

### Times
- `GET /api/teams/` - Listar times
- `POST /api/teams/` - Criar time
- `GET /api/teams/{id}/` - Detalhes de um time
- `PUT /api/teams/{id}/` - Atualizar time
- `DELETE /api/teams/{id}/` - Excluir time

### Usuários
- `GET /api/users/` - Listar usuários
- `POST /api/users/` - Criar usuário
- `GET /api/users/{id}/` - Detalhes de um usuário
- `PUT /api/users/{id}/` - Atualizar usuário
- `DELETE /api/users/{id}/` - Excluir usuário

### Papéis e Permissões
- `GET /api/roles/` - Listar papéis
- `POST /api/roles/` - Criar papel
- `GET /api/permissions/` - Listar permissões
- `GET /api/user-roles/` - Listar associações usuário-papel
- `POST /api/user-roles/` - Criar associação usuário-papel
- `GET /api/role-permissions/` - Listar associações papel-permissão
- `POST /api/role-permissions/` - Criar associação papel-permissão

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

4. Run the development server:
   ```bash
   python manage.py runserver
   ```

### Adding new dependencies

```bash
uv add <package-name>
```

### Docker Deployment

The project includes Docker configuration for easy deployment:

```bash
docker-compose up -d
```

This will start both the Django application and the PostgreSQL database.

## API Documentation

API documentation is available at `/api/docs/` when the server is running. 