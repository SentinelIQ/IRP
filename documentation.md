# Documentação da Nova Estrutura da API

## Visão Geral

Este documento descreve a nova estrutura modularizada da API, detalhando a organização de diretórios, a comunicação entre módulos e os padrões adotados.

## Estrutura de Diretórios

A API foi reorganizada em módulos independentes, cada um representando um domínio da aplicação:

```
irp/
├── accounts/            # Gestão de usuários, organizações e controle de acesso
├── alerts/              # Alertas de segurança
├── audit/               # Logs de auditoria
├── cases/               # Casos de investigação
├── common/              # Código compartilhado entre os módulos
├── integrations/        # Integrações com sistemas externos
│   └── misp/            # Integração com MISP
├── knowledge_base/      # Base de conhecimento
├── metrics/             # Métricas e dashboards
├── mitre/               # Framework MITRE ATT&CK
├── notifications/       # Sistema de notificações
├── observables/         # Observáveis de segurança
├── reports/             # Geração de relatórios
└── timeline/            # Eventos de timeline
```

## Módulos

### accounts
Responsável pelo gerenciamento de usuários, organizações, equipes, funções e permissões.

### alerts
Contém modelos e funcionalidades para alertas de segurança, incluindo severidade, status e campos personalizados.

### audit
Mantém registros de auditoria para todas as ações realizadas na plataforma.

### cases
Gerencia casos de investigação, tarefas, status e campos personalizados.

### common
Fornece funcionalidades compartilhadas, como modelos base, utilitários, middlewares e permissões.

### integrations
Contém subpacotes para integrações com sistemas externos:
- **misp**: Integração com a plataforma MISP para compartilhamento de inteligência de ameaças.

### knowledge_base
Gerencia artigos da base de conhecimento e categorias.

### metrics
Responsável por métricas, snapshots e dashboards.

### mitre
Implementa o framework MITRE ATT&CK com táticas e técnicas.

### notifications
Sistema de notificações com canais, regras e logs.

### observables
Gerencia observáveis de segurança, tipos e níveis TLP/PAP.

### reports
Geração de relatórios a partir de casos e templates.

### timeline
Registra eventos de timeline relacionados a casos e alertas.

## Relações entre Módulos

Os módulos podem se comunicar entre si através de importações. Alguns módulos dependem fortemente de outros:

- **alerts** e **cases** dependem de **observables** e **mitre**
- **timeline** é utilizado por **alerts** e **cases**
- **metrics** depende de vários módulos para coletar estatísticas
- Todos os módulos dependem de **common** para funcionalidades compartilhadas
- Todos os módulos interagem com **accounts** para controle de acesso

## Padrões de Projeto

### Estrutura de Arquivos
Cada módulo segue uma estrutura padrão:
- `__init__.py`: Inicialização do módulo
- `admin.py`: Configuração do admin do Django
- `apps.py`: Configuração do aplicativo Django
- `models.py`: Modelos de dados
- `serializers.py`: Serializers para API REST
- `services.py`: Lógica de negócio
- `views.py`: Views da API
- `urls.py`: Rotas da API
- `tests.py`: Testes automatizados

### APIs e Rotas
As APIs seguem o padrão RESTful e utilizam o Django REST Framework. As rotas são organizadas por módulo:

```
/api/v2/accounts/...
/api/v2/alerts/...
/api/v2/cases/...
```

### Modelos Base
O módulo `common` fornece modelos base abstratos que são herdados por outros módulos:
- `BaseModel`: Contém campos comuns como UUID, created_at e updated_at
- `OrganizationOwnedModel`: Para entidades que pertencem a uma organização
- `UserTrackingModel`: Para rastreamento de criação e modificação
- `SoftDeleteModel`: Para exclusão lógica

### Auditoria
O módulo `audit` fornece funcionalidades para registrar ações dos usuários. Todas as operações críticas são auditadas usando o decorator `audit_action`.

### Middlewares
O módulo `common` implementa middlewares personalizados:
- `RequestMiddleware`: Armazena a requisição atual para acesso em qualquer lugar da aplicação

## Migrations e Deploy

### Migrations
Cada módulo possui suas próprias migrations. Ao fazer alterações nos modelos, execute:
```
python manage.py makemigrations
python manage.py migrate
```

### Deploy
O processo de deploy envolve:
1. Atualizar o código-fonte
2. Instalar dependências
3. Aplicar migrations
4. Coletar arquivos estáticos
5. Reiniciar os serviços (web, celery, etc.)

## Considerações Futuras

- Mover mais lógica para serviços, reduzindo o código nas views
- Implementar testes automatizados mais abrangentes
- Melhorar a documentação da API
- Implementar cache para melhorar o desempenho 