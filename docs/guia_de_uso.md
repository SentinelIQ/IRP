# Guia de Uso da Aplicação IRP (Incident Response Platform)

Este guia fornece instruções detalhadas sobre como configurar, inicializar e utilizar o sistema IRP, uma plataforma de resposta a incidentes de segurança.

## Índice

1. [Requisitos do Sistema](#requisitos-do-sistema)
2. [Instalação](#instalação)
3. [Inicialização do Sistema](#inicialização-do-sistema)
4. [Estrutura Organizacional](#estrutura-organizacional)
5. [Gerenciamento de Usuários](#gerenciamento-de-usuários)
6. [Permissões e Papéis](#permissões-e-papéis)
7. [Casos e Alertas](#casos-e-alertas)
8. [Observáveis](#observáveis)
9. [Relatórios](#relatórios)
10. [Solução de Problemas](#solução-de-problemas)

## Requisitos do Sistema

- Python 3.10 ou superior
- PostgreSQL 13 ou superior
- Ambiente virtual Python (opcional, mas recomendado)
- Docker (opcional, para ambiente containerizado)

## Instalação

### Instalação Local

1. Clone o repositório:
   ```bash
   git clone <url-do-repositório>
   cd irp
   ```

2. Configure o ambiente virtual:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Linux/MacOS
   # ou
   .venv\Scripts\activate     # Windows
   ```

3. Instale as dependências:
   ```bash
   pip install -e .
   ```

4. Configure as variáveis de ambiente (crie ou edite o arquivo `.env`):
   ```
   DEBUG=True
   SECRET_KEY=sua-chave-secreta
   DATABASE_URL=postgresql://user:password@localhost:5432/irp
   ```

5. Execute as migrações:
   ```bash
   python manage.py migrate
   ```

### Instalação com Docker

1. Configure o arquivo `.env` conforme necessário
2. Execute:
   ```bash
   docker-compose up -d
   ```

## Inicialização do Sistema

### Configuração Inicial

Após a instalação, é necessário configurar o sistema com dados iniciais. Utilizamos um comando personalizado do Django para isso:

```bash
python manage.py setup_initial_data
```

Este comando configura:
- Usuário administrador
- Organização principal
- Permissões e papéis
- Dados de referência (severidades, status, tipos de observáveis, etc.)

#### Opções de Configuração

O comando `setup_initial_data` aceita várias opções para personalizar a inicialização:

```bash
# Personalizar usuário admin
python manage.py setup_initial_data --admin-username=admin2 --admin-email=admin2@example.com --admin-password=senha123

# Personalizar nome da organização principal
python manage.py setup_initial_data --org-name="Minha Empresa"

# Forçar reconfiguração mesmo se dados já existirem
python manage.py setup_initial_data --force

# Pular a configuração de dados de referência
python manage.py setup_initial_data --skip-reference-data
```

Após a execução, o comando exibirá as informações de acesso (URL, usuário e senha).

**IMPORTANTE**: Guarde essas informações em um local seguro e altere a senha do administrador após o primeiro acesso.

## Estrutura Organizacional

O sistema utiliza uma estrutura multi-tenant composta por:

### Organizações

As organizações são entidades de nível superior que separam completamente os dados.

- Para criar uma nova organização:
  - Acesse o menu "Administração" > "Organizações"
  - Clique em "Nova Organização"
  - Preencha os campos obrigatórios (nome, descrição, informações de contato)

### Times

Times são agrupamentos de usuários dentro de uma organização.

- Para criar um novo time:
  - Acesse o menu "Administração" > "Times"
  - Clique em "Novo Time"
  - Preencha os campos obrigatórios (nome, descrição)
  - Selecione a organização à qual o time pertence

- Para adicionar usuários a um time:
  - Acesse a página de detalhes do time
  - Vá para a aba "Membros"
  - Clique em "Adicionar Membro"
  - Selecione os usuários a serem adicionados

## Gerenciamento de Usuários

### Criação de Usuários

1. Acesse o menu "Administração" > "Usuários"
2. Clique em "Novo Usuário"
3. Preencha os campos obrigatórios:
   - Nome de usuário
   - E-mail
   - Senha
   - Organização
4. Opcionalmente, selecione times aos quais o usuário pertencerá
5. Atribua papéis ao usuário (veja a seção de Permissões e Papéis)

### Edição de Usuários

1. Acesse o menu "Administração" > "Usuários"
2. Localize o usuário na lista e clique em "Editar"
3. Realize as alterações necessárias

### Redefinição de Senha

Para redefinir a senha de um usuário como administrador:

1. Acesse a página de detalhes do usuário
2. Clique em "Redefinir Senha"
3. Informe a nova senha e confirme

Para alterar sua própria senha:

1. Clique no seu nome de usuário no canto superior direito
2. Selecione "Meu Perfil"
3. Clique em "Alterar Senha"
4. Informe a senha atual e a nova senha

## Permissões e Papéis

O sistema utiliza um modelo de controle de acesso baseado em papéis (RBAC).

### Papéis Padrão

- **Administrador**: Acesso total ao sistema
- **Coordenador**: Pode gerenciar casos, alertas e configurações, mas não usuários
- **Analista**: Pode visualizar e editar casos e alertas
- **Somente Leitura**: Acesso apenas para visualização
- **Usuário Básico**: Acesso mínimo ao sistema

### Criação de Papéis Personalizados

1. Acesse o menu "Administração" > "Papéis"
2. Clique em "Novo Papel"
3. Dê um nome e descrição ao papel
4. Selecione as permissões desejadas
5. Salve o papel

### Atribuição de Papéis a Usuários

1. Acesse a página de detalhes do usuário
2. Vá para a aba "Papéis"
3. Clique em "Atribuir Papel"
4. Selecione o papel e a organização
5. Clique em "Salvar"

## Casos e Alertas

### Alertas

Os alertas são notificações de eventos de segurança que podem se tornar casos.

- Para visualizar alertas:
  - Acesse o menu "Alertas"
  
- Para criar um alerta:
  1. Acesse o menu "Alertas"
  2. Clique em "Novo Alerta"
  3. Preencha os campos obrigatórios (título, descrição, severidade, etc.)
  4. Adicione observáveis, se necessário
  
- Para escalar um alerta para um caso:
  1. Abra o alerta
  2. Clique em "Escalar para Caso"
  3. Preencha os dados adicionais necessários
  4. Confirme a operação

### Casos

Os casos são investigações de incidentes de segurança.

- Para visualizar casos:
  - Acesse o menu "Casos"
  
- Para criar um caso:
  1. Acesse o menu "Casos"
  2. Clique em "Novo Caso"
  3. Preencha os campos obrigatórios (título, descrição, severidade, etc.)
  4. Adicione tarefas, observáveis, etc.

## Observáveis

Observáveis são indicadores técnicos relacionados a casos ou alertas.

### Tipos de Observáveis Suportados

- Endereços IP (IPv4, IPv6)
- Nomes de domínio
- URLs
- Endereços de e-mail
- Hashes de arquivos (MD5, SHA1, SHA256)
- Nomes de arquivos
- Contas de usuário
- Nomes de processos
- Chaves de registro do Windows
- Endereços MAC

### Adição de Observáveis

1. No detalhe de um caso ou alerta, vá para a aba "Observáveis"
2. Clique em "Adicionar Observável"
3. Selecione o tipo de observável
4. Preencha o valor
5. Selecione os níveis TLP e PAP apropriados
6. Adicione contexto, se necessário

## Relatórios

Para gerar relatórios:

1. Acesse o menu "Relatórios"
2. Selecione o tipo de relatório
3. Configure os filtros desejados
4. Clique em "Gerar Relatório"
5. O relatório pode ser baixado em PDF, DOCX ou HTML

## Solução de Problemas

### Problemas de Inicialização

- Se o comando `setup_initial_data` falhar com erro de banco de dados:
  1. Verifique se as credenciais do banco de dados estão corretas
  2. Certifique-se de que as migrações foram aplicadas corretamente

- Se aparecer conflito de permissões:
  1. Utilize a opção `--force` para sobrescrever os dados existentes
  2. Ou restaure o banco de dados para um estado limpo antes de inicializar

### Problemas de Acesso

- Se não conseguir fazer login:
  1. Verifique se o usuário foi criado corretamente
  2. Tente redefinir a senha pelo Django Admin
  3. Verifique se o usuário está associado a uma organização

- Se não tiver acesso a determinadas funcionalidades:
  1. Verifique se o usuário tem o papel adequado
  2. Verifique se o papel tem as permissões necessárias
  3. Consulte o administrador do sistema para ajustar as permissões 