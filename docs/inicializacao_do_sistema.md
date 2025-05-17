# Inicialização do Sistema IRP

Este documento descreve em detalhes o processo de inicialização e configuração inicial do sistema IRP (Incident Response Platform), focando especialmente no comando unificado `setup_initial_data`.

## O que é o Comando `setup_initial_data`?

O comando `setup_initial_data` é um script Django personalizado criado para configurar todos os dados iniciais necessários para o funcionamento da plataforma. Este comando unifica a configuração de:

- Usuário administrador
- Organização principal
- Permissões e papéis do sistema
- Dados de referência (severidades, status, tipos de observáveis, etc.)

Em vez de executar múltiplos comandos ou configurar manualmente, este script facilita a inicialização completa do sistema em uma única operação.

## Como Executar

A forma básica de executar o comando é:

```bash
python manage.py setup_initial_data
```

Por padrão, o comando irá:
1. Criar um usuário administrador com nome `admin` e e-mail `admin@example.com`
2. Gerar uma senha aleatória segura para o administrador (exibida no console)
3. Criar uma organização principal chamada "Organização Principal"
4. Configurar permissões e papéis do sistema
5. Configurar dados de referência para alertas, casos e observáveis

## Opções Disponíveis

O comando aceita várias opções para personalizar a inicialização:

| Opção | Descrição | Exemplo |
|-------|-----------|---------|
| `--admin-username` | Define o nome do usuário administrador | `--admin-username=diretor` |
| `--admin-email` | Define o e-mail do usuário administrador | `--admin-email=diretor@empresa.com` |
| `--admin-password` | Define a senha do usuário administrador (se não fornecida, uma senha aleatória será gerada) | `--admin-password=S3nh@S3gur@` |
| `--org-name` | Define o nome da organização principal | `--org-name="Empresa Security"` |
| `--force` | Força a reconfiguração mesmo que dados já existam | `--force` |
| `--skip-reference-data` | Pula a criação de dados de referência (útil para atualizações) | `--skip-reference-data` |

## Exemplos de Uso

### Configuração Básica
```bash
python manage.py setup_initial_data
```

### Personalização Completa
```bash
python manage.py setup_initial_data --admin-username=diretor --admin-email=diretor@empresa.com --admin-password=S3nh@S3gur@ --org-name="Empresa Security"
```

### Reconfiguração Forçada
```bash
python manage.py setup_initial_data --force
```

### Apenas Atualizar Administrador e Organização (Sem Dados de Referência)
```bash
python manage.py setup_initial_data --skip-reference-data
```

## O Que é Configurado

### 1. Etapa de Permissões e Papéis

Esta etapa configura:

- **Permissões**: Códigos de permissão para todas as funcionalidades do sistema (organizações, times, usuários, casos, alertas, etc.)
- **Papéis**: Conjuntos de permissões pré-configurados para perfis comuns:
  - Administrador: Acesso total ao sistema (todas as permissões)
  - Analista: Permissões para trabalhar com casos e alertas
  - Coordenador: Permissões para gerenciar equipes e configurações
  - Somente Leitura: Permissões apenas para visualização
  - Usuário Básico: Permissões mínimas necessárias

### 2. Etapa de Usuário Admin e Organização

Esta etapa configura:

- **Usuário Administrador**: Cria um superusuário no Django com perfil de sistema
- **Organização Principal**: Cria a organização inicial do sistema
- **Perfil de Administrador**: Associa o usuário admin à organização e configura seu perfil
- **Associação de Papel**: Associa o papel de Administrador ao usuário admin

### 3. Etapa de Dados de Referência

Esta etapa configura:

- **Severidades de Alertas**: Low, Medium, High, Critical
- **Status de Alertas**: New, Open, In Progress, Escalated, Closed (False Positive), Closed (Resolved)
- **Severidades de Casos**: Low, Medium, High, Critical
- **Status de Casos**: Open, Investigating, Containment, Eradication, Recovery, Closed, Closed (False Positive)
- **Status de Tarefas**: ToDo, In Progress, Done, Blocked
- **Tipos de Observáveis**: ipv4-addr, ipv6-addr, domain-name, url, email-addr, file-hash-md5, etc.
- **Níveis TLP**: RED, AMBER, GREEN, WHITE
- **Níveis PAP**: RED, AMBER, GREEN, WHITE

## Solução de Problemas

### A Inicialização Falha com Erro de Banco de Dados

1. Verifique se o banco de dados está criado e acessível
2. Certifique-se de que as migrações foram aplicadas:
   ```bash
   python manage.py migrate
   ```
3. Verifique as credenciais do banco de dados no arquivo .env

### Erro de Permissão Negada

1. Certifique-se de que o usuário do banco de dados tem permissões suficientes
2. Em ambiente Docker, verifique se os volumes estão configurados corretamente

### Conflito de Dados Existentes

1. Use a opção `--force` para sobrescrever dados existentes:
   ```bash
   python manage.py setup_initial_data --force
   ```
2. Alternativamente, limpe o banco de dados e reinicie:
   ```bash
   python manage.py flush  # Cuidado! Isso apaga todos os dados
   python manage.py migrate
   python manage.py setup_initial_data
   ```

### Não Consigo Fazer Login Após Inicialização

1. Verifique se anotou corretamente a senha gerada automaticamente
2. Tente redefinir a senha pelo Django Admin:
   ```bash
   python manage.py changepassword admin
   ```

## Considerações para Produção

Ao inicializar o sistema em ambiente de produção:

1. Use uma senha forte e segura para o administrador
2. Após o primeiro login, altere a senha gerada automaticamente
3. Em ambientes sensíveis, considere usar a opção `--admin-password` para definir manualmente a senha (evitando mostrar a senha no console)
4. Considere remover ou restringir o acesso ao arquivo .env após a configuração
5. Em ambientes de alta segurança, revise manualmente as permissões dos papéis após a inicialização 