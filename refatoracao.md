# Plano de Modularização da API

Baseado na análise do código, sugiro reorganizar a estrutura da aplicação em módulos mais coesos. O projeto atual tem um único aplicativo `api` que contém toda a funcionalidade, tornando difícil a manutenção à medida que o sistema cresce.

## 1. Estrutura proposta de módulos

```
irp/  # Nome do pacote principal (Incident Response Platform)
  ├── accounts/  # Gerenciamento de usuários, perfis, funções e permissões
  │   ├── __init__.py
  │   ├── admin.py
  │   ├── apps.py
  │   ├── models.py
  │   ├── serializers.py
  │   ├── services.py
  │   ├── views.py
  │   ├── urls.py
  │   └── tests.py
  │
  ├── alerts/  # Gerenciamento de alertas
  │   ├── __init__.py
  │   ├── admin.py
  │   ├── apps.py
  │   ├── models.py
  │   ├── serializers.py
  │   ├── services.py
  │   ├── views.py
  │   ├── urls.py
  │   └── tests.py
  │
  ├── cases/  # Gerenciamento de casos
  │   ├── __init__.py
  │   ├── admin.py
  │   ├── apps.py
  │   ├── models.py
  │   ├── serializers.py
  │   ├── services.py
  │   ├── views.py
  │   ├── urls.py
  │   └── tests.py
  │
  ├── observables/  # Gerenciamento de observáveis
  │   ├── __init__.py
  │   ├── admin.py
  │   ├── apps.py
  │   ├── models.py
  │   ├── serializers.py
  │   ├── services.py
  │   ├── views.py
  │   ├── urls.py
  │   └── tests.py
  │
  ├── timeline/  # Gerenciamento da linha do tempo
  │   ├── __init__.py
  │   ├── admin.py
  │   ├── apps.py
  │   ├── models.py
  │   ├── serializers.py
  │   ├── services.py
  │   ├── views.py
  │   ├── urls.py
  │   └── tests.py
  │
  ├── mitre/  # Integração com MITRE ATT&CK
  │   ├── __init__.py
  │   ├── admin.py
  │   ├── apps.py
  │   ├── models.py
  │   ├── serializers.py
  │   ├── services.py
  │   ├── views.py
  │   ├── urls.py
  │   └── tests.py
  │
  ├── knowledge_base/  # Base de conhecimento
  │   ├── __init__.py
  │   ├── admin.py
  │   ├── apps.py
  │   ├── models.py
  │   ├── serializers.py
  │   ├── services.py
  │   ├── views.py
  │   ├── urls.py
  │   └── tests.py
  │
  ├── notifications/  # Sistema de notificações
  │   ├── __init__.py
  │   ├── admin.py
  │   ├── apps.py
  │   ├── models.py
  │   ├── serializers.py
  │   ├── services.py
  │   ├── views.py
  │   ├── urls.py
  │   └── tests.py
  │
  ├── metrics/  # Métricas e dashboard
  │   ├── __init__.py
  │   ├── admin.py
  │   ├── apps.py
  │   ├── models.py
  │   ├── serializers.py
  │   ├── services.py
  │   ├── views.py
  │   ├── urls.py
  │   └── tests.py
  │
  ├── audit/  # Auditoria
  │   ├── __init__.py
  │   ├── admin.py
  │   ├── apps.py
  │   ├── models.py
  │   ├── serializers.py
  │   ├── services.py
  │   ├── views.py
  │   ├── urls.py
  │   └── tests.py
  │
  ├── integrations/  # Integrações externas (MISP, etc.)
  │   ├── __init__.py
  │   ├── misp/
  │   │   ├── __init__.py
  │   │   ├── models.py
  │   │   ├── serializers.py
  │   │   ├── services.py
  │   │   ├── views.py
  │   │   └── urls.py
  │   └── apps.py
  │
  ├── reports/  # Geração de relatórios
  │   ├── __init__.py
  │   ├── admin.py
  │   ├── apps.py
  │   ├── models.py
  │   ├── serializers.py
  │   ├── services.py
  │   ├── views.py
  │   ├── urls.py
  │   └── tests.py
  │
  ├── common/  # Código compartilhado e utilitários
  │   ├── __init__.py
  │   ├── models.py
  │   ├── utils.py
  │   ├── middleware.py
  │   └── permissions.py
```

## 2. Passos para a modularização

1. **Criar a estrutura de diretórios**:
   - Criar os pacotes conforme a estrutura acima

2. **Migrar modelos**:
   - Mover os modelos relacionados para cada pacote
   - Atualizar as referências entre modelos utilizando o sistema de importação do Django

3. **Migrar serializers**:
   - Mover os serializers para os pacotes correspondentes
   - Atualizar as importações

4. **Migrar views**:
   - Distribuir as views para os pacotes apropriados
   - Atualizar as importações

5. **Criar URLConf para cada módulo**:
   - Definir as rotas específicas para cada módulo
   - Atualizar o URLConf principal para incluir os módulos

6. **Atualizar os serviços**:
   - Mover as classes de serviço para os pacotes apropriados
   - Atualizar as importações

7. **Configurar aplicativos Django**:
   - Criar classes `AppConfig` para cada módulo
   - Registrar os aplicativos em `INSTALLED_APPS`

8. **Migrações do banco de dados**:
   - Criar migrações para refletir a nova estrutura

## 3. Estratégia de migração

Para realizar a migração sem impactar o sistema em produção, recomendo:

1. **Abordagem gradual**: migrar um módulo de cada vez
2. **Manter compatibilidade temporária**: criar importações de compatibilidade no aplicativo `api` original
3. **Testes abrangentes**: garantir que a funcionalidade continue intacta após cada módulo migrado
4. **Remoção gradual**: remover o código do aplicativo `api` original à medida que os novos módulos são validados

## 4. Benefícios desta modularização

- **Maior coesão**: cada módulo tem responsabilidades bem definidas
- **Menor acoplamento**: dependências explícitas entre módulos
- **Manutenção simplificada**: alterações em um módulo têm impacto limitado em outros
- **Código mais organizado**: facilita a compreensão do sistema
- **Melhor testabilidade**: testes mais focados em funcionalidades específicas
- **Escalabilidade**: facilita o desenvolvimento paralelo por diferentes equipes

## 5. Exemplo detalhado: Migração do módulo Accounts

Para ilustrar o processo, vamos detalhar o processo de migração do módulo `accounts`:

1. **Criar a estrutura**:
   ```
   mkdir -p irp/accounts
   touch irp/accounts/__init__.py
   touch irp/accounts/admin.py
   touch irp/accounts/apps.py
   touch irp/accounts/models.py
   touch irp/accounts/serializers.py
   touch irp/accounts/views.py
   touch irp/accounts/urls.py
   touch irp/accounts/tests.py
   ```

2. **Mover os modelos**:
   - Mover `Organization`, `Team`, `Profile`, `Role`, `Permission`, `UserRole`, `RolePermission` para `irp/accounts/models.py`

3. **Mover os serializers**:
   - Mover os serializers correspondentes para `irp/accounts/serializers.py`

4. **Mover as views**:
   - Mover `OrganizationViewSet`, `TeamViewSet`, `ProfileViewSet`, `RoleViewSet`, `PermissionViewSet`, `UserRoleViewSet`, `RolePermissionViewSet` para `irp/accounts/views.py`

5. **Configurar URLs**:
   - Criar rotas específicas em `irp/accounts/urls.py`

6. **Atualizar admin.py**:
   - Mover os registros de admin para `irp/accounts/admin.py`

7. **Configurar o app**:
   ```python
   # irp/accounts/apps.py
   from django.apps import AppConfig

   class AccountsConfig(AppConfig):
       default_auto_field = 'django.db.models.BigAutoField'
       name = 'irp.accounts'
       verbose_name = 'User & Organization Management'
   ```

8. **Atualizar INSTALLED_APPS**:
   ```python
   INSTALLED_APPS = [
       # ...
       'irp.accounts.apps.AccountsConfig',
       # ...
   ]
   ```

## 6. Próximos passos

Após a modularização, recomendo:

1. **Revisão da arquitetura**: avaliar se a divisão dos módulos atende às necessidades do projeto
2. **Implementação de testes**: expandir a cobertura de testes para cada módulo
3. **Documentação**: atualizar a documentação para refletir a nova estrutura
4. **Análise de desempenho**: verificar se a modularização afetou o desempenho
5. **Refinamento da API**: revisitar os endpoints para garantir consistência entre os módulos

## 7. Distribuição dos modelos por módulo

### accounts
- Organization
- Team
- Profile
- Role
- Permission
- UserRole
- RolePermission

### alerts
- AlertSeverity
- AlertStatus
- Alert
- AlertComment
- AlertCustomFieldDefinition
- AlertCustomFieldValue
- AlertObservable
- AlertMitreTechnique

### cases
- CaseSeverity
- CaseStatus
- CaseTemplate
- Case
- CaseComment
- CaseCustomFieldDefinition
- CaseCustomFieldValue
- CaseObservable
- CaseMitreTechnique
- Task
- TaskStatus

### observables
- ObservableType
- TLPLevel
- PAPLevel
- Observable

### timeline
- TimelineEvent

### mitre
- MitreTactic
- MitreTechnique
- TechniqueTactic

### knowledge_base
- KBCategory
- KBArticle
- KBArticleVersion

### notifications
- NotificationEvent
- NotificationChannel
- NotificationRule
- NotificationLog

### metrics
- Metric
- MetricSnapshot
- Dashboard
- DashboardWidget

### audit
- AuditLog

### integrations/misp
- MISPInstance
- MISPExport
- MISPImport
- ObservableMISPMapping

### reports
- ReportTemplate
- GeneratedReport

## 8. Mapeamento das views e arquivos

A seguir, um mapeamento de cada view para seu respectivo módulo:

### accounts
- OrganizationViewSet
- TeamViewSet
- ProfileViewSet
- RoleViewSet
- PermissionViewSet
- UserRoleViewSet
- RolePermissionViewSet
- UserViewSet

### alerts
- AlertSeverityViewSet
- AlertStatusViewSet
- AlertViewSet
- AlertCommentViewSet
- AlertCustomFieldDefinitionViewSet
- AlertCustomFieldValueViewSet
- AlertObservableViewSet
- AlertMitreTechniqueViewSet

### cases
- CaseSeverityViewSet
- CaseStatusViewSet
- CaseTemplateViewSet
- CaseViewSet
- CaseCommentViewSet
- CaseCustomFieldDefinitionViewSet
- CaseCustomFieldValueViewSet
- TaskStatusViewSet
- TaskViewSet
- CaseObservableViewSet
- CaseMitreTechniqueViewSet

### observables
- ObservableTypeViewSet
- TLPLevelViewSet
- PAPLevelViewSet
- ObservableViewSet

### timeline
- TimelineEventViewSet
- create_timeline_event

### mitre
- MitreTacticViewSet
- MitreTechniqueViewSet
- import_mitre_attack

### knowledge_base
- KBCategoryViewSet
- KBArticleViewSet
- kb_search
- kb_related_articles

### notifications
- NotificationEventViewSet
- NotificationChannelViewSet
- NotificationRuleViewSet
- NotificationLogViewSet
- NotificationViewSet

### metrics
- MetricViewSet
- MetricSnapshotViewSet
- DashboardViewSet
- DashboardWidgetViewSet
- dashboard_stats
- calculate_metrics

### audit
- AuditLogViewSet

### integrations/misp
- MISPInstanceViewSet
- MISPImportViewSet
- MISPExportViewSet
- trigger_misp_import
- export_case_to_misp

### reports
- ReportTemplateViewSet
- GeneratedReportViewSet
- generate_case_report
- reports

### common (ou mantida na raiz)
- HelloWorldView
- LoginView
- LogoutView 