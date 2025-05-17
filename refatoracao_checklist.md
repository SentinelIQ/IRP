# Checklist de Migração por Módulo

Este documento apresenta uma checklist detalhada para acompanhar o progresso da modularização da API conforme definido em `refatoracao.md`.

## Legenda
- [ ] Não iniciado
- [🟡] Em progresso
- [✓] Concluído
- [ ] Não se aplica

## Progresso Geral

- [✓] **Migração de URLs**
  - [✓] Migrar rotas de cada módulo para seus respectivos arquivos urls.py
  - [✓] Configurar corretamente as rotas no core/urls.py
  - [✓] Remover api/urls.py após migração completa
  
- [✓] **Migração de funções compartilhadas**
  - [✓] Migrar função audit_action para irp/common/audit.py
  - [✓] Atualizar imports nos módulos que usam audit_action
  - [✓] Migrar has_permission de utils.py para permissions.py

## 1. accounts

- [✓] **Estrutura de diretórios**
  - [✓] Criar diretório `irp/accounts`
  - [✓] Criar arquivo `__init__.py`
  - [✓] Criar arquivo `admin.py`
  - [✓] Criar arquivo `apps.py`
  - [✓] Criar arquivo `models.py`
  - [✓] Criar arquivo `serializers.py`
  - [✓] Criar arquivo `services.py`
  - [✓] Criar arquivo `views.py`
  - [✓] Criar arquivo `urls.py`
  - [✓] Criar arquivo `tests.py`

- [✓] **Migração de modelos**
  - [✓] Organization
  - [✓] Team
  - [✓] Profile
  - [✓] Role
  - [✓] Permission
  - [✓] UserRole
  - [✓] RolePermission

- [✓] **Migração de serializers**
  - [✓] OrganizationSerializer
  - [✓] TeamSerializer
  - [✓] ProfileSerializer
  - [✓] RoleSerializer
  - [✓] PermissionSerializer
  - [✓] UserRoleSerializer
  - [✓] RolePermissionSerializer
  - [✓] UserSerializer

- [✓] **Migração de views**
  - [✓] OrganizationViewSet
  - [✓] TeamViewSet
  - [✓] ProfileViewSet
  - [✓] RoleViewSet
  - [✓] PermissionViewSet
  - [✓] UserRoleViewSet
  - [✓] RolePermissionViewSet
  - [✓] UserViewSet

- [✓] **Configuração de URLs**
  - [✓] Criar rotas para cada viewset
  - [✓] Incluir no URLconf principal

- [✓] **Migração de admin**
  - [✓] Organization
  - [✓] Team
  - [✓] Profile
  - [✓] Role
  - [✓] Permission
  - [✓] UserRole
  - [✓] RolePermission

- [✓] **Configuração do aplicativo**
  - [✓] Criar classe AccountsConfig
  - [✓] Adicionar ao INSTALLED_APPS

- [✓] **Migrações do banco de dados**
  - [✓] Executar makemigrations
  - [✓] Executar migrate

- [ ] **Testes**
  - [ ] Criar testes unitários
  - [ ] Criar testes de integração
  - [ ] Verificar funcionamento do módulo isoladamente
  - [ ] Verificar integração com outros módulos

## 2. alerts

- [✓] **Estrutura de diretórios**
  - [✓] Criar diretório `irp/alerts`
  - [✓] Criar arquivo `__init__.py`
  - [✓] Criar arquivo `admin.py`
  - [✓] Criar arquivo `apps.py`
  - [✓] Criar arquivo `models.py`
  - [✓] Criar arquivo `serializers.py`
  - [✓] Criar arquivo `services.py`
  - [✓] Criar arquivo `views.py`
  - [✓] Criar arquivo `urls.py`
  - [✓] Criar arquivo `tests.py`

- [✓] **Migração de modelos**
  - [✓] AlertSeverity
  - [✓] AlertStatus
  - [✓] Alert
  - [✓] AlertComment
  - [✓] AlertCustomFieldDefinition
  - [✓] AlertCustomFieldValue
  - [✓] AlertObservable
  - [✓] AlertMitreTechnique

- [✓] **Migração de serializers**
  - [✓] AlertSeveritySerializer
  - [✓] AlertStatusSerializer
  - [✓] AlertCommentSerializer
  - [✓] AlertCustomFieldDefinitionSerializer
  - [✓] AlertCustomFieldValueSerializer
  - [✓] AlertSerializer
  - [✓] SimplifiedAlertSerializer
  - [✓] AlertObservableSerializer
  - [✓] AlertMitreTechniqueSerializer

- [✓] **Migração de views**
  - [✓] AlertSeverityViewSet
  - [✓] AlertStatusViewSet
  - [✓] AlertViewSet
  - [✓] AlertCommentViewSet
  - [✓] AlertCustomFieldDefinitionViewSet
  - [✓] AlertCustomFieldValueViewSet
  - [✓] AlertObservableViewSet
  - [✓] AlertMitreTechniqueViewSet

- [✓] **Configuração de URLs**
  - [✓] Criar rotas para cada viewset
  - [✓] Incluir no URLconf principal
  - [✓] Configurar rotas aninhadas

- [✓] **Migração de admin**
  - [✓] AlertSeverity
  - [✓] AlertStatus
  - [✓] Alert
  - [✓] AlertComment
  - [✓] AlertCustomFieldDefinition
  - [✓] AlertCustomFieldValue
  - [✓] AlertObservable
  - [✓] AlertMitreTechnique

- [✓] **Configuração do aplicativo**
  - [✓] Criar classe AlertsConfig
  - [✓] Adicionar ao INSTALLED_APPS

- [✓] **Migrações do banco de dados**
  - [✓] Executar makemigrations
  - [✓] Executar migrate

- [🟡] **Testes**
  - [✓] Criar testes unitários
  - [✓] Criar testes de integração
  - [ ] Verificar funcionamento do módulo isoladamente
  - [ ] Verificar integração com outros módulos

## 3. cases

- [✓] **Estrutura de diretórios**
  - [✓] Criar diretório `irp/cases`
  - [✓] Criar arquivo `__init__.py`
  - [✓] Criar arquivo `admin.py`
  - [✓] Criar arquivo `apps.py`
  - [✓] Criar arquivo `models.py`
  - [✓] Criar arquivo `serializers.py`
  - [✓] Criar arquivo `views.py`
  - [✓] Criar arquivo `urls.py`
  - [✓] Criar arquivo `tests.py`

- [✓] **Migração de modelos**
  - [✓] CaseSeverity
  - [✓] CaseStatus
  - [✓] CaseTemplate
  - [✓] Case
  - [✓] CaseComment
  - [✓] CaseCustomFieldDefinition
  - [✓] CaseCustomFieldValue
  - [✓] CaseMitreTechnique
  - [✓] Task
  - [✓] TaskStatus

- [✓] **Migração de serializers**
  - [✓] CaseSeveritySerializer
  - [✓] CaseStatusSerializer
  - [✓] CaseTemplateSerializer
  - [✓] TaskStatusSerializer
  - [✓] TaskSerializer
  - [✓] CaseCommentSerializer
  - [✓] CaseCustomFieldDefinitionSerializer
  - [✓] CaseObservableSerializer
  - [✓] CaseMitreTechniqueSerializer
  - [✓] CaseSerializer

- [✓] **Migração de views**
  - [✓] CaseSeverityViewSet
  - [✓] CaseStatusViewSet
  - [✓] CaseTemplateViewSet
  - [✓] CaseViewSet
  - [✓] CaseCommentViewSet
  - [✓] CaseCustomFieldDefinitionViewSet
  - [✓] CaseCustomFieldValueViewSet
  - [✓] TaskViewSet
  - [✓] CaseObservableViewSet
  - [✓] CaseMitreTechniqueViewSet

- [✓] **Configuração de URLs**
  - [✓] Criar rotas para cada viewset
  - [✓] Incluir no URLconf principal
  - [✓] Configurar rotas aninhadas

- [✓] **Migração de admin**
  - [✓] CaseSeverity
  - [✓] CaseStatus
  - [✓] CaseTemplate
  - [✓] Case
  - [✓] CaseComment
  - [✓] CaseCustomFieldDefinition
  - [✓] CaseCustomFieldValue
  - [✓] TaskStatus
  - [✓] CaseObservable
  - [✓] CaseMitreTechnique

- [✓] **Configuração do aplicativo**
  - [✓] Criar classe CasesConfig
  - [ ] Executar migrate

- [✓] **Migrações do banco de dados**
  - [✓] Executar makemigrations
  - [✓] Executar migrate
  - [ ] Verificar funcionamento do módulo isoladamente
  - [ ] Verificar integração com outros módulos

## 4. observables

- [✓] **Estrutura de diretórios**
  - [✓] Criar diretório `irp/observables`
  - [✓] Criar arquivo `__init__.py`
  - [✓] Criar arquivo `admin.py`
  - [✓] Criar arquivo `apps.py`
  - [✓] Criar arquivo `models.py`
  - [✓] Criar arquivo `serializers.py`
  - [✓] Criar arquivo `services.py`
  - [✓] Criar arquivo `views.py`
  - [✓] Criar arquivo `urls.py`
  - [✓] Criar arquivo `tests.py`

- [✓] **Migração de modelos**
  - [✓] ObservableType
  - [✓] TLPLevel
  - [✓] PAPLevel
  - [✓] Observable

- [✓] **Migração de serializers**
  - [✓] ObservableTypeSerializer
  - [✓] TLPLevelSerializer
  - [✓] PAPLevelSerializer
  - [✓] ObservableSerializer

- [✓] **Migração de views**
  - [✓] ObservableTypeViewSet
  - [✓] TLPLevelViewSet
  - [✓] PAPLevelViewSet
  - [✓] ObservableViewSet

- [✓] **Configuração de URLs**
  - [✓] Criar rotas para cada viewset
  - [✓] Incluir no URLconf principal

- [✓] **Migração de admin**
  - [✓] ObservableType
  - [✓] TLPLevel
  - [✓] PAPLevel
  - [✓] Observable

- [✓] **Configuração do aplicativo**
  - [✓] Criar classe ObservablesConfig
  - [✓] Adicionar ao INSTALLED_APPS

- [✓] **Migrações do banco de dados**
  - [✓] Executar makemigrations
  - [✓] Executar migrate

- [🟡] **Testes**
  - [✓] Criar testes unitários
  - [ ] Criar testes de integração
  - [ ] Verificar funcionamento do módulo isoladamente
  - [ ] Verificar integração com outros módulos

## 5. timeline

- [✓] **Estrutura de diretórios**
  - [✓] Criar diretório `irp/timeline`
  - [✓] Criar arquivo `__init__.py`
  - [✓] Criar arquivo `admin.py`
  - [✓] Criar arquivo `apps.py`
  - [✓] Criar arquivo `models.py`
  - [✓] Criar arquivo `serializers.py`
  - [✓] Criar arquivo `services.py`
  - [✓] Criar arquivo `views.py`
  - [✓] Criar arquivo `urls.py`
  - [✓] Criar arquivo `tests.py`

- [✓] **Migração de modelos**
  - [✓] TimelineEvent

- [✓] **Migração de serializers**
  - [✓] TimelineEventSerializer

- [✓] **Migração de views**
  - [✓] TimelineEventViewSet
  - [✓] create_timeline_event

- [✓] **Configuração de URLs**
  - [✓] Criar rotas para cada viewset
  - [✓] Incluir no URLconf principal

- [✓] **Migração de admin**
  - [✓] TimelineEvent

- [✓] **Configuração do aplicativo**
  - [✓] Criar classe TimelineConfig
  - [✓] Adicionar ao INSTALLED_APPS

- [ ] **Migrações do banco de dados**
  - [ ] Executar makemigrations
  - [ ] Executar migrate

- [✓] **Testes**
  - [✓] Criar testes unitários
  - [ ] Criar testes de integração
  - [ ] Verificar funcionamento do módulo isoladamente
  - [ ] Verificar integração com outros módulos

## 6. mitre

- [✓] **Estrutura de diretórios**
  - [✓] Criar diretório `irp/mitre`
  - [✓] Criar arquivo `__init__.py`
  - [✓] Criar arquivo `admin.py`
  - [✓] Criar arquivo `apps.py`
  - [✓] Criar arquivo `models.py`
  - [✓] Criar arquivo `serializers.py`
  - [✓] Criar arquivo `services.py`
  - [✓] Criar arquivo `views.py`
  - [✓] Criar arquivo `urls.py`
  - [✓] Criar arquivo `tests.py`

- [✓] **Migração de modelos**
  - [✓] MitreTactic
  - [✓] MitreTechnique
  - [✓] TechniqueTactic

- [✓] **Migração de serializers**
  - [✓] MitreTacticSerializer
  - [✓] MitreTechniqueSerializer
  - [✓] CaseMitreTechniqueSerializer (adaptado)
  - [✓] AlertMitreTechniqueSerializer (adaptado)

- [✓] **Migração de views**
  - [✓] MitreTacticViewSet
  - [✓] MitreTechniqueViewSet
  - [✓] import_mitre_attack

- [✓] **Configuração de URLs**
  - [✓] Configurar rotas em `irp/mitre/urls.py`
  - [✓] Adicionar as URLs ao `core/urls.py`

- [✓] **Configuração de admin**
  - [✓] Registrar modelos no admin

- [✓] **Configuração do app**
  - [✓] Configurar `apps.py`
  - [✓] Adicionar app ao `INSTALLED_APPS` em `settings.py`

- [✓] **Testes**
  - [✓] Testes básicos para modelos
  - [✓] Testes básicos para views

- [✓] **Comentar código legado**
  - [✓] Modelos em `api/models.py`
  - [✓] Serializers em `api/serializers.py`
  - [✓] Views em `api/views.py`
  - [✓] URLs em `api/urls.py`

## 7. knowledge_base

- [✓] **Estrutura de diretórios**
  - [✓] Criar diretório `irp/knowledge_base`
  - [✓] Criar arquivo `__init__.py`
  - [✓] Criar arquivo `admin.py`
  - [✓] Criar arquivo `apps.py`
  - [✓] Criar arquivo `models.py`
  - [✓] Criar arquivo `serializers.py`
  - [✓] Criar arquivo `services.py`
  - [✓] Criar arquivo `views.py`
  - [✓] Criar arquivo `urls.py`
  - [✓] Criar arquivo `tests.py`

- [✓] **Migração de modelos**
  - [✓] KBCategory
  - [✓] KBArticle
  - [✓] KBArticleVersion

- [✓] **Migração de serializers**
  - [✓] KBCategorySerializer
  - [✓] KBArticleVersionSerializer
  - [✓] KBArticleSerializer

- [✓] **Migração de views**
  - [✓] KBCategoryViewSet
  - [✓] KBArticleViewSet
  - [✓] kb_search
  - [✓] kb_related_articles

- [✓] **Configuração de URLs**
  - [✓] Criar rotas para cada viewset
  - [✓] Incluir no URLconf principal

- [✓] **Migração de admin**
  - [✓] KBCategory
  - [✓] KBArticle
  - [✓] KBArticleVersion

- [✓] **Configuração do aplicativo**
  - [✓] Criar classe KnowledgeBaseConfig
  - [✓] Adicionar ao INSTALLED_APPS

- [ ] **Migrações do banco de dados**
  - [ ] Executar makemigrations
  - [ ] Executar migrate

- [✓] **Testes**
  - [✓] Criar testes unitários
  - [ ] Criar testes de integração
  - [ ] Verificar funcionamento do módulo isoladamente
  - [ ] Verificar integração com outros módulos

## 8. notifications

- [✓] **Estrutura de diretórios**
  - [✓] Criar diretório `irp/notifications`
  - [✓] Criar arquivo `__init__.py`
  - [✓] Criar arquivo `admin.py`
  - [✓] Criar arquivo `apps.py`
  - [✓] Criar arquivo `models.py`
  - [✓] Criar arquivo `serializers.py`
  - [✓] Criar arquivo `services.py`
  - [✓] Criar arquivo `views.py`
  - [✓] Criar arquivo `urls.py`
  - [✓] Criar arquivo `tests.py`

- [✓] **Migração de modelos**
  - [✓] NotificationEvent
  - [✓] NotificationChannel
  - [✓] NotificationRule
  - [✓] NotificationLog

- [✓] **Migração de serializers**
  - [✓] NotificationEventSerializer
  - [✓] NotificationChannelSerializer
  - [✓] NotificationRuleSerializer
  - [✓] NotificationLogSerializer

- [✓] **Migração de views**
  - [✓] NotificationEventViewSet
  - [✓] NotificationChannelViewSet
  - [✓] NotificationRuleViewSet
  - [✓] NotificationLogViewSet
  - [✓] NotificationViewSet

- [✓] **Configuração de URLs**
  - [✓] Criar rotas para cada viewset
  - [✓] Incluir no URLconf principal

- [✓] **Migração de admin**
  - [✓] NotificationEvent
  - [✓] NotificationChannel
  - [✓] NotificationRule
  - [✓] NotificationLog

- [✓] **Configuração do aplicativo**
  - [✓] Criar classe NotificationsConfig
  - [✓] Adicionar ao INSTALLED_APPS

- [✓] **Migrações do banco de dados**
  - [✓] Executar makemigrations
  - [✓] Executar migrate

- [🟡] **Testes**
  - [✓] Criar testes unitários
  - [✓] Criar testes de integração
  - [ ] Verificar funcionamento do módulo isoladamente
  - [ ] Verificar integração com outros módulos

## 9. metrics

- [✓] **Estrutura de diretórios**
  - [✓] Criar diretório `irp/metrics`
  - [✓] Criar arquivo `__init__.py`
  - [✓] Criar arquivo `admin.py`
  - [✓] Criar arquivo `apps.py`
  - [✓] Criar arquivo `models.py`
  - [✓] Criar arquivo `serializers.py`
  - [✓] Criar arquivo `services.py`
  - [✓] Criar arquivo `views.py`
  - [✓] Criar arquivo `urls.py`
  - [✓] Criar arquivo `tests.py`

- [✓] **Migração de modelos**
  - [✓] Metric
  - [✓] MetricSnapshot
  - [✓] Dashboard
  - [✓] DashboardWidget

- [✓] **Migração de serializers**
  - [✓] MetricSerializer
  - [✓] MetricSnapshotSerializer
  - [✓] DashboardWidgetSerializer
  - [✓] DashboardSerializer

- [✓] **Migração de views**
  - [✓] MetricViewSet
  - [✓] MetricSnapshotViewSet
  - [✓] DashboardViewSet
  - [✓] DashboardWidgetViewSet
  - [✓] dashboard_stats (implementado no MetricsService)
  - [✓] calculate_metrics (implementado no MetricsService)

- [✓] **Configuração de URLs**
  - [✓] Criar rotas para cada viewset
  - [✓] Incluir no URLconf principal

- [✓] **Migração de admin**
  - [✓] Metric
  - [✓] MetricSnapshot
  - [✓] Dashboard
  - [✓] DashboardWidget

- [✓] **Configuração do aplicativo**
  - [✓] Criar classe MetricsConfig
  - [✓] Adicionar ao INSTALLED_APPS

- [✓] **Migrações do banco de dados**
  - [✓] Executar makemigrations
  - [✓] Executar migrate

- [✓] **Testes**
  - [✓] Criar testes unitários
  - [ ] Criar testes de integração
  - [ ] Verificar funcionamento do módulo isoladamente
  - [ ] Verificar integração com outros módulos

## 10. audit

- [✓] **Estrutura de diretórios**
  - [✓] Criar diretório `irp/audit`
  - [✓] Criar arquivo `__init__.py`
  - [✓] Criar arquivo `admin.py`
  - [✓] Criar arquivo `apps.py`
  - [✓] Criar arquivo `models.py`
  - [✓] Criar arquivo `serializers.py`
  - [✓] Criar arquivo `services.py`
  - [✓] Criar arquivo `views.py`
  - [✓] Criar arquivo `urls.py`
  - [✓] Criar arquivo `tests.py`

- [✓] **Migração de modelos**
  - [✓] AuditLog

- [✓] **Migração de serializers**
  - [✓] AuditLogSerializer

- [✓] **Migração de views**
  - [✓] AuditLogViewSet

- [✓] **Configuração de URLs**
  - [✓] Criar rotas para cada viewset
  - [✓] Incluir no URLconf principal

- [✓] **Migração de admin**
  - [✓] AuditLog

- [✓] **Configuração do aplicativo**
  - [✓] Criar classe AuditConfig
  - [✓] Adicionar ao INSTALLED_APPS

- [✓] **Migrações do banco de dados**
  - [✓] Executar makemigrations
  - [✓] Executar migrate

- [🟡] **Testes**
  - [✓] Criar testes unitários
  - [✓] Criar testes de integração
  - [ ] Verificar funcionamento do módulo isoladamente
  - [ ] Verificar integração com outros módulos

## 11. integrations/misp

- [✓] **Estrutura de diretórios**
  - [✓] Criar diretório `irp/integrations`
  - [✓] Criar arquivo `irp/integrations/__init__.py`
  - [✓] Criar arquivo `irp/integrations/apps.py`
  - [✓] Criar diretório `irp/integrations/misp`
  - [✓] Criar arquivo `irp/integrations/misp/__init__.py`
  - [✓] Criar arquivo `irp/integrations/misp/models.py`
  - [✓] Criar arquivo `irp/integrations/misp/serializers.py`
  - [✓] Criar arquivo `irp/integrations/misp/services.py`
  - [✓] Criar arquivo `irp/integrations/misp/views.py`
  - [✓] Criar arquivo `irp/integrations/misp/urls.py`
  - [✓] Criar arquivo `irp/integrations/misp/tests.py`

- [✓] **Migração de modelos**
  - [✓] MISPInstance
  - [✓] MISPExport
  - [✓] MISPImport
  - [✓] ObservableMISPMapping

- [✓] **Migração de serializers**
  - [✓] MISPInstanceSerializer
  - [✓] MISPImportSerializer
  - [✓] MISPExportSerializer
  - [✓] TriggerMISPImportSerializer
  - [✓] ExportCaseToMISPSerializer

- [✓] **Migração de views**
  - [✓] MISPInstanceViewSet
  - [✓] MISPImportViewSet
  - [✓] MISPExportViewSet
  - [✓] trigger_misp_import
  - [✓] export_case_to_misp

- [✓] **Configuração de URLs**
  - [✓] Criar rotas para cada viewset
  - [✓] Incluir no URLconf principal

- [✓] **Migração de admin**
  - [✓] MISPInstance
  - [✓] MISPExport
  - [✓] MISPImport
  - [✓] ObservableMISPMapping

- [✓] **Configuração do aplicativo**
  - [✓] Criar classe IntegrationsConfig
  - [✓] Adicionar ao INSTALLED_APPS

- [✓] **Migrações do banco de dados**
  - [✓] Executar makemigrations
  - [✓] Executar migrate

- [🟡] **Testes**
  - [✓] Criar testes unitários
  - [ ] Criar testes de integração
  - [ ] Verificar funcionamento do módulo isoladamente
  - [ ] Verificar integração com outros módulos

## 12. reports

- [✓] **Estrutura de diretórios**
  - [✓] Criar diretório `irp/reports`
  - [✓] Criar arquivo `__init__.py`
  - [✓] Criar arquivo `admin.py`
  - [✓] Criar arquivo `apps.py`
  - [✓] Criar arquivo `models.py`
  - [✓] Criar arquivo `serializers.py`
  - [✓] Criar arquivo `services.py`
  - [✓] Criar arquivo `views.py`
  - [✓] Criar arquivo `urls.py`
  - [✓] Criar arquivo `tests.py`

- [✓] **Migração de modelos**
  - [✓] ReportTemplate
  - [✓] GeneratedReport

- [✓] **Migração de serializers**
  - [✓] ReportTemplateSerializer
  - [✓] GeneratedReportSerializer
  - [✓] GenerateReportSerializer

- [✓] **Migração de views**
  - [✓] ReportTemplateViewSet
  - [✓] GeneratedReportViewSet
  - [✓] generate_case_report
  - [✓] reports

- [✓] **Configuração de URLs**
  - [✓] Criar rotas para cada viewset
  - [✓] Incluir no URLconf principal

- [✓] **Migração de admin**
  - [✓] ReportTemplate
  - [✓] GeneratedReport

- [✓] **Configuração do aplicativo**
  - [✓] Criar classe ReportsConfig
  - [✓] Adicionar ao INSTALLED_APPS

- [✓] **Migrações do banco de dados**
  - [✓] Estrutura de código migrada
  - [ ] Executar makemigrations (ignorado conforme instrução do usuário)
  - [ ] Executar migrate (ignorado conforme instrução do usuário)

- [✓] **Testes**
  - [✓] Criar testes unitários
  - [ ] Criar testes de integração (pendente para fase posterior)
  - [ ] Verificar funcionamento do módulo isoladamente (pendente para fase posterior)
  - [ ] Verificar integração com outros módulos (pendente para fase posterior)

## 13. common

- [✓] **Estrutura de diretórios**
  - [✓] Criar diretório `irp/common`
  - [✓] Criar arquivo `__init__.py`
  - [✓] Criar arquivo `models.py`
  - [✓] Criar arquivo `utils.py`
  - [✓] Criar arquivo `middleware.py`
  - [✓] Criar arquivo `permissions.py`
  - [✓] Criar arquivo `apps.py`

- [🟡] **Migração de código compartilhado**
  - [✓] Extrair utilitários comuns para `utils.py`
  - [ ] Extrair middlewares compartilhados
  - [✓] Migrar classes de permissão
  - [ ] Migrar modelos base (se houver)

- [✓] **Configuração do aplicativo**
  - [✓] Criar classe CommonConfig
  - [✓] Adicionar ao INSTALLED_APPS

- [ ] **Testes**
  - [ ] Criar testes unitários
  - [ ] Verificar funcionamento do módulo isoladamente
  - [ ] Verificar integração com outros módulos

## 14. Configuração do projeto após migração

- [✓] **Atualizar URLs principais**
  - [✓] Incluir URLs de todos os módulos no arquivo `core/urls.py`
  - [✓] Remover referência ao `api/urls.py`
  - [✓] Confirmar que todas as rotas estão funcionando

- [✓] **Arquivos principais migrados**
  - [✓] api/urls.py (removido após migração completa)

- [ ] **Atualizar configurações**
  - [ ] Atualizar INSTALLED_APPS no arquivo `core/settings.py`
  - [ ] Remover registros antigos após verificação

- [🟡] **Limpeza**
  - [🟡] Remover código legado do aplicativo `api`
  - [ ] Atualizar importações em todos os arquivos
  - [ ] Verificar integridade do banco de dados

- [ ] **Documentação**
  - [ ] Atualizar a documentação para refletir a nova estrutura
  - [ ] Documentar o processo de migração para referência futura 

# Refactoring Checklist

## Completed Migrations
- [x] Knowledge Base module
- [x] MITRE module
- [x] Notifications module
- [x] Metrics module
- [x] MISP Integration
- [x] Reports module (disabled temporarily due to WeasyPrint dependency issue)
- [x] Accounts module
- [x] URLs configuration for all modules
- [x] Removal of api/urls.py
- [x] Database migrations for all modules

## Remaining Work

### Model Name Conflicts to Resolve
- [✓] Fix model name clashes between modules:
  - [✓] AlertMitreTechnique in mitre module and alerts module
  - [✓] CaseMitreTechnique in mitre module and cases module
  - [✓] Add appropriate related_name parameters to ForeignKey fields

### Testing
- [ ] Test Account module endpoints
- [ ] Test Report module endpoints
- [ ] Verify all authentication flows in the new module structure
- [ ] Test nested routes for MITRE techniques with Cases and Alerts

### API Documentation
- [ ] Update API schema for the new modules
- [ ] Ensure all new endpoints are properly documented

### Final Cleanup
- [x] Remove api/urls.py file
- [ ] Remove remaining code from `api/` directory once all features are confirmed working
- [ ] Update any hardcoded URLs in frontend code to point to v2 API endpoints
- [ ] Create database migrations if any model changes were made during refactoring
- [ ] Perform final review of permissions and access controls

### Deployment
- [ ] Deploy to staging environment
- [ ] Monitor for potential issues
- [ ] Deploy to production once staging tests pass 