from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from api.models import (
    Organization, Team, Profile, Role, Permission, UserRole, RolePermission,
    AlertSeverity, AlertStatus, CaseSeverity, CaseStatus, TaskStatus,
    ObservableType, TLPLevel, PAPLevel
)
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Inicializa o sistema com dados base necessários para operação'

    def handle(self, *args, **kwargs):
        self.stdout.write('Inicializando sistema...')
        
        # 1. Criar permissões básicas
        self._create_permissions()
        
        # 2. Criar funções (roles) básicas
        self._create_roles()
        
        # 3. Criar severidades de alertas
        self._create_alert_severities()
        
        # 4. Criar status de alertas
        self._create_alert_statuses()
        
        # 5. Criar severidades de casos
        self._create_case_severities()
        
        # 6. Criar status de casos
        self._create_case_statuses()
        
        # 7. Criar status de tarefas
        self._create_task_statuses()
        
        # 8. Criar tipos de observáveis
        self._create_observable_types()
        
        # 9. Criar níveis de TLP
        self._create_tlp_levels()
        
        # 10. Criar níveis de PAP
        self._create_pap_levels()
        
        self.stdout.write(self.style.SUCCESS('Sistema inicializado com sucesso!'))
    
    def _create_permissions(self):
        self.stdout.write('Criando permissões...')
        
        permissions = [
            # Permissões administrativas
            {"code": "manage_organizations", "name": "Gerenciar Organizações", "description": "Criar, editar e excluir organizações"},
            {"code": "manage_teams", "name": "Gerenciar Times", "description": "Criar, editar e excluir times"},
            {"code": "manage_users", "name": "Gerenciar Usuários", "description": "Criar, editar e excluir usuários"},
            {"code": "manage_roles", "name": "Gerenciar Funções", "description": "Criar, editar e excluir funções"},
            {"code": "manage_permissions", "name": "Gerenciar Permissões", "description": "Criar, editar e excluir permissões"},
            {"code": "assign_roles", "name": "Atribuir Funções", "description": "Atribuir funções a usuários"},
            {"code": "assign_permissions", "name": "Atribuir Permissões", "description": "Atribuir permissões a funções"},
            
            # Permissões para Alertas
            {"code": "alert:view", "name": "Ver Alertas", "description": "Visualizar alertas"},
            {"code": "alert:create", "name": "Criar Alertas", "description": "Criar novos alertas"},
            {"code": "alert:edit", "name": "Editar Alertas", "description": "Editar alertas existentes"},
            {"code": "alert:delete", "name": "Excluir Alertas", "description": "Excluir alertas"},
            {"code": "alert:comment", "name": "Comentar Alertas", "description": "Adicionar comentários a alertas"},
            {"code": "alert:escalate", "name": "Escalar Alertas", "description": "Escalar alertas para casos"},
            
            # Permissões para Casos
            {"code": "case:view", "name": "Ver Casos", "description": "Visualizar casos"},
            {"code": "case:create", "name": "Criar Casos", "description": "Criar novos casos"},
            {"code": "case:edit", "name": "Editar Casos", "description": "Editar casos existentes"},
            {"code": "case:delete", "name": "Excluir Casos", "description": "Excluir casos"},
            {"code": "case:comment", "name": "Comentar Casos", "description": "Adicionar comentários a casos"},
            
            # Permissões para Tarefas
            {"code": "task:view", "name": "Ver Tarefas", "description": "Visualizar tarefas"},
            {"code": "task:create", "name": "Criar Tarefas", "description": "Criar novas tarefas"},
            {"code": "task:edit", "name": "Editar Tarefas", "description": "Editar tarefas existentes"},
            {"code": "task:delete", "name": "Excluir Tarefas", "description": "Excluir tarefas"},
            
            # Permissões para Observáveis
            {"code": "observable:view", "name": "Ver Observáveis", "description": "Visualizar observáveis"},
            {"code": "observable:create", "name": "Criar Observáveis", "description": "Criar novos observáveis"},
            {"code": "observable:edit", "name": "Editar Observáveis", "description": "Editar observáveis existentes"},
            {"code": "observable:delete", "name": "Excluir Observáveis", "description": "Excluir observáveis"},
            
            # Permissões para Configurações
            {"code": "manage_alert_settings", "name": "Gerenciar Configurações de Alertas", "description": "Gerenciar severidades, status e campos customizados de alertas"},
            {"code": "manage_case_settings", "name": "Gerenciar Configurações de Casos", "description": "Gerenciar severidades, status e campos customizados de casos"},
            {"code": "manage_case_templates", "name": "Gerenciar Templates de Casos", "description": "Criar, editar e excluir templates de casos"},
            
            # Permissões para Dashboard e Relatórios
            {"code": "view_dashboard", "name": "Ver Dashboard", "description": "Visualizar o dashboard com estatísticas"},
            {"code": "generate_reports", "name": "Gerar Relatórios", "description": "Gerar e visualizar relatórios"},
        ]
        
        for perm_data in permissions:
            Permission.objects.update_or_create(
                code=perm_data["code"],
                defaults={
                    "name": perm_data["name"],
                    "description": perm_data["description"]
                }
            )
        
        self.stdout.write(f'Criadas {len(permissions)} permissões')
    
    def _create_roles(self):
        self.stdout.write('Criando funções (roles)...')
        
        # Define os papéis básicos com suas permissões
        roles = [
            {
                "name": "Administrador",
                "description": "Acesso total ao sistema",
                "permissions": ["*"]  # Wildcard para todas as permissões
            },
            {
                "name": "Analista",
                "description": "Analista de segurança padrão",
                "permissions": [
                    "alert:view", "alert:edit", "alert:comment", "alert:escalate",
                    "case:view", "case:edit", "case:comment",
                    "task:view", "task:create", "task:edit",
                    "observable:view", "observable:create", "observable:edit",
                    "view_dashboard"
                ]
            },
            {
                "name": "Coordenador",
                "description": "Coordenador de equipe de segurança",
                "permissions": [
                    "alert:view", "alert:create", "alert:edit", "alert:delete", "alert:comment", "alert:escalate",
                    "case:view", "case:create", "case:edit", "case:delete", "case:comment",
                    "task:view", "task:create", "task:edit", "task:delete",
                    "observable:view", "observable:create", "observable:edit", "observable:delete",
                    "manage_alert_settings", "manage_case_settings", "manage_case_templates",
                    "view_dashboard", "generate_reports"
                ]
            },
            {
                "name": "Somente Leitura",
                "description": "Acesso somente leitura ao sistema",
                "permissions": [
                    "alert:view", "case:view", "task:view", "observable:view", "view_dashboard"
                ]
            }
        ]
        
        for role_data in roles:
            role, created = Role.objects.update_or_create(
                name=role_data["name"],
                defaults={
                    "description": role_data["description"]
                }
            )
            
            # Atribuir permissões
            if "*" in role_data["permissions"]:
                # Para administrador, atribuir todas as permissões
                for perm in Permission.objects.all():
                    RolePermission.objects.update_or_create(role=role, permission=perm)
            else:
                for perm_code in role_data["permissions"]:
                    perm = Permission.objects.get(code=perm_code)
                    RolePermission.objects.update_or_create(role=role, permission=perm)
        
        self.stdout.write(f'Criadas {len(roles)} funções')
    
    def _create_alert_severities(self):
        self.stdout.write('Criando severidades de alertas...')
        
        severities = [
            {"name": "Low", "level_order": 1, "color_code": "#28a745"},
            {"name": "Medium", "level_order": 2, "color_code": "#ffc107"},
            {"name": "High", "level_order": 3, "color_code": "#fd7e14"},
            {"name": "Critical", "level_order": 4, "color_code": "#dc3545"}
        ]
        
        for sev_data in severities:
            AlertSeverity.objects.update_or_create(
                name=sev_data["name"],
                defaults={
                    "level_order": sev_data["level_order"],
                    "color_code": sev_data["color_code"]
                }
            )
        
        self.stdout.write(f'Criadas {len(severities)} severidades de alertas')
    
    def _create_alert_statuses(self):
        self.stdout.write('Criando status de alertas...')
        
        statuses = [
            {"name": "New", "description": "Alerta recém-criado", "is_default_open_status": True, "is_terminal_status": False, "color_code": "#17a2b8"},
            {"name": "Open", "description": "Alerta aberto em análise", "is_default_open_status": False, "is_terminal_status": False, "color_code": "#007bff"},
            {"name": "In Progress", "description": "Análise em andamento", "is_default_open_status": False, "is_terminal_status": False, "color_code": "#6f42c1"},
            {"name": "Escalated", "description": "Escalado para caso", "is_default_open_status": False, "is_terminal_status": True, "color_code": "#fd7e14"},
            {"name": "Closed - False Positive", "description": "Encerrado como falso positivo", "is_default_open_status": False, "is_terminal_status": True, "color_code": "#6c757d"},
            {"name": "Closed - Resolved", "description": "Encerrado como resolvido", "is_default_open_status": False, "is_terminal_status": True, "color_code": "#28a745"}
        ]
        
        for status_data in statuses:
            AlertStatus.objects.update_or_create(
                name=status_data["name"],
                organization=None,  # Status global
                defaults={
                    "description": status_data["description"],
                    "is_default_open_status": status_data["is_default_open_status"],
                    "is_terminal_status": status_data["is_terminal_status"],
                    "color_code": status_data["color_code"]
                }
            )
        
        self.stdout.write(f'Criados {len(statuses)} status de alertas')
    
    def _create_case_severities(self):
        self.stdout.write('Criando severidades de casos...')
        
        severities = [
            {"name": "Low", "level_order": 1, "color_code": "#28a745"},
            {"name": "Medium", "level_order": 2, "color_code": "#ffc107"},
            {"name": "High", "level_order": 3, "color_code": "#fd7e14"},
            {"name": "Critical", "level_order": 4, "color_code": "#dc3545"}
        ]
        
        for sev_data in severities:
            CaseSeverity.objects.update_or_create(
                name=sev_data["name"],
                defaults={
                    "level_order": sev_data["level_order"],
                    "color_code": sev_data["color_code"]
                }
            )
        
        self.stdout.write(f'Criadas {len(severities)} severidades de casos')
    
    def _create_case_statuses(self):
        self.stdout.write('Criando status de casos...')
        
        statuses = [
            {"name": "Open", "description": "Caso recém-aberto", "is_default_open_status": True, "is_terminal_status": False, "color_code": "#17a2b8"},
            {"name": "Investigating", "description": "Investigação em andamento", "is_default_open_status": False, "is_terminal_status": False, "color_code": "#007bff"},
            {"name": "Containment", "description": "Fase de contenção", "is_default_open_status": False, "is_terminal_status": False, "color_code": "#fd7e14"},
            {"name": "Eradication", "description": "Fase de erradicação", "is_default_open_status": False, "is_terminal_status": False, "color_code": "#6f42c1"},
            {"name": "Recovery", "description": "Fase de recuperação", "is_default_open_status": False, "is_terminal_status": False, "color_code": "#20c997"},
            {"name": "Closed", "description": "Caso encerrado", "is_default_open_status": False, "is_terminal_status": True, "color_code": "#28a745"},
            {"name": "Closed - False Positive", "description": "Encerrado como falso positivo", "is_default_open_status": False, "is_terminal_status": True, "color_code": "#6c757d"}
        ]
        
        for status_data in statuses:
            CaseStatus.objects.update_or_create(
                name=status_data["name"],
                organization=None,  # Status global
                defaults={
                    "description": status_data["description"],
                    "is_default_open_status": status_data["is_default_open_status"],
                    "is_terminal_status": status_data["is_terminal_status"],
                    "color_code": status_data["color_code"]
                }
            )
        
        self.stdout.write(f'Criados {len(statuses)} status de casos')
    
    def _create_task_statuses(self):
        self.stdout.write('Criando status de tarefas...')
        
        statuses = [
            {"name": "ToDo", "color_code": "#17a2b8"},
            {"name": "In Progress", "color_code": "#007bff"},
            {"name": "Done", "color_code": "#28a745"},
            {"name": "Blocked", "color_code": "#dc3545"}
        ]
        
        for status_data in statuses:
            TaskStatus.objects.update_or_create(
                name=status_data["name"],
                defaults={
                    "color_code": status_data["color_code"]
                }
            )
        
        self.stdout.write(f'Criados {len(statuses)} status de tarefas')
    
    def _create_observable_types(self):
        self.stdout.write('Criando tipos de observáveis...')
        
        types = [
            {"name": "ipv4-addr", "description": "Endereço IPv4"},
            {"name": "ipv6-addr", "description": "Endereço IPv6"},
            {"name": "domain-name", "description": "Nome de domínio"},
            {"name": "url", "description": "URL completa"},
            {"name": "email-addr", "description": "Endereço de email"},
            {"name": "file-hash-md5", "description": "Hash MD5 de arquivo"},
            {"name": "file-hash-sha1", "description": "Hash SHA1 de arquivo"},
            {"name": "file-hash-sha256", "description": "Hash SHA256 de arquivo"},
            {"name": "file-name", "description": "Nome de arquivo"},
            {"name": "user-account", "description": "Conta de usuário"},
            {"name": "process-name", "description": "Nome de processo"},
            {"name": "windows-registry-key", "description": "Chave de registro do Windows"},
            {"name": "mac-addr", "description": "Endereço MAC"}
        ]
        
        for type_data in types:
            ObservableType.objects.update_or_create(
                name=type_data["name"],
                defaults={
                    "description": type_data["description"]
                }
            )
        
        self.stdout.write(f'Criados {len(types)} tipos de observáveis')
    
    def _create_tlp_levels(self):
        self.stdout.write('Criando níveis TLP...')
        
        levels = [
            {"name": "RED", "description": "Não divulgar, restrito a participantes específicos"},
            {"name": "AMBER", "description": "Divulgação limitada, restrito à organização"},
            {"name": "GREEN", "description": "Divulgação limitada a comunidade"},
            {"name": "WHITE", "description": "Divulgação irrestrita"}
        ]
        
        for level_data in levels:
            TLPLevel.objects.update_or_create(
                name=level_data["name"],
                defaults={
                    "description": level_data["description"]
                }
            )
        
        self.stdout.write(f'Criados {len(levels)} níveis TLP')
    
    def _create_pap_levels(self):
        self.stdout.write('Criando níveis PAP...')
        
        levels = [
            {"name": "WHITE", "description": "Pode ser distribuído sem restrições"},
            {"name": "GREEN", "description": "Pode ser distribuído para organizações ou comunidades específicas"},
            {"name": "AMBER", "description": "Divulgação limitada, uso organizacional apenas"},
            {"name": "RED", "description": "Uso pessoal apenas, não compartilhar"}
        ]
        
        for level_data in levels:
            PAPLevel.objects.update_or_create(
                name=level_data["name"],
                defaults={
                    "description": level_data["description"]
                }
            )
        
        self.stdout.write(f'Criados {len(levels)} níveis PAP') 