from django.contrib.auth.models import User
from django.db import transaction
from django.utils.text import slugify

from .models import Organization, Team, Profile, Role, Permission, UserRole, RolePermission


class OrganizationService:
    @staticmethod
    def create_organization(name, description=None, contact_info=None):
        """
        Create a new organization with a slug based on the name.
        
        Args:
            name (str): The name of the organization
            description (str, optional): Description of the organization
            contact_info (str, optional): Contact information
            
        Returns:
            Organization: The created organization
        """
        slug = slugify(name)
        
        # Check if slug already exists and append a number if needed
        base_slug = slug
        counter = 1
        while Organization.objects.filter(slug=slug).exists():
            slug = f"{base_slug}-{counter}"
            counter += 1
        
        return Organization.objects.create(
            name=name,
            description=description or "",
            contact_info=contact_info or "",
            slug=slug
        )
    
    @staticmethod
    def add_user_to_organization(user, organization, is_admin=False):
        """
        Add a user to an organization by creating or updating their profile.
        
        Args:
            user (User): The user to add
            organization (Organization): The organization to add the user to
            is_admin (bool, optional): Whether the user should be an admin of the organization
            
        Returns:
            Profile: The user's profile
        """
        # Get or create profile
        profile, created = Profile.objects.get_or_create(user=user)
        
        # Update profile
        profile.organization = organization
        if is_admin:
            profile.is_system_admin = True
        profile.save()
        
        return profile


class TeamService:
    @staticmethod
    def create_team(name, organization, description=None):
        """
        Create a new team in an organization.
        
        Args:
            name (str): The name of the team
            organization (Organization): The organization the team belongs to
            description (str, optional): Description of the team
            
        Returns:
            Team: The created team
        """
        return Team.objects.create(
            name=name,
            organization=organization,
            description=description or ""
        )
    
    @staticmethod
    def add_user_to_team(user, team):
        """
        Add a user to a team.
        
        Args:
            user (User): The user to add
            team (Team): The team to add the user to
            
        Returns:
            Team: The updated team
        """
        team.members.add(user)
        return team


class RoleService:
    @staticmethod
    @transaction.atomic
    def create_role_with_permissions(name, description=None, permission_codes=None):
        """
        Create a new role with the specified permissions.
        
        Args:
            name (str): The name of the role
            description (str, optional): Description of the role
            permission_codes (list, optional): List of permission codes to assign to the role
            
        Returns:
            Role: The created role
        """
        # Create role
        role = Role.objects.create(
            name=name,
            description=description or ""
        )
        
        # Add permissions if provided
        if permission_codes:
            permissions = Permission.objects.filter(code__in=permission_codes)
            for permission in permissions:
                RolePermission.objects.create(role=role, permission=permission)
        
        return role
    
    @staticmethod
    @transaction.atomic
    def assign_role_to_user(user, role, organization):
        """
        Assign a role to a user in a specific organization.
        
        Args:
            user (User): The user to assign the role to
            role (Role): The role to assign
            organization (Organization): The organization context
            
        Returns:
            UserRole: The created user role assignment
        """
        # Check if the assignment already exists
        user_role, created = UserRole.objects.get_or_create(
            user=user,
            role=role,
            organization=organization
        )
        
        return user_role
    
    @staticmethod
    @transaction.atomic
    def setup_default_permissions():
        """
        Configura as permissões padrão do sistema. Esta função deve ser executada
        durante a inicialização/migração do banco de dados.
        
        Retorna:
            list: Lista de permissões criadas
        """
        # Lista de permissões padrão do sistema
        default_permissions = [
            # Organizações
            {"code": "organization:view", "name": "Visualizar organizações", "description": "Permite visualizar organizações"},
            {"code": "organization:create", "name": "Criar organizações", "description": "Permite criar novas organizações"},
            {"code": "organization:edit", "name": "Editar organizações", "description": "Permite editar organizações existentes"},
            {"code": "organization:delete", "name": "Excluir organizações", "description": "Permite excluir organizações"},
            {"code": "manage_organizations", "name": "Gerenciar organizações", "description": "Permite gerenciar totalmente organizações"},
            
            # Times
            {"code": "team:view", "name": "Visualizar times", "description": "Permite visualizar times"},
            {"code": "team:create", "name": "Criar times", "description": "Permite criar novos times"},
            {"code": "team:edit", "name": "Editar times", "description": "Permite editar times existentes"},
            {"code": "team:delete", "name": "Excluir times", "description": "Permite excluir times"},
            {"code": "manage_teams", "name": "Gerenciar times", "description": "Permite gerenciar totalmente times"},
            
            # Usuários
            {"code": "user:view", "name": "Visualizar usuários", "description": "Permite visualizar usuários"},
            {"code": "user:create", "name": "Criar usuários", "description": "Permite criar novos usuários"},
            {"code": "user:edit", "name": "Editar usuários", "description": "Permite editar usuários existentes"},
            {"code": "user:delete", "name": "Excluir usuários", "description": "Permite excluir usuários"},
            {"code": "manage_users", "name": "Gerenciar usuários", "description": "Permite gerenciar totalmente usuários"},
            
            # Papéis e Permissões
            {"code": "manage_roles", "name": "Gerenciar papéis", "description": "Permite gerenciar papéis"},
            {"code": "manage_permissions", "name": "Gerenciar permissões", "description": "Permite gerenciar permissões"},
            {"code": "assign_roles", "name": "Atribuir papéis", "description": "Permite atribuir papéis a usuários"},
            {"code": "assign_permissions", "name": "Atribuir permissões", "description": "Permite atribuir permissões a papéis"},
            
            # Super permissão (curinga)
            {"code": "*", "name": "Todas as permissões", "description": "Concede todas as permissões do sistema"},
        ]
        
        created_permissions = []
        
        # Criar as permissões se não existirem
        for perm_data in default_permissions:
            perm, created = Permission.objects.get_or_create(
                code=perm_data["code"],
                defaults={"name": perm_data["name"], "description": perm_data["description"]}
            )
            if created:
                created_permissions.append(perm)
            
        return created_permissions
    
    @staticmethod
    @transaction.atomic
    def setup_default_roles(organization=None):
        """
        Configura os papéis padrão do sistema ou para uma organização específica.
        
        Args:
            organization (Organization, optional): A organização para a qual criar papéis.
                Se None, apenas cria papéis globais do sistema.
                
        Retorna:
            dict: Dicionário com os papéis criados
        """
        # Primeiro, garantir que as permissões existam
        RoleService.setup_default_permissions()
        
        # Papéis padrão do sistema
        default_roles = {
            "admin": {
                "name": "Administrador",
                "description": "Acesso total ao sistema",
                "permissions": ["*"]  # Curinga para todas as permissões
            },
            "analyst": {
                "name": "Analista",
                "description": "Pode visualizar e contribuir, mas não administrar",
                "permissions": [
                    "organization:view", "team:view", "user:view",
                    "case:view", "case:create", "case:edit",
                    "alert:view", "alert:create", "alert:edit",
                    "observable:view", "observable:create", "observable:edit"
                ]
            },
            "user": {
                "name": "Usuário Básico",
                "description": "Acesso básico de visualização",
                "permissions": [
                    "organization:view", "team:view", "user:view",
                    "case:view", "alert:view", "observable:view"
                ]
            }
        }
        
        created_roles = {}
        
        # Se uma organização for especificada, adaptar os nomes dos papéis
        prefix = f"{organization.name} - " if organization else ""
        
        # Criar os papéis
        for role_code, role_data in default_roles.items():
            role_name = f"{prefix}{role_data['name']}"
            
            # Verificar se o papel já existe
            role_exists = Role.objects.filter(name=role_name).exists()
            
            if not role_exists:
                # Criar o papel
                role = Role.objects.create(
                    name=role_name,
                    description=role_data["description"]
                )
                
                # Associar permissões
                for perm_code in role_data["permissions"]:
                    try:
                        perm = Permission.objects.get(code=perm_code)
                        RolePermission.objects.create(role=role, permission=perm)
                    except Permission.DoesNotExist:
                        # Log ou tratar a ausência da permissão
                        pass
                
                created_roles[role_code] = role
        
        return created_roles


class UserService:
    @staticmethod
    @transaction.atomic
    def create_user_with_profile(username, email, password, full_name=None, organization=None, is_admin=False):
        """
        Cria um novo usuário com perfil e, opcionalmente, associa a uma organização.
        
        Args:
            username (str): Nome de usuário
            email (str): E-mail do usuário
            password (str): Senha do usuário
            full_name (str, optional): Nome completo do usuário
            organization (Organization, optional): Organização a qual o usuário pertence
            is_admin (bool, optional): Se o usuário deve ser um administrador da organização
            
        Retorna:
            User: O usuário criado
        """
        # Criar usuário
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password
        )
        
        # Criar perfil
        profile = Profile.objects.create(
            user=user,
            full_name=full_name or username,
            organization=organization,
            is_system_admin=is_admin
        )
        
        # Se tiver organização e for admin, atribuir papel de admin
        if organization and is_admin:
            # Verificar se existem papéis padrão, senão criar
            admin_roles = Role.objects.filter(name__icontains='Administrador')
            
            if admin_roles.exists():
                admin_role = admin_roles.first()
                UserRole.objects.create(
                    user=user,
                    role=admin_role,
                    organization=organization
                )
        
        return user
    
    @staticmethod
    def assign_user_to_team(user, team):
        """
        Adiciona um usuário a um time.
        
        Args:
            user (User): O usuário a ser adicionado
            team (Team): O time ao qual adicionar o usuário
            
        Retorna:
            bool: True se adicionado com sucesso, False se já fazia parte ou ocorreu erro
        """
        # Verificar se o usuário já está no time
        if team.members.filter(id=user.id).exists():
            return False
        
        # Verificar se o usuário pertence à mesma organização do time
        if hasattr(user, 'profile') and user.profile.organization != team.organization:
            return False
        
        # Adicionar usuário ao time
        team.members.add(user)
        return True
    
    @staticmethod
    @transaction.atomic
    def setup_initial_admin(username="admin", email="admin@example.com", password="admin123", organization_name="Organização Principal"):
        """
        Configura um usuário administrador inicial e uma organização principal se não existirem.
        Útil para inicialização do sistema.
        
        Args:
            username (str): Nome do usuário admin
            email (str): E-mail do usuário admin
            password (str): Senha do usuário admin
            organization_name (str): Nome da organização principal
            
        Retorna:
            tuple: (user, organization) - O usuário e a organização criados/encontrados
        """
        # Verificar se já existe um superusuário
        if User.objects.filter(is_superuser=True).exists():
            superuser = User.objects.filter(is_superuser=True).first()
            # Verificar se já existe uma organização
            if Organization.objects.exists():
                return superuser, Organization.objects.first()
            
            # Criar organização
            org = OrganizationService.create_organization(organization_name)
            
            # Associar superuser à organização se não tiver perfil
            if not hasattr(superuser, 'profile'):
                Profile.objects.create(
                    user=superuser,
                    full_name=superuser.get_full_name() or superuser.username,
                    organization=org,
                    is_system_admin=True
                )
            
            return superuser, org
        
        # Criar organização principal se não existir
        org = None
        if not Organization.objects.exists():
            org = OrganizationService.create_organization(organization_name)
        else:
            org = Organization.objects.first()
        
        # Configurar permissões
        RoleService.setup_default_permissions()
        
        # Configurar papéis para a organização
        roles = RoleService.setup_default_roles(org)
        
        # Criar superusuário admin
        admin_user = User.objects.create_superuser(
            username=username,
            email=email,
            password=password
        )
        
        # Criar perfil admin
        Profile.objects.create(
            user=admin_user,
            full_name="Administrador do Sistema",
            organization=org,
            is_system_admin=True
        )
        
        # Associar papel de admin
        if 'admin' in roles:
            UserRole.objects.create(
                user=admin_user,
                role=roles['admin'],
                organization=org
            )
        
        return admin_user, org
