from rest_framework import permissions
from .models import UserRole, RolePermission

class HasRolePermission(permissions.BasePermission):
    """
    Permissão personalizada para verificar se um usuário tem a permissão necessária
    através das suas funções (roles).
    
    A view que usa esta permissão deve ter um atributo 'required_permission'
    que especifica o código da permissão necessária.
    """
    
    def has_permission(self, request, view):
        # Adminstradores do Django têm permissão automática
        if request.user.is_superuser:
            return True
        
        # Obtém a permissão necessária da view
        required_permission = getattr(view, 'required_permission', None)
        
        # Se não há permissão requerida, negamos o acesso para segurança
        if not required_permission:
            return False
        
        # Verifica se o usuário tem perfil e organização
        if not hasattr(request.user, 'profile') or not request.user.profile.organization:
            return False
        
        # Administradores do sistema têm permissão automática
        if request.user.profile.is_system_admin:
            return True
        
        # Para usuários regulares, verificar se algum dos seus papéis tem a permissão necessária
        organization = request.user.profile.organization
        
        # Obter todos os papéis do usuário nesta organização
        user_roles = UserRole.objects.filter(
            user=request.user,
            organization=organization
        )
        
        # Para cada papel, verificar se tem a permissão necessária
        for user_role in user_roles:
            role = user_role.role
            
            # Verificar se o papel tem a permissão específica ou permissão curinga (*)
            has_permission = RolePermission.objects.filter(
                role=role,
                permission__code=required_permission
            ).exists() or RolePermission.objects.filter(
                role=role,
                permission__code='*'
            ).exists()
            
            if has_permission:
                return True
        
        return False

class IsOwnerOrHasPermission(permissions.BasePermission):
    """
    Permissão personalizada que permite acesso se o usuário é dono do objeto
    ou tem a permissão necessária.
    
    A view que usa esta permissão deve ter:
    - Um atributo 'required_permission' que especifica o código da permissão necessária
    - O objeto deve ter um campo 'user' que indica o proprietário
    """
    
    def has_permission(self, request, view):
        # Delegar para HasRolePermission para verificação básica
        return HasRolePermission().has_permission(request, view)
    
    def has_object_permission(self, request, view, obj):
        # Se o usuário é o proprietário do objeto
        if hasattr(obj, 'user') and obj.user == request.user:
            return True
        
        # Se o usuário é o executor de uma tarefa
        if hasattr(obj, 'assignee') and obj.assignee == request.user:
            return True
        
        # Caso contrário, delegar para HasRolePermission
        return HasRolePermission().has_permission(request, view)

def has_permission(user, permission_code):
    """
    Função utilitária para verificar se um usuário tem uma permissão específica.
    Pode ser usada em código fora das views da API.
    """
    # Adminstradores do Django têm permissão automática
    if user.is_superuser:
        return True
    
    # Verifica se o usuário tem perfil e organização
    if not hasattr(user, 'profile') or not user.profile.organization:
        return False
    
    # Administradores do sistema têm permissão automática
    if user.profile.is_system_admin:
        return True
    
    # Para usuários regulares, verificar se algum dos seus papéis tem a permissão necessária
    organization = user.profile.organization
    
    # Obter todos os papéis do usuário nesta organização
    user_roles = UserRole.objects.filter(
        user=user,
        organization=organization
    )
    
    # Para cada papel, verificar se tem a permissão necessária
    for user_role in user_roles:
        role = user_role.role
        
        # Verificar se o papel tem a permissão específica ou permissão curinga (*)
        has_perm = RolePermission.objects.filter(
            role=role,
            permission__code=permission_code
        ).exists() or RolePermission.objects.filter(
            role=role,
            permission__code='*'
        ).exists()
        
        if has_perm:
            return True
    
    return False 