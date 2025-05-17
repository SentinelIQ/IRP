from rest_framework import viewsets, permissions
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework import status
from django.contrib.auth import authenticate
from rest_framework.decorators import api_view, permission_classes, action

from .models import Organization, Team, Profile, Role, Permission, UserRole, RolePermission
from .serializers import (
    OrganizationSerializer, TeamSerializer, ProfileSerializer, 
    RoleSerializer, PermissionSerializer, UserRoleSerializer,
    RolePermissionSerializer, UserSerializer
)
from irp.common.permissions import HasRolePermission, has_permission
from irp.common.audit import audit_action
from irp.audit.services import AuditService


class OrganizationViewSet(viewsets.ModelViewSet):
    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_organizations'
    
    @audit_action(entity_type='ORGANIZATION', action_type='CREATE')
    def perform_create(self, serializer):
        return super().perform_create(serializer)
        
    @audit_action(entity_type='ORGANIZATION', action_type='UPDATE')
    def perform_update(self, serializer):
        return super().perform_update(serializer)
        
    @audit_action(entity_type='ORGANIZATION', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)
        
    @audit_action(entity_type='ORGANIZATION', action_type='VIEW')
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)


class TeamViewSet(viewsets.ModelViewSet):
    queryset = Team.objects.all()
    serializer_class = TeamSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_teams'

    def get_queryset(self):
        # Verificar se estamos acessando por uma rota aninhada (organização específica)
        if 'organization_pk' in self.kwargs:
            organization_id = self.kwargs['organization_pk']
            # Verificar se o usuário tem permissão para acessar esta organização
            user = self.request.user
            if user.profile.organization.organization_id == int(organization_id) or user.profile.is_system_admin:
                return Team.objects.filter(organization__organization_id=organization_id)
            else:
                return Team.objects.none()
        else:
            # Não estamos numa rota aninhada, aplicar filtro por organização do usuário
            user = self.request.user
            if user.profile.is_system_admin:
                return Team.objects.all()
            else:
                return Team.objects.filter(organization=user.profile.organization)
    
    @audit_action(entity_type='TEAM', action_type='CREATE')
    def perform_create(self, serializer):
        # Verificar se estamos acessando por uma rota aninhada (organização específica)
        if 'organization_pk' in self.kwargs:
            # Obter organização a partir da URL
            organization_id = self.kwargs['organization_pk']
            try:
                organization = Organization.objects.get(organization_id=organization_id)
                serializer.save(organization=organization)
            except Organization.DoesNotExist:
                raise serializers.ValidationError({'organization': 'Organização não encontrada'})
        else:
            # Utilizar organização do usuário
            user = self.request.user
            if not user.profile.organization:
                raise serializers.ValidationError({'organization': 'Usuário não está associado a uma organização'})
            serializer.save(organization=user.profile.organization)
            
    @audit_action(entity_type='TEAM', action_type='UPDATE')
    def perform_update(self, serializer):
        return super().perform_update(serializer)
        
    @audit_action(entity_type='TEAM', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)
        
    @audit_action(entity_type='TEAM', action_type='VIEW')
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)


class ProfileViewSet(viewsets.ModelViewSet):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    @audit_action(entity_type='PROFILE', action_type='CREATE')
    def perform_create(self, serializer):
        return super().perform_create(serializer)
        
    @audit_action(entity_type='PROFILE', action_type='UPDATE')
    def perform_update(self, serializer):
        return super().perform_update(serializer)
        
    @audit_action(entity_type='PROFILE', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)
        
    @audit_action(entity_type='PROFILE', action_type='VIEW')
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)


class RoleViewSet(viewsets.ModelViewSet):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_roles'
    
    @audit_action(entity_type='ROLE', action_type='CREATE')
    def perform_create(self, serializer):
        return super().perform_create(serializer)
        
    @audit_action(entity_type='ROLE', action_type='UPDATE')
    def perform_update(self, serializer):
        return super().perform_update(serializer)
        
    @audit_action(entity_type='ROLE', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)
        
    @audit_action(entity_type='ROLE', action_type='VIEW')
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)


class PermissionViewSet(viewsets.ModelViewSet):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_permissions'
    
    @audit_action(entity_type='PERMISSION', action_type='CREATE')
    def perform_create(self, serializer):
        return super().perform_create(serializer)
        
    @audit_action(entity_type='PERMISSION', action_type='UPDATE')
    def perform_update(self, serializer):
        return super().perform_update(serializer)
        
    @audit_action(entity_type='PERMISSION', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)
        
    @audit_action(entity_type='PERMISSION', action_type='VIEW')
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)


class UserRoleViewSet(viewsets.ModelViewSet):
    queryset = UserRole.objects.all()
    serializer_class = UserRoleSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'assign_roles'
    
    @audit_action(entity_type='USER_ROLE', action_type='CREATE')
    def perform_create(self, serializer):
        return super().perform_create(serializer)
        
    @audit_action(entity_type='USER_ROLE', action_type='UPDATE')
    def perform_update(self, serializer):
        return super().perform_update(serializer)
        
    @audit_action(entity_type='USER_ROLE', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)
        
    @audit_action(entity_type='USER_ROLE', action_type='VIEW')
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)


class RolePermissionViewSet(viewsets.ModelViewSet):
    queryset = RolePermission.objects.all()
    serializer_class = RolePermissionSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'assign_permissions'
    
    @audit_action(entity_type='ROLE_PERMISSION', action_type='CREATE')
    def perform_create(self, serializer):
        return super().perform_create(serializer)
        
    @audit_action(entity_type='ROLE_PERMISSION', action_type='UPDATE')
    def perform_update(self, serializer):
        return super().perform_update(serializer)
        
    @audit_action(entity_type='ROLE_PERMISSION', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)
        
    @audit_action(entity_type='ROLE_PERMISSION', action_type='VIEW')
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    @audit_action(entity_type='USER', action_type='CREATE')
    def perform_create(self, serializer):
        user = serializer.save()
        # Cria perfil automaticamente
        Profile.objects.create(user=user)

    @audit_action(entity_type='USER', action_type='UPDATE')    
    def perform_update(self, serializer):
        return super().perform_update(serializer)
        
    @audit_action(entity_type='USER', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)
        
    @audit_action(entity_type='USER', action_type='VIEW')
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

    def get_queryset(self):
        # Usuário só vê a si mesmo ou membros da sua organização
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            org = user.profile.organization
            return User.objects.filter(profile__organization=org)
        return User.objects.filter(id=user.id)


# Views de autenticação
class HelloWorldView(APIView):
    """
    Simple view to test if the API is working and validate authentication.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    @audit_action(entity_type='API', action_type='TEST')
    def get(self, request):
        user = request.user
        return Response({
            "message": f"Hello, {user.username}! Welcome to IRP API.",
            "authenticated": True,
            "user_id": user.id
        })


class LoginView(APIView):
    """
    Endpoint to authenticate users and return a token.
    """
    permission_classes = [permissions.AllowAny]
    
    @audit_action(entity_type='AUTH', action_type='LOGIN')
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        
        if not username or not password:
            return Response({'error': 'Please provide both username and password'}, 
                            status=status.HTTP_400_BAD_REQUEST)
        
        user = authenticate(username=username, password=password)
        
        if not user:
            return Response({'error': 'Invalid credentials'}, 
                            status=status.HTTP_401_UNAUTHORIZED)
        
        # Get or create token
        token, created = Token.objects.get_or_create(user=user)
        
        # Return user info and token
        return Response({
            'token': token.key,
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'is_staff': user.is_staff,
        })


class LogoutView(APIView):
    """
    Endpoint to logout users (revoke token).
    """
    permission_classes = [permissions.IsAuthenticated]
    
    @audit_action(entity_type='AUTH', action_type='LOGOUT')
    def post(self, request):
        # Delete the token to logout
        try:
            request.user.auth_token.delete()
            
            # Registrar logout para auditoria
            user = request.user
            if user and hasattr(user, 'profile') and user.profile and user.profile.organization:
                AuditService.log_action(
                    user=user,
                    organization=user.profile.organization,
                    entity_type='USER',
                    entity_id=str(user.id),
                    action_type='LOGOUT',
                    request=request
                )
            
            return Response({"message": "Successfully logged out."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ChangePasswordView(APIView):
    """
    Endpoint para alterar a senha do usuário logado.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    @audit_action(entity_type='USER', action_type='CHANGE_PASSWORD')
    def post(self, request):
        user = request.user
        current_password = request.data.get('current_password')
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')
        
        # Validar entrada
        if not current_password or not new_password or not confirm_password:
            return Response(
                {'error': 'Por favor, informe a senha atual e a nova senha (com confirmação)'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Verificar se a senha atual está correta
        if not user.check_password(current_password):
            return Response(
                {'error': 'Senha atual incorreta'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Verificar se as novas senhas coincidem
        if new_password != confirm_password:
            return Response(
                {'error': 'As novas senhas não coincidem'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Alterar a senha
        user.set_password(new_password)
        user.save()
        
        # Atualizar o token
        if hasattr(user, 'auth_token'):
            user.auth_token.delete()
        token, _ = Token.objects.get_or_create(user=user)
        
        return Response({
            'message': 'Senha alterada com sucesso',
            'token': token.key
        })


class AdminResetPasswordView(APIView):
    """
    Endpoint para administradores redefinir a senha de outro usuário.
    """
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'user:edit'
    
    @audit_action(entity_type='USER', action_type='ADMIN_RESET_PASSWORD')
    def post(self, request, user_id):
        try:
            target_user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                {'error': 'Usuário não encontrado'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Verificar se o usuário alvo pertence à mesma organização
        admin_user = request.user
        if (hasattr(admin_user, 'profile') and hasattr(target_user, 'profile') and 
            admin_user.profile.organization != target_user.profile.organization and
            not admin_user.profile.is_system_admin):
            return Response(
                {'error': 'Você não tem permissão para redefinir a senha deste usuário'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        new_password = request.data.get('new_password')
        confirm_password = request.data.get('confirm_password')
        
        # Validar entrada
        if not new_password or not confirm_password:
            return Response(
                {'error': 'Por favor, informe a nova senha (com confirmação)'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Verificar se as novas senhas coincidem
        if new_password != confirm_password:
            return Response(
                {'error': 'As senhas não coincidem'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Redefinir a senha
        target_user.set_password(new_password)
        target_user.save()
        
        # Revogar os tokens existentes do usuário
        if hasattr(target_user, 'auth_token'):
            target_user.auth_token.delete()
        
        # Registrar na auditoria a troca de senha (pelo admin)
        if hasattr(admin_user, 'profile') and admin_user.profile.organization:
            AuditService.log_action(
                user=admin_user,
                organization=admin_user.profile.organization,
                entity_type='USER',
                entity_id=str(target_user.id),
                action_type='PASSWORD_RESET',
                details_after={'reset_by_admin': admin_user.username},
                request=request
            )
        
        return Response({
            'message': f'Senha do usuário {target_user.username} redefinida com sucesso'
        })


@api_view(['GET'])
@permission_classes([permissions.AllowAny])
@audit_action(entity_type='API', action_type='STATUS')
def test_api_status(request):
    """
    Endpoint to test if the API is up and running.
    """
    return Response({
        "status": "ok",
        "message": "API is running",
        "version": "1.0.0"
    }, status=status.HTTP_200_OK)
