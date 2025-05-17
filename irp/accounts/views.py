from rest_framework import viewsets, permissions
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework import status
from django.contrib.auth import authenticate
from rest_framework.decorators import api_view, permission_classes, action
from django.utils import timezone
import ldap
import json
import logging
from cryptography.fernet import Fernet

from .models import Organization, Team, Profile, Role, Permission, UserRole, RolePermission, LDAPConfig
from .serializers import (
    OrganizationSerializer, TeamSerializer, ProfileSerializer, 
    RoleSerializer, PermissionSerializer, UserRoleSerializer,
    RolePermissionSerializer, UserSerializer, LDAPConfigSerializer
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


class LDAPConfigViewSet(viewsets.ModelViewSet):
    """
    API endpoint for LDAP/AD configuration management.
    """
    queryset = LDAPConfig.objects.all()
    serializer_class = LDAPConfigSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'ldap:manage'
    
    @audit_action(entity_type='LDAP_CONFIG', action_type='CREATE')
    def perform_create(self, serializer):
        return super().perform_create(serializer)
        
    @audit_action(entity_type='LDAP_CONFIG', action_type='UPDATE')
    def perform_update(self, serializer):
        return super().perform_update(serializer)
        
    @audit_action(entity_type='LDAP_CONFIG', action_type='DELETE')
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)
        
    @audit_action(entity_type='LDAP_CONFIG', action_type='VIEW')
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)
    
    @audit_action(entity_type='LDAP_CONFIG', action_type='TEST')
    @action(detail=True, methods=['post'])
    def test_connection(self, request, pk=None):
        """
        Test the LDAP/AD connection with the provided configuration.
        """
        ldap_config = self.get_object()
        
        try:
            # Initialize LDAP connection
            ldap_connection = self._get_ldap_connection(ldap_config)
            
            # Try to bind with the provided credentials
            ldap_connection.simple_bind_s(ldap_config.bind_dn, ldap_config.bind_password)
            
            # Unbind when done
            ldap_connection.unbind_s()
            
            return Response({
                'status': 'success',
                'message': 'Successfully connected to LDAP server and authenticated'
            })
        except ldap.INVALID_CREDENTIALS:
            return Response({
                'status': 'error',
                'message': 'Invalid credentials. Check bind DN and password.'
            }, status=status.HTTP_400_BAD_REQUEST)
        except ldap.SERVER_DOWN:
            return Response({
                'status': 'error',
                'message': 'Failed to connect to LDAP server. Check server URL and network connection.'
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'status': 'error',
                'message': f'LDAP connection error: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @audit_action(entity_type='LDAP_CONFIG', action_type='SYNC')
    @action(detail=True, methods=['post'])
    def trigger_sync(self, request, pk=None):
        """
        Trigger a manual synchronization with the LDAP/AD server.
        """
        ldap_config = self.get_object()
        
        if not has_permission(request.user, 'ldap:sync'):
            return Response({
                'status': 'error',
                'message': 'You do not have permission to trigger LDAP synchronization'
            }, status=status.HTTP_403_FORBIDDEN)
        
        try:
            # Update status to PENDING
            ldap_config.last_sync_status = 'PENDING'
            ldap_config.save(update_fields=['last_sync_status'])
            
            # Trigger the synchronization task
            from .tasks import sync_ldap_users
            sync_ldap_users.delay(str(ldap_config.config_id))
            
            return Response({
                'status': 'success',
                'message': 'LDAP synchronization triggered successfully'
            })
        except Exception as e:
            ldap_config.last_sync_status = 'FAILED'
            ldap_config.last_sync_message = str(e)
            ldap_config.last_sync_timestamp = timezone.now()
            ldap_config.save(update_fields=[
                'last_sync_status', 'last_sync_message', 'last_sync_timestamp'
            ])
            
            return Response({
                'status': 'error',
                'message': f'Failed to trigger LDAP synchronization: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def _get_ldap_connection(self, ldap_config):
        """
        Create and return an LDAP connection based on the configuration.
        """
        # Set global LDAP options
        ldap.set_option(ldap.OPT_REFERRALS, 0)
        ldap.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)
        
        # Create connection
        ldap_connection = ldap.initialize(ldap_config.server_url)
        
        # Configure TLS if enabled
        if ldap_config.ldap_tls_enabled:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            if ldap_config.ldap_tls_ca_cert_path:
                ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, ldap_config.ldap_tls_ca_cert_path)
            
            if ldap_config.server_url.startswith('ldap://'):
                ldap_connection.start_tls_s()
        
        return ldap_connection


class LDAPAuthenticationBackend(object):
    """
    Custom authentication backend for LDAP/AD integration.
    This allows users to authenticate using their LDAP/AD credentials.
    """
    
    def authenticate(self, request, username=None, password=None):
        if not username or not password:
            return None
        
        # Find active LDAP configurations
        ldap_configs = LDAPConfig.objects.filter(
            is_active=True, 
            enable_delegated_authentication=True
        )
        
        if not ldap_configs.exists():
            return None  # No active LDAP configuration with delegated auth
        
        # Try each LDAP configuration until one works
        for ldap_config in ldap_configs:
            try:
                # Initialize LDAP connection
                ldap_connection = self._get_ldap_connection(ldap_config)
                
                # Find user in LDAP
                user_dn = self._find_user_dn(ldap_connection, ldap_config, username)
                if not user_dn:
                    continue  # User not found in this LDAP, try next one
                
                # Authenticate user against LDAP
                try:
                    ldap_connection.simple_bind_s(user_dn, password)
                except ldap.INVALID_CREDENTIALS:
                    continue  # Invalid credentials, try next LDAP config
                
                # Get user attributes from LDAP
                user_attrs = self._get_user_attributes(ldap_connection, ldap_config, user_dn)
                
                # Find or create user in local database
                user, created = self._get_or_create_local_user(ldap_config, username, user_attrs)
                
                # Unbind LDAP connection
                ldap_connection.unbind_s()
                
                return user
            except Exception as e:
                logging.error(f"LDAP authentication error: {str(e)}")
                continue
        
        return None
    
    def _get_ldap_connection(self, ldap_config):
        """
        Create and return an LDAP connection based on the configuration.
        """
        # Set global LDAP options
        ldap.set_option(ldap.OPT_REFERRALS, 0)
        ldap.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)
        
        # Create connection
        ldap_connection = ldap.initialize(ldap_config.server_url)
        
        # Configure TLS if enabled
        if ldap_config.ldap_tls_enabled:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            if ldap_config.ldap_tls_ca_cert_path:
                ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, ldap_config.ldap_tls_ca_cert_path)
            
            if ldap_config.server_url.startswith('ldap://'):
                ldap_connection.start_tls_s()
        
        return ldap_connection
    
    def _find_user_dn(self, ldap_connection, ldap_config, username):
        """
        Find the user's DN in the LDAP directory.
        """
        # Get username attribute from mapping
        username_attr = ldap_config.user_attribute_mapping.get('username', 'sAMAccountName')
        
        # Build search filter
        search_filter = f"(&{ldap_config.user_search_filter}({username_attr}={username}))"
        
        # Search for user
        result = ldap_connection.search_s(
            ldap_config.user_base_dn,
            ldap.SCOPE_SUBTREE,
            search_filter,
            ['distinguishedName']
        )
        
        if not result or len(result) == 0:
            return None
        
        return result[0][0]  # Return the DN
    
    def _get_user_attributes(self, ldap_connection, ldap_config, user_dn):
        """
        Get user attributes from LDAP.
        """
        # Get attributes needed from mapping
        attrs_to_retrieve = list(ldap_config.user_attribute_mapping.values())
        
        # Add any additional attributes we might need
        if 'userAccountControl' not in attrs_to_retrieve:
            attrs_to_retrieve.append('userAccountControl')
        
        # Search for user attributes
        result = ldap_connection.search_s(
            user_dn,
            ldap.SCOPE_BASE,
            '(objectClass=*)',
            attrs_to_retrieve
        )
        
        if not result or len(result) == 0:
            return {}
        
        return result[0][1]  # Return the attributes
    
    def _get_or_create_local_user(self, ldap_config, username, user_attrs):
        """
        Find or create the user in the local database.
        """
        # Map attributes from LDAP to local fields
        mapping = ldap_config.user_attribute_mapping
        user_data = {}
        
        for local_field, ldap_attr in mapping.items():
            if ldap_attr in user_attrs:
                # LDAP returns values as lists of bytes
                attr_value = user_attrs[ldap_attr][0]
                if isinstance(attr_value, bytes):
                    attr_value = attr_value.decode('utf-8')
                user_data[local_field] = attr_value
        
        # Check if user exists using username from mapping
        username_field = user_data.get('username', username)
        try:
            user = User.objects.get(username=username_field)
            created = False
            
            # Update user fields if needed
            update_fields = []
            
            if 'email' in user_data and user.email != user_data['email']:
                user.email = user_data['email']
                update_fields.append('email')
            
            if 'first_name' in user_data and user.first_name != user_data['first_name']:
                user.first_name = user_data['first_name']
                update_fields.append('first_name')
            
            if 'last_name' in user_data and user.last_name != user_data['last_name']:
                user.last_name = user_data['last_name']
                update_fields.append('last_name')
            
            if update_fields:
                user.save(update_fields=update_fields)
            
            # Update profile as well
            if hasattr(user, 'profile'):
                profile_update_fields = []
                
                if 'full_name' in user_data and user.profile.full_name != user_data['full_name']:
                    user.profile.full_name = user_data['full_name']
                    profile_update_fields.append('full_name')
                
                # Set LDAP identifier
                if not user.profile.external_id or not user.profile.managed_by_ldap:
                    user.profile.external_id = user_attrs.get('distinguishedName', [b''])[0].decode('utf-8')
                    user.profile.managed_by_ldap = True
                    profile_update_fields.extend(['external_id', 'managed_by_ldap'])
                
                if profile_update_fields:
                    user.profile.save(update_fields=profile_update_fields)
        
        except User.DoesNotExist:
            # Create new user
            user_kwargs = {
                'username': username_field,
                'email': user_data.get('email', ''),
                'first_name': user_data.get('first_name', ''),
                'last_name': user_data.get('last_name', ''),
                'is_active': True,
                'is_staff': False,
                'is_superuser': False
            }
            
            user = User.objects.create_user(**user_kwargs)
            created = True
            
            # Create or update profile
            profile = Profile.objects.get_or_create(user=user)[0]
            profile.full_name = user_data.get('full_name', '')
            profile.external_id = user_attrs.get('distinguishedName', [b''])[0].decode('utf-8')
            profile.managed_by_ldap = True
            profile.save()
            
            # If organization mapping is provided, assign user to organization
            if ldap_config.organization:
                profile.organization = ldap_config.organization
                profile.save(update_fields=['organization'])
        
        return user, created
    
    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
