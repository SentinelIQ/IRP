from rest_framework import viewsets, permissions
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework import status
from django.contrib.auth import authenticate
from rest_framework.decorators import api_view

from .models import Organization, Team, Profile, Role, Permission, UserRole, RolePermission
from .serializers import (
    OrganizationSerializer, TeamSerializer, ProfileSerializer, 
    RoleSerializer, PermissionSerializer, UserRoleSerializer,
    RolePermissionSerializer, UserSerializer
)
from irp.common.permissions import HasRolePermission


class OrganizationViewSet(viewsets.ModelViewSet):
    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_organizations'


class TeamViewSet(viewsets.ModelViewSet):
    queryset = Team.objects.all()
    serializer_class = TeamSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_teams'

    def get_queryset(self):
        # Isolamento multi-tenant: só times da organização do usuário
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            return Team.objects.filter(organization=user.profile.organization)
        return Team.objects.none()

    def perform_create(self, serializer):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            serializer.save(organization=user.profile.organization)
        else:
            serializer.save()


class ProfileViewSet(viewsets.ModelViewSet):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer
    permission_classes = [permissions.IsAuthenticated]


class RoleViewSet(viewsets.ModelViewSet):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_roles'


class PermissionViewSet(viewsets.ModelViewSet):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'manage_permissions'


class UserRoleViewSet(viewsets.ModelViewSet):
    queryset = UserRole.objects.all()
    serializer_class = UserRoleSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'assign_roles'


class RolePermissionViewSet(viewsets.ModelViewSet):
    queryset = RolePermission.objects.all()
    serializer_class = RolePermissionSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'assign_permissions'


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        user = serializer.save()
        # Cria perfil automaticamente
        Profile.objects.create(user=user)

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
    
    def get(self, request):
        return Response({'message': 'Hello World!'})


class LoginView(APIView):
    """
    Endpoint to authenticate users and return a token.
    """
    permission_classes = [permissions.AllowAny]
    
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
    
    def post(self, request):
        # Delete the token to logout
        try:
            request.user.auth_token.delete()
            return Response({'message': 'Successfully logged out'}, 
                           status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, 
                           status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
def test_api_status(request):
    """
    View para testar se a API está funcionando corretamente.
    """
    return Response({
        "status": "ok",
        "message": "API V2 está funcionando corretamente",
        "modules": [
            "accounts", 
            "alerts", 
            "cases", 
            "observables", 
            "timeline", 
            "knowledge_base", 
            "metrics", 
            "notifications", 
            "audit", 
            "mitre",
            "integrations"
        ]
    })
