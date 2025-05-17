from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_nested import routers
from rest_framework.authtoken.views import obtain_auth_token
from .views import (
    OrganizationViewSet, TeamViewSet, ProfileViewSet, RoleViewSet, PermissionViewSet,
    UserRoleViewSet, RolePermissionViewSet, UserViewSet,
    HelloWorldView, LoginView, LogoutView, test_api_status,
    ChangePasswordView, AdminResetPasswordView, LDAPConfigViewSet
)

router = DefaultRouter()

# Organization and User Management
router.register(r'organizations', OrganizationViewSet)
router.register(r'teams', TeamViewSet)
router.register(r'profiles', ProfileViewSet)
router.register(r'roles', RoleViewSet)
router.register(r'permissions', PermissionViewSet)
router.register(r'user-roles', UserRoleViewSet)
router.register(r'role-permissions', RolePermissionViewSet)
router.register(r'users', UserViewSet)
router.register(r'ldap-configs', LDAPConfigViewSet)

# Configuração de routers aninhados (times por organização)
organizations_router = routers.NestedSimpleRouter(router, r'organizations', lookup='organization')
organizations_router.register(r'teams', TeamViewSet, basename='organization-teams')

urlpatterns = [
    path('', include(router.urls)),
    path('', include(organizations_router.urls)),
    
    # Rotas de autenticação
    path('auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('token-auth/', obtain_auth_token, name='token_auth'),
    path('hello/', HelloWorldView.as_view(), name='hello'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('change-password/', ChangePasswordView.as_view(), name='change_password'),
    path('reset-password/<int:user_id>/', AdminResetPasswordView.as_view(), name='admin_reset_password'),
    
    # Teste de status da API
    path('test-status/', test_api_status, name='test_api_status'),
]
