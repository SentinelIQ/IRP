from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework.authtoken.views import obtain_auth_token
from .views import (
    OrganizationViewSet, TeamViewSet, ProfileViewSet, RoleViewSet, PermissionViewSet,
    UserRoleViewSet, RolePermissionViewSet, UserViewSet,
    HelloWorldView, LoginView, LogoutView, test_api_status
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

urlpatterns = [
    path('', include(router.urls)),
    # Rotas de autenticação
    path('auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('token-auth/', obtain_auth_token, name='token_auth'),
    path('hello/', HelloWorldView.as_view(), name='hello'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('test-status/', test_api_status, name='test_api_status'),
]
