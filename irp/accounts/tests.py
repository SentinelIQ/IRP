from django.test import TestCase
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from rest_framework import status
from .models import Organization, Team, Profile, Role, Permission, UserRole, RolePermission
from .services import RoleService, UserService, OrganizationService, TeamService

class AccountsModelTests(TestCase):
    def setUp(self):
        # Create test user
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        # Create test organization
        self.organization = Organization.objects.create(
            name='Test Organization',
            description='Test Description',
            slug='test-org'
        )
        
        # Create profile for test user
        self.profile = Profile.objects.create(
            user=self.user,
            full_name='Test User',
            organization=self.organization
        )
    
    def test_organization_creation(self):
        """Test organization creation"""
        self.assertEqual(self.organization.name, 'Test Organization')
        self.assertEqual(self.organization.slug, 'test-org')
        
    def test_profile_creation(self):
        """Test profile creation and association with user and organization"""
        self.assertEqual(self.profile.user, self.user)
        self.assertEqual(self.profile.organization, self.organization)
        self.assertEqual(self.profile.full_name, 'Test User')

    def test_team_creation(self):
        """Test team creation and member association"""
        team = Team.objects.create(
            name='Test Team',
            description='Test Team Description',
            organization=self.organization
        )
        team.members.add(self.user)
        
        self.assertEqual(team.name, 'Test Team')
        self.assertEqual(team.organization, self.organization)
        self.assertTrue(self.user in team.members.all())


class AccountsAPITests(TestCase):
    def setUp(self):
        # Create test user
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.client = APIClient()
        
        # Create test organization
        self.organization = Organization.objects.create(
            name='Test Organization',
            description='Test Description',
            slug='test-org'
        )
        
        # Create profile for test user with system admin privileges
        self.profile = Profile.objects.create(
            user=self.user,
            full_name='Test User',
            organization=self.organization,
            is_system_admin=True  # Make the user a system admin for testing
        )
        
        # Authenticate the client
        self.client.force_authenticate(user=self.user)
        
        # Create test team
        self.team = Team.objects.create(
            name='Test Team',
            description='Test Team Description',
            organization=self.organization
        )
        self.team.members.add(self.user)
    
    def test_get_organizations(self):
        """Test retrieving organizations"""
        response = self.client.get('/api/v2/organizations/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(len(response.data) > 0)
        
    def test_create_organization(self):
        """Test creating a new organization"""
        data = {
            'name': 'New Organization',
            'description': 'New Description',
            'contact_info': 'contact@example.com'
        }
        response = self.client.post('/api/v2/organizations/', data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['name'], 'New Organization')
        self.assertTrue('slug' in response.data)
        
    def test_get_teams(self):
        """Test retrieving teams"""
        response = self.client.get('/api/v2/teams/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(len(response.data) > 0)
        
    def test_create_team(self):
        """Test creating a new team"""
        data = {
            'name': 'New Team',
            'description': 'New Team Description'
        }
        response = self.client.post('/api/v2/teams/', data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['name'], 'New Team')
        self.assertEqual(response.data['organization']['organization_id'], self.organization.organization_id)
        
    def test_get_organization_teams(self):
        """Test retrieving teams of a specific organization"""
        url = f'/api/v2/organizations/{self.organization.organization_id}/teams/'
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(len(response.data) > 0)
        
    def test_create_organization_team(self):
        """Test creating a team for a specific organization"""
        url = f'/api/v2/organizations/{self.organization.organization_id}/teams/'
        data = {
            'name': 'Org Specific Team',
            'description': 'Team created via org endpoint'
        }
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['name'], 'Org Specific Team')
        self.assertEqual(response.data['organization']['organization_id'], self.organization.organization_id)
        
    def test_get_profile(self):
        """Test retrieving user profile"""
        response = self.client.get(f'/api/v2/profiles/{self.profile.id}/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['full_name'], 'Test User')
        
    def test_login_logout(self):
        """Test login and logout functionality"""
        # Unauthenticate the client
        self.client.force_authenticate(user=None)
        
        # Test login
        login_data = {
            'username': 'testuser',
            'password': 'testpass123'
        }
        login_response = self.client.post('/api/v2/login/', login_data)
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        self.assertTrue('token' in login_response.data)
        
        # Test authentication with token
        token = login_response.data['token']
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token}')
        
        # Test accessing protected resource
        resource_response = self.client.get('/api/v2/organizations/')
        self.assertEqual(resource_response.status_code, status.HTTP_200_OK)
        
        # Test logout
        logout_response = self.client.post('/api/v2/logout/')
        self.assertEqual(logout_response.status_code, status.HTTP_200_OK)
        
        # Test access after logout (should fail)
        self.client.credentials()  # Remove token
        after_logout_response = self.client.get('/api/v2/organizations/')
        self.assertEqual(after_logout_response.status_code, status.HTTP_401_UNAUTHORIZED)


class ServiceTests(TestCase):
    def setUp(self):
        # Criar permissões e papéis para teste
        RoleService.setup_default_permissions()
        
        # Criar organização para teste
        self.organization = OrganizationService.create_organization(
            name='Test Org',
            description='Test Org Description',
            contact_info='test@example.org'
        )
        
        # Criar papéis para a organização
        self.roles = RoleService.setup_default_roles(self.organization)
    
    def test_create_user_with_profile(self):
        """Test creating a user with profile service"""
        user = UserService.create_user_with_profile(
            username='serviceuser',
            email='service@example.com',
            password='servicepass123',
            full_name='Service Test User',
            organization=self.organization,
            is_admin=True
        )
        
        self.assertEqual(user.username, 'serviceuser')
        self.assertEqual(user.email, 'service@example.com')
        self.assertTrue(hasattr(user, 'profile'))
        self.assertEqual(user.profile.full_name, 'Service Test User')
        self.assertEqual(user.profile.organization, self.organization)
        
        # Verificar se o usuário recebeu o papel de admin
        user_roles = UserRole.objects.filter(user=user)
        self.assertTrue(user_roles.exists())
        
    def test_create_team_and_add_user(self):
        """Test team creation and user assignment services"""
        # Criar usuário
        user = UserService.create_user_with_profile(
            username='teamuser',
            email='team@example.com',
            password='teampass123',
            organization=self.organization
        )
        
        # Criar time
        team = TeamService.create_team(
            name='Service Test Team',
            organization=self.organization,
            description='Team created via service'
        )
        
        # Adicionar usuário ao time
        success = UserService.assign_user_to_team(user, team)
        
        self.assertTrue(success)
        self.assertTrue(user in team.members.all())
        
        # Tentar adicionar novamente (deve falhar)
        success = UserService.assign_user_to_team(user, team)
        self.assertFalse(success)
