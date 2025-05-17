from django.test import TestCase
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from rest_framework import status
from .models import Organization, Team, Profile, Role, Permission, UserRole, RolePermission

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
        
        # Create profile for test user
        self.profile = Profile.objects.create(
            user=self.user,
            full_name='Test User',
            organization=self.organization,
            is_system_admin=True  # Make the user a system admin for testing
        )
        
        # Authenticate the client
        self.client.force_authenticate(user=self.user)
    
    def test_get_organizations(self):
        """Test retrieving organizations"""
        response = self.client.get('/api/organizations/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        
    def test_get_profile(self):
        """Test retrieving user profile"""
        response = self.client.get(f'/api/profiles/{self.profile.id}/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['full_name'], 'Test User')
