from django.test import TestCase
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from rest_framework import status
from .models import AlertSeverity, AlertStatus, Alert
from irp.accounts.models import Organization, Profile


class AlertsModelTests(TestCase):
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
            organization=self.organization,
            is_system_admin=True
        )
        
        # Create test alert severity
        self.severity = AlertSeverity.objects.create(
            name='High',
            level_order=3,
            color_code='#ff0000'
        )
        
        # Create test alert status
        self.status = AlertStatus.objects.create(
            name='Open',
            organization=self.organization,
            is_default_open_status=True,
            color_code='#00ff00'
        )
        
        # Create test alert
        self.alert = Alert.objects.create(
            title='Test Alert',
            source_system='Test System',
            description='Test Description',
            severity=self.severity,
            status=self.status,
            organization=self.organization
        )
    
    def test_alert_creation(self):
        """Test alert creation"""
        self.assertEqual(self.alert.title, 'Test Alert')
        self.assertEqual(self.alert.severity, self.severity)
        self.assertEqual(self.alert.status, self.status)
        self.assertEqual(self.alert.organization, self.organization)


class AlertsAPITests(TestCase):
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
            is_system_admin=True
        )
        
        # Create test alert severity
        self.severity = AlertSeverity.objects.create(
            name='High',
            level_order=3,
            color_code='#ff0000'
        )
        
        # Create test alert status
        self.status = AlertStatus.objects.create(
            name='Open',
            organization=self.organization,
            is_default_open_status=True,
            color_code='#00ff00'
        )
        
        # Create test alert
        self.alert = Alert.objects.create(
            title='Test Alert',
            source_system='Test System',
            description='Test Description',
            severity=self.severity,
            status=self.status,
            organization=self.organization
        )
        
        # Authenticate the client
        self.client.force_authenticate(user=self.user)
    
    def test_get_alerts(self):
        """Test retrieving alerts"""
        response = self.client.get('/api/alerts/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
