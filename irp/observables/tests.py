from django.test import TestCase
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from rest_framework import status

from .models import ObservableType, TLPLevel, PAPLevel, Observable


class ObservablesModelTests(TestCase):
    def setUp(self):
        # Create test user
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        # Create test observable type
        self.observable_type = ObservableType.objects.create(
            name='IP Address',
            description='IPv4 or IPv6 address'
        )
        
        # Create test TLP level
        self.tlp_level = TLPLevel.objects.create(
            name='TLP:AMBER',
            description='Limited disclosure, restricted to participants organizations'
        )
        
        # Create test PAP level
        self.pap_level = PAPLevel.objects.create(
            name='Block Immediately',
            description='Block this indicator immediately on all systems'
        )
        
        # Create test observable
        self.observable = Observable.objects.create(
            value='192.168.1.1',
            type=self.observable_type,
            description='Test IP address',
            is_ioc=True,
            tlp_level=self.tlp_level,
            pap_level=self.pap_level,
            added_by=self.user
        )
    
    def test_observable_type_creation(self):
        self.assertEqual(self.observable_type.name, 'IP Address')
        self.assertEqual(self.observable_type.description, 'IPv4 or IPv6 address')
    
    def test_tlp_level_creation(self):
        self.assertEqual(self.tlp_level.name, 'TLP:AMBER')
    
    def test_pap_level_creation(self):
        self.assertEqual(self.pap_level.name, 'Block Immediately')
    
    def test_observable_creation(self):
        self.assertEqual(self.observable.value, '192.168.1.1')
        self.assertEqual(self.observable.type, self.observable_type)
        self.assertEqual(self.observable.tlp_level, self.tlp_level)
        self.assertEqual(self.observable.pap_level, self.pap_level)
        self.assertEqual(self.observable.added_by, self.user)
        self.assertTrue(self.observable.is_ioc)


class ObservableAPITests(TestCase):
    def setUp(self):
        # Create test user
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        # Setup API client
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        
        # Create test observable type
        self.observable_type = ObservableType.objects.create(
            name='IP Address',
            description='IPv4 or IPv6 address'
        )
    
    def test_create_observable_type(self):
        url = '/api/v2/observables/observable-types/'
        data = {
            'name': 'Domain',
            'description': 'Domain name'
        }
        # Note: In a real test, you would make the actual request and check the response
        # This is just a placeholder for the structure
