from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from unittest.mock import patch, MagicMock
import uuid

from django.contrib.auth.models import User
from irp.accounts.models import Organization, Profile
from irp.integrations.misp.models import MISPInstance, MISPImport, MISPExport
from irp.integrations.misp.services import MISPService


class MISPModelsTestCase(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Test Organization",
            short_name="test-org"
        )
        
        self.misp_instance = MISPInstance.objects.create(
            name="Test MISP",
            url="https://test-misp.example.com",
            api_key="test-api-key",
            organization=self.organization,
            verify_ssl=True,
            default_distribution=0,
            default_threat_level=2,
            default_analysis=0
        )
        
    def test_misp_instance_creation(self):
        """Test creating a MISP instance"""
        self.assertEqual(self.misp_instance.name, "Test MISP")
        self.assertEqual(self.misp_instance.url, "https://test-misp.example.com")
        self.assertEqual(self.misp_instance.organization, self.organization)
        self.assertTrue(self.misp_instance.is_active)
        self.assertIsNone(self.misp_instance.last_import_timestamp)

    def test_misp_instance_string_representation(self):
        """Test the string representation of a MISP instance"""
        self.assertEqual(
            str(self.misp_instance), 
            f"Test MISP (https://test-misp.example.com)"
        )


class MISPAPITestCase(TestCase):
    def setUp(self):
        # Create test organization
        self.organization = Organization.objects.create(
            name="Test Organization",
            short_name="test-org"
        )
        
        # Create test user
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpassword',
            is_staff=True
        )
        
        # Create profile for user
        self.profile = Profile.objects.create(
            user=self.user,
            organization=self.organization
        )
        
        # Create MISP instance
        self.misp_instance = MISPInstance.objects.create(
            name="Test MISP",
            url="https://test-misp.example.com",
            api_key="test-api-key",
            organization=self.organization,
            verify_ssl=True
        )
        
        # Set up API client
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    @patch('irp.integrations.misp.services.MISPService.test_connection')
    def test_misp_test_connection(self, mock_test_connection):
        """Test the MISP test connection endpoint"""
        # Set up mock return value
        mock_test_connection.return_value = (True, "Connection successful!")
        
        # Make API request
        url = reverse('misp-instance-test-connection', kwargs={'pk': self.misp_instance.instance_id})
        response = self.client.post(url)
        
        # Check response
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['success'], True)
        self.assertEqual(response.data['message'], "Connection successful!")
        
        # Verify mock was called correctly
        mock_test_connection.assert_called_once_with(self.misp_instance)


class MISPServiceTestCase(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name="Test Organization",
            short_name="test-org"
        )
        
        self.misp_instance = MISPInstance.objects.create(
            name="Test MISP",
            url="https://test-misp.example.com",
            api_key="test-api-key",
            organization=self.organization,
            verify_ssl=True
        )
    
    @patch('irp.integrations.misp.services.PyMISP')
    def test_get_misp_client(self, mock_pymisp):
        """Test creating a MISP client"""
        # Set up mock
        mock_pymisp_instance = MagicMock()
        mock_pymisp.return_value = mock_pymisp_instance
        
        # Call the service
        client = MISPService.get_misp_client(self.misp_instance)
        
        # Check result
        self.assertEqual(client, mock_pymisp_instance)
        
        # Verify mock was called correctly
        mock_pymisp.assert_called_once_with(
            url=self.misp_instance.url,
            key=self.misp_instance.api_key,
            ssl=self.misp_instance.verify_ssl,
            timeout=60
        )
    
    @patch('irp.integrations.misp.services.MISPService.get_misp_client')
    def test_test_connection(self, mock_get_client):
        """Test MISP connection testing"""
        # Set up mock
        mock_client = MagicMock()
        mock_client.get_version.return_value = {'version': '2.4.160'}
        mock_get_client.return_value = mock_client
        
        # Call the service
        success, message = MISPService.test_connection(self.misp_instance)
        
        # Check result
        self.assertTrue(success)
        self.assertEqual(message, "Conexão bem-sucedida. Versão MISP: 2.4.160")
        
        # Verify mocks were called correctly
        mock_get_client.assert_called_once_with(self.misp_instance)
        mock_client.get_version.assert_called_once() 