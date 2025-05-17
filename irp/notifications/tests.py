from django.test import TestCase
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from rest_framework import status
import json

from irp.accounts.models import Organization, Profile
from .models import NotificationEvent, NotificationChannel, NotificationRule, NotificationLog
from .services import NotificationService


class NotificationModelsTestCase(TestCase):
    def setUp(self):
        # Create a test organization and user
        self.organization = Organization.objects.create(
            name="Test Organization",
            description="Test Organization Description"
        )
        
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpassword"
        )
        
        self.profile = Profile.objects.create(
            user=self.user,
            organization=self.organization
        )
        
        # Create notification event
        self.event = NotificationEvent.objects.create(
            event_name="TEST_EVENT",
            description="Test event for notifications"
        )
        
        # Create notification channel
        self.channel = NotificationChannel.objects.create(
            organization=self.organization,
            channel_type="WEBHOOK",
            name="Test Webhook",
            configuration={
                "url": "https://example.com/webhook",
                "headers": {"Content-Type": "application/json"}
            },
            is_active=True
        )
        
        # Create notification rule
        self.rule = NotificationRule.objects.create(
            organization=self.organization,
            name="Test Rule",
            event_type=self.event,
            channel=self.channel,
            conditions={"test_field": "test_value"},
            message_template="Test notification: {{ message }}",
            is_active=True
        )
    
    def test_notification_event_str(self):
        """Test the string representation of NotificationEvent"""
        self.assertEqual(str(self.event), "TEST_EVENT")
    
    def test_notification_channel_str(self):
        """Test the string representation of NotificationChannel"""
        self.assertEqual(str(self.channel), "Test Webhook (Webhook)")
    
    def test_notification_rule_str(self):
        """Test the string representation of NotificationRule"""
        self.assertEqual(str(self.rule), "Test Rule")
    
    def test_process_event_conditions_match(self):
        """Test processing an event with matching conditions"""
        # Mock the send_notification method to avoid actual HTTP requests
        original_send = NotificationService._send_notification
        NotificationService._send_notification = lambda cls, channel, message, payload: (True, "Test success")
        
        payload = {
            "message": "Test message",
            "test_field": "test_value"
        }
        
        # Process the event
        logs = NotificationService.process_event("TEST_EVENT", payload, self.organization)
        
        # Verify log was created
        self.assertEqual(len(logs), 1)
        log = NotificationLog.objects.get(log_id=logs[0])
        self.assertEqual(log.status, "SUCCESS")
        self.assertEqual(log.rule, self.rule)
        
        # Restore original method
        NotificationService._send_notification = original_send
    
    def test_process_event_conditions_no_match(self):
        """Test processing an event with non-matching conditions"""
        payload = {
            "message": "Test message",
            "test_field": "wrong_value"
        }
        
        # Process the event
        logs = NotificationService.process_event("TEST_EVENT", payload, self.organization)
        
        # Verify no logs were created
        self.assertEqual(len(logs), 0)
        self.assertEqual(NotificationLog.objects.count(), 0)


class NotificationAPITestCase(TestCase):
    def setUp(self):
        # Create test data similar to the model test case
        self.organization = Organization.objects.create(
            name="Test Organization",
            description="Test Organization Description"
        )
        
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpassword"
        )
        
        self.profile = Profile.objects.create(
            user=self.user,
            organization=self.organization
        )
        
        # Setup API client
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        
        # Create basic test data
        self.event = NotificationEvent.objects.create(
            event_name="TEST_EVENT",
            description="Test event for notifications"
        )
    
    def test_list_notification_events(self):
        """Test listing notification events"""
        response = self.client.get('/api/notification-events/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['event_name'], 'TEST_EVENT')
    
    def test_create_notification_channel(self):
        """Test creating a notification channel"""
        data = {
            "channel_type": "WEBHOOK",
            "name": "Test Channel",
            "configuration": {
                "url": "https://example.com/webhook"
            },
            "is_active": True
        }
        
        response = self.client.post('/api/notification-channels/', data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(NotificationChannel.objects.count(), 1)
        channel = NotificationChannel.objects.first()
        self.assertEqual(channel.name, "Test Channel")
        self.assertEqual(channel.organization, self.organization) 