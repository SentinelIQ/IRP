from django.test import TestCase
from django.utils import timezone
from django.contrib.auth import get_user_model
from rest_framework.test import APITestCase, APIClient
from .models import TimelineEvent
from .services import create_timeline_event

User = get_user_model()

class TimelineEventModelTest(TestCase):
    def setUp(self):
        # Setup code will be implemented later when the cases module is available
        pass
    
    def test_create_timeline_event(self):
        # Test will be implemented later when the cases module is available
        pass

class TimelineEventAPITest(APITestCase):
    def setUp(self):
        # Setup code will be implemented later when the cases module is available
        self.client = APIClient()
    
    def test_list_timeline_events(self):
        # Test will be implemented later when the cases module is available
        pass
    
    def test_create_timeline_event(self):
        # Test will be implemented later when the cases module is available
        pass
