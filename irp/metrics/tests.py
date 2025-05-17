from django.test import TestCase
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import date, timedelta
from .models import Metric, MetricSnapshot, Dashboard, DashboardWidget
from irp.accounts.models import Organization, Profile


class MetricModelTests(TestCase):
    def setUp(self):
        self.metric = Metric.objects.create(
            name='test_metric',
            display_name='Test Metric',
            description='Test metric description',
            metric_type='COUNT',
            entity_type='ALERT'
        )
    
    def test_metric_creation(self):
        self.assertEqual(self.metric.name, 'test_metric')
        self.assertEqual(self.metric.display_name, 'Test Metric')
        self.assertEqual(self.metric.metric_type, 'COUNT')
        self.assertEqual(self.metric.entity_type, 'ALERT')


class DashboardModelTests(TestCase):
    def setUp(self):
        # Create a user
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpassword'
        )
        
        # Create an organization
        self.organization = Organization.objects.create(
            name='Test Organization',
            contact_email='contact@testorg.com'
        )
        
        # Create a profile for the user
        self.profile = Profile.objects.create(
            user=self.user,
            organization=self.organization
        )
        
        # Create a metric
        self.metric = Metric.objects.create(
            name='test_metric',
            display_name='Test Metric',
            description='Test metric description',
            metric_type='COUNT',
            entity_type='ALERT'
        )
        
        # Create a dashboard
        self.dashboard = Dashboard.objects.create(
            name='Test Dashboard',
            description='Test dashboard description',
            organization=self.organization,
            is_system=False,
            created_by=self.user
        )
    
    def test_dashboard_creation(self):
        self.assertEqual(self.dashboard.name, 'Test Dashboard')
        self.assertEqual(self.dashboard.organization, self.organization)
        self.assertEqual(self.dashboard.created_by, self.user)
        self.assertFalse(self.dashboard.is_system)
    
    def test_dashboard_widget_creation(self):
        widget = DashboardWidget.objects.create(
            dashboard=self.dashboard,
            title='Test Widget',
            widget_type='COUNTER',
            metric=self.metric,
            config={'color': 'blue'},
            position={'x': 0, 'y': 0, 'w': 2, 'h': 1}
        )
        
        self.assertEqual(widget.dashboard, self.dashboard)
        self.assertEqual(widget.title, 'Test Widget')
        self.assertEqual(widget.widget_type, 'COUNTER')
        self.assertEqual(widget.metric, self.metric)
        self.assertEqual(widget.config, {'color': 'blue'})
        self.assertEqual(widget.position, {'x': 0, 'y': 0, 'w': 2, 'h': 1})


class MetricSnapshotTests(TestCase):
    def setUp(self):
        # Create organization
        self.organization = Organization.objects.create(
            name='Test Organization',
            contact_email='contact@testorg.com'
        )
        
        # Create metric
        self.metric = Metric.objects.create(
            name='test_metric',
            display_name='Test Metric',
            description='Test metric description',
            metric_type='COUNT',
            entity_type='ALERT'
        )
    
    def test_metric_snapshot_creation(self):
        today = timezone.now().date()
        
        snapshot = MetricSnapshot.objects.create(
            metric=self.metric,
            organization=self.organization,
            date=today,
            granularity='DAILY',
            dimensions={'status': 'open'},
            value=42.0
        )
        
        self.assertEqual(snapshot.metric, self.metric)
        self.assertEqual(snapshot.organization, self.organization)
        self.assertEqual(snapshot.date, today)
        self.assertEqual(snapshot.granularity, 'DAILY')
        self.assertEqual(snapshot.dimensions, {'status': 'open'})
        self.assertEqual(snapshot.value, 42.0) 