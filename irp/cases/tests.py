from django.test import TestCase
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from rest_framework import status

from irp.accounts.models import Organization, Profile
from irp.cases.models import CaseSeverity, CaseStatus, Case, Task, TaskStatus


class CaseModelTestCase(TestCase):
    def setUp(self):
        self.organization = Organization.objects.create(
            name='Test Organization',
            description='Test Organization Description'
        )
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpassword'
        )
        self.profile = Profile.objects.create(
            user=self.user,
            organization=self.organization
        )
        self.severity = CaseSeverity.objects.create(
            name='High',
            level_order=30,
            color_code='#FF0000'
        )
        self.status = CaseStatus.objects.create(
            name='Open',
            description='Open case',
            organization=self.organization,
            is_default_open_status=True,
            color_code='#00FF00'
        )

    def test_case_creation(self):
        case = Case.objects.create(
            title='Test Case',
            description='Test Case Description',
            severity=self.severity,
            status=self.status,
            organization=self.organization,
            reporter=self.user
        )
        self.assertEqual(case.title, 'Test Case')
        self.assertEqual(case.organization, self.organization)
        self.assertEqual(case.severity, self.severity)
        self.assertEqual(case.status, self.status)
        self.assertEqual(case.reporter, self.user)


class CaseAPITestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.organization = Organization.objects.create(
            name='Test Organization',
            description='Test Organization Description'
        )
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpassword'
        )
        self.profile = Profile.objects.create(
            user=self.user,
            organization=self.organization
        )
        self.severity = CaseSeverity.objects.create(
            name='High',
            level_order=30,
            color_code='#FF0000'
        )
        self.status = CaseStatus.objects.create(
            name='Open',
            description='Open case',
            organization=self.organization,
            is_default_open_status=True,
            color_code='#00FF00'
        )
        self.task_status = TaskStatus.objects.create(
            name='ToDo',
            color_code='#0000FF'
        )
        self.client.force_authenticate(user=self.user)

    def test_create_case(self):
        data = {
            'title': 'API Test Case',
            'description': 'Case created via API test',
            'severity_id': self.severity.id,
            'status_id': self.status.id,
            'tags': ['test', 'api']
        }
        response = self.client.post('/api/cases/cases/', data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Case.objects.count(), 1)
        case = Case.objects.first()
        self.assertEqual(case.title, 'API Test Case')
        self.assertEqual(case.reporter, self.user)

    def test_list_cases(self):
        Case.objects.create(
            title='Test Case 1',
            description='Test Case Description',
            severity=self.severity,
            status=self.status,
            organization=self.organization,
            reporter=self.user
        )
        Case.objects.create(
            title='Test Case 2',
            description='Second Test Case Description',
            severity=self.severity,
            status=self.status,
            organization=self.organization,
            reporter=self.user
        )
        
        response = self.client.get('/api/cases/cases/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 2)

    def test_create_task(self):
        case = Case.objects.create(
            title='Test Case',
            description='Test Case Description',
            severity=self.severity,
            status=self.status,
            organization=self.organization,
            reporter=self.user
        )
        
        data = {
            'title': 'Test Task',
            'description': 'Test Task Description',
            'status_id': self.task_status.id
        }
        
        response = self.client.post(f'/api/cases/cases/{case.case_id}/tasks/', data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Task.objects.count(), 1)
        task = Task.objects.first()
        self.assertEqual(task.title, 'Test Task')
        self.assertEqual(task.case, case) 