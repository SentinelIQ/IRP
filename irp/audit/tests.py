from django.test import TestCase
from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status
import uuid

from .models import AuditLog
from .services import AuditService
from irp.accounts.models import Organization, Role, Permission


class AuditLogModelTest(TestCase):
    """Testes para o modelo AuditLog."""
    
    def setUp(self):
        # Criar usuário e organização para testes
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.organization = Organization.objects.create(
            name='Test Organization',
            slug='test-org'
        )
    
    def test_create_audit_log(self):
        """Teste básico de criação de log de auditoria."""
        log = AuditLog.objects.create(
            user=self.user,
            organization=self.organization,
            entity_type='TEST',
            entity_id='123',
            action_type='CREATE',
            details_after={'test': 'data'}
        )
        
        self.assertEqual(AuditLog.objects.count(), 1)
        self.assertEqual(log.user, self.user)
        self.assertEqual(log.organization, self.organization)
        self.assertEqual(log.entity_type, 'TEST')
        self.assertEqual(log.action_type, 'CREATE')
        self.assertEqual(log.details_after, {'test': 'data'})


class AuditServiceTest(TestCase):
    """Testes para o serviço AuditService."""
    
    def setUp(self):
        # Criar usuário e organização para testes
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.organization = Organization.objects.create(
            name='Test Organization',
            slug='test-org'
        )
    
    def test_log_action(self):
        """Teste do método log_action do AuditService."""
        entity_id = str(uuid.uuid4())
        
        log = AuditService.log_action(
            user=self.user,
            organization=self.organization,
            entity_type='TEST',
            entity_id=entity_id,
            action_type='CREATE',
            details_before=None,
            details_after={'name': 'Test Entity'}
        )
        
        self.assertIsNotNone(log)
        self.assertEqual(log.user, self.user)
        self.assertEqual(log.organization, self.organization)
        self.assertEqual(log.entity_type, 'TEST')
        self.assertEqual(log.entity_id, entity_id)
        self.assertEqual(log.action_type, 'CREATE')
        self.assertEqual(log.details_after, {'name': 'Test Entity'})
    
    def test_get_entity_history(self):
        """Teste do método get_entity_history do AuditService."""
        entity_id = str(uuid.uuid4())
        
        # Criar alguns logs para a mesma entidade
        for action in ['CREATE', 'UPDATE', 'VIEW']:
            AuditLog.objects.create(
                user=self.user,
                organization=self.organization,
                entity_type='TEST',
                entity_id=entity_id,
                action_type=action
            )
        
        # Criar um log para outra entidade
        AuditLog.objects.create(
            user=self.user,
            organization=self.organization,
            entity_type='TEST',
            entity_id=str(uuid.uuid4()),
            action_type='CREATE'
        )
        
        # Obter histórico da entidade
        history = AuditService.get_entity_history('TEST', entity_id)
        
        self.assertEqual(history.count(), 3)
        actions = [log.action_type for log in history]
        self.assertIn('CREATE', actions)
        self.assertIn('UPDATE', actions)
        self.assertIn('VIEW', actions)


# Testes de API serão implementados futuramente
class AuditAPITest(APITestCase):
    """Testes para a API de auditoria."""
    
    def setUp(self):
        """Configuração inicial para os testes de API."""
        self.client = APIClient()
        
        # Criar usuário, organização, permissões e token
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.organization = Organization.objects.create(
            name='Test Organization',
            slug='test-org'
        )
        
        # Criar logs de auditoria para teste
        for i in range(5):
            AuditLog.objects.create(
                user=self.user,
                organization=self.organization,
                entity_type='TEST',
                entity_id=f'test-{i}',
                action_type='CREATE',
                details_after={'index': i}
            )
    
    # Os testes de API serão implementados quando a integração estiver completa 