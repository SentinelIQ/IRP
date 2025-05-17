from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from rest_framework import status

from .models import MitreTactic, MitreTechnique, TechniqueTactic

class MitreModelTests(TestCase):
    def setUp(self):
        # Criar táticas de teste
        self.tactic1 = MitreTactic.objects.create(
            tactic_id='TA0001',
            name='Initial Access',
            description='Técnicas para ganhar acesso inicial',
            url='https://attack.mitre.org/tactics/TA0001',
            version='v10.0'
        )
        
        self.tactic2 = MitreTactic.objects.create(
            tactic_id='TA0002',
            name='Execution',
            description='Técnicas para executar código',
            url='https://attack.mitre.org/tactics/TA0002',
            version='v10.0'
        )
        
        # Criar técnicas de teste
        self.technique1 = MitreTechnique.objects.create(
            technique_id='T1190',
            name='Exploit Public-Facing Application',
            description='Exploração de aplicações expostas publicamente',
            url='https://attack.mitre.org/techniques/T1190',
            is_subtechnique=False,
            version='v10.0'
        )
        
        self.technique2 = MitreTechnique.objects.create(
            technique_id='T1059',
            name='Command and Scripting Interpreter',
            description='Uso de interpretadores de script',
            url='https://attack.mitre.org/techniques/T1059',
            is_subtechnique=False,
            version='v10.0'
        )
        
        # Criar subtécnica
        self.subtechnique = MitreTechnique.objects.create(
            technique_id='T1059.001',
            name='PowerShell',
            description='Uso de PowerShell',
            url='https://attack.mitre.org/techniques/T1059/001',
            is_subtechnique=True,
            parent_technique=self.technique2,
            version='v10.0'
        )
        
        # Associar técnicas a táticas
        TechniqueTactic.objects.create(technique=self.technique1, tactic=self.tactic1)
        TechniqueTactic.objects.create(technique=self.technique2, tactic=self.tactic2)
        TechniqueTactic.objects.create(technique=self.subtechnique, tactic=self.tactic2)
    
    def test_tactic_str(self):
        """Testar representação string da tática"""
        self.assertEqual(str(self.tactic1), 'TA0001 - Initial Access')
    
    def test_technique_str(self):
        """Testar representação string da técnica"""
        self.assertEqual(str(self.technique1), 'T1190 - Exploit Public-Facing Application')
    
    def test_technique_tactic_relationship(self):
        """Testar relacionamentos entre técnicas e táticas"""
        self.assertIn(self.tactic1, self.technique1.tactics.all())
        self.assertIn(self.tactic2, self.technique2.tactics.all())
    
    def test_subtechnique_relationship(self):
        """Testar relacionamento entre técnica e subtécnica"""
        self.assertEqual(self.subtechnique.parent_technique, self.technique2)
        self.assertIn(self.subtechnique, self.technique2.subtechniques.all())

class MitreAPITests(APITestCase):
    def setUp(self):
        # Configurar cliente API
        self.client = APIClient()
        
        # Criar dados de teste
        self.tactic = MitreTactic.objects.create(
            tactic_id='TA0001',
            name='Initial Access',
            description='Técnicas para ganhar acesso inicial',
            url='https://attack.mitre.org/tactics/TA0001',
            version='v10.0'
        )
        
        self.technique = MitreTechnique.objects.create(
            technique_id='T1190',
            name='Exploit Public-Facing Application',
            description='Exploração de aplicações expostas publicamente',
            url='https://attack.mitre.org/techniques/T1190',
            is_subtechnique=False,
            version='v10.0'
        )
        
        TechniqueTactic.objects.create(technique=self.technique, tactic=self.tactic)
    
    # Os testes de API serão implementados depois que a autenticação for configurada
    # e os endpoints estiverem disponíveis
