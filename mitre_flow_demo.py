"""
Script para demonstrar o fluxo completo do módulo MITRE ATT&CK.

Este script mostra:
1. Sincronização de dados MITRE ATT&CK
2. Criação de casos e alertas de exemplo
3. Associação de técnicas MITRE a casos e alertas
4. Consulta e visualização das técnicas associadas
5. Uso de fases da kill chain

Para executar: python manage.py shell < mitre_flow_demo.py
"""

import os
import django
import json
import uuid
import datetime
from django.utils import timezone
from django.db.models import Count, Q
from django.contrib.auth.models import User

# Configurar ambiente Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

# Importar modelos após configuração do Django
from irp.mitre.models import MitreTactic, MitreTechnique, TechniqueTactic, CaseMitreTechnique
from irp.mitre.services import sync_mitre_attack_data, get_techniques_by_tactic, get_kill_chain_phases
from irp.cases.models import Case
from irp.alerts.models import Alert
from django.contrib.auth.models import User

# Definir cores para saída do console
class Color:
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_header(text):
    print(f"\n{Color.BOLD}{Color.BLUE}{'=' * 80}{Color.END}")
    print(f"{Color.BOLD}{Color.BLUE}{text.center(80)}{Color.END}")
    print(f"{Color.BOLD}{Color.BLUE}{'=' * 80}{Color.END}\n")

def print_subheader(text):
    print(f"\n{Color.BOLD}{Color.YELLOW}{text}{Color.END}")
    print(f"{Color.YELLOW}{'-' * len(text)}{Color.END}")

def print_success(text):
    print(f"{Color.GREEN}✓ {text}{Color.END}")

def print_error(text):
    print(f"{Color.RED}❌ {text}{Color.END}")

def print_info(text):
    print(f"{Color.BLUE}→ {text}{Color.END}")

def create_demo_data():
    """Criar dados de demonstração (organização, usuário, caso, alerta)"""
    print_header("CRIANDO DADOS DE DEMONSTRAÇÃO")
    
    try:
        # Criar ou obter usuário admin
        print_subheader("Criando usuário administrador")
        admin_user, created = User.objects.get_or_create(
            username="admin",
            defaults={
                "email": "admin@example.com",
                "is_staff": True,
                "is_superuser": True
            }
        )
        
        if created:
            admin_user.set_password("admin123")
            admin_user.save()
            print_success("Usuário admin criado com senha admin123")
        else:
            print_info("Usuário admin já existe")
            
        # Verificar se já existe alguma organização
        if hasattr(admin_user, 'profile') and admin_user.profile and admin_user.profile.organization:
            organization = admin_user.profile.organization
            print_info(f"Usando organização existente: {organization.name}")
        else:
            # Se não houver profile, tentar criar pelo admin
            try:
                from irp.accounts.models import Organization, Profile
                
                # Criar organização
                print_subheader("Criando organização")
                organization, created = Organization.objects.get_or_create(
                    name="Organização Demo",
                    defaults={
                        "description": "Organização para demonstração do módulo MITRE",
                        "contact_email": "demo@example.com"
                    }
                )
                
                if created:
                    print_success("Organização criada: Organização Demo")
                else:
                    print_info("Organização já existe: Organização Demo")
                
                # Criar perfil para o usuário admin
                if not hasattr(admin_user, 'profile'):
                    profile = Profile.objects.create(
                        user=admin_user,
                        organization=organization,
                        role="admin"
                    )
                    print_success("Perfil criado para usuário admin")
            except ImportError:
                print_error("Não foi possível criar organização - módulo accounts não disponível")
                organization = None
        
        # Criar caso de demonstração
        print_subheader("Criando caso de demonstração")
        try:
            case, created = Case.objects.get_or_create(
                title="Caso Demo - Ataque de Phishing",
                defaults={
                    "case_id": f"CASE-{uuid.uuid4().hex[:8].upper()}",
                    "description": "Investigação de ataque de phishing contra executivos",
                    "status": "in_progress",
                    "priority": "high",
                    "organization": organization,
                    "created_by": admin_user
                }
            )
            
            if created:
                print_success(f"Caso criado: {case.title} (ID: {case.case_id})")
            else:
                print_info(f"Caso já existe: {case.title} (ID: {case.case_id})")
        except Exception as e:
            print_error(f"Erro ao criar caso: {str(e)}")
            case = None
        
        # Criar alerta de demonstração
        print_subheader("Criando alerta de demonstração")
        try:
            alert, created = Alert.objects.get_or_create(
                title="Alerta Demo - Acesso Suspeito",
                defaults={
                    "alert_id": f"ALERT-{uuid.uuid4().hex[:8].upper()}",
                    "description": "Tentativa de acesso a sistemas críticos de origem suspeita",
                    "status": "new",
                    "severity": "critical",
                    "organization": organization,
                    "created_by": admin_user
                }
            )
            
            if created:
                print_success(f"Alerta criado: {alert.title} (ID: {alert.alert_id})")
            else:
                print_info(f"Alerta já existe: {alert.title} (ID: {alert.alert_id})")
        except Exception as e:
            print_error(f"Erro ao criar alerta: {str(e)}")
            alert = None
        
        return admin_user, organization, case, alert
    
    except Exception as e:
        print_error(f"Erro ao criar dados de demonstração: {str(e)}")
        return None, None, None, None

def sync_mitre_data():
    """Sincronizar dados MITRE ATT&CK se necessário"""
    print_header("SINCRONIZAÇÃO DO MITRE ATT&CK")
    
    # Verificar se já existem dados
    tactics_count = MitreTactic.objects.count()
    techniques_count = MitreTechnique.objects.count()
    
    if tactics_count > 0 and techniques_count > 0:
        print_info(f"Dados MITRE já existem: {tactics_count} táticas e {techniques_count} técnicas")
        
        # Verificar se existem relações
        relations_count = TechniqueTactic.objects.count()
        if relations_count > 0:
            print_info(f"Existem {relations_count} relações entre técnicas e táticas")
            return True
        else:
            print_info("Não existem relações entre técnicas e táticas. Sincronizando...")
    else:
        print_info("Sem dados MITRE. Iniciando sincronização...")
    
    try:
        # Definir uma flag para simular em vez de realmente sincronizar (leva muito tempo)
        SIMULATE_SYNC = True
        
        if SIMULATE_SYNC:
            print_info("Modo de simulação ativado - não será feita sincronização real")
            
            # Criar algumas táticas manualmente para demonstração
            if tactics_count == 0:
                print_subheader("Criando táticas de demonstração")
                
                tactics_data = [
                    {
                        'tactic_id': 'TA0001',
                        'name': 'Initial Access',
                        'short_name': 'initial-access',
                        'description': 'Técnicas para obter acesso inicial a redes',
                        'url': 'https://attack.mitre.org/tactics/TA0001/'
                    },
                    {
                        'tactic_id': 'TA0002',
                        'name': 'Execution',
                        'short_name': 'execution',
                        'description': 'Técnicas para executar código malicioso',
                        'url': 'https://attack.mitre.org/tactics/TA0002/'
                    },
                    {
                        'tactic_id': 'TA0003',
                        'name': 'Persistence',
                        'short_name': 'persistence',
                        'description': 'Técnicas para manter acesso durante reinicializações',
                        'url': 'https://attack.mitre.org/tactics/TA0003/'
                    },
                    {
                        'tactic_id': 'TA0004',
                        'name': 'Privilege Escalation',
                        'short_name': 'privilege-escalation',
                        'description': 'Técnicas para obter permissões de nível superior',
                        'url': 'https://attack.mitre.org/tactics/TA0004/'
                    },
                    {
                        'tactic_id': 'TA0005',
                        'name': 'Defense Evasion',
                        'short_name': 'defense-evasion',
                        'description': 'Técnicas para evitar detecção',
                        'url': 'https://attack.mitre.org/tactics/TA0005/'
                    }
                ]
                
                for tactic_data in tactics_data:
                    tactic, created = MitreTactic.objects.update_or_create(
                        tactic_id=tactic_data['tactic_id'],
                        defaults={
                            'name': tactic_data['name'],
                            'short_name': tactic_data['short_name'],
                            'description': tactic_data['description'],
                            'url': tactic_data['url'],
                            'version': '12.0'
                        }
                    )
                    if created:
                        print_success(f"Tática criada: {tactic.name} ({tactic.tactic_id})")
                
                print_success(f"Táticas de demonstração criadas: {len(tactics_data)}")
            
            # Criar algumas técnicas manualmente para demonstração
            if techniques_count == 0:
                print_subheader("Criando técnicas de demonstração")
                
                techniques_data = [
                    {
                        'technique_id': 'T1566',
                        'name': 'Phishing',
                        'description': 'Phishing é uma técnica de engenharia social para adquirir informações ou instalar malware.',
                        'url': 'https://attack.mitre.org/techniques/T1566/',
                        'is_subtechnique': False,
                        'parent_technique': None,
                        'kill_chain_phases': ['initial-access']
                    },
                    {
                        'technique_id': 'T1566.001',
                        'name': 'Spearphishing Attachment',
                        'description': 'Anexos de phishing direcionados a alvos específicos',
                        'url': 'https://attack.mitre.org/techniques/T1566/001/',
                        'is_subtechnique': True,
                        'parent_technique_id': 'T1566',
                        'kill_chain_phases': ['initial-access']
                    },
                    {
                        'technique_id': 'T1204',
                        'name': 'User Execution',
                        'description': 'Técnicas que dependem de ações do usuário para executar código malicioso',
                        'url': 'https://attack.mitre.org/techniques/T1204/',
                        'is_subtechnique': False,
                        'parent_technique': None,
                        'kill_chain_phases': ['execution']
                    },
                    {
                        'technique_id': 'T1078',
                        'name': 'Valid Accounts',
                        'description': 'Uso de contas legítimas para acesso ou persistência',
                        'url': 'https://attack.mitre.org/techniques/T1078/',
                        'is_subtechnique': False,
                        'parent_technique': None,
                        'kill_chain_phases': ['defense-evasion', 'persistence', 'privilege-escalation', 'initial-access']
                    },
                    {
                        'technique_id': 'T1053',
                        'name': 'Scheduled Task/Job',
                        'description': 'Uso de tarefas agendadas para persistência e execução',
                        'url': 'https://attack.mitre.org/techniques/T1053/',
                        'is_subtechnique': False,
                        'parent_technique': None,
                        'kill_chain_phases': ['execution', 'persistence', 'privilege-escalation']
                    }
                ]
                
                # Primeiro criar técnicas pai
                parent_techniques = {}
                for technique_data in techniques_data:
                    if not technique_data['is_subtechnique']:
                        technique, created = MitreTechnique.objects.update_or_create(
                            technique_id=technique_data['technique_id'],
                            defaults={
                                'name': technique_data['name'],
                                'description': technique_data['description'],
                                'url': technique_data['url'],
                                'is_subtechnique': False,
                                'parent_technique': None,
                                'version': '12.0'
                            }
                        )
                        parent_techniques[technique_data['technique_id']] = technique
                        if created:
                            print_success(f"Técnica criada: {technique.name} ({technique.technique_id})")
                
                # Depois criar subtécnicas
                for technique_data in techniques_data:
                    if technique_data['is_subtechnique']:
                        parent = parent_techniques.get(technique_data['parent_technique_id'])
                        if parent:
                            technique, created = MitreTechnique.objects.update_or_create(
                                technique_id=technique_data['technique_id'],
                                defaults={
                                    'name': technique_data['name'],
                                    'description': technique_data['description'],
                                    'url': technique_data['url'],
                                    'is_subtechnique': True,
                                    'parent_technique': parent,
                                    'version': '12.0'
                                }
                            )
                            if created:
                                print_success(f"Subtécnica criada: {technique.name} ({technique.technique_id})")
                
                print_success(f"Técnicas de demonstração criadas: {len(techniques_data)}")
                
                # Criar relações entre técnicas e táticas
                print_subheader("Criando relações entre técnicas e táticas")
                
                for technique_data in techniques_data:
                    technique = MitreTechnique.objects.get(technique_id=technique_data['technique_id'])
                    
                    for phase_name in technique_data['kill_chain_phases']:
                        tactic = MitreTactic.objects.filter(short_name=phase_name).first()
                        if tactic:
                            relation, created = TechniqueTactic.objects.get_or_create(
                                technique=technique,
                                tactic=tactic
                            )
                            if created:
                                print_success(f"Relação criada: {technique.technique_id} -> {tactic.tactic_id}")
                
                print_success("Relações criadas com sucesso")
        else:
            # Sincronização real com a fonte MITRE
            print_subheader("Iniciando sincronização real com MITRE ATT&CK")
            result = sync_mitre_attack_data()
            print_success(f"Sincronização concluída: {result['tactics_count']} táticas, {result['techniques_count']} técnicas, {result['relationships_count']} relações")
        
        return True
    except Exception as e:
        print_error(f"Erro na sincronização: {str(e)}")
        return False

def associate_mitre_techniques(user, case, alert):
    """Associar técnicas MITRE a casos e alertas"""
    print_header("ASSOCIANDO TÉCNICAS MITRE ATT&CK")
    
    if not case and not alert:
        print_error("Nenhum caso ou alerta disponível para associar técnicas")
        return False
    
    try:
        # Obter algumas técnicas para associar
        initial_access = MitreTechnique.objects.filter(tactics__short_name='initial-access').first()
        execution = MitreTechnique.objects.filter(tactics__short_name='execution').first()
        persistence = MitreTechnique.objects.filter(tactics__short_name='persistence').first()
        
        if not initial_access or not execution or not persistence:
            print_error("Não foi possível encontrar técnicas para associar")
            return False
        
        # Associar técnicas ao caso
        if case:
            print_subheader(f"Associando técnicas ao caso: {case.title}")
            
            # 1. Technique: Phishing (Initial Access)
            phishing = MitreTechnique.objects.filter(technique_id='T1566').first()
            if phishing:
                case_technique, created = CaseMitreTechnique.objects.update_or_create(
                    case=case,
                    technique=phishing,
                    defaults={
                        'added_by': user,
                        'kill_chain_phase': 'initial-access',
                        'confidence_score': 90,
                        'detection_method': 'Email Analysis',
                        'artifacts': 'Email hash: 5f2b7a..., Subject: Invoice #12345',
                        'impact_level': 'high',
                        'mitigation_status': 'in_progress',
                        'first_observed': timezone.now() - datetime.timedelta(days=2),
                        'last_observed': timezone.now() - datetime.timedelta(days=1),
                        'notes': 'Campanha de phishing sofisticada visando executivos'
                    }
                )
                
                if created:
                    print_success(f"Técnica associada ao caso: {phishing.technique_id} - {phishing.name}")
                else:
                    print_info(f"Técnica já associada ao caso: {phishing.technique_id} - {phishing.name}")
            
            # 2. Technique: User Execution (Execution)
            user_execution = MitreTechnique.objects.filter(technique_id='T1204').first()
            if user_execution:
                case_technique, created = CaseMitreTechnique.objects.update_or_create(
                    case=case,
                    technique=user_execution,
                    defaults={
                        'added_by': user,
                        'kill_chain_phase': 'execution',
                        'confidence_score': 85,
                        'detection_method': 'EDR Alert',
                        'artifacts': 'Process: winword.exe, Command line: winword.exe /q /dde',
                        'impact_level': 'medium',
                        'mitigation_status': 'not_started',
                        'first_observed': timezone.now() - datetime.timedelta(days=1, hours=23),
                        'last_observed': timezone.now() - datetime.timedelta(days=1, hours=22),
                        'notes': 'Usuário abriu documento malicioso do email'
                    }
                )
                
                if created:
                    print_success(f"Técnica associada ao caso: {user_execution.technique_id} - {user_execution.name}")
                else:
                    print_info(f"Técnica já associada ao caso: {user_execution.technique_id} - {user_execution.name}")
        
        # Associar técnicas ao alerta
        if alert:
            print_subheader(f"Associando técnicas ao alerta: {alert.title}")
            
            # 1. Technique: Valid Accounts (Privilege Escalation)
            valid_accounts = MitreTechnique.objects.filter(technique_id='T1078').first()
            if valid_accounts:
                alert_technique, created = CaseMitreTechnique.objects.update_or_create(
                    alert=alert,
                    technique=valid_accounts,
                    defaults={
                        'added_by': user,
                        'kill_chain_phase': 'privilege-escalation',
                        'confidence_score': 75,
                        'detection_method': 'SIEM Rule',
                        'artifacts': 'User: admin, Source IP: 185.23.45.67, Login time: 02:34 AM',
                        'impact_level': 'critical',
                        'mitigation_status': 'not_started',
                        'first_observed': timezone.now() - datetime.timedelta(hours=6),
                        'last_observed': timezone.now() - datetime.timedelta(hours=5),
                        'notes': 'Login suspeito com credenciais válidas fora do horário comercial'
                    }
                )
                
                if created:
                    print_success(f"Técnica associada ao alerta: {valid_accounts.technique_id} - {valid_accounts.name}")
                else:
                    print_info(f"Técnica já associada ao alerta: {valid_accounts.technique_id} - {valid_accounts.name}")
            
            # 2. Technique: Scheduled Task (Persistence)
            scheduled_task = MitreTechnique.objects.filter(technique_id='T1053').first()
            if scheduled_task:
                alert_technique, created = CaseMitreTechnique.objects.update_or_create(
                    alert=alert,
                    technique=scheduled_task,
                    defaults={
                        'added_by': user,
                        'kill_chain_phase': 'persistence',
                        'confidence_score': 80,
                        'detection_method': 'Audit Log',
                        'artifacts': 'Task Name: "SysUpdater", Command: powershell.exe -enc Base64...',
                        'impact_level': 'high',
                        'mitigation_status': 'not_started',
                        'first_observed': timezone.now() - datetime.timedelta(hours=5, minutes=30),
                        'last_observed': timezone.now() - datetime.timedelta(hours=5),
                        'notes': 'Tarefa agendada criada após o login suspeito'
                    }
                )
                
                if created:
                    print_success(f"Técnica associada ao alerta: {scheduled_task.technique_id} - {scheduled_task.name}")
                else:
                    print_info(f"Técnica já associada ao alerta: {scheduled_task.technique_id} - {scheduled_task.name}")
        
        return True
    except Exception as e:
        print_error(f"Erro ao associar técnicas: {str(e)}")
        return False

def query_mitre_data(case, alert):
    """Consultar dados MITRE associados a casos e alertas"""
    print_header("CONSULTANDO DADOS MITRE ATT&CK")
    
    # 1. Obter estatísticas gerais
    print_subheader("Estatísticas gerais")
    try:
        tactics_count = MitreTactic.objects.count()
        techniques_count = MitreTechnique.objects.count()
        relations_count = TechniqueTactic.objects.count()
        
        print_info(f"Total de táticas: {tactics_count}")
        print_info(f"Total de técnicas: {techniques_count}")
        print_info(f"Total de relações tática-técnica: {relations_count}")
        
        # Contagem de técnicas por tática
        tactics = MitreTactic.objects.annotate(techniques_count=Count('techniques')).order_by('tactic_id')
        print_subheader("Técnicas por tática")
        for tactic in tactics:
            print_info(f"{tactic.tactic_id} - {tactic.name}: {tactic.techniques_count} técnicas")
        
        # Fases da kill chain
        print_subheader("Fases da Kill Chain disponíveis")
        kill_chain_phases = get_kill_chain_phases()
        for phase in kill_chain_phases:
            print_info(f"{phase['tactic_id']} - {phase['name']} ({phase['phase_name']})")
    
    except Exception as e:
        print_error(f"Erro ao obter estatísticas: {str(e)}")
    
    # 2. Consultar técnicas associadas ao caso
    if case:
        print_subheader(f"Técnicas associadas ao caso: {case.title}")
        try:
            case_techniques = CaseMitreTechnique.objects.filter(case=case).select_related('technique')
            
            if case_techniques.exists():
                for ct in case_techniques:
                    tactics = ", ".join([t.name for t in ct.technique.tactics.all()])
                    print(f"\n{Color.BOLD}{ct.technique.technique_id} - {ct.technique.name}{Color.END}")
                    print(f"• Fase da Kill Chain: {ct.kill_chain_phase}")
                    print(f"• Confiança: {ct.confidence_score}%")
                    print(f"• Impacto: {ct.impact_level}")
                    print(f"• Método de detecção: {ct.detection_method}")
                    print(f"• Status da mitigação: {ct.mitigation_status}")
                    print(f"• Táticas associadas: {tactics}")
                    print(f"• Primeira observação: {ct.first_observed}")
                    print(f"• Última observação: {ct.last_observed}")
                    print(f"• Artefatos: {ct.artifacts}")
                    print(f"• Notas: {ct.notes}")
            else:
                print_info("Nenhuma técnica associada a este caso")
        except Exception as e:
            print_error(f"Erro ao consultar técnicas do caso: {str(e)}")
    
    # 3. Consultar técnicas associadas ao alerta
    if alert:
        print_subheader(f"Técnicas associadas ao alerta: {alert.title}")
        try:
            alert_techniques = CaseMitreTechnique.objects.filter(alert=alert).select_related('technique')
            
            if alert_techniques.exists():
                for at in alert_techniques:
                    tactics = ", ".join([t.name for t in at.technique.tactics.all()])
                    print(f"\n{Color.BOLD}{at.technique.technique_id} - {at.technique.name}{Color.END}")
                    print(f"• Fase da Kill Chain: {at.kill_chain_phase}")
                    print(f"• Confiança: {at.confidence_score}%")
                    print(f"• Impacto: {at.impact_level}")
                    print(f"• Método de detecção: {at.detection_method}")
                    print(f"• Status da mitigação: {at.mitigation_status}")
                    print(f"• Táticas associadas: {tactics}")
                    print(f"• Primeira observação: {at.first_observed}")
                    print(f"• Última observação: {at.last_observed}")
                    print(f"• Artefatos: {at.artifacts}")
                    print(f"• Notas: {at.notes}")
            else:
                print_info("Nenhuma técnica associada a este alerta")
        except Exception as e:
            print_error(f"Erro ao consultar técnicas do alerta: {str(e)}")

def run_demo():
    """Executar demonstração completa"""
    print_header("DEMONSTRAÇÃO DO MÓDULO MITRE ATT&CK")
    
    # 1. Sincronizar dados MITRE se necessário
    sync_mitre_data()
    
    # 2. Criar dados de demonstração
    user, organization, case, alert = create_demo_data()
    
    # 3. Associar técnicas MITRE aos casos e alertas
    if user:
        associate_mitre_techniques(user, case, alert)
    
    # 4. Consultar dados MITRE
    query_mitre_data(case, alert)
    
    print_header("DEMONSTRAÇÃO CONCLUÍDA")
    print_info("O módulo MITRE ATT&CK está configurado e funcional")
    print_info("Você pode acessar os dados através da interface de administração ou da API")

if __name__ == "__main__":
    run_demo() 