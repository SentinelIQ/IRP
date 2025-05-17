#!/usr/bin/env python
"""
MITRE ATT&CK Integration Demo

This script demonstrates the capabilities of the MITRE ATT&CK integration
by performing the following operations:
1. Synchronizing MITRE ATT&CK data
2. Creating test entities (users, organizations, cases, alerts)
3. Associating MITRE techniques with cases and alerts
4. Querying techniques by various criteria
5. Demonstrating the kill chain visualization

To run this script:
python manage.py shell < test_mitre_integration.py
"""

import os
import sys
import django
import json
from datetime import datetime, timedelta
from django.utils import timezone
from django.db import transaction
from django.contrib.auth.models import User

# Function to print colored text for better readability
def print_colored(text, color="green"):
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "purple": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "end": "\033[0m"
    }
    print(f"{colors.get(color, colors['white'])}{text}{colors['end']}")

# Step 1: Synchronize MITRE ATT&CK data
print_colored("\n[1] Synchronizing MITRE ATT&CK data...", "blue")
from irp.mitre.services import sync_mitre_attack_data
try:
    result = sync_mitre_attack_data()
    print_colored(f"Synchronization successful!", "green")
    print(f"- Tactics: {result['tactics_count']}")
    print(f"- Techniques: {result['techniques_count']}")
    print(f"- Subtechniques: {result['subtechniques_count']}")
    print(f"- Relationships: {result['relationships_count']}")
    print(f"- Version: {result['version']}")
except Exception as e:
    print_colored(f"Error synchronizing MITRE data: {e}", "red")
    sys.exit(1)

# Step 2: Create test data (organization, users, cases, alerts)
print_colored("\n[2] Creating test data...", "blue")
from django.contrib.auth.models import User
from irp.cases.models import Case, Organization
from irp.alerts.models import Alert
from irp.accounts.models import Profile

# Create test organization if it doesn't exist
org_name = "MITRE Demo Organization"
try:
    org = Organization.objects.get(name=org_name)
    print(f"Using existing organization: {org_name}")
except Organization.DoesNotExist:
    org = Organization.objects.create(
        name=org_name,
        description="Organization for MITRE ATT&CK integration testing"
    )
    print(f"Created organization: {org_name}")

# Create test user if it doesn't exist
username = "mitre_demo_user"
try:
    user = User.objects.get(username=username)
    print(f"Using existing user: {username}")
except User.DoesNotExist:
    user = User.objects.create_user(
        username=username,
        email="mitre_demo@example.com",
        password="secure_password"
    )
    user.first_name = "MITRE"
    user.last_name = "Demo User"
    user.save()
    
    # Create profile for the user
    profile, created = Profile.objects.get_or_create(
        user=user,
        defaults={"organization": org}
    )
    if not created:
        profile.organization = org
        profile.save()
    
    print(f"Created user: {username}")

# Create test case
case_title = "MITRE ATT&CK Demo Case"
try:
    case = Case.objects.get(title=case_title, organization=org)
    print(f"Using existing case: {case_title}")
except Case.DoesNotExist:
    case = Case.objects.create(
        title=case_title,
        description="Case for testing MITRE ATT&CK integration",
        status="open",
        priority="high",
        created_by=user,
        organization=org
    )
    print(f"Created case: {case_title}")

# Create test alert
alert_title = "MITRE ATT&CK Demo Alert"
try:
    alert = Alert.objects.get(title=alert_title, organization=org)
    print(f"Using existing alert: {alert_title}")
except Alert.DoesNotExist:
    alert = Alert.objects.create(
        title=alert_title,
        description="Alert for testing MITRE ATT&CK integration",
        severity="high",
        status="new",
        created_by=user,
        organization=org
    )
    print(f"Created alert: {alert_title}")

# Step 3: Associate MITRE techniques with cases and alerts
print_colored("\n[3] Associating MITRE techniques with cases and alerts...", "blue")
from irp.mitre.models import MitreTechnique, MitreTactic, CaseMitreTechnique

# Select some common techniques for demo
techniques_to_associate = [
    # Initial Access
    "T1566",  # Phishing
    "T1190",  # Exploit Public-Facing Application
    
    # Execution
    "T1059",  # Command and Scripting Interpreter
    
    # Persistence
    "T1136",  # Create Account
    
    # Privilege Escalation
    "T1068",  # Exploitation for Privilege Escalation
    
    # Defense Evasion
    "T1070",  # Indicator Removal
    
    # Discovery
    "T1087",  # Account Discovery
    
    # Lateral Movement
    "T1021",  # Remote Services
    
    # Collection
    "T1119",  # Automated Collection
    
    # Command and Control
    "T1071",  # Application Layer Protocol
    
    # Exfiltration
    "T1567",  # Exfiltration Over Web Service
    
    # Impact
    "T1485"   # Data Destruction
]

# Function to associate a technique with a case with varying attributes
def associate_technique(technique_id, case_obj, alert_obj=None, **kwargs):
    technique = MitreTechnique.objects.get(technique_id=technique_id)
    
    # Get kill chain phase from first tactic
    if not kwargs.get('kill_chain_phase') and technique.tactics.exists():
        first_tactic = technique.tactics.first()
        if first_tactic and first_tactic.short_name:
            kwargs['kill_chain_phase'] = first_tactic.short_name
    
    # Set default values
    defaults = {
        'technique': technique,
        'added_by': user,
        'notes': f"Técnica {technique_id} associada para demonstração",
        'first_observed': timezone.now() - timedelta(days=7),
        'last_observed': timezone.now(),
        'confidence_score': 75,
        'detection_method': "Análise manual",
        'artifacts': "Logs do sistema, capturas de tela, artefatos de memória",
        'impact_level': "médio",
        'mitigation_status': "em andamento"
    }
    
    # Override defaults with provided kwargs
    defaults.update(kwargs)
    
    # Determine if we're associating with a case or alert
    if case_obj:
        defaults['case'] = case_obj
    if alert_obj:
        defaults['alert'] = alert_obj
    
    # Create or update the association
    association, created = CaseMitreTechnique.objects.update_or_create(
        technique=technique,
        case=case_obj,
        alert=alert_obj,
        defaults=defaults
    )
    
    return association, created

# Associate techniques with the case with varying attributes
print("\nAssociating techniques with the case:")
techniques_created = 0

for i, technique_id in enumerate(techniques_to_associate):
    try:
        # Create variations in the data for different techniques
        confidence = 50 + (i * 5) % 50  # Vary between 50-95
        impact_levels = ["baixo", "médio", "alto"]
        impact = impact_levels[i % len(impact_levels)]
        mitigation_status = ["não iniciada", "em andamento", "concluída"][i % 3]
        
        # First observed times with increasing time gaps
        first_observed = timezone.now() - timedelta(days=30 - i)
        
        # Associate with either case, alert, or both
        if i % 3 == 0:  # Associate with case only
            assoc, created = associate_technique(
                technique_id, case, None,
                confidence_score=confidence,
                impact_level=impact,
                mitigation_status=mitigation_status,
                first_observed=first_observed
            )
            target = "case only"
        elif i % 3 == 1:  # Associate with alert only
            assoc, created = associate_technique(
                technique_id, None, alert,
                confidence_score=confidence,
                impact_level=impact,
                mitigation_status=mitigation_status,
                first_observed=first_observed
            )
            target = "alert only"
        else:  # Associate with both
            assoc, created = associate_technique(
                technique_id, case, alert,
                confidence_score=confidence,
                impact_level=impact,
                mitigation_status=mitigation_status,
                first_observed=first_observed
            )
            target = "both case and alert"
        
        if created:
            techniques_created += 1
            print(f"  ✓ Associated {technique_id} with {target}")
        else:
            print(f"  ℹ {technique_id} already associated with {target}")
            
    except MitreTechnique.DoesNotExist:
        print(f"  ✗ Technique {technique_id} not found")
    except Exception as e:
        print(f"  ✗ Error associating {technique_id}: {e}")

print(f"\nSuccessfully associated {techniques_created} new techniques")

# Step 4: Querying techniques
print_colored("\n[4] Demonstrating technique querying capabilities...", "blue")
from irp.mitre.services import get_techniques_by_tactic, search_techniques, get_technique_details
from irp.mitre.services import get_kill_chain_phases, get_technique_by_kill_chain_phase

# Get techniques by tactic
print("\nTechniques for Initial Access (TA0001):")
initial_access_techniques = get_techniques_by_tactic("TA0001")
for i, technique in enumerate(initial_access_techniques[:5], 1):  # Show first 5
    print(f"  {i}. {technique.technique_id} - {technique.name}")
if initial_access_techniques.count() > 5:
    print(f"  ... and {initial_access_techniques.count() - 5} more")

# Search techniques
print("\nSearch results for 'phishing':")
phishing_techniques = search_techniques("phishing")
for i, technique in enumerate(phishing_techniques, 1):
    print(f"  {i}. {technique.technique_id} - {technique.name}")

# Get technique details
print("\nDetails for T1566 (Phishing):")
details = get_technique_details("T1566")
if details:
    print(f"  ID: {details['id']}")
    print(f"  Name: {details['name']}")
    print(f"  Description: {details['description'][:100]}...")
    print(f"  Tactics: {', '.join(t['name'] for t in details['tactics'])}")
    if details['related_techniques']:
        print(f"  Related techniques: {len(details['related_techniques'])}")
else:
    print("  Technique not found")

# Get kill chain phases
print("\nAvailable Kill Chain Phases:")
phases = get_kill_chain_phases()
for i, phase in enumerate(phases, 1):
    print(f"  {i}. {phase['tactic_id']} - {phase['name']} ({phase['phase_name']})")

# Get techniques by kill chain phase
print("\nTechniques in 'persistence' phase:")
persistence_techniques = get_technique_by_kill_chain_phase("persistence")
for i, technique in enumerate(persistence_techniques[:5], 1):  # Show first 5
    print(f"  {i}. {technique.technique_id} - {technique.name}")
if persistence_techniques.count() > 5:
    print(f"  ... and {persistence_techniques.count() - 5} more")

# Step 5: Summarize case-technique associations
print_colored("\n[5] Summarizing MITRE associations for the case...", "blue")
case_techniques = CaseMitreTechnique.objects.filter(case=case)

print(f"\nCase '{case.title}' has {case_techniques.count()} associated MITRE techniques")

# Group by kill chain phase
phases_dict = {}
for ct in case_techniques:
    phase = ct.kill_chain_phase or "Unknown"
    if phase not in phases_dict:
        phases_dict[phase] = []
    phases_dict[phase].append(ct)

# Display techniques by kill chain phase
for phase, techniques in sorted(phases_dict.items()):
    print(f"\nPhase: {phase} ({len(techniques)} techniques)")
    for ct in techniques:
        confidence = f"({ct.confidence_score}% confidence)" if ct.confidence_score else ""
        print(f"  • {ct.technique.technique_id} - {ct.technique.name} {confidence}")
        if ct.notes:
            print(f"    Notes: {ct.notes}")
        if ct.detection_method:
            print(f"    Detected via: {ct.detection_method}")
        if ct.mitigation_status:
            print(f"    Mitigation: {ct.mitigation_status}")

print_colored("\nMITRE ATT&CK Integration Demo Complete", "purple") 