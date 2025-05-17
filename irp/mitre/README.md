# MITRE ATT&CK Integration

This module provides integration with the MITRE ATT&CK framework, allowing you to correlate security incidents with known attack techniques and tactics.

## Features

- Synchronization with the official MITRE ATT&CK Enterprise matrix
- Association of MITRE techniques with cases and alerts
- Enhanced tracking with kill chain phase, confidence scores, and mitigation status
- Timeline integration for technique detection and mitigation
- Rich querying capabilities by tactic, technique ID, or kill chain phase

## Data Model

The module consists of the following models:

- **MitreTactic**: Represents MITRE ATT&CK tactics (e.g., Initial Access, Execution)
- **MitreTechnique**: Represents MITRE ATT&CK techniques and sub-techniques
- **TechniqueTactic**: Maps the many-to-many relationship between techniques and tactics
- **CaseMitreTechnique**: Associates techniques with cases/alerts with additional context fields

## API Endpoints

### Core Endpoints

- `GET /api/mitre/tactics/` - List all tactics
- `GET /api/mitre/techniques/` - List all techniques
- `GET /api/mitre/techniques/?tactic=TA0001` - Filter techniques by tactic
- `GET /api/mitre/techniques/sync/` - Synchronize with MITRE ATT&CK data
- `GET /api/mitre/kill-chain-phases/` - Get available kill chain phases

### Case/Alert Technique Associations

- `GET /api/cases/{case_id}/mitre-techniques/` - List techniques for a case
- `POST /api/cases/{case_id}/mitre-techniques/` - Add technique to a case
- `GET /api/alerts/{alert_id}/mitre-techniques/` - List techniques for an alert
- `POST /api/alerts/{alert_id}/mitre-techniques/` - Add technique to an alert

## Usage

### Synchronizing MITRE ATT&CK Data

The module can synchronize with the official MITRE ATT&CK Enterprise matrix. This process:

1. Downloads the latest data from the MITRE CTI repository
2. Updates tactics, techniques, and sub-techniques
3. Maps techniques to their associated tactics using kill chain phases
4. Maintains relationships between parent techniques and sub-techniques

To trigger synchronization:

```python
from irp.mitre.services import sync_mitre_attack_data

result = sync_mitre_attack_data()
print(f"Synchronized {result['techniques_count']} techniques")
```

### Associating Techniques with Cases

```python
from irp.mitre.models import MitreTechnique, CaseMitreTechnique
from irp.cases.models import Case

# Get a case and technique
case = Case.objects.get(case_id='CASE-123')
technique = MitreTechnique.objects.get(technique_id='T1566')  # Phishing

# Associate technique with case with additional context
CaseMitreTechnique.objects.create(
    case=case,
    technique=technique,
    added_by=request.user,
    notes="Phishing email detected with malicious attachment",
    kill_chain_phase="initial-access",
    confidence_score=85,
    detection_method="Email security gateway",
    artifacts="Email headers, attachment hash: 123abc...",
    impact_level="high",
    mitigation_status="completed",
    first_observed=detected_time,
    last_observed=remediated_time
)
```

### Querying Techniques by Kill Chain Phase

```python
from irp.mitre.services import get_technique_by_kill_chain_phase

# Get all techniques in the "execution" phase
execution_techniques = get_technique_by_kill_chain_phase("execution")

for technique in execution_techniques:
    print(f"{technique.technique_id} - {technique.name}")
```

## Demo

A complete demonstration of the MITRE integration can be found in the `test_mitre_integration.py` script. Run it with:

```
python manage.py shell < test_mitre_integration.py
```

## Enhancements

The MITRE module can be extended with:

- Visual kill chain representation in the UI
- STIX/TAXII integration for threat intelligence
- Automated technique suggestion based on observables
- Statistical analysis of most common techniques across cases 