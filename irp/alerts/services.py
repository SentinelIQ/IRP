from django.db import transaction
from django.utils import timezone
from django.db.models import Q, Count

from .models import Alert, AlertStatus
from irp.cases.models import Case, CaseStatus, CaseSeverity, Task, TaskStatus
from irp.cases.services import CaseTemplateService


class AlertService:
    @staticmethod
    def create_alert(title, source_system, description, severity, organization, 
                    external_id=None, raw_event_data=None, tags=None, assignee=None):
        """
        Create a new alert with appropriate status and timestamps.
        
        Args:
            title (str): Alert title
            source_system (str): Source system identifier
            description (str): Alert description
            severity (AlertSeverity): Severity level
            organization (Organization): Organization the alert belongs to
            external_id (str, optional): External reference ID
            raw_event_data (dict, optional): Raw event data in JSON format
            tags (list, optional): List of tags
            assignee (User, optional): User assigned to the alert
            
        Returns:
            Alert: The created alert
        """
        # Determine the default status based on organization
        default_status = AlertStatus.objects.filter(
            organization=organization,
            is_default_open_status=True
        ).first() or AlertStatus.objects.filter(
            organization__isnull=True,
            is_default_open_status=True
        ).first()
        
        # Create alert
        alert = Alert.objects.create(
            title=title,
            source_system=source_system,
            description=description,
            severity=severity,
            status=default_status,
            organization=organization,
            external_alert_id=external_id,
            raw_event_data=raw_event_data or {},
            tags=tags or [],
            assignee=assignee,
            first_seen_at=timezone.now()
        )
        
        return alert
    
    @staticmethod
    def update_alert_status(alert, new_status, user=None):
        """
        Update the status of an alert, recording the change.
        
        Args:
            alert (Alert): The alert to update
            new_status (AlertStatus): The new status to set
            user (User, optional): The user making the change
            
        Returns:
            Alert: The updated alert
        """
        if alert.status == new_status:
            return alert
        
        old_status = alert.status
        alert.status = new_status
        alert.updated_at = timezone.now()
        alert.save()
        
        # Audit log will be implemented in the audit module
        
        return alert
    
    @staticmethod
    @transaction.atomic
    def merge_alerts(primary_alert, secondary_alerts, user=None):
        """
        Merge multiple alerts into a primary alert.
        
        Args:
            primary_alert (Alert): The primary alert that will remain after merging
            secondary_alerts (list): List of Alert objects to merge into the primary
            user (User, optional): The user performing the merge
            
        Returns:
            Alert: The updated primary alert
        """
        if not secondary_alerts:
            return primary_alert
        
        # Update artifact count
        artifact_count = primary_alert.artifact_count
        
        for alert in secondary_alerts:
            if alert.id == primary_alert.id:
                continue
                
            # Combine artifact counts
            artifact_count += alert.artifact_count
            
            # Migrate observables (will be implemented once observable module is migrated)
            # Move related observables to the primary alert
            # for observable_link in alert.alert_observables.all():
            #     observable = observable_link.observable
            #     AlertObservable.objects.get_or_create(
            #         alert=primary_alert,
            #         observable=observable,
            #         defaults={'sighted_at': timezone.now()}
            #     )
            
            # Mark secondary alert as merged
            alert.is_deleted = True
            alert.save()
        
        # Update primary alert
        primary_alert.artifact_count = artifact_count
        primary_alert.save()
        
        return primary_alert
        
    @staticmethod
    @transaction.atomic
    def escalate_to_case(alert, user, template=None, case_title=None, case_description=None):
        """
        Escalate an alert to a new case.
        
        Args:
            alert (Alert): The alert to escalate
            user (User): The user performing the escalation
            template (CaseTemplate, optional): Template to use for the new case
            case_title (str, optional): Custom title for the new case, if not using template default
            case_description (str, optional): Custom description for the new case
            
        Returns:
            Case: The newly created case
        """
        organization = alert.organization
        
        # Get default case status
        default_status = CaseStatus.objects.filter(
            organization=organization,
            is_default_open_status=True
        ).first() or CaseStatus.objects.filter(
            organization__isnull=True,
            is_default_open_status=True
        ).first()
        
        # Map alert severity to case severity
        # This assumes alert and case severities have the same levels, adjust if needed
        case_severity = CaseSeverity.objects.filter(
            level_order=alert.severity.level_order
        ).first()
        
        # Set default title if none provided
        default_title = case_title or f"Case from Alert: {alert.title}"
        default_description = case_description or alert.description
        
        # Get observables associated with the alert
        from irp.observables.models import Observable
        alert_observable_ids = list(alert.alert_observables.all().values_list('observable', flat=True))
        observables = []
        if alert_observable_ids:
            observables = list(Observable.objects.filter(observable_id__in=alert_observable_ids))
        
        # Apply template using the template service if a template is provided
        template_data = {}
        if template:
            # Create context for template variable substitution
            context = CaseTemplateService.create_context_for_template(
                alert=alert,
                user=user,
                observables=observables
            )
            
            # Apply template with variable substitution
            template_data = CaseTemplateService.apply_template(
                template=template,
                context=context,
                default_title=default_title
            )
        
        # Create the case
        case = Case.objects.create(
            title=template_data.get('title', default_title),
            description=template_data.get('description', default_description),
            severity=case_severity,
            status=default_status,
            organization=organization,
            assignee=alert.assignee,  # Maintain the same assignee if any
            reporter=user,
            template=template,
            tags=template_data.get('tags', alert.tags.copy() if alert.tags else [])
        )
        
        # Link the alert to the case
        case.alerts.add(alert)
        
        # Update alert status to indicate it's been escalated
        escalated_status = AlertStatus.objects.filter(
            Q(organization=organization) | Q(organization__isnull=True),
            name__icontains='escalat'  # Find a status with 'escalated' in the name
        ).first()
        
        if escalated_status:
            alert.status = escalated_status
            alert.save()
            
        # Create tasks from template data if provided
        default_task_status = TaskStatus.objects.first()  # Get the first task status (assuming it's "To Do")
        
        predefined_tasks = template_data.get('predefined_tasks', [])
        if predefined_tasks:
            for i, task_def in enumerate(predefined_tasks):
                Task.objects.create(
                    case=case,
                    title=task_def.get('title', 'Untitled Task'),
                    description=task_def.get('description', ''),
                    status=default_task_status,
                    order=task_def.get('order', i)
                    # Assignee would be handled elsewhere if there's a role-based assignment
                )
                
        # Copy observables from alert to case
        for alert_observable in alert.alert_observables.all():
            try:
                observable_id = alert_observable.observable
                observable = Observable.objects.get(observable_id=observable_id)
                case.case_observables.create(
                    observable=observable,
                    sighted_at=alert_observable.sighted_at
                )
            except Observable.DoesNotExist:
                # Skip if observable doesn't exist
                pass
        
        # Create timeline event
        from irp.timeline.services import create_timeline_event
        create_timeline_event(
            case=case,
            organization=organization,
            event_type='CASE_CREATED_FROM_ALERT',
            description=f"Caso criado a partir do alerta: {alert.title}",
            actor=user,
            metadata={
                'alert_id': str(alert.alert_id),
                'alert_title': alert.title,
                'alert_source': alert.source_system
            }
        )
        
        return case
        
    @staticmethod
    def find_similar_alerts(alert, max_results=10):
        """
        Find alerts similar to the provided alert based on various criteria.
        
        Args:
            alert (Alert): The alert to find similar alerts for
            max_results (int, optional): Maximum number of similar alerts to return
            
        Returns:
            list: List of dicts containing alert objects and similarity scores
        """
        organization = alert.organization
        
        # Start with alerts from the same organization that aren't deleted
        # and aren't the alert we're comparing against
        base_query = Alert.objects.filter(
            organization=organization,
            is_deleted=False
        ).exclude(
            alert_id=alert.alert_id
        )
        
        # Get alerts with the same external ID (strong match)
        external_id_matches = []
        if alert.external_alert_id:
            external_id_matches = list(base_query.filter(
                external_alert_id=alert.external_alert_id,
                source_system=alert.source_system
            ).values_list('alert_id', flat=True))
        
        # Get alerts with similar titles from the same source system
        title_matches = base_query.filter(
            source_system=alert.source_system,
            title__icontains=alert.title[:30]  # Use first 30 chars to avoid too-specific matches
        ).exclude(
            alert_id__in=external_id_matches  # Exclude alerts already matched by external ID
        ).values_list('alert_id', flat=True)
        
        # Find alerts with shared observables
        observable_matches = []
        
        # Get all observables associated with the current alert
        from irp.observables.models import Observable
        alert_observable_ids = set(alert.alert_observables.all().values_list('observable', flat=True))
        
        if alert_observable_ids:
            # Find other alerts that share at least one observable with our alert
            from .models import AlertObservable
            observable_matches = AlertObservable.objects.filter(
                observable__in=alert_observable_ids,  # Match any of our observables
                alert__organization=organization,
                alert__is_deleted=False
            ).exclude(
                alert__alert_id=alert.alert_id
            ).exclude(
                alert__alert_id__in=external_id_matches + list(title_matches)  # Exclude already matched alerts
            ).values('alert').annotate(
                shared_count=Count('alert')  # Count how many observables are shared
            ).order_by('-shared_count')[:max_results]
            
            observable_matches = [match['alert'] for match in observable_matches]
        
        # Compile results with scores
        results = []
        
        # External ID matches (highest score - 100)
        for alert_id in external_id_matches:
            similar_alert = Alert.objects.get(alert_id=alert_id)
            results.append({
                'alert': similar_alert,
                'score': 100,
                'match_reason': 'External alert ID'
            })
        
        # Title matches (score 70)
        for alert_id in title_matches:
            similar_alert = Alert.objects.get(alert_id=alert_id)
            results.append({
                'alert': similar_alert,
                'score': 70,
                'match_reason': 'Similar title'
            })
        
        # Observable matches (score depends on number of shared observables)
        for alert_id in observable_matches:
            similar_alert = Alert.objects.get(alert_id=alert_id)
            # Count shared observables
            similar_alert_observables = set(similar_alert.alert_observables.all().values_list('observable', flat=True))
            shared_count = len(alert_observable_ids.intersection(similar_alert_observables))
            
            # Calculate score: base 50 + 5 per shared observable, max 80
            score = min(80, 50 + (shared_count * 5))
            
            results.append({
                'alert': similar_alert,
                'score': score,
                'match_reason': f'Shared observables ({shared_count})'
            })
        
        # Sort by score (highest first) and limit results
        results.sort(key=lambda x: x['score'], reverse=True)
        return results[:max_results]
