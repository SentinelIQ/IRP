from django.db import transaction
from django.utils import timezone

from .models import Alert, AlertStatus


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
