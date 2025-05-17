import json
from django.utils import timezone
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response

from irp.common.permissions import HasRolePermission
from .models import NotificationEvent, NotificationChannel, NotificationRule, NotificationLog
from .serializers import (
    NotificationEventSerializer, NotificationChannelSerializer,
    NotificationRuleSerializer, NotificationLogSerializer
)
from .services import NotificationService


class NotificationEventViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for notification events (readonly)
    """
    queryset = NotificationEvent.objects.all()
    serializer_class = NotificationEventSerializer
    permission_classes = [permissions.IsAuthenticated]


class NotificationChannelViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing notification channels
    """
    serializer_class = NotificationChannelSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'notification:manage'
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            return NotificationChannel.objects.filter(organization=user.profile.organization)
        return NotificationChannel.objects.none()
    
    def perform_create(self, serializer):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            serializer.save(organization=user.profile.organization)
        else:
            raise PermissionError("User must belong to an organization")
    
    @action(detail=True, methods=['post'])
    def test(self, request, pk=None):
        """
        Test a notification channel
        """
        channel = self.get_object()
        
        # Create a test payload
        test_payload = {
            'message': 'This is a test notification',
            'timestamp': timezone.now().isoformat(),
            'sender': request.user.username
        }
        
        # Send test notification
        success, response_details = NotificationService._send_notification(
            channel=channel, 
            message="This is a test notification from your Incident Response Platform", 
            payload=test_payload
        )
        
        return Response({
            'success': success,
            'message': 'Test notification sent successfully' if success else 'Failed to send test notification',
            'details': response_details
        })


class NotificationRuleViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing notification rules
    """
    serializer_class = NotificationRuleSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'notification:manage'
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            return NotificationRule.objects.filter(organization=user.profile.organization)
        return NotificationRule.objects.none()
    
    def perform_create(self, serializer):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            serializer.save(organization=user.profile.organization)
        else:
            raise PermissionError("User must belong to an organization")
    
    @action(detail=True, methods=['post'])
    def test(self, request, pk=None):
        """
        Test a notification rule with a sample payload
        """
        rule = self.get_object()
        
        # Get or create a test payload
        test_payload = request.data.get('payload', {})
        if not test_payload:
            # Create default test payload based on event type
            event_name = rule.event_type.event_name
            if 'ALERT' in event_name:
                test_payload = {
                    'alert_id': 'test-alert-id',
                    'title': 'Test Alert',
                    'description': 'This is a test alert',
                    'severity': 'Critical',
                    'status': 'New',
                    'created_at': timezone.now().isoformat(),
                    'organization_id': str(rule.organization.organization_id),
                    'organization_name': rule.organization.name,
                }
            elif 'CASE' in event_name:
                test_payload = {
                    'case_id': 'test-case-id',
                    'title': 'Test Case',
                    'description': 'This is a test case',
                    'severity': 'High',
                    'status': 'Open',
                    'created_at': timezone.now().isoformat(),
                    'organization_id': str(rule.organization.organization_id),
                    'organization_name': rule.organization.name,
                }
            else:
                test_payload = {
                    'event_name': event_name,
                    'timestamp': timezone.now().isoformat(),
                    'organization_id': str(rule.organization.organization_id),
                    'organization_name': rule.organization.name,
                    'test': True
                }
        
        # Check conditions
        conditions_met = NotificationService._evaluate_conditions(rule.conditions, test_payload)
        
        # If conditions are met, send test notification
        if conditions_met:
            message = NotificationService._render_template(rule.message_template, test_payload) if rule.message_template else json.dumps(test_payload)
            success, response_details = NotificationService._send_notification(
                channel=rule.channel, 
                message=message, 
                payload=test_payload
            )
            
            return Response({
                'conditions_met': True,
                'notification_sent': success,
                'message': message,
                'details': response_details
            })
        else:
            return Response({
                'conditions_met': False,
                'message': 'Test payload does not meet rule conditions',
                'rule_conditions': rule.conditions,
                'test_payload': test_payload
            })


class NotificationLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for viewing notification logs (readonly)
    """
    serializer_class = NotificationLogSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'notification:view'
    
    def get_queryset(self):
        user = self.request.user
        if hasattr(user, 'profile') and user.profile.organization:
            return NotificationLog.objects.filter(organization=user.profile.organization)
        return NotificationLog.objects.none()


class NotificationViewSet(viewsets.ViewSet):
    """
    ViewSet for triggering notifications manually and testing notification rules
    """
    permission_classes = [permissions.IsAuthenticated]
    
    @action(detail=False, methods=['post'])
    def trigger_event(self, request):
        """
        Manually trigger a notification event
        """
        user = request.user
        if not hasattr(user, 'profile') or not user.profile.organization:
            return Response(
                {'detail': 'User not associated with an organization'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        event_name = request.data.get('event_name')
        payload = request.data.get('payload', {})
        
        if not event_name:
            return Response(
                {'detail': 'event_name is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Process the event using the notification service
            notification_logs = NotificationService.process_event(
                event_name=event_name,
                payload=payload,
                organization=user.profile.organization
            )
            
            if notification_logs:
                return Response({
                    'success': True,
                    'message': f"Event '{event_name}' processed successfully",
                    'notification_logs': notification_logs
                })
            else:
                return Response({
                    'success': False,
                    'message': f"No notifications were sent for event '{event_name}'",
                    'reason': "No matching active rules found or rule conditions not met"
                })
                
        except Exception as e:
            return Response(
                {'detail': f"Error processing event: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            ) 