import json
import logging
import requests
from django.conf import settings
from django.core.mail import send_mail
from django.template import Template, Context
from .models import NotificationLog, NotificationRule
from django.utils import timezone
from django.db import connection
from django.db.models import Count, Avg, Sum, F, Q
import smtplib
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from jinja2 import Template
from urllib.parse import urljoin
from django.utils.dateparse import parse_date

logger = logging.getLogger(__name__)

class NotificationService:
    """
    Service for processing events and sending notifications through configured channels
    based on notification rules.
    """
    
    @classmethod
    def process_event(cls, event_name, payload, organization=None):
        """
        Process an event by finding matching rules and sending notifications.
        
        Args:
            event_name: The name of the event (e.g., 'ALERT_CREATED')
            payload: Dictionary containing event data
            organization: The organization for which to process the event
            
        Returns:
            List of notification log IDs created
        """
        from api.models import NotificationEvent, NotificationRule, NotificationLog
        
        if not organization:
            logger.error("Organization is required for processing events")
            return []
        
        try:
            # Find the event type
            try:
                event_type = NotificationEvent.objects.get(event_name=event_name)
            except NotificationEvent.DoesNotExist:
                logger.warning(f"Event type '{event_name}' not found")
                return []
            
            # Find all active rules for this event and organization
            rules = NotificationRule.objects.filter(
                event_type=event_type,
                organization=organization,
                is_active=True
            ).select_related('channel')
            
            if not rules:
                logger.debug(f"No active rules found for event '{event_name}' in org '{organization.name}'")
                return []
            
            notification_logs = []
            
            # Process each matching rule
            for rule in rules:
                if cls._evaluate_conditions(rule.conditions, payload):
                    # If conditions are met, send the notification
                    try:
                        # Check if the channel is active
                        if not rule.channel.is_active:
                            continue
                            
                        # Format message using template if provided
                        message = cls._render_template(rule.message_template, payload) if rule.message_template else json.dumps(payload)
                        
                        # Send notification through the appropriate channel
                        success, response_details = cls._send_notification(rule.channel, message, payload)
                        
                        # Create log entry
                        log_entry = NotificationLog.objects.create(
                            rule=rule,
                            channel=rule.channel,
                            organization=organization,
                            event_payload=payload,
                            status='SUCCESS' if success else 'FAILED',
                            response_details=response_details
                        )
                        
                        notification_logs.append(str(log_entry.log_id))
                        
                        if not success:
                            logger.error(f"Failed to send notification for rule '{rule.name}': {response_details}")
                    
                    except Exception as e:
                        logger.exception(f"Error sending notification for rule '{rule.name}': {str(e)}")
                        # Log the failure
                        log_entry = NotificationLog.objects.create(
                            rule=rule,
                            channel=rule.channel,
                            organization=organization,
                            event_payload=payload,
                            status='FAILED',
                            response_details=str(e)
                        )
                        notification_logs.append(str(log_entry.log_id))
            
            return notification_logs
            
        except Exception as e:
            logger.exception(f"Error processing event '{event_name}': {str(e)}")
            return []
    
    @classmethod
    def _evaluate_conditions(cls, conditions, payload):
        """
        Evaluate if the conditions match the payload.
        
        Args:
            conditions: Dictionary of conditions to evaluate
            payload: Event payload data
            
        Returns:
            Boolean indicating if conditions are met
        """
        if not conditions:
            return True  # No conditions means always match
        
        try:
            for field, condition in conditions.items():
                # Handle nested fields with dot notation (e.g., "alert.severity")
                field_parts = field.split('.')
                value = payload
                for part in field_parts:
                    if part in value:
                        value = value[part]
                    else:
                        return False  # Field doesn't exist
                
                # Different condition types
                if isinstance(condition, dict):
                    operator = condition.get('operator')
                    expected_value = condition.get('value')
                    
                    if operator == 'equals':
                        if value != expected_value:
                            return False
                    elif operator == 'not_equals':
                        if value == expected_value:
                            return False
                    elif operator == 'contains':
                        if expected_value not in value:
                            return False
                    elif operator == 'greater_than':
                        if not (value > expected_value):
                            return False
                    elif operator == 'less_than':
                        if not (value < expected_value):
                            return False
                    elif operator == 'in':
                        if value not in expected_value:
                            return False
                    elif operator == 'not_in':
                        if value in expected_value:
                            return False
                else:
                    # Simple equality check
                    if value != condition:
                        return False
            
            return True
        
        except Exception as e:
            logger.exception(f"Error evaluating conditions: {str(e)}")
            return False
    
    @classmethod
    def _render_template(cls, template_string, payload):
        """
        Render a template with the payload data.
        
        Args:
            template_string: Jinja2 template string
            payload: Data to use in the template
            
        Returns:
            Rendered template string
        """
        try:
            if not template_string:
                return json.dumps(payload)
                
            # Basic variable substitution with Jinja2
            template = Template(template_string)
            return template.render(**payload)
        except Exception as e:
            logger.exception(f"Error rendering template: {str(e)}")
            return json.dumps(payload)
    
    @classmethod
    def _send_notification(cls, channel, message, payload):
        """
        Send notification through the specified channel.
        
        Args:
            channel: NotificationChannel object
            message: Formatted message to send
            payload: Original event payload
            
        Returns:
            Tuple of (success, response_details)
        """
        channel_type = channel.channel_type
        config = channel.configuration
        
        if channel_type == 'WEBHOOK':
            return cls._send_webhook(config, message, payload)
        elif channel_type == 'EMAIL':
            return cls._send_email(config, message, payload)
        elif channel_type == 'SLACK':
            return cls._send_slack(config, message, payload)
        elif channel_type == 'CUSTOM_HTTP':
            return cls._send_custom_http(config, message, payload)
        else:
            return False, f"Unsupported channel type: {channel_type}"
    
    @classmethod
    def _send_webhook(cls, config, message, payload):
        """Send notification to a webhook"""
        try:
            url = config.get('url')
            if not url:
                return False, "Webhook URL not configured"
                
            headers = config.get('headers', {'Content-Type': 'application/json'})
            
            # If message is not valid JSON already, wrap it in a message field
            try:
                json_payload = json.loads(message)
                data = json_payload
            except (json.JSONDecodeError, TypeError):
                data = {'message': message, 'payload': payload}
            
            response = requests.post(
                url, 
                json=data, 
                headers=headers, 
                timeout=10
            )
            
            if response.status_code >= 200 and response.status_code < 300:
                return True, f"Webhook delivery successful. Status: {response.status_code}"
            else:
                return False, f"Webhook delivery failed. Status: {response.status_code}, Response: {response.text[:200]}"
                
        except Exception as e:
            return False, f"Error sending webhook: {str(e)}"
    
    @classmethod
    def _send_email(cls, config, message, payload):
        """Send notification via email"""
        try:
            to_addresses = config.get('to_addresses', [])
            subject = cls._render_template(config.get('subject_template', 'Notification'), payload)
            
            if not to_addresses:
                return False, "No recipient email addresses configured"
            
            # Create a multipart message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = settings.EMAIL_HOST_USER
            msg['To'] = ', '.join(to_addresses)
            
            # Create the plain-text and HTML version of your message
            text_part = MIMEText(message, 'plain')
            
            # Add parts to MIMEMultipart message
            msg.attach(text_part)
            
            # If HTML template is provided, add HTML part as well
            html_template = config.get('html_template')
            if html_template:
                html_body = cls._render_template(html_template, payload)
                html_part = MIMEText(html_body, 'html')
                msg.attach(html_part)
            
            # Using Django's email backend
            from django.core.mail import send_mail
            
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=to_addresses,
                fail_silently=False,
                html_message=html_body if html_template else None
            )
            
            return True, f"Email sent successfully to {to_addresses}"
            
        except Exception as e:
            return False, f"Error sending email: {str(e)}"
    
    @classmethod
    def _send_slack(cls, config, message, payload):
        """Send notification to Slack"""
        try:
            webhook_url = config.get('webhook_url')
            if not webhook_url:
                return False, "Slack webhook URL not configured"
            
            channel_name = config.get('channel_name')
            username = config.get('username', 'Incident Response Platform')
            
            # Format for Slack
            slack_payload = {
                'text': message,
                'username': username
            }
            
            if channel_name:
                slack_payload['channel'] = channel_name
                
            # Add blocks if available
            blocks = config.get('blocks')
            if blocks:
                try:
                    # If blocks is a string template, render it
                    if isinstance(blocks, str):
                        blocks_rendered = cls._render_template(blocks, payload)
                        slack_payload['blocks'] = json.loads(blocks_rendered)
                    else:
                        slack_payload['blocks'] = blocks
                except Exception as e:
                    logger.warning(f"Failed to parse Slack blocks: {str(e)}")
            
            response = requests.post(
                webhook_url,
                json=slack_payload,
                timeout=10
            )
            
            if response.text == 'ok':
                return True, "Slack notification sent successfully"
            else:
                return False, f"Slack notification failed. Response: {response.text[:200]}"
                
        except Exception as e:
            return False, f"Error sending Slack notification: {str(e)}"
    
    @classmethod
    def _send_custom_http(cls, config, message, payload):
        """Send notification via custom HTTP request"""
        try:
            url = config.get('url')
            method = config.get('method', 'POST').upper()
            
            if not url:
                return False, "Custom HTTP URL not configured"
            
            headers = config.get('headers', {})
            
            # Determine the request body format
            body_format = config.get('body_format', 'json')
            
            if body_format == 'json':
                # If message is not valid JSON, wrap it in a message field
                try:
                    data = json.loads(message)
                except (json.JSONDecodeError, TypeError):
                    data = {'message': message, 'payload': payload}
                
                # Use requests' json parameter for proper JSON serialization
                kwargs = {'json': data}
            elif body_format == 'form':
                # Parse message into form data if possible
                try:
                    data = json.loads(message)
                    kwargs = {'data': data}
                except (json.JSONDecodeError, TypeError):
                    kwargs = {'data': {'message': message}}
            elif body_format == 'text':
                kwargs = {'data': message}
            else:
                return False, f"Unsupported body format: {body_format}"
            
            # Make the HTTP request
            response = requests.request(
                method,
                url,
                headers=headers,
                timeout=10,
                **kwargs
            )
            
            # Check if request was successful (2xx)
            if response.status_code >= 200 and response.status_code < 300:
                return True, f"Custom HTTP request successful. Status: {response.status_code}"
            else:
                return False, f"Custom HTTP request failed. Status: {response.status_code}, Response: {response.text[:200]}"
                
        except Exception as e:
            return False, f"Error sending custom HTTP request: {str(e)}"


class MetricsService:
    """
    Service for calculating, storing, and retrieving metrics data
    """
    
    @classmethod
    def calculate_metric(cls, metric, organization, start_date, end_date, granularity='DAILY', dimensions=None):
        """
        Calculate a metric value for a specific time period.
        
        Args:
            metric: Metric model object
            organization: Organization model object
            start_date: Start date for calculation
            end_date: End date for calculation
            granularity: Time granularity (DAILY, WEEKLY, MONTHLY)
            dimensions: Dictionary of dimension values to filter by
            
        Returns:
            Calculated metric value(s)
        """
        from api.models import MetricSnapshot
        
        try:
            # Prepare the query parameters
            params = {
                'org_id': organization.organization_id,
                'start_date': start_date,
                'end_date': end_date
            }
            
            # Add any dimension parameters
            if dimensions:
                for key, value in dimensions.items():
                    params[key] = value
            
            # Execute the calculation query
            with connection.cursor() as cursor:
                # Replace parameter placeholders in the query
                query = metric.calculation_query
                
                # Execute the query
                cursor.execute(query, params)
                results = cursor.fetchall()
                
            # For custom metrics, the query should return the desired structure
            # For standard metrics, we convert to the appropriate format
            formatted_results = []
            
            if results:
                # Get column names
                columns = [col[0] for col in cursor.description]
                
                # Convert to list of dicts
                for row in results:
                    formatted_results.append(dict(zip(columns, row)))
                
                # For single value metrics
                if len(formatted_results) == 1 and len(formatted_results[0]) == 1:
                    return list(formatted_results[0].values())[0]
                
                return formatted_results
            
            return None
            
        except Exception as e:
            logger.exception(f"Error calculating metric '{metric.name}': {str(e)}")
            return None
    
    @classmethod
    def store_metric_snapshot(cls, metric, organization, date, value, granularity='DAILY', dimensions=None):
        """
        Store a metric snapshot for a specific date.
        
        Args:
            metric: Metric model object
            organization: Organization model object
            date: Date for the snapshot
            value: Metric value
            granularity: Time granularity (DAILY, WEEKLY, MONTHLY)
            dimensions: Dictionary of dimension values
            
        Returns:
            Created MetricSnapshot object
        """
        from api.models import MetricSnapshot
        
        dimensions = dimensions or {}
        
        try:
            snapshot = MetricSnapshot.objects.create(
                metric=metric,
                organization=organization,
                date=date,
                granularity=granularity,
                dimensions=dimensions,
                value=value
            )
            
            return snapshot
            
        except Exception as e:
            logger.exception(f"Error storing metric snapshot for '{metric.name}': {str(e)}")
            return None
    
    @classmethod
    def get_metric_data(cls, metric, organization, start_date, end_date, granularity='DAILY', dimensions=None):
        """
        Get metric data for a specific time period.
        First checks if snapshots exist, then falls back to calculation.
        
        Args:
            metric: Metric model object
            organization: Organization model object
            start_date: Start date for query
            end_date: End date for query
            granularity: Time granularity (DAILY, WEEKLY, MONTHLY)
            dimensions: Dictionary of dimension values to filter by
            
        Returns:
            Dictionary with metric data
        """
        from api.models import MetricSnapshot
        
        dimensions = dimensions or {}
        
        try:
            # Try to get snapshots first
            snapshots = MetricSnapshot.objects.filter(
                metric=metric,
                organization=organization,
                date__gte=start_date,
                date__lte=end_date,
                granularity=granularity
            )
            
            # Filter by dimensions if provided
            for key, value in dimensions.items():
                snapshots = snapshots.filter(dimensions__contains={key: value})
            
            if snapshots.exists():
                # Group by date
                data_points = {}
                for snapshot in snapshots:
                    date_str = snapshot.date.isoformat()
                    if date_str not in data_points:
                        data_points[date_str] = {
                            'date': date_str,
                            'value': snapshot.value
                        }
                    else:
                        # If multiple snapshots for same date (with different dimensions)
                        # we need to combine them based on metric type
                        if metric.metric_type == 'COUNT' or metric.metric_type == 'SUM':
                            data_points[date_str]['value'] += snapshot.value
                        elif metric.metric_type == 'AVERAGE':
                            # For averages, we would need more complex logic
                            # This is a simplified approach
                            data_points[date_str]['value'] = (data_points[date_str]['value'] + snapshot.value) / 2
                
                return {
                    'metric': {
                        'id': metric.metric_id,
                        'name': metric.name,
                        'display_name': metric.display_name,
                        'type': metric.metric_type
                    },
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat(),
                    'granularity': granularity,
                    'dimensions': dimensions,
                    'data_points': list(data_points.values())
                }
            
            # If no snapshots, calculate on the fly
            dates = cls._get_date_range(start_date, end_date, granularity)
            data_points = []
            
            for date in dates:
                # Calculate for each date
                value = cls.calculate_metric(
                    metric, 
                    organization, 
                    date, 
                    cls._get_end_of_period(date, granularity),
                    granularity,
                    dimensions
                )
                
                if value is not None:
                    data_points.append({
                        'date': date.isoformat(),
                        'value': value
                    })
            
            return {
                'metric': {
                    'id': metric.metric_id,
                    'name': metric.name,
                    'display_name': metric.display_name,
                    'type': metric.metric_type
                },
                'start_date': start_date.isoformat(),
                'end_date': end_date.isoformat(),
                'granularity': granularity,
                'dimensions': dimensions,
                'data_points': data_points
            }
                
        except Exception as e:
            logger.exception(f"Error getting metric data for '{metric.name}': {str(e)}")
            return {
                'error': str(e),
                'metric': {
                    'id': metric.metric_id,
                    'name': metric.name,
                    'display_name': metric.display_name
                }
            }
    
    @classmethod
    def _get_date_range(cls, start_date, end_date, granularity):
        """Generate a list of dates between start and end date based on granularity"""
        dates = []
        current = start_date
        
        while current <= end_date:
            dates.append(current)
            
            if granularity == 'DAILY':
                current += timedelta(days=1)
            elif granularity == 'WEEKLY':
                current += timedelta(weeks=1)
            elif granularity == 'MONTHLY':
                # Move to the first day of the next month
                year = current.year + (current.month // 12)
                month = (current.month % 12) + 1
                current = current.replace(year=year, month=month, day=1)
        
        return dates
    
    @classmethod
    def _get_end_of_period(cls, date, granularity):
        """Get the end date for a period based on the granularity"""
        if granularity == 'DAILY':
            return date + timedelta(days=1) - timedelta(microseconds=1)
        elif granularity == 'WEEKLY':
            return date + timedelta(weeks=1) - timedelta(microseconds=1)
        elif granularity == 'MONTHLY':
            # Move to the first day of the next month, then subtract 1 microsecond
            year = date.year + (date.month // 12)
            month = (date.month % 12) + 1
            next_month = date.replace(year=year, month=month, day=1)
            return next_month - timedelta(microseconds=1) 