import json
import logging
import requests
from django.utils import timezone
from jinja2 import Template
from .models import NotificationLog, NotificationRule, NotificationEvent, NotificationChannel

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
                timeout=10  # Timeout after 10 seconds
            )
            
            response.raise_for_status()
            return True, f"Webhook notification sent successfully: {response.status_code}"
        
        except requests.exceptions.RequestException as e:
            return False, f"Webhook error: {str(e)}"
        except Exception as e:
            return False, f"Unexpected error sending webhook: {str(e)}"
    
    @classmethod
    def _send_email(cls, config, message, payload):
        """Send notification via email"""
        try:
            from django.core.mail import send_mail
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            import smtplib
            
            recipients = config.get('recipients', [])
            if not recipients:
                return False, "No email recipients configured"
                
            subject = config.get('subject', 'Notification from IRP')
            
            # Create email message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = config.get('from_email', 'noreply@irp.example.com')
            msg['To'] = ', '.join(recipients)
            
            # Attach plain text and HTML versions
            text_part = MIMEText(message, 'plain')
            msg.attach(text_part)
            
            # If HTML template is provided, use it
            html_template = config.get('html_template')
            if html_template:
                try:
                    from django.template import Template, Context
                    t = Template(html_template)
                    c = Context(payload)
                    html_content = t.render(c)
                    html_part = MIMEText(html_content, 'html')
                    msg.attach(html_part)
                except Exception as e:
                    logger.error(f"Error rendering HTML email template: {str(e)}")
            
            # Use Django's send_mail function if SMTP settings are configured in settings
            try:
                send_mail(
                    subject=subject,
                    message=message,
                    from_email=config.get('from_email', 'noreply@irp.example.com'),
                    recipient_list=recipients,
                    fail_silently=False,
                )
                return True, f"Email sent successfully to {', '.join(recipients)}"
            except Exception as e:
                logger.error(f"Failed to send email through Django: {str(e)}")
                
                # Fall back to direct SMTP if Django mail fails or specific SMTP settings are provided
                smtp_host = config.get('smtp_host')
                smtp_port = config.get('smtp_port', 587)
                smtp_user = config.get('smtp_user')
                smtp_password = config.get('smtp_password')
                
                if smtp_host and smtp_user and smtp_password:
                    server = smtplib.SMTP(smtp_host, smtp_port)
                    server.starttls()
                    server.login(smtp_user, smtp_password)
                    server.send_message(msg)
                    server.quit()
                    return True, f"Email sent successfully via SMTP to {', '.join(recipients)}"
                else:
                    return False, f"Email configuration error: Missing SMTP credentials"
                
        except Exception as e:
            return False, f"Email error: {str(e)}"
    
    @classmethod
    def _send_slack(cls, config, message, payload):
        """Send notification to Slack"""
        try:
            webhook_url = config.get('webhook_url')
            if not webhook_url:
                return False, "Slack webhook URL not configured"
                
            channel = config.get('channel')
            username = config.get('username', 'IRP Bot')
            icon_emoji = config.get('icon_emoji', ':warning:')
            
            # Build Slack message payload
            slack_payload = {
                'text': message,
                'username': username,
                'icon_emoji': icon_emoji
            }
            
            if channel:
                slack_payload['channel'] = channel
                
            # Add blocks if configured
            blocks = config.get('blocks')
            if blocks:
                try:
                    # Try to render blocks with payload data
                    from jinja2 import Template
                    import json
                    
                    blocks_json = json.dumps(blocks)
                    template = Template(blocks_json)
                    rendered_blocks = json.loads(template.render(**payload))
                    slack_payload['blocks'] = rendered_blocks
                except Exception as e:
                    logger.error(f"Error rendering Slack blocks: {str(e)}")
                    
            response = requests.post(
                webhook_url,
                json=slack_payload,
                timeout=10
            )
            
            response.raise_for_status()
            return True, "Slack notification sent successfully"
        
        except requests.exceptions.RequestException as e:
            return False, f"Slack webhook error: {str(e)}"
        except Exception as e:
            return False, f"Unexpected error sending to Slack: {str(e)}"
    
    @classmethod
    def _send_custom_http(cls, config, message, payload):
        """Send notification via custom HTTP endpoint"""
        try:
            url = config.get('url')
            if not url:
                return False, "Custom HTTP URL not configured"
                
            method = config.get('method', 'POST').upper()
            headers = config.get('headers', {})
            auth = None
            
            # Set up authentication if provided
            auth_type = config.get('auth_type')
            if auth_type == 'basic':
                auth = (
                    config.get('auth_username', ''),
                    config.get('auth_password', '')
                )
            elif auth_type == 'bearer':
                headers['Authorization'] = f"Bearer {config.get('auth_token', '')}"
                
            # Prepare data based on content type
            content_type = headers.get('Content-Type', 'application/json')
            
            if 'application/json' in content_type:
                # If message is not valid JSON already, wrap it in a message field
                try:
                    data = json.loads(message)
                except (json.JSONDecodeError, TypeError):
                    data = {'message': message, 'payload': payload}
                    
                # Handle custom request
                if method == 'POST':
                    response = requests.post(url, json=data, headers=headers, auth=auth, timeout=30)
                elif method == 'PUT':
                    response = requests.put(url, json=data, headers=headers, auth=auth, timeout=30)
                elif method == 'PATCH':
                    response = requests.patch(url, json=data, headers=headers, auth=auth, timeout=30)
                elif method == 'GET':
                    response = requests.get(url, params=data, headers=headers, auth=auth, timeout=30)
                else:
                    return False, f"Unsupported HTTP method: {method}"
            else:
                # For non-JSON content types, send data as is
                if method == 'POST':
                    response = requests.post(url, data=message, headers=headers, auth=auth, timeout=30)
                elif method == 'PUT':
                    response = requests.put(url, data=message, headers=headers, auth=auth, timeout=30)
                elif method == 'PATCH':
                    response = requests.patch(url, data=message, headers=headers, auth=auth, timeout=30)
                elif method == 'GET':
                    response = requests.get(url, params={'message': message}, headers=headers, auth=auth, timeout=30)
                else:
                    return False, f"Unsupported HTTP method: {method}"
                    
            # Check if the request was successful and return result
            response.raise_for_status()
            return True, f"Custom HTTP notification sent successfully: {response.status_code}"
            
        except requests.exceptions.RequestException as e:
            return False, f"Custom HTTP error: {str(e)}"
        except Exception as e:
            return False, f"Unexpected error sending custom HTTP request: {str(e)}" 