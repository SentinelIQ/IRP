from django.db import transaction
from django.utils import timezone
import re
from datetime import datetime

from .models import Case, CaseTemplate


class CaseTemplateService:
    """
    Serviço para gerenciar templates de caso, incluindo substituição de variáveis.
    """
    
    @staticmethod
    def parse_template_variables(template_text, context):
        """
        Substitui variáveis no formato {{var_name}} em um texto por valores do contexto.
        
        Args:
            template_text (str): Texto do template com variáveis no formato {{var_name}}
            context (dict): Dicionário com valores para substituir as variáveis
            
        Returns:
            str: Texto com variáveis substituídas
        """
        if not template_text:
            return template_text
            
        # Regex para identificar variáveis no formato {{var_name}} ou {{var_name.attribute[index]}}
        pattern = r'{{([\w\.]+(?:\[\d+\])?)}}'
        
        def replace_var(match):
            var_path = match.group(1).strip()
            
            # Parse array access like observables.domain[0]
            array_match = re.match(r'([\w\.]+)\[(\d+)\]', var_path)
            if array_match:
                base_path = array_match.group(1)
                index = int(array_match.group(2))
                
                # Navigate through the object path (e.g., observables.domain)
                parts = base_path.split('.')
                value = context
                
                for part in parts:
                    if part in value:
                        value = value[part]
                    else:
                        return match.group(0)  # Return original if path not found
                
                # Get the item at specified index, if it exists
                if isinstance(value, list) and len(value) > index:
                    return str(value[index])
                else:
                    return match.group(0)  # Return original if index not found
            
            # Regular object path like user.name
            parts = var_path.split('.')
            value = context
            
            for part in parts:
                if part in value:
                    value = value[part]
                else:
                    return match.group(0)  # Return original if path not found
            
            return str(value)
        
        # Replace all variables in the template
        return re.sub(pattern, replace_var, template_text)
    
    @staticmethod
    def create_context_for_template(alert=None, user=None, observables=None):
        """
        Cria um contexto para substituição de variáveis em um template de caso.
        
        Args:
            alert (Alert, optional): Alerta associado ao caso
            user (User, optional): Usuário criando o caso
            observables (list, optional): Lista de observáveis a serem incluídos no contexto
            
        Returns:
            dict: Contexto para substituição de variáveis
        """
        context = {
            'date': {
                'now': timezone.now().strftime('%Y-%m-%d %H:%M:%S'),
                'today': timezone.now().strftime('%Y-%m-%d'),
                'year': timezone.now().year,
                'month': timezone.now().month,
                'day': timezone.now().day
            }
        }
        
        # Add user information
        if user:
            context['user'] = {
                'name': user.get_full_name() or user.username,
                'username': user.username,
                'email': user.email
            }
        
        # Add alert information
        if alert:
            context['alert'] = {
                'id': str(alert.alert_id),
                'title': alert.title,
                'source': alert.source_system,
                'severity': alert.severity.name if alert.severity else 'Unknown',
                'first_seen': alert.first_seen_at.strftime('%Y-%m-%d %H:%M:%S') if alert.first_seen_at else 'Unknown'
            }
        
        # Group observables by type
        if observables:
            obs_by_type = {}
            for obs in observables:
                type_name = obs.type.name
                if type_name not in obs_by_type:
                    obs_by_type[type_name] = []
                obs_by_type[type_name].append(obs.value)
            
            context['observables'] = obs_by_type
        
        return context
    
    @staticmethod
    def apply_template(template, context, default_title=None):
        """
        Aplica um template de caso, substituindo variáveis pelo contexto.
        
        Args:
            template (CaseTemplate): Template de caso
            context (dict): Contexto para substituição de variáveis
            default_title (str, optional): Título padrão se não for possível aplicar o template
            
        Returns:
            dict: Informações do caso com variáveis substituídas
        """
        result = {
            'title': default_title or 'Novo Caso',
            'description': '',
            'predefined_tasks': []
        }
        
        if template:
            # Apply title format if provided
            if template.default_title_format:
                parsed_title = CaseTemplateService.parse_template_variables(
                    template.default_title_format, 
                    context
                )
                # Only use parsed title if variables were successfully replaced
                if '{{' not in parsed_title:
                    result['title'] = parsed_title
            
            # Pass through other template values
            result['severity_id'] = template.default_severity_id if template.default_severity else None
            result['tags'] = template.default_tags
            
            # Process predefined tasks
            if template.predefined_tasks:
                result['predefined_tasks'] = []
                
                for task_def in template.predefined_tasks:
                    # Parse task title and description
                    task_title = CaseTemplateService.parse_template_variables(
                        task_def.get('title', 'Task'), 
                        context
                    )
                    
                    task_description = CaseTemplateService.parse_template_variables(
                        task_def.get('description', ''), 
                        context
                    )
                    
                    result['predefined_tasks'].append({
                        'title': task_title,
                        'description': task_description,
                        'order': task_def.get('order', 0),
                        'default_assignee_role_id': task_def.get('default_assignee_role_id')
                    })
        
        return result 