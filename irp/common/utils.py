import datetime
import json
import re
import uuid
from django.utils import timezone
from django.conf import settings
from django.db import models

def generate_uuid():
    """
    Gera um UUID único para uso em modelos
    """
    return str(uuid.uuid4())

def get_client_ip(request):
    """
    Obtém o IP do cliente a partir da requisição
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def truncate_string(value, max_length=100, suffix='...'):
    """
    Trunca uma string caso ela seja maior que max_length
    """
    if not value or not isinstance(value, str):
        return value
        
    if len(value) <= max_length:
        return value
        
    return value[:max_length - len(suffix)] + suffix

def sanitize_filename(filename):
    """
    Remove caracteres inválidos de nomes de arquivos
    """
    # Remove caracteres não permitidos em sistemas de arquivos
    sanitized = re.sub(r'[\\/*?:"<>|]', '', filename)
    # Substitui espaços por underscores
    sanitized = sanitized.replace(' ', '_')
    return sanitized

class JSONEncoder(json.JSONEncoder):
    """
    Encoder JSON customizado para lidar com tipos de dados do Django
    """
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        elif isinstance(obj, datetime.date):
            return obj.isoformat()
        elif isinstance(obj, datetime.time):
            return obj.isoformat()
        elif isinstance(obj, models.Model):
            return str(obj)
        elif isinstance(obj, uuid.UUID):
            return str(obj)
        return super().default(obj)

def format_datetime(dt, format_str=None):
    """
    Formata um objeto datetime para string no formato ISO ou personalizado
    """
    if not dt:
        return None
        
    if not isinstance(dt, datetime.datetime):
        return str(dt)
        
    if format_str:
        return dt.strftime(format_str)
    
    return dt.isoformat()

def now():
    """
    Retorna o datetime atual com timezone
    """
    return timezone.now()

def calculate_time_difference(start_time, end_time=None):
    """
    Calcula a diferença de tempo entre dois datetimes
    """
    if end_time is None:
        end_time = timezone.now()
        
    if not start_time:
        return None
        
    difference = end_time - start_time
    return difference.total_seconds()

def get_object_or_none(model_class, **kwargs):
    """
    Retorna um objeto ou None se não existir (sem lançar exceção)
    """
    try:
        return model_class.objects.get(**kwargs)
    except model_class.DoesNotExist:
        return None
    except model_class.MultipleObjectsReturned:
        return model_class.objects.filter(**kwargs).first()
