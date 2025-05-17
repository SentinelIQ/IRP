from django.db import transaction
from django.utils import timezone
import re
import ipaddress
from urllib.parse import urlparse

from .models import ObservableType, TLPLevel, PAPLevel, Observable


class ObservableService:
    # Regex patterns para identificar diferentes tipos de observáveis
    PATTERNS = {
        'ipv4': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        'ipv6': r'(?:(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))',
        'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        'url': r'(?:https?|ftp)://(?:(?:[a-zA-Z0-9\$\-\_\.\+\!\*\'\(\)\,\;\?\&\=]|(?:\%[a-fA-F0-9]{2})){1,64}(?:\:(?:[a-zA-Z0-9\$\-\_\.\+\!\*\'\(\)\,\;\?\&\=]|(?:\%[a-fA-F0-9]{2})){1,25})?\@)?(?:(?:[a-zA-Z0-9][a-zA-Z0-9\-]{0,64}\.)+(?:[a-zA-Z]{2,}\.?))|(?:(?:25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9][0-9]|[1-9])\.(?:25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9][0-9]|[1-9]|0)\.(?:25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9][0-9]|[1-9]|0)\.(?:25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[1-9][0-9]|[0-9]))(?:\:\d{1,5})?(?:\/(?:[a-zA-Z0-9\;\/\?\:\@\&\=\#\~\-\.\+\!\*\'\(\)\,\_]|(?:\%[a-fA-F0-9]{2}))*)?(?:\b|\?)',
        'email': r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
        'md5': r'\b[a-fA-F0-9]{32}\b',
        'sha1': r'\b[a-fA-F0-9]{40}\b',
        'sha256': r'\b[a-fA-F0-9]{64}\b'
    }

    @staticmethod
    def validate_observable(obs_type, value):
        """
        Valida se o valor corresponde ao tipo de observável especificado.
        
        Args:
            obs_type (str): Tipo de observável ('ipv4', 'domain', etc)
            value (str): Valor do observável
            
        Returns:
            bool: True se o valor for válido para o tipo, False caso contrário
        """
        if obs_type == 'ipv4':
            try:
                ip = ipaddress.IPv4Address(value)
                # Excluir IPs privados, localhost, etc.
                return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast)
            except:
                return False
        elif obs_type == 'ipv6':
            try:
                ip = ipaddress.IPv6Address(value)
                return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast)
            except:
                return False
        elif obs_type == 'domain':
            # Verificações básicas para domínios
            if value.endswith('.'):
                value = value[:-1]
            # Excluir nomes de domínio comuns internos e de teste
            if any(suffix in value for suffix in ['.local', '.internal', '.test', '.example', '.invalid']):
                return False
            # Verificar se tem pelo menos um ponto
            return '.' in value and len(value.split('.')[-1]) >= 2
        elif obs_type == 'url':
            try:
                parsed_url = urlparse(value)
                # Verificar se tem um esquema e um caminho mínimo
                return parsed_url.scheme in ['http', 'https', 'ftp'] and parsed_url.netloc
            except:
                return False
        elif obs_type == 'email':
            # Verificação simples para emails
            parts = value.split('@')
            return len(parts) == 2 and '.' in parts[1] and len(parts[1].split('.')[-1]) >= 2
        elif obs_type in ['md5', 'sha1', 'sha256']:
            # Verificação de comprimento e caracteres válidos para hashes
            lengths = {'md5': 32, 'sha1': 40, 'sha256': 64}
            return len(value) == lengths[obs_type] and all(c in '0123456789abcdefABCDEF' for c in value)
        return True  # Assumir válido para tipos não específicos

    @staticmethod
    def extract_observables(text):
        """
        Extrai observáveis de um texto usando expressões regulares.
        
        Args:
            text (str): Texto para extrair observáveis
            
        Returns:
            dict: Mapeamento de tipo de observável para lista de valores encontrados
        """
        if not text:
            return {}
            
        result = {}
        
        # Executar cada padrão regex no texto
        for obs_type, pattern in ObservableService.PATTERNS.items():
            matches = re.findall(pattern, text)
            # Filtrar apenas valores válidos e remover duplicados
            valid_matches = []
            for value in matches:
                if ObservableService.validate_observable(obs_type, value) and value not in valid_matches:
                    valid_matches.append(value)
            
            if valid_matches:
                result[obs_type] = valid_matches
                
        return result
    
    @staticmethod
    @transaction.atomic
    def create_or_get_observables(extracted_observables, user, organization):
        """
        Cria ou recupera objetos Observable a partir de observáveis extraídos.
        
        Args:
            extracted_observables (dict): Resultado de extract_observables
            user (User): Usuário que está criando os observáveis
            organization (Organization): Organização do usuário
            
        Returns:
            list: Lista de objetos Observable criados ou recuperados
        """
        result = []
        
        # Mapear tipos de observáveis para modelos ObservableType
        type_mapping = {}
        for obs_type in extracted_observables.keys():
            obs_type_obj, _ = ObservableType.objects.get_or_create(name=obs_type)
            type_mapping[obs_type] = obs_type_obj
        
        # Obter níveis TLP e PAP padrão (WHITE e "No Action")
        default_tlp = TLPLevel.objects.filter(name="WHITE").first()
        default_pap = PAPLevel.objects.filter(name__icontains="No Action").first()
        
        # Criar ou recuperar observáveis
        for obs_type, values in extracted_observables.items():
            type_obj = type_mapping[obs_type]
            for value in values:
                observable, created = Observable.objects.get_or_create(
                    value=value,
                    type=type_obj,
                    defaults={
                        'description': f"Automatically extracted from text",
                        'tags': [obs_type],
                        'is_ioc': False,
                        'tlp_level': default_tlp,
                        'pap_level': default_pap,
                        'added_by': user,
                        'added_at': timezone.now()
                    }
                )
                result.append(observable)
                
        return result
    
    @staticmethod
    def extract_and_create_observables_from_text(text, user, organization):
        """
        Extrai observáveis de um texto e cria objetos Observable para eles.
        
        Args:
            text (str): Texto para extrair observáveis
            user (User): Usuário que está criando os observáveis
            organization (Organization): Organização do usuário
            
        Returns:
            list: Lista de objetos Observable criados ou recuperados
        """
        extracted = ObservableService.extract_observables(text)
        return ObservableService.create_or_get_observables(extracted, user, organization)

    @staticmethod
    def create_observable(value, type_obj, description=None, is_ioc=False, 
                         tlp_level=None, pap_level=None, tags=None, added_by=None):
        """
        Create a new observable or return an existing one with the same value and type.
        
        Args:
            value (str): The observable value (e.g., IP address, domain, hash)
            type_obj (ObservableType): The type of observable
            description (str, optional): Description of the observable
            is_ioc (bool, optional): Whether this is an indicator of compromise
            tlp_level (TLPLevel, optional): Traffic Light Protocol level
            pap_level (PAPLevel, optional): Permissible Actions Protocol level
            tags (list, optional): List of tags for the observable
            added_by (User, optional): User who added the observable
            
        Returns:
            Observable: The created or existing observable
        """
        # Check if observable already exists
        observable, created = Observable.objects.get_or_create(
            value=value,
            type=type_obj,
            defaults={
                'description': description or '',
                'is_ioc': is_ioc,
                'tlp_level': tlp_level,
                'pap_level': pap_level,
                'tags': tags or [],
                'added_by': added_by
            }
        )
        
        # If not created but some fields need updating
        if not created:
            updated = False
            
            if description and not observable.description:
                observable.description = description
                updated = True
            
            if is_ioc and not observable.is_ioc:
                observable.is_ioc = True
                updated = True
            
            if tlp_level and not observable.tlp_level:
                observable.tlp_level = tlp_level
                updated = True
                
            if pap_level and not observable.pap_level:
                observable.pap_level = pap_level
                updated = True
            
            if tags:
                # Merge tags without duplicates
                new_tags = list(set(observable.tags + tags))
                if new_tags != observable.tags:
                    observable.tags = new_tags
                    updated = True
            
            if updated:
                observable.save()
        
        return observable
    
    @staticmethod
    def get_observable_by_value_and_type(value, type_name):
        """
        Find an observable by its value and type name.
        
        Args:
            value (str): The observable value
            type_name (str): The name of the observable type
            
        Returns:
            Observable: The found observable or None
        """
        try:
            observable_type = ObservableType.objects.get(name=type_name)
            return Observable.objects.filter(value=value, type=observable_type).first()
        except ObservableType.DoesNotExist:
            return None
