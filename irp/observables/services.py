from django.db import transaction
from django.utils import timezone

from .models import ObservableType, TLPLevel, PAPLevel, Observable


class ObservableService:
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
