import uuid
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
from .utils import generate_uuid

class BaseModel(models.Model):
    """
    Modelo base com campos comuns para a maioria dos modelos da aplicação
    """
    id = models.UUIDField(primary_key=True, default=generate_uuid, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        abstract = True

class OrganizationOwnedModel(BaseModel):
    """
    Modelo base para entidades que pertencem a uma organização
    """
    organization = models.ForeignKey(
        'accounts.Organization', 
        on_delete=models.CASCADE, 
        related_name="%(class)ss"
    )
    
    class Meta:
        abstract = True
        
class UserTrackingModel(BaseModel):
    """
    Modelo base que rastreia o criador e o último modificador
    """
    created_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        related_name="%(class)s_created"
    )
    updated_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        related_name="%(class)s_updated"
    )
    
    class Meta:
        abstract = True
        
class OrganizationAndUserTrackingModel(OrganizationOwnedModel, UserTrackingModel):
    """
    Modelo base que combina propriedade da organização e rastreamento de usuários
    """
    class Meta:
        abstract = True
        
class SoftDeleteModel(models.Model):
    """
    Modelo base que suporta exclusão lógica
    """
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)
    deleted_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        related_name="%(class)s_deleted", 
        blank=True
    )
    
    class Meta:
        abstract = True
    
    def soft_delete(self, user=None):
        """
        Marca o objeto como excluído sem removê-lo do banco de dados
        """
        self.is_deleted = True
        self.deleted_at = timezone.now()
        if user:
            self.deleted_by = user
        self.save()
        
    def restore(self):
        """
        Restaura um objeto anteriormente excluído
        """
        self.is_deleted = False
        self.deleted_at = None
        self.deleted_by = None
        self.save()
