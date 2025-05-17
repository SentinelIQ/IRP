from rest_framework import viewsets, permissions, filters, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend

from .models import AuditLog
from .serializers import AuditLogSerializer
from irp.common.permissions import HasRolePermission


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint para visualização de logs de auditoria.
    Este endpoint fornece uma visão somente leitura de todas as ações 
    registradas no sistema.
    """
    queryset = AuditLog.objects.all()
    serializer_class = AuditLogSerializer
    permission_classes = [permissions.IsAuthenticated, HasRolePermission]
    required_permission = 'view_audit_logs'
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['entity_type', 'action_type', 'user']
    search_fields = ['entity_id', 'details_after']
    ordering_fields = ['timestamp', 'entity_type', 'action_type']
    ordering = ['-timestamp']
    
    def get_queryset(self):
        """
        Filtra os logs de auditoria com base no usuário autenticado.
        Administradores do sistema podem ver todos os logs, enquanto usuários
        regulares só podem ver logs de sua própria organização.
        """
        user = self.request.user
        
        # System admins can see all logs
        if user.is_superuser or getattr(user.profile, 'is_system_admin', False):
            return AuditLog.objects.all()
        
        # Regular users can only see logs from their organization
        if hasattr(user, 'profile') and user.profile.organization:
            return AuditLog.objects.filter(organization=user.profile.organization)
            
        return AuditLog.objects.none()
    
    @action(detail=False, methods=['get'])
    def entity_history(self, request):
        """
        Obtém o histórico de auditoria para uma entidade específica.
        
        Parâmetros de consulta:
        - entity_type: Tipo da entidade (ALERT, CASE, etc.)
        - entity_id: ID da entidade
        """
        entity_type = request.query_params.get('entity_type')
        entity_id = request.query_params.get('entity_id')
        
        if not entity_type or not entity_id:
            return Response(
                {"detail": "Both entity_type and entity_id parameters are required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        queryset = self.get_queryset().filter(
            entity_type=entity_type,
            entity_id=entity_id
        ).order_by('-timestamp')
        
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
            
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data) 