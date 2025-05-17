import threading
import uuid

# Variável local para armazenar dados de requisição 
_request_local = threading.local()

def get_current_request():
    """Retorna a requisição atual armazenada no thread local"""
    if hasattr(_request_local, 'request'):
        return _request_local.request
    return None

def get_current_user():
    """Retorna o usuário autenticado da requisição atual ou None"""
    request = get_current_request()
    if request and hasattr(request, 'user') and request.user.is_authenticated:
        return request.user
    return None

def get_request_id():
    """Retorna o ID único da requisição atual"""
    if hasattr(_request_local, 'request_id'):
        return _request_local.request_id
    return None

class RequestMiddleware:
    """
    Middleware para armazenar a requisição atual em um thread local,
    permitindo acesso a ela de qualquer parte da aplicação.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Gera um ID único para a requisição
        request_id = str(uuid.uuid4())
        
        # Armazena a requisição e seu ID no thread local
        _request_local.request = request
        _request_local.request_id = request_id
        
        # Adiciona o request_id aos headers da resposta
        response = self.get_response(request)
        response['X-Request-ID'] = request_id
        
        # Limpa o thread local após a requisição
        _request_local.request = None
        _request_local.request_id = None
        
        return response
