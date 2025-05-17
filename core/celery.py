import os
from celery import Celery

# Definir a variável de ambiente para as configurações do Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')

# Criar instância do Celery
app = Celery('core')

# Carregar configuração do Django settings
app.config_from_object('django.conf:settings', namespace='CELERY')

# Importar configuração do beat schedule
from core.celery_beat_config import beat_schedule

# Configurar o schedule do Beat
app.conf.beat_schedule = beat_schedule

# Autodescoberta de tarefas em arquivos tasks.py de cada app Django
app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}') 