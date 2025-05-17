from celery import shared_task
import logging

from .services import ReportService

logger = logging.getLogger(__name__)

@shared_task
def generate_scheduled_reports():
    """
    Tarefa Celery para processar todos os relatórios agendados pendentes
    """
    try:
        logger.info("Iniciando processamento de relatórios agendados")
        ReportService.process_scheduled_reports()
        logger.info("Processamento de relatórios agendados concluído")
        return True
    except Exception as e:
        logger.error(f"Erro durante o processamento de relatórios agendados: {str(e)}")
        return False 