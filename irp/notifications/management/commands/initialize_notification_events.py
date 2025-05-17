from django.core.management.base import BaseCommand
from irp.notifications.models import NotificationEvent

class Command(BaseCommand):
    help = 'Inicializa os tipos de eventos de notificação padrão no sistema'

    def handle(self, *args, **options):
        # Lista de eventos padrão do sistema
        default_events = [
            # Eventos de Alerta
            {
                'event_name': 'ALERT_CREATED',
                'description': 'Um novo alerta foi criado no sistema',
                'payload_schema': {
                    'alert': {
                        'alert_id': 'string',
                        'title': 'string',
                        'description': 'string',
                        'severity': 'string',
                        'status': 'string',
                        'source': 'string',
                    },
                    'organization': {
                        'organization_id': 'string',
                        'name': 'string'
                    }
                }
            },
            {
                'event_name': 'ALERT_UPDATED',
                'description': 'Um alerta foi atualizado',
                'payload_schema': {
                    'alert': {
                        'alert_id': 'string',
                        'title': 'string',
                        'description': 'string',
                        'severity': 'string',
                        'status': 'string',
                        'changes': 'object',
                    },
                    'organization': {
                        'organization_id': 'string',
                        'name': 'string'
                    }
                }
            },
            {
                'event_name': 'ALERT_STATUS_CHANGED',
                'description': 'O status de um alerta foi alterado',
                'payload_schema': {
                    'alert': {
                        'alert_id': 'string',
                        'title': 'string',
                        'old_status': 'string',
                        'new_status': 'string',
                    },
                    'organization': {
                        'organization_id': 'string',
                        'name': 'string'
                    }
                }
            },
            {
                'event_name': 'ALERT_SEVERITY_CHANGED',
                'description': 'A severidade de um alerta foi alterada',
                'payload_schema': {
                    'alert': {
                        'alert_id': 'string',
                        'title': 'string',
                        'old_severity': 'string',
                        'new_severity': 'string',
                    },
                    'organization': {
                        'organization_id': 'string',
                        'name': 'string'
                    }
                }
            },
            {
                'event_name': 'ALERT_ASSIGNED',
                'description': 'Um alerta foi atribuído a um usuário',
                'payload_schema': {
                    'alert': {
                        'alert_id': 'string',
                        'title': 'string',
                        'severity': 'string',
                        'assignee': 'string',
                    },
                    'organization': {
                        'organization_id': 'string',
                        'name': 'string'
                    }
                }
            },
            {
                'event_name': 'ALERT_ESCALATED_TO_CASE',
                'description': 'Um alerta foi escalado para um caso',
                'payload_schema': {
                    'alert': {
                        'alert_id': 'string',
                        'title': 'string',
                    },
                    'case': {
                        'case_id': 'string',
                        'title': 'string',
                    },
                    'organization': {
                        'organization_id': 'string',
                        'name': 'string'
                    }
                }
            },
            
            # Eventos de Caso
            {
                'event_name': 'CASE_CREATED',
                'description': 'Um novo caso foi criado no sistema',
                'payload_schema': {
                    'case': {
                        'case_id': 'string',
                        'title': 'string',
                        'description': 'string',
                        'severity': 'string',
                        'status': 'string',
                    },
                    'organization': {
                        'organization_id': 'string',
                        'name': 'string'
                    }
                }
            },
            {
                'event_name': 'CASE_UPDATED',
                'description': 'Um caso foi atualizado',
                'payload_schema': {
                    'case': {
                        'case_id': 'string',
                        'title': 'string',
                        'changes': 'object',
                    },
                    'organization': {
                        'organization_id': 'string',
                        'name': 'string'
                    }
                }
            },
            {
                'event_name': 'CASE_STATUS_CHANGED',
                'description': 'O status de um caso foi alterado',
                'payload_schema': {
                    'case': {
                        'case_id': 'string',
                        'title': 'string',
                        'old_status': 'string',
                        'new_status': 'string',
                    },
                    'organization': {
                        'organization_id': 'string',
                        'name': 'string'
                    }
                }
            },
            {
                'event_name': 'CASE_SEVERITY_CHANGED',
                'description': 'A severidade de um caso foi alterada',
                'payload_schema': {
                    'case': {
                        'case_id': 'string',
                        'title': 'string',
                        'old_severity': 'string',
                        'new_severity': 'string',
                    },
                    'organization': {
                        'organization_id': 'string',
                        'name': 'string'
                    }
                }
            },
            {
                'event_name': 'CASE_USER_ASSIGNED',
                'description': 'Um caso foi atribuído a um usuário',
                'payload_schema': {
                    'case': {
                        'case_id': 'string',
                        'title': 'string',
                        'severity': 'string',
                        'assignee': 'string',
                    },
                    'organization': {
                        'organization_id': 'string',
                        'name': 'string'
                    }
                }
            },
            {
                'event_name': 'CASE_CLOSED',
                'description': 'Um caso foi fechado',
                'payload_schema': {
                    'case': {
                        'case_id': 'string',
                        'title': 'string',
                        'resolution': 'string',
                    },
                    'organization': {
                        'organization_id': 'string',
                        'name': 'string'
                    }
                }
            },
            {
                'event_name': 'CASE_IMPORTANT_UPDATE',
                'description': 'Uma atualização importante foi feita em um caso',
                'payload_schema': {
                    'case': {
                        'case_id': 'string',
                        'title': 'string',
                    },
                    'event': {
                        'description': 'string',
                        'actor': 'string',
                    },
                    'organization': {
                        'organization_id': 'string',
                        'name': 'string'
                    }
                }
            },
            
            # Eventos de Tarefa
            {
                'event_name': 'TASK_CREATED',
                'description': 'Uma nova tarefa foi criada em um caso',
                'payload_schema': {
                    'task': {
                        'task_id': 'string',
                        'title': 'string',
                        'due_date': 'string',
                    },
                    'case': {
                        'case_id': 'string',
                        'title': 'string',
                    },
                    'organization': {
                        'organization_id': 'string',
                        'name': 'string'
                    }
                }
            },
            {
                'event_name': 'TASK_COMPLETED',
                'description': 'Uma tarefa foi concluída em um caso',
                'payload_schema': {
                    'task': {
                        'task_id': 'string',
                        'title': 'string',
                    },
                    'case': {
                        'case_id': 'string',
                        'title': 'string',
                    },
                    'organization': {
                        'organization_id': 'string',
                        'name': 'string'
                    }
                }
            },
            {
                'event_name': 'TASK_USER_ASSIGNED',
                'description': 'Uma tarefa foi atribuída a um usuário',
                'payload_schema': {
                    'task': {
                        'task_id': 'string',
                        'title': 'string',
                        'assignee': 'string',
                    },
                    'case': {
                        'case_id': 'string',
                        'title': 'string',
                    },
                    'organization': {
                        'organization_id': 'string',
                        'name': 'string'
                    }
                }
            },
            {
                'event_name': 'TASK_OVERDUE',
                'description': 'Uma tarefa está atrasada',
                'payload_schema': {
                    'task': {
                        'task_id': 'string',
                        'title': 'string',
                        'due_date': 'string',
                        'assignee': 'string',
                    },
                    'case': {
                        'case_id': 'string',
                        'title': 'string',
                    },
                    'organization': {
                        'organization_id': 'string',
                        'name': 'string'
                    }
                }
            },
            
            # Eventos de Observáveis
            {
                'event_name': 'OBSERVABLE_ADDED_TO_CASE',
                'description': 'Um observável importante foi adicionado a um caso',
                'payload_schema': {
                    'observable': {
                        'observable_id': 'string',
                        'value': 'string',
                        'type': 'string',
                    },
                    'case': {
                        'case_id': 'string',
                        'title': 'string',
                    },
                    'organization': {
                        'organization_id': 'string',
                        'name': 'string'
                    }
                }
            },
            
            # Eventos de MITRE ATT&CK
            {
                'event_name': 'MITRE_TECHNIQUE_ADDED_TO_CASE',
                'description': 'Uma técnica MITRE ATT&CK foi adicionada a um caso',
                'payload_schema': {
                    'technique': {
                        'technique_id': 'string',
                        'name': 'string',
                        'tactic': 'string',
                    },
                    'case': {
                        'case_id': 'string',
                        'title': 'string',
                    },
                    'organization': {
                        'organization_id': 'string',
                        'name': 'string'
                    }
                }
            },
            
            # Eventos de Comentários
            {
                'event_name': 'COMMENT_ADDED_TO_CASE',
                'description': 'Um comentário foi adicionado a um caso',
                'payload_schema': {
                    'comment': {
                        'comment_id': 'string',
                        'content': 'string',
                        'author': 'string',
                    },
                    'case': {
                        'case_id': 'string',
                        'title': 'string',
                    },
                    'organization': {
                        'organization_id': 'string',
                        'name': 'string'
                    }
                }
            },
            
            # Eventos de Relatórios
            {
                'event_name': 'REPORT_GENERATED',
                'description': 'Um relatório foi gerado para um caso',
                'payload_schema': {
                    'report': {
                        'report_id': 'string',
                        'type': 'string',
                        'generated_by': 'string',
                    },
                    'case': {
                        'case_id': 'string',
                        'title': 'string',
                    },
                    'organization': {
                        'organization_id': 'string',
                        'name': 'string'
                    }
                }
            },
            
            # Eventos de Sistema
            {
                'event_name': 'SYSTEM_HEALTH_ALERT',
                'description': 'Alerta sobre a saúde do sistema',
                'payload_schema': {
                    'severity': 'string',
                    'message': 'string',
                    'component': 'string',
                    'timestamp': 'string',
                }
            },
        ]
        
        # Contador de eventos criados/atualizados
        created_count = 0
        updated_count = 0
        
        # Processar cada evento da lista
        for event_data in default_events:
            event, created = NotificationEvent.objects.update_or_create(
                event_name=event_data['event_name'],
                defaults={
                    'description': event_data['description'],
                    'payload_schema': event_data.get('payload_schema', {})
                }
            )
            
            if created:
                created_count += 1
            else:
                updated_count += 1
        
        self.stdout.write(self.style.SUCCESS(
            f'Inicialização concluída: {created_count} eventos criados, {updated_count} eventos atualizados'
        )) 