import logging
import json
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any, Union

from django.conf import settings
from django.utils import timezone
from pymisp import PyMISP, MISPEvent, MISPAttribute, MISPObject, MISPTag

from irp.integrations.misp.models import (
    MISPInstance, MISPImport, MISPExport, ObservableMISPMapping,
    MISPTaxonomy, MISPTaxonomyEntry, CaseTaxonomyTag, AlertTaxonomyTag, ObservableTaxonomyTag
)
from irp.observables.models import Observable, ObservableType
from irp.cases.models import Case, CaseObservable, CaseMitreTechnique
from irp.alerts.models import Alert, AlertObservable
from irp.accounts.models import Organization
from irp.mitre.models import MitreTechnique
from irp.timeline.models import TimelineEvent

logger = logging.getLogger(__name__)

class MISPService:
    """
    Serviço para interagir com instâncias MISP
    """
    
    @staticmethod
    def get_misp_client(misp_instance: MISPInstance) -> PyMISP:
        """
        Cria um cliente PyMISP para uma instância MISP
        """
        try:
            return PyMISP(
                url=misp_instance.url,
                key=misp_instance.api_key,
                ssl=misp_instance.verify_ssl,
                timeout=60  # Timeout em segundos
            )
        except Exception as e:
            logger.error(f"Erro ao criar cliente MISP para {misp_instance.name}: {str(e)}")
            raise
    
    @staticmethod
    def test_connection(misp_instance: MISPInstance) -> Tuple[bool, str]:
        """
        Testa a conexão com uma instância MISP
        Retorna (sucesso, mensagem)
        """
        try:
            misp = MISPService.get_misp_client(misp_instance)
            result = misp.get_version()
            
            if 'version' in result:
                return True, f"Conexão bem-sucedida. Versão MISP: {result['version']}"
            else:
                return False, "Resposta recebida, mas formato inesperado."
                
        except Exception as e:
            logger.error(f"Erro ao testar conexão com MISP {misp_instance.name}: {str(e)}")
            return False, f"Erro de conexão: {str(e)}"
    
    @staticmethod
    def import_from_misp(
        misp_instance: MISPInstance,
        organization: Organization,
        from_timestamp: Optional[datetime] = None,
        filter_tags: Optional[List[str]] = None,
        create_alerts: bool = True,
        imported_by=None,
        import_taxonomies: bool = True  # Novo parâmetro para importar taxonomias
    ) -> MISPImport:
        """
        Importa eventos MISP para a plataforma
        """
        try:
            # Criar registro de importação
            misp_import = MISPImport.objects.create(
                misp_instance=misp_instance,
                organization=organization,
                imported_by=imported_by,
                status='PENDING'
            )
            
            # Estabelecer conexão com MISP
            misp = MISPService.get_misp_client(misp_instance)
            
            # Determinar from_timestamp
            if not from_timestamp and misp_instance.last_import_timestamp:
                from_timestamp = misp_instance.last_import_timestamp
            elif not from_timestamp:
                # Se não tiver timestamp, usa 30 dias atrás por default
                from_timestamp = timezone.now() - timezone.timedelta(days=30)
            
            # Converter timestamp para formato MISP
            timestamp = int(from_timestamp.timestamp())
            
            # Construir parâmetros de busca
            search_params = {"timestamp": timestamp, "published": True}
            
            if filter_tags or misp_instance.import_filter_tags:
                tags = filter_tags or misp_instance.import_filter_tags
                search_params["tags"] = tags
            
            # Buscar eventos
            logger.info(f"Buscando eventos MISP desde {from_timestamp}")
            events = misp.search(controller='events', return_format='json', **search_params)
            
            if not events or 'response' not in events or not events['response']:
                logger.info(f"Nenhum evento encontrado para importação")
                misp_import.status = 'SUCCESS'
                misp_import.save()
                # Atualizar timestamp de última importação mesmo que não haja eventos
                misp_instance.last_import_timestamp = timezone.now()
                misp_instance.save()
                return misp_import
            
            # Processar eventos
            imported_events_count = 0
            imported_attributes_count = 0
            created_alerts_count = 0
            created_observables_count = 0
            updated_observables_count = 0
            imported_tags_count = 0  # Contador de tags importadas
            
            for event_data in events['response']:
                try:
                    event = event_data['Event']
                    misp_event_uuid = event['uuid']
                    
                    # Processar evento
                    if create_alerts:
                        # Criar alerta baseado no evento
                        alert_data = {
                            'title': event['info'],
                            'description': f"Importado do MISP (ID: {event['id']})\n\n" + 
                                          (event.get('analysis', '') or 'Sem análise disponível'),
                            'source': f"MISP ({misp_instance.name})",
                            'organization': organization,
                            'external_reference': misp_event_uuid
                        }
                        
                        # Mapear severidade
                        threat_level = event.get('threat_level_id')
                        if threat_level:
                            if threat_level == '1':  # High
                                alert_data['severity_id'] = organization.alert_severities.get(name='High').id
                            elif threat_level == '2':  # Medium
                                alert_data['severity_id'] = organization.alert_severities.get(name='Medium').id
                            else:  # Low ou Undefined
                                alert_data['severity_id'] = organization.alert_severities.get(name='Low').id
                        
                        # Criar o alerta
                        from irp.alerts.serializers import AlertSerializer
                        serializer = AlertSerializer(data=alert_data)
                        if serializer.is_valid():
                            alert = serializer.save()
                            created_alerts_count += 1
                            
                            # Processar tags do evento
                            if import_taxonomies and 'Tag' in event:
                                for tag in event.get('Tag', []):
                                    MISPService._process_tag_for_entity(
                                        tag_name=tag.get('name', ''),
                                        entity=alert,
                                        entity_type='alert',
                                        user=imported_by
                                    )
                                    imported_tags_count += 1
                        else:
                            logger.error(f"Erro ao criar alerta do evento MISP {misp_event_uuid}: {serializer.errors}")
                            continue
                    
                    # Processar atributos
                    if 'Attribute' in event:
                        for attribute in event['Attribute']:
                            try:
                                # Mapear tipo de observável
                                obs_type = MISPService._map_misp_attribute_to_observable_type(attribute['type'])
                                if not obs_type:
                                    continue
                                
                                # Verificar se já existe
                                observable, created = Observable.objects.get_or_create(
                                    value=attribute['value'],
                                    type=obs_type,
                                    defaults={
                                        'is_ioc': attribute.get('to_ids', False),
                                        'organization': organization,
                                        'description': attribute.get('comment', '') or 'Importado do MISP',
                                        'source': f"MISP ({misp_instance.name})"
                                    }
                                )
                                
                                if created:
                                    created_observables_count += 1
                                else:
                                    observable.is_ioc = observable.is_ioc or attribute.get('to_ids', False)
                                    observable.save()
                                    updated_observables_count += 1
                                
                                # Criar mapeamento MISP-Observable
                                ObservableMISPMapping.objects.update_or_create(
                                    observable=observable,
                                    misp_instance=misp_instance,
                                    misp_attribute_uuid=attribute['uuid'],
                                    defaults={'misp_event_uuid': misp_event_uuid}
                                )
                                
                                # Processar tags do atributo
                                if import_taxonomies and 'Tag' in attribute:
                                    for tag in attribute.get('Tag', []):
                                        MISPService._process_tag_for_entity(
                                            tag_name=tag.get('name', ''),
                                            entity=observable,
                                            entity_type='observable',
                                            user=imported_by
                                        )
                                        imported_tags_count += 1
                                
                                # Associar ao alerta se criado
                                if create_alerts and 'alert' in locals():
                                    AlertObservable.objects.create(
                                        alert=alert,
                                        observable=observable
                                    )
                                
                                imported_attributes_count += 1
                                
                            except Exception as attr_error:
                                logger.error(f"Erro ao processar atributo MISP {attribute.get('uuid', 'N/A')}: {str(attr_error)}")
                    
                    imported_events_count += 1
                    
                except Exception as event_error:
                    logger.error(f"Erro ao processar evento MISP {event_data.get('Event', {}).get('uuid', 'N/A')}: {str(event_error)}")
            
            # Atualizar registro de importação
            misp_import.status = 'SUCCESS'
            misp_import.imported_events_count = imported_events_count
            misp_import.imported_attributes_count = imported_attributes_count
            misp_import.created_alerts_count = created_alerts_count
            misp_import.created_observables_count = created_observables_count
            misp_import.updated_observables_count = updated_observables_count
            misp_import.save()
            
            # Atualizar timestamp de última importação
            misp_instance.last_import_timestamp = timezone.now()
            misp_instance.save()
            
            logger.info(f"Importação MISP concluída: {imported_events_count} eventos, {imported_attributes_count} atributos, {created_alerts_count} alertas, {created_observables_count} observáveis criados, {updated_observables_count} observáveis atualizados, {imported_tags_count} tags importadas")
            
            return misp_import
            
        except Exception as e:
            logger.error(f"Erro durante importação MISP: {str(e)}")
            if 'misp_import' in locals():
                misp_import.status = 'FAILURE'
                misp_import.error_message = str(e)
                misp_import.save()
                return misp_import
            raise
    
    @staticmethod
    def _process_tag_for_entity(tag_name: str, entity, entity_type: str, user=None):
        """
        Processa uma tag MISP para uma entidade (alerta, caso ou observável)
        
        Args:
            tag_name: Nome da tag no formato namespace:predicate="value"
            entity: Objeto de alerta, caso ou observável
            entity_type: Tipo de entidade ("alert", "case" ou "observable")
            user: Usuário que está realizando a importação
        """
        # Verificar se a tag corresponde a uma taxonomia
        tag_parts = tag_name.split(':', 1)
        if len(tag_parts) != 2:
            return False  # Não é uma tag de taxonomia
        
        namespace = tag_parts[0]
        predicate_value = tag_parts[1]
        
        # Extrair valor, se presente
        if '=' in predicate_value:
            predicate, value = predicate_value.split('=', 1)
            # Remover aspas do valor
            value = value.strip('"')
        else:
            predicate = predicate_value
            value = ''
        
        # Verificar se a taxonomia existe
        try:
            taxonomies = MISPTaxonomy.objects.filter(
                namespace=namespace, 
                enabled_for_platform=True
            )
            
            if not taxonomies.exists():
                return False
            
            # Procurar a entrada correspondente
            for taxonomy in taxonomies:
                try:
                    entry = MISPTaxonomyEntry.objects.get(
                        taxonomy=taxonomy,
                        predicate=predicate,
                        value=value
                    )
                    
                    # Associar a tag à entidade
                    if entity_type == 'alert':
                        AlertTaxonomyTag.objects.update_or_create(
                            alert=entity,
                            taxonomy_entry=entry,
                            defaults={'linked_by': user}
                        )
                    elif entity_type == 'case':
                        CaseTaxonomyTag.objects.update_or_create(
                            case=entity,
                            taxonomy_entry=entry,
                            defaults={'linked_by': user}
                        )
                    elif entity_type == 'observable':
                        ObservableTaxonomyTag.objects.update_or_create(
                            observable=entity,
                            taxonomy_entry=entry,
                            defaults={'linked_by': user}
                        )
                    
                    return True
                    
                except MISPTaxonomyEntry.DoesNotExist:
                    continue
            
            return False
            
        except Exception as e:
            logger.error(f"Erro ao processar tag {tag_name} para {entity_type}: {str(e)}")
            return False
    
    @staticmethod
    def export_case_to_misp(
        case: Case,
        misp_instance: MISPInstance,
        include_observables: bool = True,
        include_timeline: bool = False,
        include_mitre_techniques: bool = True,
        distribution: Optional[int] = None,
        threat_level: Optional[int] = None,
        analysis: Optional[int] = None,
        additional_tags: Optional[List[str]] = None,
        exported_by=None
    ) -> MISPExport:
        """
        Exporta um caso para o MISP como um novo evento
        """
        # Definir valores padrão se não fornecidos
        distribution = distribution if distribution is not None else misp_instance.default_distribution
        threat_level = threat_level if threat_level is not None else misp_instance.default_threat_level
        analysis = analysis if analysis is not None else misp_instance.default_analysis
        
        # Criar registro de exportação
        misp_export = MISPExport.objects.create(
            misp_instance=misp_instance,
            case=case,
            misp_event_uuid=uuid.uuid4(),  # Temporário até receber o UUID real do MISP
            exported_by=exported_by,
            status='PENDING'
        )
        
        try:
            # Conectar ao MISP
            misp = MISPService.get_misp_client(misp_instance)
            
            # Criar evento MISP
            event = MISPEvent()
            event.info = case.title
            event.distribution = distribution
            event.threat_level_id = threat_level
            event.analysis = analysis
            
            # Adicionar descrição como atributo de texto
            if case.description:
                event.add_attribute('comment', case.description)
            
            # Adicionar tags
            tags = []
            if misp_instance.export_default_tags:
                tags.extend(misp_instance.export_default_tags)
            if additional_tags:
                tags.extend(additional_tags)
                
            # Adicionar tags específicas da plataforma
            tags.append(f'tlp:{case.tlp_level.name.lower()}' if case.tlp_level else 'tlp:amber')
            tags.append(f'severity:{case.severity.name.lower()}' if case.severity else 'severity:medium')
            tags.append(f'status:{case.status.name.lower()}' if case.status else 'status:open')
            
            # Adicionar tags de taxonomia do caso
            case_taxonomy_tags = CaseTaxonomyTag.objects.filter(case=case).select_related('taxonomy_entry')
            for case_tag in case_taxonomy_tags:
                tags.append(case_tag.taxonomy_entry.tag_name)
            
            # Adicionar tags MISP
            for tag in tags:
                event.add_tag(tag)
            
            # Adicionar observáveis como atributos
            exported_observables_count = 0
            if include_observables:
                observables = CaseObservable.objects.filter(case=case)
                for case_obs in observables:
                    observable = case_obs.observable
                    if observable:
                        # Mapear tipo para formato MISP
                        misp_type, misp_category = MISPService._map_observable_type_to_misp_attribute(observable.type)
                        if misp_type:
                            # Adicionat atributo
                            attribute = event.add_attribute(
                                type=misp_type,
                                value=observable.value,
                                category=misp_category,
                                to_ids=observable.is_ioc,
                                comment=observable.description,
                                distribution=distribution
                            )
                            
                            # Adicionar tags específicas do observável, se houver
                            if observable.tags:
                                for tag in observable.tags:
                                    attribute.add_tag(tag)
                            
                            # Adicionar tags de taxonomia do observável
                            obs_taxonomy_tags = ObservableTaxonomyTag.objects.filter(observable=observable).select_related('taxonomy_entry')
                            for obs_tag in obs_taxonomy_tags:
                                attribute.add_tag(obs_tag.taxonomy_entry.tag_name)
                                    
                            exported_observables_count += 1
            
            # Adicionar técnicas MITRE ATT&CK
            if include_mitre_techniques:
                mitre_techniques = CaseMitreTechnique.objects.select_related('technique').filter(case=case)
                for case_technique in mitre_techniques:
                    technique = case_technique.technique
                    galaxy_name = "mitre-attack-pattern"
                    tag = f'misp-galaxy:{galaxy_name}="{technique.technique_id} - {technique.name}"'
                    event.add_tag(tag)
            
            # Adicionar eventos da timeline
            if include_timeline:
                timeline_events = TimelineEvent.objects.filter(case=case)
                for timeline_event in timeline_events:
                    event.add_attribute(
                        type='comment',
                        value=f"[{timeline_event.event_time}] {timeline_event.event_type}: {timeline_event.description}",
                        category='Other',
                        comment='Timeline Event'
                    )
            
            # Enviar o evento para o MISP
            result = misp.add_event(event)
            
            # Verificar resultado
            if 'errors' in result:
                misp_export.status = 'FAILURE'
                misp_export.error_message = str(result['errors'])
            else:
                # Atualizar com o UUID real
                misp_event_uuid = result['Event']['uuid']
                misp_export.misp_event_uuid = misp_event_uuid
                misp_export.status = 'SUCCESS'
                misp_export.exported_observables_count = exported_observables_count
            
            misp_export.save()
            return misp_export
            
        except Exception as e:
            # Registrar erro
            misp_export.status = 'FAILURE'
            misp_export.error_message = str(e)
            misp_export.save()
            logger.error(f"Erro ao exportar caso {case.case_id} para MISP: {str(e)}")
            return misp_export
    
    @staticmethod
    def _map_misp_attribute_to_observable_type(misp_type: str) -> Optional[ObservableType]:
        """
        Mapeia um tipo de atributo MISP para um tipo de observável da plataforma
        """
        mapping = {
            'ip-src': 'IP Address',
            'ip-dst': 'IP Address',
            'hostname': 'Domain',
            'domain': 'Domain',
            'url': 'URL',
            'md5': 'MD5',
            'sha1': 'SHA1',
            'sha256': 'SHA256',
            'email-src': 'Email',
            'email-dst': 'Email',
            'filename': 'Filename',
        }
        
        observable_type_name = mapping.get(misp_type)
        if not observable_type_name:
            return None
            
        try:
            return ObservableType.objects.get(name=observable_type_name)
        except ObservableType.DoesNotExist:
            logger.warning(f"Tipo de observável '{observable_type_name}' não encontrado")
            return None
    
    @staticmethod
    def _map_observable_type_to_misp_attribute(observable_type: ObservableType) -> Tuple[str, str]:
        """
        Mapeia um tipo de observável da plataforma para um tipo e categoria de atributo MISP
        Retorna (tipo, categoria)
        """
        mapping = {
            'IP Address': ('ip-dst', 'Network activity'),
            'Domain': ('domain', 'Network activity'),
            'URL': ('url', 'Network activity'),
            'MD5': ('md5', 'Payload delivery'),
            'SHA1': ('sha1', 'Payload delivery'),
            'SHA256': ('sha256', 'Payload delivery'),
            'Email': ('email', 'Network activity'),
            'Filename': ('filename', 'Payload delivery')
        }
        
        return mapping.get(observable_type.name, (None, None))
    
    @staticmethod
    def get_taxonomies(misp_instance: MISPInstance) -> List[Dict]:
        """
        Obtém a lista de taxonomias disponíveis na instância MISP
        """
        try:
            misp = MISPService.get_misp_client(misp_instance)
            result = misp.taxonomies()
            
            if not result or 'errors' in result:
                logger.error(f"Erro ao obter taxonomias do MISP {misp_instance.name}: {result.get('errors', 'Resposta vazia')}")
                return []
            
            return result['Taxonomy'] if 'Taxonomy' in result else []
        except Exception as e:
            logger.error(f"Erro ao obter taxonomias do MISP {misp_instance.name}: {str(e)}")
            return []
    
    @staticmethod
    def get_taxonomy_details(misp_instance: MISPInstance, namespace: str) -> Dict:
        """
        Obtém detalhes de uma taxonomia específica, incluindo predicados e valores
        """
        try:
            misp = MISPService.get_misp_client(misp_instance)
            result = misp.taxonomy_details(namespace)
            
            if not result or 'errors' in result:
                logger.error(f"Erro ao obter detalhes da taxonomia {namespace} do MISP {misp_instance.name}: {result.get('errors', 'Resposta vazia')}")
                return {}
            
            return result
        except Exception as e:
            logger.error(f"Erro ao obter detalhes da taxonomia {namespace} do MISP {misp_instance.name}: {str(e)}")
            return {}
    
    @staticmethod
    def sync_taxonomies(misp_instance: MISPInstance, force_update: bool = False) -> Dict:
        """
        Sincroniza taxonomias do MISP com a plataforma
        
        Args:
            misp_instance: Instância MISP para sincronização
            force_update: Se True, atualiza todas as taxonomias, 
                         ignorando o timestamp da última sincronização
        
        Returns:
            Dict com estatísticas da sincronização
        """
        if not misp_instance.import_taxonomies:
            logger.info(f"Sincronização de taxonomias desabilitada para {misp_instance.name}")
            return {
                'success': True,
                'message': 'Sincronização de taxonomias desabilitada para esta instância',
                'taxonomies_created': 0,
                'taxonomies_updated': 0,
                'entries_created': 0,
                'entries_updated': 0
            }
        
        stats = {
            'taxonomies_created': 0,
            'taxonomies_updated': 0,
            'entries_created': 0,
            'entries_updated': 0
        }
        
        try:
            # Obter taxonomias disponíveis
            taxonomies = MISPService.get_taxonomies(misp_instance)
            if not taxonomies:
                return {
                    'success': False,
                    'message': 'Nenhuma taxonomia encontrada na instância MISP',
                    **stats
                }
            
            # Processar cada taxonomia
            for taxonomy_data in taxonomies:
                namespace = taxonomy_data.get('namespace')
                if not namespace:
                    continue
                
                # Obter ou criar taxonomia
                taxonomy, created = MISPTaxonomy.objects.update_or_create(
                    misp_instance=misp_instance,
                    namespace=namespace,
                    defaults={
                        'description': taxonomy_data.get('description', ''),
                        'version': int(taxonomy_data.get('version', 1))
                    }
                )
                
                if created:
                    stats['taxonomies_created'] += 1
                else:
                    stats['taxonomies_updated'] += 1
                
                # Obter detalhes da taxonomia com predicados e valores
                taxonomy_details = MISPService.get_taxonomy_details(misp_instance, namespace)
                if not taxonomy_details:
                    continue
                
                # Processar predicados e valores
                for predicate_data in taxonomy_details.get('values', []):
                    predicate = predicate_data.get('predicate')
                    if not predicate:
                        continue
                    
                    # Processar valores do predicado (se existirem)
                    if 'expanded' in predicate_data and predicate_data.get('values'):
                        for value_data in predicate_data.get('values', []):
                            value = value_data.get('value', '')
                            entry, entry_created = MISPTaxonomyEntry.objects.update_or_create(
                                taxonomy=taxonomy,
                                predicate=predicate,
                                value=value,
                                defaults={
                                    'description_expanded': value_data.get('expanded', '')
                                }
                            )
                            
                            if entry_created:
                                stats['entries_created'] += 1
                            else:
                                stats['entries_updated'] += 1
                    else:
                        # Predicado sem valores específicos
                        entry, entry_created = MISPTaxonomyEntry.objects.update_or_create(
                            taxonomy=taxonomy,
                            predicate=predicate,
                            value='',
                            defaults={
                                'description_expanded': predicate_data.get('expanded', '')
                            }
                        )
                        
                        if entry_created:
                            stats['entries_created'] += 1
                        else:
                            stats['entries_updated'] += 1
            
            # Atualizar timestamp da última sincronização
            misp_instance.last_taxonomy_sync_timestamp = timezone.now()
            misp_instance.save()
            
            return {
                'success': True,
                'message': f"Sincronização concluída: {stats['taxonomies_created']} taxonomias criadas, {stats['taxonomies_updated']} atualizadas, {stats['entries_created']} entradas criadas, {stats['entries_updated']} atualizadas",
                **stats
            }
            
        except Exception as e:
            logger.error(f"Erro durante sincronização de taxonomias para {misp_instance.name}: {str(e)}")
            return {
                'success': False,
                'message': f"Erro durante sincronização: {str(e)}",
                **stats
            }
    
    @staticmethod
    def add_tag_to_misp_event(misp: PyMISP, event_uuid: str, tag_name: str) -> bool:
        """
        Adiciona uma tag a um evento MISP
        """
        try:
            result = misp.tag(event_uuid, tag_name)
            return bool(result and not result.get('errors'))
        except Exception as e:
            logger.error(f"Erro ao adicionar tag {tag_name} ao evento {event_uuid}: {str(e)}")
            return False
    
    @staticmethod
    def add_tag_to_misp_attribute(misp: PyMISP, attribute_uuid: str, tag_name: str) -> bool:
        """
        Adiciona uma tag a um atributo MISP
        """
        try:
            result = misp.tag(attribute_uuid, tag_name)
            return bool(result and not result.get('errors'))
        except Exception as e:
            logger.error(f"Erro ao adicionar tag {tag_name} ao atributo {attribute_uuid}: {str(e)}")
            return False 