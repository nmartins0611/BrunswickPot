"""
Elasticsearch Producer
Indexes honeypot events into Elasticsearch with daily index rotation
"""

from typing import Dict, Any, List
import logging
from datetime import datetime
from queue import Queue
from threading import Thread, Event
import time

try:
    from elasticsearch import Elasticsearch, helpers
    from elasticsearch.exceptions import ElasticsearchException
    ELASTICSEARCH_AVAILABLE = True
except ImportError:
    ELASTICSEARCH_AVAILABLE = False

from .base import BaseProducer, ProducerConnectionError, ProducerSendError

logger = logging.getLogger(__name__)


class ElasticsearchProducer(BaseProducer):
    """Producer for indexing events into Elasticsearch"""

    def __init__(self, config: Dict[str, Any], honeypot_id: str = "honeypot-01"):
        """
        Initialize Elasticsearch producer

        Args:
            config: Elasticsearch configuration dictionary
            honeypot_id: Identifier for this honeypot instance
        """
        super().__init__(config, producer_name="ElasticsearchProducer")

        if not ELASTICSEARCH_AVAILABLE:
            self.logger.error("elasticsearch library not available. Install with: pip install elasticsearch")
            self.enabled = False
            return

        self.honeypot_id = honeypot_id
        self.hosts = config.get('hosts', ['http://localhost:9200'])
        self.username = config.get('username')
        self.password = config.get('password')
        self.index_prefix = config.get('index_prefix', 'honeypot-events')
        self.use_ssl = config.get('use_ssl', False)
        self.verify_certs = config.get('verify_certs', True)
        self.ca_certs = config.get('ca_certs')
        self.timeout = config.get('timeout', 30)
        self.max_retries = config.get('max_retries', 3)
        self.bulk_size = config.get('bulk_size', 100)

        # Bulk indexing
        self.bulk_queue = Queue()
        self.bulk_thread = None
        self.stop_event = Event()

        # Statistics
        self.events_indexed = 0
        self.events_failed = 0

        self.es_client = None

        if self.enabled:
            try:
                self._initialize_client()
                self._create_index_template()
                self._start_bulk_thread()
                self.logger.info(f"Elasticsearch producer initialized (bulk_size={self.bulk_size})")
            except Exception as e:
                self.logger.error(f"Failed to initialize Elasticsearch: {e}")
                self.enabled = False

    def _initialize_client(self):
        """Initialize Elasticsearch client"""
        es_config = {
            'hosts': self.hosts,
            'timeout': self.timeout,
            'max_retries': self.max_retries,
            'retry_on_timeout': True
        }

        # Add authentication if configured
        if self.username and self.password:
            es_config['basic_auth'] = (self.username, self.password)

        # Add SSL configuration
        if self.use_ssl:
            es_config['use_ssl'] = True
            es_config['verify_certs'] = self.verify_certs
            if self.ca_certs:
                es_config['ca_certs'] = self.ca_certs

        self.es_client = Elasticsearch(**es_config)

        # Test connection
        if not self.es_client.ping():
            raise ProducerConnectionError("Failed to connect to Elasticsearch")

        self.logger.info(f"Connected to Elasticsearch: {self.hosts}")

    def _create_index_template(self):
        """Create index template for honeypot events"""
        template_name = f"{self.index_prefix}-template"

        template = {
            'index_patterns': [f"{self.index_prefix}-*"],
            'template': {
                'settings': {
                    'number_of_shards': 3,
                    'number_of_replicas': 1,
                    'refresh_interval': '5s'
                },
                'mappings': {
                    'properties': {
                        'timestamp': {'type': 'date'},
                        'honeypot_id': {'type': 'keyword'},
                        'service': {'type': 'keyword'},
                        'event_type': {'type': 'keyword'},
                        'severity': {'type': 'keyword'},
                        'source_ip': {'type': 'ip'},
                        'source_port': {'type': 'integer'},
                        'session_id': {'type': 'keyword'},
                        'user_agent': {'type': 'text'},
                        'username': {'type': 'keyword'},
                        'attack_type': {'type': 'keyword'},
                        'enrichment': {
                            'properties': {
                                'geoip': {
                                    'properties': {
                                        'country': {'type': 'keyword'},
                                        'city': {'type': 'keyword'},
                                        'location': {'type': 'geo_point'}
                                    }
                                },
                                'asn': {
                                    'properties': {
                                        'autonomous_system_number': {'type': 'integer'},
                                        'autonomous_system_organization': {'type': 'keyword'}
                                    }
                                },
                                'reputation': {
                                    'properties': {
                                        'abuse_confidence_score': {'type': 'integer'},
                                        'total_reports': {'type': 'integer'},
                                        'risk_level': {'type': 'keyword'}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        try:
            # Create or update template
            self.es_client.indices.put_index_template(name=template_name, body=template)
            self.logger.info(f"Created/updated Elasticsearch index template: {template_name}")
        except Exception as e:
            self.logger.warning(f"Failed to create index template: {e}")

    def send(self, event: Dict[str, Any]) -> bool:
        """
        Queue event for bulk indexing

        Args:
            event: Event dictionary to index

        Returns:
            bool: True if queued successfully
        """
        if not self.enabled or not self.es_client:
            return False

        try:
            # Prepare event for Elasticsearch
            es_event = self._prepare_event(event)

            # Add to bulk queue
            self.bulk_queue.put(es_event)

            return True

        except Exception as e:
            self.logger.error(f"Failed to queue event for Elasticsearch: {e}")
            return False

    def _prepare_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare event for Elasticsearch indexing

        Args:
            event: Original event dictionary

        Returns:
            Prepared event with index metadata
        """
        # Get current date for index name
        now = datetime.utcnow()
        index_name = f"{self.index_prefix}-{now.strftime('%Y.%m.%d')}"

        # Add geo_point for mapping if geoip enrichment exists
        if 'enrichment' in event and 'geoip' in event['enrichment']:
            geoip = event['enrichment']['geoip']
            if geoip.get('latitude') and geoip.get('longitude'):
                geoip['location'] = {
                    'lat': geoip['latitude'],
                    'lon': geoip['longitude']
                }

        return {
            '_index': index_name,
            '_source': event
        }

    def _start_bulk_thread(self):
        """Start background thread for bulk indexing"""
        self.bulk_thread = Thread(target=self._bulk_worker, daemon=True)
        self.bulk_thread.start()
        self.logger.debug("Bulk indexing thread started")

    def _bulk_worker(self):
        """Background worker that indexes events in bulk"""
        bulk_buffer = []

        while not self.stop_event.is_set():
            try:
                # Collect events for bulk indexing
                try:
                    event = self.bulk_queue.get(timeout=1)
                    bulk_buffer.append(event)
                except:
                    pass  # Timeout, no event available

                # Index when buffer reaches bulk_size or on timeout with pending events
                if len(bulk_buffer) >= self.bulk_size or (len(bulk_buffer) > 0 and self.bulk_queue.empty()):
                    self._bulk_index(bulk_buffer)
                    bulk_buffer = []

            except Exception as e:
                self.logger.error(f"Bulk worker error: {e}")

        # Flush remaining events on shutdown
        if bulk_buffer:
            self._bulk_index(bulk_buffer)

    def _bulk_index(self, events: List[Dict[str, Any]]):
        """
        Bulk index events to Elasticsearch

        Args:
            events: List of prepared events
        """
        if not events:
            return

        try:
            # Use bulk helper for efficient indexing
            success, failed = helpers.bulk(
                self.es_client,
                events,
                raise_on_error=False,
                raise_on_exception=False
            )

            self.events_indexed += success
            self.events_failed += len(failed) if isinstance(failed, list) else 0

            self.logger.debug(f"Bulk indexed {success} events to Elasticsearch")

            if failed:
                self.logger.warning(f"Failed to index {len(failed)} events")

        except Exception as e:
            self.events_failed += len(events)
            self.logger.error(f"Bulk indexing failed: {e}")

    def health_check(self) -> bool:
        """
        Check Elasticsearch cluster health

        Returns:
            bool: True if cluster is accessible
        """
        if not self.enabled or not self.es_client:
            return False

        try:
            health = self.es_client.cluster.health()
            status = health.get('status')
            is_healthy = status in ['green', 'yellow']
            self.logger.debug(f"Elasticsearch health check: {status}")
            return is_healthy

        except Exception as e:
            self.logger.error(f"Elasticsearch health check failed: {e}")
            return False

    def close(self):
        """Close producer and flush pending events"""
        if self.bulk_thread:
            self.logger.info("Flushing pending Elasticsearch events...")
            self.stop_event.set()
            self.bulk_thread.join(timeout=10)

        if self.es_client:
            self.es_client.close()

        self.logger.info(f"Elasticsearch producer closed (indexed={self.events_indexed}, failed={self.events_failed})")

    def get_stats(self) -> Dict[str, Any]:
        """Get producer statistics"""
        return {
            'events_indexed': self.events_indexed,
            'events_failed': self.events_failed,
            'queue_size': self.bulk_queue.qsize(),
            'bulk_size': self.bulk_size
        }
