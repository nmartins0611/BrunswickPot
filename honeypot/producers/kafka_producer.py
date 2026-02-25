"""
Kafka Producer
Sends honeypot events to Apache Kafka topics
Refactored from original nohoney.py implementation
"""

from typing import Dict, Any
import logging
import json

try:
    from kafka import KafkaProducer as KafkaClient
    from kafka.errors import KafkaError
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False

from .base import BaseProducer, ProducerConnectionError, ProducerSendError

logger = logging.getLogger(__name__)


class KafkaProducer(BaseProducer):
    """Producer for sending events to Kafka"""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Kafka producer

        Args:
            config: Kafka configuration dictionary
        """
        super().__init__(config, producer_name="KafkaProducer")

        if not KAFKA_AVAILABLE:
            self.logger.error("kafka-python library not available. Install with: pip install kafka-python")
            self.enabled = False
            return

        self.bootstrap_servers = config.get('bootstrap_servers', ['localhost:9092'])
        self.topic = config.get('topic', 'honeypot-events')
        self.ssl_enabled = config.get('ssl_enabled', False)
        self.sasl_mechanism = config.get('sasl_mechanism')
        self.sasl_username = config.get('sasl_username')
        self.sasl_password = config.get('sasl_password')

        self.producer = None

        if self.enabled:
            try:
                self._initialize_producer()
                self.logger.info(f"Kafka producer initialized (topic: {self.topic})")
            except Exception as e:
                self.logger.error(f"Failed to initialize Kafka producer: {e}")
                self.enabled = False

    def _initialize_producer(self):
        """Initialize Kafka producer client"""
        kafka_config = {
            'bootstrap_servers': self.bootstrap_servers,
            'value_serializer': lambda v: json.dumps(v).encode('utf-8'),
            'acks': 1,  # Wait for leader acknowledgment
            'retries': 3,
            'max_in_flight_requests_per_connection': 1
        }

        # Add SSL/SASL if configured
        if self.ssl_enabled:
            kafka_config['security_protocol'] = 'SASL_SSL'

        if self.sasl_mechanism:
            kafka_config['sasl_mechanism'] = self.sasl_mechanism
            kafka_config['sasl_plain_username'] = self.sasl_username or ''
            kafka_config['sasl_plain_password'] = self.sasl_password or ''

        try:
            self.producer = KafkaClient(**kafka_config)
            self.logger.info(f"Connected to Kafka: {self.bootstrap_servers}")
        except Exception as e:
            raise ProducerConnectionError(f"Failed to connect to Kafka: {e}")

    def send(self, event: Dict[str, Any]) -> bool:
        """
        Send event to Kafka topic

        Args:
            event: Event dictionary to send

        Returns:
            bool: True if sent successfully
        """
        if not self.enabled or not self.producer:
            return False

        try:
            # Send to Kafka (async)
            future = self.producer.send(self.topic, event)

            # Optional: Wait for confirmation (with timeout)
            # record_metadata = future.get(timeout=10)
            # self.logger.debug(f"Event sent to Kafka partition {record_metadata.partition}")

            return True

        except KafkaError as e:
            self.logger.error(f"Kafka send error: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error sending to Kafka: {e}")
            return False

    def health_check(self) -> bool:
        """
        Check Kafka connectivity

        Returns:
            bool: True if connected to Kafka
        """
        if not self.enabled or not self.producer:
            return False

        try:
            # Try to get cluster metadata as health check
            metadata = self.producer._metadata
            if metadata:
                self.logger.debug("Kafka health check passed")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Kafka health check failed: {e}")
            return False

    def close(self):
        """Close Kafka producer and flush pending messages"""
        if self.producer:
            try:
                self.logger.info("Flushing pending Kafka messages...")
                self.producer.flush(timeout=10)
                self.producer.close()
                self.logger.info("Kafka producer closed")
            except Exception as e:
                self.logger.error(f"Error closing Kafka producer: {e}")

    def flush(self, timeout: int = 10):
        """
        Flush pending messages

        Args:
            timeout: Flush timeout in seconds
        """
        if self.producer:
            self.producer.flush(timeout=timeout)
