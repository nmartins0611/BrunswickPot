"""
Base Producer Abstract Class
All event producers (Kafka, Database, Splunk, Elasticsearch, Webhook) inherit from this class
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class BaseProducer(ABC):
    """Abstract base class for all event producers"""

    def __init__(self, config: Dict[str, Any], producer_name: str = "BaseProducer"):
        """
        Initialize the producer

        Args:
            config: Configuration dictionary for this producer
            producer_name: Name of the producer for logging
        """
        self.config = config
        self.producer_name = producer_name
        self.enabled = config.get('enabled', False)
        self.logger = logging.getLogger(f"{__name__}.{producer_name}")

        if self.enabled:
            self.logger.info(f"{producer_name} enabled")
        else:
            self.logger.debug(f"{producer_name} disabled")

    @abstractmethod
    def send(self, event: Dict[str, Any]) -> bool:
        """
        Send event to destination

        Args:
            event: Event dictionary to send

        Returns:
            bool: True if successful, False otherwise
        """
        pass

    @abstractmethod
    def close(self) -> None:
        """Clean up resources (close connections, flush buffers, etc.)"""
        pass

    @abstractmethod
    def health_check(self) -> bool:
        """
        Check if producer is healthy and ready to send events

        Returns:
            bool: True if healthy, False otherwise
        """
        pass

    def __enter__(self):
        """Context manager support"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager cleanup"""
        self.close()
        return False

    def __repr__(self) -> str:
        """String representation"""
        status = "enabled" if self.enabled else "disabled"
        return f"<{self.producer_name} ({status})>"


class ProducerError(Exception):
    """Base exception for producer errors"""
    pass


class ProducerConnectionError(ProducerError):
    """Raised when producer cannot connect to destination"""
    pass


class ProducerSendError(ProducerError):
    """Raised when producer fails to send event"""
    pass
