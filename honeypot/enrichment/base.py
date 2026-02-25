"""
Base Enricher Abstract Class
All enrichers inherit from this class
"""

from abc import ABC, abstractmethod
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


class BaseEnricher(ABC):
    """Abstract base class for all enrichers"""

    def __init__(self, config: Dict[str, Any], enricher_name: str = "BaseEnricher"):
        """
        Initialize enricher

        Args:
            config: Configuration dictionary for this enricher
            enricher_name: Name of the enricher for logging
        """
        self.config = config
        self.enricher_name = enricher_name
        self.enabled = config.get('enabled', False)
        self.logger = logging.getLogger(f"{__name__}.{enricher_name}")

        if self.enabled:
            self.logger.info(f"{enricher_name} enabled")
        else:
            self.logger.debug(f"{enricher_name} disabled")

    @abstractmethod
    def enrich(self, ip: str) -> Dict[str, Any]:
        """
        Enrich IP address with threat intelligence

        Args:
            ip: IP address to enrich

        Returns:
            Dictionary with enrichment data
        """
        pass

    def __repr__(self) -> str:
        """String representation"""
        status = "enabled" if self.enabled else "disabled"
        return f"<{self.enricher_name} ({status})>"
