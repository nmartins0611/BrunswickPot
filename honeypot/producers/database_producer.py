"""
Database Producer
Stores honeypot events in local SQLite or PostgreSQL database for forensics analysis
"""

from typing import Dict, Any
import logging

from .base import BaseProducer, ProducerConnectionError, ProducerSendError
from ..database.persistence import DatabaseManager

logger = logging.getLogger(__name__)


class DatabaseProducer(BaseProducer):
    """Producer for persisting events to database"""

    def __init__(self, config: Dict[str, Any], honeypot_id: str = "honeypot-01"):
        """
        Initialize database producer

        Args:
            config: Database configuration dictionary
            honeypot_id: Identifier for this honeypot instance
        """
        super().__init__(config, producer_name="DatabaseProducer")

        self.honeypot_id = honeypot_id
        self.db_manager = None

        if self.enabled:
            try:
                self.db_manager = DatabaseManager(config)
                self.logger.info("Database producer initialized successfully")
            except Exception as e:
                self.logger.error(f"Failed to initialize database: {e}")
                raise ProducerConnectionError(f"Database initialization failed: {e}")

    def send(self, event: Dict[str, Any]) -> bool:
        """
        Store event in database

        Args:
            event: Event dictionary to store

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.enabled or not self.db_manager:
            return False

        try:
            event_id = self.db_manager.insert_event(event, self.honeypot_id)

            if event_id:
                self.logger.debug(f"Event stored in database: {event_id}")
                return True
            else:
                self.logger.warning("Failed to store event in database")
                return False

        except Exception as e:
            self.logger.error(f"Database send error: {e}")
            raise ProducerSendError(f"Failed to send to database: {e}")

    def health_check(self) -> bool:
        """
        Check database connectivity

        Returns:
            bool: True if database is accessible
        """
        if not self.enabled or not self.db_manager:
            return False

        try:
            # Try to count events as a health check
            count = self.db_manager.count_events()
            self.logger.debug(f"Database health check passed ({count} events)")
            return True
        except Exception as e:
            self.logger.error(f"Database health check failed: {e}")
            return False

    def close(self) -> None:
        """Close database connections"""
        if self.db_manager:
            self.db_manager.close()
            self.logger.info("Database connections closed")

    def get_recent_events(self, limit: int = 100, **filters) -> list:
        """
        Query recent events from database

        Args:
            limit: Maximum number of events to return
            **filters: Additional filters (service, source_ip, severity, etc.)

        Returns:
            List of event dictionaries
        """
        if not self.enabled or not self.db_manager:
            return []

        try:
            return self.db_manager.query_events(limit=limit, **filters)
        except Exception as e:
            self.logger.error(f"Failed to query events: {e}")
            return []

    def get_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get aggregate statistics from database

        Args:
            hours: Time window in hours

        Returns:
            Dictionary with statistics
        """
        if not self.enabled or not self.db_manager:
            return {}

        try:
            return self.db_manager.get_statistics(hours=hours)
        except Exception as e:
            self.logger.error(f"Failed to get statistics: {e}")
            return {}
