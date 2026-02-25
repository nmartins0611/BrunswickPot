"""
Database Persistence Manager
Handles database connections, CRUD operations, and retention policies
"""

from sqlalchemy import create_engine, and_, or_, desc, func, text
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.pool import StaticPool, QueuePool
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
import logging
import threading
import time
import os

from .models import Base, HoneypotEvent

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages database connections and operations"""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize database manager

        Args:
            config: Database configuration dictionary
        """
        self.config = config
        self.db_type = config.get('type', 'sqlite')
        self.retention_days = config.get('retention_days', 90)
        self.cleanup_interval_hours = config.get('cleanup_interval_hours', 24)

        # Create database engine
        self.engine = self._create_engine()

        # Create session factory
        self.Session = scoped_session(sessionmaker(bind=self.engine))

        # Create tables if they don't exist
        self._create_tables()

        # Start background cleanup task
        self._cleanup_thread = None
        if self.retention_days > 0:
            self._start_cleanup_task()

        logger.info(f"DatabaseManager initialized ({self.db_type})")

    def _create_engine(self):
        """Create SQLAlchemy engine based on configuration"""
        if self.db_type == 'sqlite':
            db_path = self.config.get('sqlite_path', '/var/lib/honeypot/events.db')

            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(db_path), exist_ok=True)

            # SQLite configuration
            engine = create_engine(
                f'sqlite:///{db_path}',
                connect_args={'check_same_thread': False},
                poolclass=StaticPool,
                echo=False
            )
            logger.info(f"Using SQLite database: {db_path}")

        elif self.db_type == 'postgresql':
            pg_config = self.config.get('postgresql', {})
            host = pg_config.get('host', 'localhost')
            port = pg_config.get('port', 5432)
            database = pg_config.get('database', 'honeypot')
            username = pg_config.get('username', 'honeypot_user')
            password = pg_config.get('password', '')
            pool_size = pg_config.get('pool_size', 5)

            # PostgreSQL configuration
            connection_string = f'postgresql://{username}:{password}@{host}:{port}/{database}'
            engine = create_engine(
                connection_string,
                poolclass=QueuePool,
                pool_size=pool_size,
                max_overflow=10,
                pool_pre_ping=True,  # Verify connections before using
                echo=False
            )
            logger.info(f"Using PostgreSQL database: {host}:{port}/{database}")

        else:
            raise ValueError(f"Unsupported database type: {self.db_type}")

        return engine

    def _create_tables(self):
        """Create database tables if they don't exist"""
        try:
            Base.metadata.create_all(self.engine)
            logger.info("Database tables created/verified")
        except Exception as e:
            logger.error(f"Failed to create tables: {e}")
            raise

    @contextmanager
    def get_session(self):
        """
        Context manager for database sessions

        Usage:
            with db_manager.get_session() as session:
                session.query(...)
        """
        session = self.Session()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error(f"Database session error: {e}")
            raise
        finally:
            session.close()

    def insert_event(self, event: Dict[str, Any], honeypot_id: str) -> Optional[str]:
        """
        Insert a honeypot event into the database

        Args:
            event: Event dictionary
            honeypot_id: ID of the honeypot instance

        Returns:
            str: Event ID if successful, None otherwise
        """
        try:
            with self.get_session() as session:
                event_model = HoneypotEvent.from_event(event, honeypot_id)
                session.add(event_model)
                session.flush()  # Get the ID before commit
                event_id = str(event_model.id)
                logger.debug(f"Inserted event {event_id}: {event.get('event_type')}")
                return event_id
        except Exception as e:
            logger.error(f"Failed to insert event: {e}")
            return None

    def query_events(
        self,
        limit: int = 100,
        offset: int = 0,
        service: Optional[str] = None,
        source_ip: Optional[str] = None,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        session_id: Optional[str] = None,
        hours: Optional[int] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """
        Query events with filters

        Args:
            limit: Maximum number of events to return
            offset: Number of events to skip
            service: Filter by service (ssh, smb, http, ldap)
            source_ip: Filter by source IP
            severity: Filter by severity (low, medium, high, critical)
            event_type: Filter by event type
            session_id: Filter by session ID
            hours: Return events from last N hours
            start_time: Filter by start time
            end_time: Filter by end time

        Returns:
            List of event dictionaries
        """
        try:
            with self.get_session() as session:
                query = session.query(HoneypotEvent)

                # Apply filters
                if service:
                    query = query.filter(HoneypotEvent.service == service)
                if source_ip:
                    query = query.filter(HoneypotEvent.source_ip == source_ip)
                if severity:
                    query = query.filter(HoneypotEvent.severity == severity)
                if event_type:
                    query = query.filter(HoneypotEvent.event_type == event_type)
                if session_id:
                    query = query.filter(HoneypotEvent.session_id == session_id)

                # Time-based filters
                if hours:
                    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
                    query = query.filter(HoneypotEvent.timestamp >= cutoff)
                if start_time:
                    query = query.filter(HoneypotEvent.timestamp >= start_time)
                if end_time:
                    query = query.filter(HoneypotEvent.timestamp <= end_time)

                # Order by timestamp descending (most recent first)
                query = query.order_by(desc(HoneypotEvent.timestamp))

                # Apply pagination
                query = query.limit(limit).offset(offset)

                # Execute and convert to dictionaries
                events = [event.to_dict() for event in query.all()]
                return events

        except Exception as e:
            logger.error(f"Failed to query events: {e}")
            return []

    def count_events(self, **filters) -> int:
        """Count events with optional filters"""
        try:
            with self.get_session() as session:
                query = session.query(func.count(HoneypotEvent.id))

                if filters.get('service'):
                    query = query.filter(HoneypotEvent.service == filters['service'])
                if filters.get('source_ip'):
                    query = query.filter(HoneypotEvent.source_ip == filters['source_ip'])
                if filters.get('hours'):
                    cutoff = datetime.now(timezone.utc) - timedelta(hours=filters['hours'])
                    query = query.filter(HoneypotEvent.timestamp >= cutoff)

                return query.scalar()
        except Exception as e:
            logger.error(f"Failed to count events: {e}")
            return 0

    def health_check(self) -> bool:
        """
        Check database connectivity and health

        Returns:
            bool: True if database is accessible and operational
        """
        try:
            # Try to execute a simple query
            with self.get_session() as session:
                session.execute(text("SELECT 1"))
            return True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False

    def get_statistics(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get aggregate statistics

        Args:
            hours: Time window in hours

        Returns:
            Dictionary with statistics
        """
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

            with self.get_session() as session:
                # Total events
                total = session.query(func.count(HoneypotEvent.id)).filter(
                    HoneypotEvent.timestamp >= cutoff
                ).scalar()

                # Events by service
                by_service = session.query(
                    HoneypotEvent.service,
                    func.count(HoneypotEvent.id)
                ).filter(
                    HoneypotEvent.timestamp >= cutoff
                ).group_by(HoneypotEvent.service).all()

                # Events by severity
                by_severity = session.query(
                    HoneypotEvent.severity,
                    func.count(HoneypotEvent.id)
                ).filter(
                    HoneypotEvent.timestamp >= cutoff
                ).group_by(HoneypotEvent.severity).all()

                # Top attackers
                top_attackers = session.query(
                    HoneypotEvent.source_ip,
                    func.count(HoneypotEvent.id).label('count')
                ).filter(
                    HoneypotEvent.timestamp >= cutoff
                ).group_by(HoneypotEvent.source_ip).order_by(
                    desc('count')
                ).limit(10).all()

                return {
                    'timeframe_hours': hours,
                    'total_events': total,
                    'by_service': dict(by_service),
                    'by_severity': dict(by_severity),
                    'top_attackers': [{'ip': ip, 'count': count} for ip, count in top_attackers]
                }

        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {}

    def cleanup_old_events(self) -> int:
        """
        Delete events older than retention_days

        Returns:
            int: Number of events deleted
        """
        if self.retention_days <= 0:
            logger.debug("Retention policy disabled (retention_days <= 0)")
            return 0

        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=self.retention_days)

            with self.get_session() as session:
                deleted_count = session.query(HoneypotEvent).filter(
                    HoneypotEvent.timestamp < cutoff
                ).delete()

                logger.info(f"Cleanup: Deleted {deleted_count} events older than {self.retention_days} days")
                return deleted_count

        except Exception as e:
            logger.error(f"Failed to cleanup old events: {e}")
            return 0

    def _cleanup_task(self):
        """Background task for periodic cleanup"""
        while self._cleanup_running:
            time.sleep(self.cleanup_interval_hours * 3600)
            self.cleanup_old_events()

    def _start_cleanup_task(self):
        """Start background cleanup thread"""
        self._cleanup_running = True
        self._cleanup_thread = threading.Thread(target=self._cleanup_task, daemon=True)
        self._cleanup_thread.start()
        logger.info(f"Cleanup task started (interval: {self.cleanup_interval_hours}h, retention: {self.retention_days}d)")

    def close(self):
        """Clean up resources"""
        # Stop cleanup task
        if self._cleanup_thread:
            self._cleanup_running = False

        # Close sessions
        self.Session.remove()

        # Dispose engine
        self.engine.dispose()

        logger.info("DatabaseManager closed")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
