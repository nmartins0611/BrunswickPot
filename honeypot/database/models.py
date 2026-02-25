"""
SQLAlchemy Database Models
Defines the schema for honeypot event storage
"""

from sqlalchemy import Column, String, Integer, DateTime, JSON, Index, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from datetime import datetime, timezone
import uuid

Base = declarative_base()


class HoneypotEvent(Base):
    """Model for storing honeypot events"""

    __tablename__ = 'honeypot_events'

    # Primary Key
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Event Metadata
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True, default=lambda: datetime.now(timezone.utc))
    honeypot_id = Column(String(255), nullable=False, index=True)
    service = Column(String(50), nullable=False, index=True)  # ssh, smb, http, ldap
    event_type = Column(String(100), nullable=False, index=True)  # ssh_auth_attempt, etc.
    severity = Column(String(20), nullable=False, index=True)  # low, medium, high, critical

    # Attacker Information
    source_ip = Column(String(45), nullable=False, index=True)  # IPv4 or IPv6
    source_port = Column(Integer, nullable=True)
    session_id = Column(String(50), nullable=True, index=True)

    # Event Data (JSON for flexibility)
    event_data = Column(JSON, nullable=False)  # Full event details
    enrichment_data = Column(JSON, nullable=True)  # GeoIP, reputation, ASN data

    # User-Agent / Client Information (if applicable)
    user_agent = Column(Text, nullable=True)
    attack_tool = Column(String(100), nullable=True, index=True)  # sqlmap, nmap, etc.

    # Extracted Credentials (if any)
    username = Column(String(255), nullable=True, index=True)
    credential_captured = Column(Integer, nullable=True, default=0)  # 0=no, 1=yes

    # Audit Fields
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Indexes for common queries
    __table_args__ = (
        # Composite indexes for time-series queries
        Index('ix_timestamp_service', 'timestamp', 'service'),
        Index('ix_source_ip_timestamp', 'source_ip', 'timestamp'),
        Index('ix_severity_timestamp', 'severity', 'timestamp'),
        Index('ix_session_id_timestamp', 'session_id', 'timestamp'),

        # Full-text search support (PostgreSQL specific, harmless for SQLite)
        # Index('ix_event_data_gin', 'event_data', postgresql_using='gin'),
    )

    def __repr__(self):
        return f"<HoneypotEvent(id={self.id}, service={self.service}, event_type={self.event_type}, source_ip={self.source_ip}, timestamp={self.timestamp})>"

    def to_dict(self):
        """Convert model to dictionary"""
        return {
            'id': str(self.id),
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'honeypot_id': self.honeypot_id,
            'service': self.service,
            'event_type': self.event_type,
            'severity': self.severity,
            'source_ip': self.source_ip,
            'source_port': self.source_port,
            'session_id': self.session_id,
            'event_data': self.event_data,
            'enrichment_data': self.enrichment_data,
            'user_agent': self.user_agent,
            'attack_tool': self.attack_tool,
            'username': self.username,
            'credential_captured': bool(self.credential_captured),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }

    @classmethod
    def from_event(cls, event: dict, honeypot_id: str):
        """
        Create HoneypotEvent from event dictionary

        Args:
            event: Event dictionary from honeypot service
            honeypot_id: ID of the honeypot instance

        Returns:
            HoneypotEvent instance
        """
        # Extract common fields
        timestamp_str = event.get('timestamp')
        if timestamp_str:
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            except:
                timestamp = datetime.now(timezone.utc)
        else:
            timestamp = datetime.now(timezone.utc)

        # Extract enrichment data if present
        enrichment_data = event.pop('enrichment', None)

        # Extract attacker session data
        attacker_session = event.pop('attacker_session', None)
        if attacker_session:
            # Store in event_data
            if 'event_data' not in event:
                event['event_data'] = {}
            event['event_data']['attacker_session'] = attacker_session

        # Create model instance
        return cls(
            timestamp=timestamp,
            honeypot_id=honeypot_id,
            service=event.get('service', 'unknown'),
            event_type=event.get('event_type', 'unknown'),
            severity=event.get('severity', 'low'),
            source_ip=event.get('source_ip', 'unknown'),
            source_port=event.get('source_port'),
            session_id=event.get('session_id'),
            event_data=event,  # Store full event
            enrichment_data=enrichment_data,
            user_agent=event.get('user_agent'),
            attack_tool=event.get('attack_tool', {}).get('tool') if isinstance(event.get('attack_tool'), dict) else event.get('attack_tool'),
            username=event.get('username') or event.get('credential_username') or event.get('attempted_username'),
            credential_captured=1 if event.get('credential_captured') else 0,
        )
