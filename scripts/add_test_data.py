#!/usr/bin/env python3
"""
Add test data to honeypot database for testing the TUI
"""

import sys
import os
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import random

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from honeypot.database.models import HoneypotEvent, Base

def create_test_events(db_path='./data/honeypot_events.db', num_events=50):
    """Create test honeypot events"""

    # Connect to database
    engine = create_engine(f'sqlite:///{db_path}')
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    # Test data
    services = ['ssh', 'http', 'smb', 'ldap']
    severities = ['low', 'medium', 'high', 'critical']
    event_types = {
        'ssh': ['ssh_auth_attempt', 'ssh_connection', 'ssh_command_executed'],
        'http': ['http_request', 'suspicious_path', 'sql_injection_attempt'],
        'smb': ['smb_connection', 'smb_share_access', 'smb_auth_attempt'],
        'ldap': ['ldap_bind_attempt', 'ldap_search', 'ldap_connection']
    }

    usernames = ['root', 'admin', 'user', 'test', 'ubuntu', 'administrator', 'guest', 'pi']
    ips = [
        '192.168.1.100', '10.0.0.50', '172.16.5.20', '203.0.113.45',
        '198.51.100.23', '45.33.32.156', '185.220.101.12', '91.134.15.89'
    ]

    countries = ['CN', 'RU', 'US', 'DE', 'FR', 'BR', 'IN', 'KR']
    cities = ['Beijing', 'Moscow', 'New York', 'Berlin', 'Paris', 'São Paulo', 'Mumbai', 'Seoul']
    risk_levels = ['low', 'medium', 'high', 'critical']

    print(f"Creating {num_events} test events...")

    for i in range(num_events):
        # Random timestamp within last 24 hours
        hours_ago = random.randint(0, 24)
        minutes_ago = random.randint(0, 59)
        timestamp = datetime.now(timezone.utc) - timedelta(hours=hours_ago, minutes=minutes_ago)

        # Random service and event type
        service = random.choice(services)
        event_type = random.choice(event_types[service])
        severity = random.choice(severities)

        # Random attacker info
        source_ip = random.choice(ips)
        source_port = random.randint(1024, 65535)
        username = random.choice(usernames)

        # Enrichment data
        country = random.choice(countries)
        city = random.choice(cities)
        risk_level = random.choice(risk_levels)
        abuse_score = random.randint(0, 100)

        enrichment_data = {
            'geoip': {
                'country': country,
                'city': city,
                'latitude': random.uniform(-90, 90),
                'longitude': random.uniform(-180, 180)
            },
            'reputation': {
                'risk_level': risk_level,
                'abuse_confidence_score': abuse_score
            },
            'asn': {
                'autonomous_system_number': random.randint(1000, 50000),
                'autonomous_system_organization': 'Test ISP'
            }
        }

        # Create event
        event_data = {
            'service': service,
            'event_type': event_type,
            'source_ip': source_ip,
            'source_port': source_port,
            'username': username,
            'severity': severity,
            'timestamp': timestamp.isoformat()
        }

        event = HoneypotEvent(
            timestamp=timestamp,
            honeypot_id='test-honeypot-01',
            service=service,
            event_type=event_type,
            severity=severity,
            source_ip=source_ip,
            source_port=source_port,
            session_id=f"sess_{i}",
            event_data=event_data,
            enrichment_data=enrichment_data,
            username=username,
            credential_captured=1 if random.random() > 0.7 else 0
        )

        session.add(event)

        if (i + 1) % 10 == 0:
            print(f"  Created {i + 1}/{num_events} events...")

    session.commit()
    session.close()

    print(f"✓ Successfully created {num_events} test events!")
    print(f"  Database: {db_path}")
    print(f"\nYou can now run the TUI dashboard:")
    print(f"  python gui/tui.py")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Add test data to honeypot database')
    parser.add_argument('--db', default='./data/honeypot_events.db', help='Database path')
    parser.add_argument('--count', type=int, default=50, help='Number of test events to create')
    args = parser.parse_args()

    create_test_events(args.db, args.count)
