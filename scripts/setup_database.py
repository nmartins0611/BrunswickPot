#!/usr/bin/env python3
"""
Database Setup Script
Initializes the honeypot database schema and verifies connectivity
"""

import os
import sys
import yaml
import argparse

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from honeypot.database.persistence import DatabaseManager
from honeypot.database.models import Base


def load_config(config_file='honeypot_config.yaml'):
    """Load configuration from YAML file"""
    if not os.path.exists(config_file):
        print(f"Error: Config file '{config_file}' not found")
        sys.exit(1)

    with open(config_file, 'r') as f:
        return yaml.safe_load(f)


def setup_database(config_file='honeypot_config.yaml', verify_only=False):
    """
    Setup honeypot database

    Args:
        config_file: Path to configuration file
        verify_only: Only verify connection, don't create tables
    """
    print("=== Honeypot Database Setup ===\n")

    # Load configuration
    config = load_config(config_file)

    db_config = config.get('database', {})

    if not db_config.get('enabled'):
        print("Error: Database not enabled in configuration")
        print("Set 'database.enabled: true' in honeypot_config.yaml")
        sys.exit(1)

    db_type = db_config.get('type', 'sqlite')
    print(f"Database type: {db_type}")

    # Display configuration
    if db_type == 'sqlite':
        db_path = db_config.get('sqlite_path', '/var/lib/honeypot/events.db')
        print(f"Database path: {db_path}")

        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

    elif db_type == 'postgresql':
        pg_config = db_config.get('postgresql', {})
        host = pg_config.get('host', 'localhost')
        port = pg_config.get('port', 5432)
        database = pg_config.get('database', 'honeypot')
        username = pg_config.get('username', 'honeypot_user')

        print(f"PostgreSQL server: {host}:{port}")
        print(f"Database name: {database}")
        print(f"Username: {username}")

    print()

    # Initialize database manager
    try:
        print("Initializing database manager...")
        db_manager = DatabaseManager(db_config)
        print("✓ Database manager initialized")
    except Exception as e:
        print(f"✗ Failed to initialize database: {e}")
        sys.exit(1)

    # Verify connection
    try:
        print("Verifying database connection...")
        if db_manager.health_check():
            print("✓ Database connection verified")
        else:
            print("✗ Database health check failed")
            sys.exit(1)
    except Exception as e:
        print(f"✗ Connection verification failed: {e}")
        sys.exit(1)

    if verify_only:
        print("\nVerification complete!")
        db_manager.close()
        return

    # Test insert
    try:
        print("Testing event insertion...")
        test_event = {
            'event_type': 'test_event',
            'service': 'test',
            'severity': 'low',
            'source_ip': '127.0.0.1',
            'source_port': 12345
        }

        event_id = db_manager.insert_event(test_event, 'test-honeypot')

        if event_id:
            print(f"✓ Test event inserted successfully (ID: {event_id})")

            # Query it back
            events = db_manager.query_events(limit=1)
            if events:
                print(f"✓ Successfully queried event from database")
            else:
                print("⚠ Warning: Could not query inserted event")

        else:
            print("✗ Failed to insert test event")
            sys.exit(1)

    except Exception as e:
        print(f"✗ Test insertion failed: {e}")
        sys.exit(1)

    # Display statistics
    try:
        print("\nDatabase statistics:")
        count = db_manager.count_events()
        print(f"  Total events: {count}")

        if count > 0:
            stats = db_manager.get_statistics(hours=24)
            print(f"  Events (last 24h): {stats.get('total_events', 0)}")

    except Exception as e:
        print(f"Warning: Could not retrieve statistics: {e}")

    # Display retention policy
    retention_days = db_config.get('retention_days', 90)
    print(f"\nRetention policy: {retention_days} days")

    if retention_days > 0:
        print(f"Events older than {retention_days} days will be automatically deleted")
    else:
        print("Retention disabled - events will be kept indefinitely")

    # Close
    db_manager.close()

    print("\n✓ Database setup complete!")
    print("\nYou can now start the honeypot:")
    print("  python -m honeypot.main")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Setup and verify honeypot database",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Setup database with default config
  python scripts/setup_database.py

  # Verify existing database
  python scripts/setup_database.py --verify-only

  # Use custom config file
  python scripts/setup_database.py --config /path/to/config.yaml
        """
    )

    parser.add_argument(
        '--config',
        default='honeypot_config.yaml',
        help='Path to configuration file'
    )

    parser.add_argument(
        '--verify-only',
        action='store_true',
        help='Only verify database connection, don\'t create tables'
    )

    args = parser.parse_args()

    try:
        setup_database(args.config, args.verify_only)
    except KeyboardInterrupt:
        print("\n\nSetup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
