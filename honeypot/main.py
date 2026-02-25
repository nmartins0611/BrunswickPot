#!/usr/bin/env python3
"""
BrunswickPot - Enhanced Multi-Service Honeypot System
Main application entry point that orchestrates all services and producers
"""

import os
import sys
import threading
import logging
import signal
import yaml
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
import hashlib
import socket

# Import existing components from nohoney.py (copied inline for now)
# These will be refactored into modules later
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import new modular components
from honeypot.producers.base import BaseProducer
from honeypot.producers.kafka_producer import KafkaProducer
from honeypot.producers.webhook_producer import WebhookProducer
from honeypot.producers.database_producer import DatabaseProducer
from honeypot.producers.splunk_producer import SplunkHECProducer
from honeypot.producers.elasticsearch_producer import ElasticsearchProducer
from honeypot.services.ssh import SSHHoneypot
from honeypot.enrichment.enrichment_manager import EnrichmentManager

logger = logging.getLogger(__name__)


def load_config(config_file='honeypot_config.yaml'):
    """Load configuration from YAML file"""
    if not os.path.exists(config_file):
        logger.error(f"Config file '{config_file}' not found")
        sys.exit(1)

    with open(config_file, 'r') as f:
        return yaml.safe_load(f)


class AttackerProfiler:
    """Extracts and profiles attacker information"""

    @staticmethod
    def extract_attacker_info(request_data, client_address):
        """Extract comprehensive attacker information"""
        info = {
            'source_ip': client_address[0],
            'source_port': client_address[1],
            'reverse_dns': AttackerProfiler.get_reverse_dns(client_address[0]),
            'session_id': AttackerProfiler.generate_session_id(client_address[0]),
        }
        return info

    @staticmethod
    def get_reverse_dns(ip):
        """Attempt reverse DNS lookup"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None

    @staticmethod
    def generate_session_id(ip):
        """Generate unique session ID for tracking attacker across services"""
        return hashlib.md5(f"{ip}-{datetime.now(timezone.utc).date()}".encode()).hexdigest()[:12]


class EventReporter:
    """Enhanced event reporter with multiple producers and enrichment"""

    def __init__(self, config):
        """Initialize event reporter with all enabled producers"""
        self.config = config
        self.honeypot_id = config['general']['honeypot_name']
        self.producers = []
        self.attacker_sessions = {}  # Track attacker sessions

        # Initialize enrichment manager
        enrichment_config = config.get('enrichment', {})
        self.enrichment_manager = None
        if enrichment_config.get('enabled'):
            try:
                self.enrichment_manager = EnrichmentManager(enrichment_config)
                logger.info("Enrichment manager initialized")
            except Exception as e:
                logger.error(f"Failed to initialize enrichment manager: {e}")

        # Initialize all enabled producers
        self._initialize_producers()

        logger.info(f"EventReporter initialized with {len(self.producers)} producers")

    def _initialize_producers(self):
        """Initialize all enabled event producers"""

        # Kafka Producer
        if self.config.get('kafka', {}).get('enabled'):
            try:
                producer = KafkaProducer(self.config['kafka'])
                if producer.enabled:
                    self.producers.append(producer)
            except Exception as e:
                logger.error(f"Failed to initialize Kafka producer: {e}")

        # Database Producer
        if self.config.get('database', {}).get('enabled'):
            try:
                producer = DatabaseProducer(self.config['database'], self.honeypot_id)
                if producer.enabled:
                    self.producers.append(producer)
            except Exception as e:
                logger.error(f"Failed to initialize Database producer: {e}")

        # Splunk Producer
        if self.config.get('splunk', {}).get('enabled'):
            try:
                producer = SplunkHECProducer(self.config['splunk'], self.honeypot_id)
                if producer.enabled:
                    self.producers.append(producer)
            except Exception as e:
                logger.error(f"Failed to initialize Splunk producer: {e}")

        # Elasticsearch Producer
        if self.config.get('elasticsearch', {}).get('enabled'):
            try:
                producer = ElasticsearchProducer(self.config['elasticsearch'], self.honeypot_id)
                if producer.enabled:
                    self.producers.append(producer)
            except Exception as e:
                logger.error(f"Failed to initialize Elasticsearch producer: {e}")

        # Webhook Producer
        if self.config.get('webhook', {}).get('enabled'):
            try:
                producer = WebhookProducer(self.config['webhook'])
                if producer.enabled:
                    self.producers.append(producer)
            except Exception as e:
                logger.error(f"Failed to initialize Webhook producer: {e}")

    def track_attacker_session(self, source_ip, event_type):
        """Track attacker activity across sessions"""
        if source_ip not in self.attacker_sessions:
            self.attacker_sessions[source_ip] = {
                'first_seen': datetime.now(timezone.utc).isoformat(),
                'event_count': 0,
                'event_types': [],
            }

        session = self.attacker_sessions[source_ip]
        session['event_count'] += 1
        session['last_seen'] = datetime.now(timezone.utc).isoformat()
        session['event_types'].append(event_type)

        return session

    def report(self, event):
        """Report event to all enabled producers with enrichment"""
        # Add metadata
        event['timestamp'] = datetime.now(timezone.utc).isoformat()
        event['honeypot_id'] = self.honeypot_id

        # Track attacker session
        source_ip = event.get('source_ip')
        if source_ip:
            session = self.track_attacker_session(source_ip, event.get('event_type', ''))
            event['attacker_session'] = {
                'first_seen': session['first_seen'],
                'last_seen': session['last_seen'],
                'total_events': session['event_count'],
                'event_types': list(set(session['event_types'])),
                'is_repeat_attacker': session['event_count'] > 1
            }

        # Enrich event with threat intelligence
        if self.enrichment_manager:
            event = self.enrichment_manager.enrich(event)

        # Log event
        logger.info(f"Event: {event['event_type']} from {source_ip} (severity: {event.get('severity', 'unknown')})")

        # Send to all producers
        for producer in self.producers:
            try:
                producer.send(event)
            except Exception as e:
                logger.error(f"Producer {producer.producer_name} failed: {e}")

    def close(self):
        """Close all producers"""
        logger.info("Closing all producers...")
        for producer in self.producers:
            try:
                producer.close()
            except Exception as e:
                logger.error(f"Error closing producer {producer.producer_name}: {e}")

        if self.enrichment_manager:
            self.enrichment_manager.close()


# Global instances
CONFIG = None
reporter = None
attacker_profiler = AttackerProfiler()


def start_ssh_honeypot():
    """Start SSH honeypot service"""
    if not CONFIG['services']['ssh']['enabled']:
        return

    try:
        ssh = SSHHoneypot(CONFIG['services']['ssh'], reporter, attacker_profiler)
        ssh.start()
    except Exception as e:
        logger.error(f"SSH honeypot error: {e}")


def main():
    """Main entry point"""
    global CONFIG, reporter

    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description="BrunswickPot Enhanced Honeypot System")
    parser.add_argument('--config', default='honeypot_config.yaml', help='Path to configuration file')
    parser.add_argument('--test-config', action='store_true', help='Test configuration and exit')
    args = parser.parse_args()

    # Load configuration
    CONFIG = load_config(args.config)

    # Setup logging
    log_level = getattr(logging, CONFIG['general']['log_level'].upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    logger.info(f"Starting BrunswickPot: {CONFIG['general']['honeypot_name']}")

    # Test configuration mode
    if args.test_config:
        logger.info("Configuration test mode")
        logger.info(f"Honeypot ID: {CONFIG['general']['honeypot_name']}")
        logger.info(f"Enabled services: {[k for k, v in CONFIG['services'].items() if v.get('enabled')]}")
        logger.info("Configuration valid!")
        return

    # Initialize event reporter
    reporter = EventReporter(CONFIG)

    # Start services in separate threads
    threads = []

    # SSH Service
    if CONFIG['services']['ssh']['enabled']:
        t = threading.Thread(target=start_ssh_honeypot, daemon=True)
        t.start()
        threads.append(t)

    # TODO: Add other services (SMB, HTTP, LDAP) - refactor from nohoney.py

    logger.info(f"All honeypot services started ({len(threads)} services)")
    logger.info("Press Ctrl+C to stop")

    # Setup graceful shutdown
    def signal_handler(sig, frame):
        logger.info("Shutting down honeypot system...")
        if reporter:
            reporter.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Keep main thread alive
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        logger.info("Shutting down honeypot system...")
        if reporter:
            reporter.close()


if __name__ == '__main__':
    main()
