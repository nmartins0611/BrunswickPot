#!/usr/bin/env python3
"""
Multi-Service Honeypot System
Simulates fileserver (SMB), webserver (HTTP), and LDAP services
Reports all interactions via Kafka or Webhook
"""

import socket
import threading
import json
import logging
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
import os
import base64
import yaml
import hashlib

# Optional imports - install with: pip install kafka-python requests pyyaml
try:
    from kafka import KafkaProducer
    KAFKA_AVAILABLE = True
except ImportError:
    KAFKA_AVAILABLE = False
    print("Warning: kafka-python not installed. Install with: pip install kafka-python")

try:
    import requests
    WEBHOOK_AVAILABLE = True
except ImportError:
    WEBHOOK_AVAILABLE = False
    print("Warning: requests not installed. Install with: pip install requests")

# Load configuration
def load_config(config_file='honeypot_config.yaml'):
    """Load configuration from YAML file"""
    if not os.path.exists(config_file):
        print(f"Config file '{config_file}' not found. Creating default config...")
        create_default_config(config_file)
    
    with open(config_file, 'r') as f:
        return yaml.safe_load(f)

def create_default_config(config_file='honeypot_config.yaml'):
    """Create a default configuration file"""
    default_config = {
        'general': {
            'honeypot_name': 'corporate-server-01',
            'log_level': 'INFO'
        },
        'kafka': {
            'enabled': False,
            'bootstrap_servers': ['localhost:9092'],
            'topic': 'honeypot-events',
            'ssl_enabled': False,
            'sasl_mechanism': None,
            'sasl_username': None,
            'sasl_password': None
        },
        'webhook': {
            'enabled': True,
            'url': 'http://localhost:8080/webhook',
            'timeout': 5,
            'retry_attempts': 3,
            'headers': {
                'Content-Type': 'application/json',
                'X-API-Key': 'your-api-key-here'
            }
        },
        'services': {
            'smb': {
                'enabled': True,
                'port': 4445,
                'banner': 'Windows Server 2019',
                'fake_shares': ['Documents', 'Shared', 'Backups', 'Finance', 'HR']
            },
            'http': {
                'enabled': True,
                'port': 8000,
                'server_header': 'Apache/2.4.41 (Ubuntu)',
                'fake_hostname': 'intranet.company.local'
            },
            'ldap': {
                'enabled': True,
                'port': 3389,
                'base_dn': 'DC=company,DC=com',
                'fake_users': [
                    'CN=John Doe,OU=Users,DC=company,DC=com',
                    'CN=Jane Smith,OU=Users,DC=company,DC=com',
                    'CN=Admin,OU=Admins,DC=company,DC=com'
                ]
            }
        },
        'alerting': {
            'alert_on_connection': False,
            'alert_on_auth_attempt': True,
            'alert_on_suspicious_patterns': True,
            'suspicious_paths': [
                '/admin', '/phpmyadmin', '/.git', '/.env', 
                '/wp-admin', '/files/passwords', '/files/database'
            ],
            'severity_thresholds': {
                'connection': 'low',
                'auth_attempt': 'high',
                'data_exfiltration': 'critical'
            }
        },
        'rate_limiting': {
            'enabled': True,
            'max_connections_per_ip': 100,
            'time_window_seconds': 3600
        }
    }
    
    with open(config_file, 'w') as f:
        yaml.dump(default_config, f, default_flow_style=False, sort_keys=False)
    
    print(f"Default config created at '{config_file}'. Please review and update settings.")

# Load config at startup
CONFIG = load_config()

# Setup logging
log_level = getattr(logging, CONFIG['general']['log_level'].upper(), logging.INFO)
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('Honeypot')


class AttackerProfiler:
    """Collects and analyzes attacker information"""
    
    @staticmethod
    def extract_attacker_info(request_data, client_address):
        """Extract comprehensive attacker information"""
        info = {
            # Network Information
            'source_ip': client_address[0],
            'source_port': client_address[1],
            'reverse_dns': AttackerProfiler.get_reverse_dns(client_address[0]),
            
            # Geolocation (placeholder - requires GeoIP library)
            'geolocation': AttackerProfiler.get_geolocation(client_address[0]),
            
            # Session tracking
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
    def get_geolocation(ip):
        """Get geolocation info (requires external API or GeoIP database)"""
        # Placeholder - can integrate with services like ipapi.co or MaxMind GeoIP
        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'asn': 'Unknown',
            'isp': 'Unknown'
        }
    
    @staticmethod
    def generate_session_id(ip):
        """Generate unique session ID for tracking attacker across services"""
        return hashlib.md5(f"{ip}-{datetime.now(timezone.utc).date()}".encode()).hexdigest()[:12]
    
    @staticmethod
    def extract_credentials(post_data):
        """Extract usernames/passwords from POST data"""
        credentials = {}
        
        # Parse form data
        if '&' in post_data:
            for pair in post_data.split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    if key.lower() in ['username', 'user', 'login', 'email']:
                        credentials['username'] = value
                    elif key.lower() in ['password', 'pass', 'pwd']:
                        credentials['password'] = value
        
        return credentials
    
    @staticmethod
    def detect_attack_tools(user_agent):
        """Detect known attack tools from User-Agent"""
        attack_tools = {
            'sqlmap': 'SQL Injection Scanner',
            'nikto': 'Web Server Scanner',
            'nmap': 'Network Scanner',
            'metasploit': 'Exploitation Framework',
            'burp': 'Web Application Testing',
            'zap': 'OWASP ZAP Security Scanner',
            'acunetix': 'Web Vulnerability Scanner',
            'nessus': 'Vulnerability Scanner',
            'masscan': 'Port Scanner',
            'gobuster': 'Directory Bruteforcer',
            'wpscan': 'WordPress Scanner',
            'curl': 'Command Line Tool',
            'wget': 'Command Line Tool',
            'python-requests': 'Python Script',
            'go-http-client': 'Go Script'
        }
        
        user_agent_lower = user_agent.lower()
        for tool, description in attack_tools.items():
            if tool in user_agent_lower:
                return {'tool': tool, 'description': description}
        
        return None
    
    @staticmethod
    def fingerprint_attacker(headers_dict):
        """Create fingerprint from HTTP headers"""
        fingerprint = {
            'user_agent': headers_dict.get('User-Agent', ''),
            'accept_language': headers_dict.get('Accept-Language', ''),
            'accept_encoding': headers_dict.get('Accept-Encoding', ''),
            'connection': headers_dict.get('Connection', ''),
            'browser_fingerprint': hashlib.md5(
                str(headers_dict).encode()
            ).hexdigest()[:16]
        }
        return fingerprint


class EventReporter:
    """Handles reporting events to Kafka and/or Webhook"""
    
    def __init__(self):
        self.kafka_producer = None
        self.attacker_sessions = {}  # Track attacker sessions
        
        if CONFIG['kafka']['enabled'] and KAFKA_AVAILABLE:
            try:
                kafka_config = {
                    'bootstrap_servers': CONFIG['kafka']['bootstrap_servers'],
                    'value_serializer': lambda v: json.dumps(v).encode('utf-8')
                }
                
                # Add SSL/SASL if configured
                if CONFIG['kafka'].get('ssl_enabled'):
                    kafka_config['security_protocol'] = 'SASL_SSL'
                
                if CONFIG['kafka'].get('sasl_mechanism'):
                    kafka_config['sasl_mechanism'] = CONFIG['kafka']['sasl_mechanism']
                    kafka_config['sasl_plain_username'] = CONFIG['kafka'].get('sasl_username', '')
                    kafka_config['sasl_plain_password'] = CONFIG['kafka'].get('sasl_password', '')
                
                self.kafka_producer = KafkaProducer(**kafka_config)
                logger.info("Kafka producer initialized")
            except Exception as e:
                logger.error(f"Failed to initialize Kafka producer: {e}")
    
    def track_attacker_session(self, source_ip, event_type):
        """Track attacker activity across sessions"""
        if source_ip not in self.attacker_sessions:
            self.attacker_sessions[source_ip] = {
                'first_seen': datetime.now(timezone.utc).isoformat(),
                'event_count': 0,
                'event_types': [],
                'targeted_services': set()
            }
        
        session = self.attacker_sessions[source_ip]
        session['event_count'] += 1
        session['last_seen'] = datetime.now(timezone.utc).isoformat()
        session['event_types'].append(event_type)
        
        return session
    
    def report(self, event):
        """Report event to configured destinations with enhanced attacker profiling"""
        event['timestamp'] = datetime.now(timezone.utc).isoformat()
        event['honeypot_id'] = CONFIG['general']['honeypot_name']
        
        # Add attacker session tracking
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
        
        # Determine if we should alert based on config
        should_alert = self._should_alert(event)
        
        if should_alert:
            logger.info(f"Event: {event['event_type']} from {event.get('source_ip', 'unknown')} (Session events: {session.get('event_count', 0)})")
        
        # Send to Kafka
        if self.kafka_producer and should_alert:
            try:
                self.kafka_producer.send(CONFIG['kafka']['topic'], event)
                logger.debug("Event sent to Kafka")
            except Exception as e:
                logger.error(f"Failed to send to Kafka: {e}")
        
        # Send to Webhook
        if CONFIG['webhook']['enabled'] and WEBHOOK_AVAILABLE and should_alert:
            self._send_to_webhook(event)
    
    def _should_alert(self, event):
        """Determine if event should trigger alert based on config"""
        event_type = event.get('event_type', '')
        
        if 'connection' in event_type and not CONFIG['alerting']['alert_on_connection']:
            return False
        
        if 'auth' in event_type and CONFIG['alerting']['alert_on_auth_attempt']:
            return True
        
        if event.get('severity') in ['high', 'critical']:
            return True
        
        return True
    
    def _send_to_webhook(self, event):
        """Send event to webhook with retry logic"""
        webhook_config = CONFIG['webhook']
        
        for attempt in range(webhook_config.get('retry_attempts', 3)):
            try:
                response = requests.post(
                    webhook_config['url'],
                    json=event,
                    headers=webhook_config.get('headers', {}),
                    timeout=webhook_config.get('timeout', 5)
                )
                
                if response.status_code == 200:
                    logger.debug(f"Event sent to webhook: {response.status_code}")
                    return
                else:
                    logger.warning(f"Webhook returned {response.status_code}, attempt {attempt+1}")
                    
            except Exception as e:
                logger.error(f"Failed to send to webhook (attempt {attempt+1}): {e}")
                
            if attempt < webhook_config.get('retry_attempts', 3) - 1:
                import time
                time.sleep(1)


reporter = EventReporter()


class SMBHoneypot:
    """Simulates an SMB/CIFS file server with interactive session"""
    
    def __init__(self):
        self.config = CONFIG['services']['smb']
        self.port = self.config['port']
        self.server = None
        self.fake_shares = self.config.get('fake_shares', [])
        
        # Fake file system structure
        self.fake_filesystem = {
            'Documents': {
                'Q4_Report.docx': b'Quarterly financial report content...',
                'Meeting_Notes.txt': b'Meeting notes from executive team...',
                'Strategy_2024.pdf': b'Strategic planning document...'
            },
            'Finance': {
                'Budget_2024.xlsx': b'Annual budget spreadsheet...',
                'Payroll.xls': b'Employee payroll information...',
                'Invoices': {
                    'INV001.pdf': b'Invoice #001 content...',
                    'INV002.pdf': b'Invoice #002 content...'
                }
            },
            'HR': {
                'Employees.csv': b'name,email,salary\nJohn Doe,jdoe@company.com,85000\n',
                'Contracts': {},
                'Benefits.pdf': b'Employee benefits package...'
            },
            'Backups': {
                'database_backup.sql': b'-- Database backup\nCREATE TABLE users...',
                'config_backup.tar.gz': b'Configuration backup archive...'
            },
            'IT': {
                'passwords.txt': b'admin:P@ssw0rd123\nroot:toor\ndbadmin:db_secret',
                'vpn_config.ovpn': b'VPN configuration file...',
                'server_keys': {}
            }
        }
    
    def handle_client(self, client_socket, addr):
        """Handle SMB client connections with interactive session"""
        session_id = hashlib.md5(f"{addr[0]}-{datetime.now(timezone.utc)}".encode()).hexdigest()[:8]
        session_data = {
            'session_id': session_id,
            'actions': [],
            'files_accessed': [],
            'files_downloaded': [],
            'commands': []
        }
        
        try:
            # Set socket timeout
            client_socket.settimeout(20)
            
            # Extract attacker information
            attacker_info = AttackerProfiler.extract_attacker_info({}, addr)
            
            reporter.report({
                'event_type': 'smb_connection',
                'service': 'smb',
                **attacker_info,
                'session_id': session_id,
                'action': 'connection_attempt',
                'severity': 'low',
                'protocol': 'SMB/CIFS',
                'protocol_version': 'unknown'
            })
            
            # Receive initial SMB negotiation
            try:
                data = client_socket.recv(4096)
            except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, socket.timeout):
                reporter.report({
                    'event_type': 'smb_port_scan',
                    'service': 'smb',
                    **attacker_info,
                    'scan_type': 'connection_reset',
                    'severity': 'low',
                    'attack_type': 'reconnaissance'
                })
                return
            
            if data:
                # Check if it's SMB1 or SMB2/3
                is_smb2 = b'\xfeSMB' in data
                
                reporter.report({
                    'event_type': 'smb_negotiation',
                    'service': 'smb',
                    **attacker_info,
                    'session_id': session_id,
                    'data_length': len(data),
                    'data_preview': base64.b64encode(data[:100]).decode('utf-8'),
                    'data_hash': hashlib.sha256(data).hexdigest(),
                    'smb_version': 'SMB2/3' if is_smb2 else 'SMB1',
                    'severity': 'medium',
                    'raw_bytes': len(data)
                })
                session_data['actions'].append('smb_negotiation')
                
                # Send proper SMB negotiate response
                try:
                    if is_smb2:
                        # SMB2/3 Negotiate Protocol Response
                        response = self.create_smb2_negotiate_response()
                    else:
                        # SMB1 Negotiate Protocol Response
                        response = self.create_smb1_negotiate_response()
                    
                    client_socket.send(response)
                    logger.debug(f"Sent SMB negotiate response ({len(response)} bytes)")
                except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
                    return
            
            # Continue handling session for multiple exchanges
            max_exchanges = 10
            for exchange in range(max_exchanges):
                try:
                    client_socket.settimeout(10)
                    data = client_socket.recv(4096)
                    
                    if not data:
                        break
                    
                    # Detect command type
                    command_info = self.detect_smb_command(data)
                    if command_info:
                        session_data['commands'].append(command_info)
                        
                        reporter.report({
                            'event_type': 'smb_command',
                            'service': 'smb',
                            **attacker_info,
                            'session_id': session_id,
                            'command': command_info['command'],
                            'description': command_info['description'],
                            'severity': 'medium'
                        })
                    
                    # Check for session setup (authentication)
                    if b'SessionSetup' in str(data) or b'\x73' in data[:8]:
                        username_attempt = self.extract_username(data)
                        session_data['username'] = username_attempt
                        session_data['actions'].append('authentication_attempt')
                        
                        reporter.report({
                            'event_type': 'smb_auth_attempt',
                            'service': 'smb',
                            **attacker_info,
                            'session_id': session_id,
                            'attempted_username': username_attempt,
                            'auth_method': 'NTLM',
                            'auth_result': 'simulated_success',
                            'severity': 'high',
                            'attack_type': 'credential_access'
                        })
                        
                        # Send success response for session setup
                        response = self.create_session_setup_response(data)
                        client_socket.send(response)
                        continue
                    
                    # Check for tree connect (share access)
                    if b'TreeConnect' in str(data) or b'\x75' in data[:8]:
                        share_name = self.extract_share_name(data)
                        session_data['actions'].append('share_access')
                        
                        reporter.report({
                            'event_type': 'smb_share_access',
                            'service': 'smb',
                            **attacker_info,
                            'session_id': session_id,
                            'share_name': share_name,
                            'severity': 'high'
                        })
                        
                        response = self.create_tree_connect_response(data)
                        client_socket.send(response)
                        continue
                    
                    # Generic response to keep connection alive
                    response = self.create_generic_response(data)
                    client_socket.send(response)
                    
                except socket.timeout:
                    logger.debug("SMB session timeout")
                    break
                except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
                    break
                
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            pass
        except Exception as e:
            logger.error(f"SMB handler error: {e}")
        finally:
            # Log complete session summary
            if session_data['actions']:
                reporter.report({
                    'event_type': 'smb_session_complete',
                    'service': 'smb',
                    **attacker_info,
                    'session_id': session_id,
                    'session_data': session_data,
                    'total_actions': len(session_data['actions']),
                    'commands': session_data['commands'],
                    'severity': 'high'
                })
            
            try:
                client_socket.close()
            except:
                pass
    
    def create_smb1_negotiate_response(self):
        """Create SMB1 Negotiate Protocol Response"""
        # SMB1 Negotiate Protocol Response - simplified but functional
        response = bytearray([
            0x00, 0x00, 0x00, 0x85,  # NetBIOS header
            0xff, 0x53, 0x4d, 0x42,  # SMB signature "\xffSMB"
            0x72,                     # Command: Negotiate Protocol
            0x00, 0x00, 0x00, 0x00,  # NT Status: Success
            0x98,                     # Flags
            0x07, 0xc8,              # Flags2
            0x00, 0x00,              # PID High
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Signature
            0x00, 0x00,              # Reserved
            0x00, 0x00,              # TID
            0x00, 0x00,              # PID
            0x00, 0x00,              # UID
            0x00, 0x00,              # MID
            # Word Count and parameters
            0x11,                     # Word Count
            0x00, 0x00,              # Dialect Index
            0x03,                     # Security Mode
            0x00, 0x00,              # Max Mpx Count
            0x01, 0x00,              # Max VCs
            0x00, 0x04, 0x11, 0x00,  # Max Buffer Size
            0x00, 0x00, 0x01, 0x00,  # Max Raw Size
            0x00, 0x00, 0x00, 0x00,  # Session Key
            0x00, 0x00, 0x00, 0x00,  # Capabilities
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # System Time
            0x00, 0x00,              # Server Time Zone
            0x00,                     # Challenge Length
            0x00, 0x00               # Byte Count
        ])
        return bytes(response)
    
    def create_smb2_negotiate_response(self):
        """Create SMB2 Negotiate Protocol Response"""
        # SMB2 Negotiate Response - simplified
        response = bytearray([
            0x00, 0x00, 0x00, 0x7c,  # NetBIOS header
            0xfe, 0x53, 0x4d, 0x42,  # SMB2 signature "\xfeSMB"
            0x40, 0x00,              # Structure Size
            0x00, 0x00,              # Credit Charge
            0x00, 0x00, 0x00, 0x00,  # Status
            0x00, 0x00,              # Command: Negotiate
            0x01, 0x00,              # Credit Request/Response
            0x00, 0x00, 0x00, 0x00,  # Flags
            0x00, 0x00, 0x00, 0x00,  # Next Command
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Message ID
            0x00, 0x00, 0x00, 0x00,  # Reserved
            0x00, 0x00, 0x00, 0x00,  # Tree ID
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Session ID
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Signature
            # Negotiate Response body
            0x41, 0x00,              # Structure Size
            0x00, 0x00,              # Security Mode
            0x11, 0x03,              # Dialect: SMB 3.1.1
            0x00, 0x00,              # Negotiate Context Count
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Server GUID
            0x00, 0x00, 0x00, 0x00,  # Capabilities
            0x00, 0x00, 0x10, 0x00,  # Max Transaction Size
            0x00, 0x00, 0x10, 0x00,  # Max Read Size
            0x00, 0x00, 0x10, 0x00,  # Max Write Size
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # System Time
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Server Start Time
            0x00, 0x00,              # Security Buffer Offset
            0x00, 0x00               # Security Buffer Length
        ])
        return bytes(response)
    
    def create_session_setup_response(self, request):
        """Create Session Setup response"""
        is_smb2 = b'\xfeSMB' in request
        
        if is_smb2:
            # SMB2 Session Setup Response
            response = bytearray([
                0x00, 0x00, 0x00, 0x48,  # NetBIOS
                0xfe, 0x53, 0x4d, 0x42,  # SMB2
                0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01, 0x00,              # Session Setup command
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Session ID
            ] + [0x00] * 32)  # Padding
        else:
            # SMB1 Session Setup Response
            response = bytearray([
                0x00, 0x00, 0x00, 0x27,
                0xff, 0x53, 0x4d, 0x42,  # SMB1
                0x73,                     # Session Setup command
                0x00, 0x00, 0x00, 0x00,
                0x98, 0x07, 0xc8,
            ] + [0x00] * 24)
        
        return bytes(response)
    
    def create_tree_connect_response(self, request):
        """Create Tree Connect response"""
        is_smb2 = b'\xfeSMB' in request
        
        if is_smb2:
            response = bytearray([
                0x00, 0x00, 0x00, 0x50,
                0xfe, 0x53, 0x4d, 0x42,
                0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x03, 0x00,              # Tree Connect command
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            ] + [0x00] * 64)
        else:
            response = bytearray([
                0x00, 0x00, 0x00, 0x27,
                0xff, 0x53, 0x4d, 0x42,
                0x75,                     # Tree Connect command
                0x00, 0x00, 0x00, 0x00,
            ] + [0x00] * 24)
        
        return bytes(response)
    
    def create_generic_response(self, request):
        """Create generic SMB response"""
        is_smb2 = b'\xfeSMB' in request
        
        if is_smb2:
            response = bytearray([0x00, 0x00, 0x00, 0x40] + [0xfe, 0x53, 0x4d, 0x42] + [0x00] * 60)
        else:
            response = bytearray([0x00, 0x00, 0x00, 0x23] + [0xff, 0x53, 0x4d, 0x42] + [0x00] * 28)
        
        return bytes(response)
    
    def extract_username(self, data):
        """Extract username from SMB auth data"""
        try:
            data_str = data.decode('utf-8', errors='ignore')
            if '\\' in data_str:
                parts = data_str.split('\\')
                for part in parts:
                    if part and len(part) > 2 and part.isprintable():
                        return part.split('\x00')[0][:50]
        except:
            pass
        return "unknown"
    
    def extract_share_name(self, data):
        """Extract share name from tree connect"""
        try:
            data_str = data.decode('utf-16-le', errors='ignore')
            if '\\' in data_str:
                parts = data_str.split('\\')
                for part in parts:
                    if part and part in self.fake_shares:
                        return part
        except:
            pass
        return "unknown"
    
    def handle_smb_session(self, client_socket, addr, attacker_info, session_id, session_data):
        """Handle interactive SMB session after authentication - DEPRECATED"""
        # This method is now integrated into handle_client
        pass
    
    def detect_smb_command(self, data):
        """Detect SMB commands from packet data"""
        try:
            # SMB command detection (simplified)
            if len(data) < 4:
                return None
            
            # Check for SMB signature
            if b'SMB' not in data and b'\xffSMB' not in data:
                return None
            
            # Detect common SMB commands by byte patterns
            commands = {
                b'\x75': {'command': 'TREE_CONNECT', 'description': 'Connect to share'},
                b'\xa2': {'command': 'NT_CREATE', 'description': 'Open/create file'},
                b'\x2d': {'command': 'OPEN', 'description': 'Open file'},
                b'\x0a': {'command': 'READ', 'description': 'Read file'},
                b'\x0b': {'command': 'WRITE', 'description': 'Write file'},
                b'\x06': {'command': 'DELETE', 'description': 'Delete file'},
                b'\x07': {'command': 'RENAME', 'description': 'Rename file'},
                b'\x32': {'command': 'TRANS2', 'description': 'Transaction'},
            }
            
            for cmd_byte, cmd_info in commands.items():
                if cmd_byte in data[4:8]:
                    # Try to extract target path/file
                    target = self.extract_path_from_smb(data)
                    return {
                        'command': cmd_info['command'],
                        'description': cmd_info['description'],
                        'target': target,
                        'raw_command_byte': cmd_byte.hex()
                    }
            
            return {'command': 'UNKNOWN', 'description': 'Unknown SMB command'}
            
        except Exception as e:
            logger.error(f"Error detecting SMB command: {e}")
            return None
    
    def extract_path_from_smb(self, data):
        """Extract file/path from SMB packet"""
        try:
            # Look for common path patterns
            data_str = data.decode('utf-8', errors='ignore')
            
            # Look for backslash paths
            if '\\' in data_str:
                parts = data_str.split('\\')
                for part in parts:
                    if part and len(part) > 2 and not part.startswith('\x00'):
                        return part.strip('\x00')
            
            # Look for forward slash paths
            if '/' in data_str:
                parts = data_str.split('/')
                for part in parts:
                    if part and len(part) > 2:
                        return part
            
            return 'unknown'
        except:
            return 'unknown'
    
    def generate_share_list(self):
        """Generate fake SMB share list response"""
        # Simplified share list response
        shares = b'\x00\x00\x00\x50' + b''.join(
            share.encode('utf-16-le') + b'\x00\x00' 
            for share in self.fake_shares[:3]
        )
        return shares
    
    def get_fake_file_content(self, file_path):
        """Return fake file content based on path"""
        # Search filesystem for matching file
        file_path_lower = file_path.lower()
        
        if 'password' in file_path_lower or 'passwd' in file_path_lower:
            return b'\x00\x00\x00\x50admin:P@ssw0rd123\nroot:toor\ndbadmin:db_secret\n'
        elif 'config' in file_path_lower:
            return b'\x00\x00\x00\x40[database]\nhost=10.0.0.5\nuser=admin\npassword=hunter2\n'
        elif 'backup' in file_path_lower or '.sql' in file_path_lower:
            return b'\x00\x00\x00\x60-- Database backup\nCREATE TABLE users (id INT, username VARCHAR(50));\n'
        elif '.csv' in file_path_lower or 'employee' in file_path_lower:
            return b'\x00\x00\x00\x45name,email,salary\nJohn Doe,jdoe@company.com,85000\n'
        else:
            return b'\x00\x00\x00\x30Fake file content for honeypot analysis...\n'
    
    def start(self):
        """Start SMB honeypot server"""
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(('0.0.0.0', self.port))
        self.server.listen(5)
        logger.info(f"SMB Honeypot listening on port {self.port}")
        
        while True:
            try:
                client, addr = self.server.accept()
                thread = threading.Thread(target=self.handle_client, args=(client, addr))
                thread.daemon = True
                thread.start()
            except Exception as e:
                logger.error(f"SMB server error: {e}")


class HTTPHoneypot(BaseHTTPRequestHandler):
    """Simulates a web server with fake directories and files"""
    
    FAKE_STRUCTURE = {
        '/': '<h1>Corporate Intranet</h1><ul><li><a href="/admin">Admin Panel</a></li><li><a href="/files">File Repository</a></li><li><a href="/api">API Docs</a></li></ul>',
        '/admin': '<h1>Admin Login</h1><form><input name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><button>Login</button></form>',
        '/files': '<h1>File Repository</h1><ul><li><a href="/files/config.ini">config.ini</a></li><li><a href="/files/database.sql">database.sql</a></li><li><a href="/files/passwords.txt">passwords.txt</a></li></ul>',
        '/api': '<h1>API Documentation</h1><p>Endpoints: /api/users, /api/auth, /api/data</p>',
        '/files/config.ini': '[database]\nhost=10.0.0.5\nuser=admin\npassword=hunter2',
        '/files/database.sql': '-- Database backup\nCREATE TABLE users (id INT, username VARCHAR(50), password_hash VARCHAR(255));',
        '/files/passwords.txt': 'admin:P@ssw0rd123\nroot:toor\nuser:letmein'
    }
    
    def log_request(self, code='-', size='-'):
        """Override to suppress default logging"""
        pass
    
    def log_error(self, format, *args):
        """Override to suppress connection reset errors"""
        # Only log actual errors, not connection resets from port scanners
        if not any(x in str(args) for x in ['Connection reset', 'Broken pipe', 'timed out']):
            logger.debug(f"HTTP error: {format % args}")
    
    def version_string(self):
        """Return configured server header"""
        return CONFIG['services']['http'].get('server_header', 'Apache/2.4.41')
    
    def handle_one_request(self):
        """Handle a single HTTP request with better error handling"""
        try:
            super().handle_one_request()
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError) as e:
            # Port scanner closed connection - log it as reconnaissance
            try:
                attacker_info = AttackerProfiler.extract_attacker_info(
                    {'headers': {}}, 
                    self.client_address
                )
                
                reporter.report({
                    'event_type': 'http_port_scan',
                    'service': 'http',
                    **attacker_info,
                    'scan_type': 'connection_reset',
                    'error': str(e),
                    'severity': 'low',
                    'attack_type': 'reconnaissance'
                })
            except:
                pass  # If logging fails, just continue
        except Exception as e:
            # Log other unexpected errors
            logger.error(f"HTTP handler unexpected error: {e}")
    
    def do_GET(self):
        """Handle GET requests"""
        # Extract comprehensive attacker information
        attacker_info = AttackerProfiler.extract_attacker_info(
            {'headers': dict(self.headers)}, 
            self.client_address
        )
        
        # Fingerprint the browser/tool
        fingerprint = AttackerProfiler.fingerprint_attacker(dict(self.headers))
        
        # Detect attack tools
        tool_detection = AttackerProfiler.detect_attack_tools(
            self.headers.get('User-Agent', '')
        )
        
        event_data = {
            'event_type': 'http_request',
            'service': 'http',
            'method': 'GET',
            'path': self.path,
            **attacker_info,
            'user_agent': self.headers.get('User-Agent', 'unknown'),
            'referer': self.headers.get('Referer', 'none'),
            'headers': dict(self.headers),
            'fingerprint': fingerprint,
            'severity': 'low',
            'http_version': self.request_version
        }
        
        # Add tool detection if found
        if tool_detection:
            event_data['attack_tool'] = tool_detection
            event_data['severity'] = 'high'
            event_data['attack_type'] = 'reconnaissance'
        
        reporter.report(event_data)
        
        # Check for suspicious paths from config
        suspicious_paths = CONFIG['alerting']['suspicious_paths']
        
        if any(sus in self.path for sus in suspicious_paths):
            reporter.report({
                'event_type': 'http_suspicious_access',
                'service': 'http',
                'path': self.path,
                **attacker_info,
                'matched_pattern': next(sus for sus in suspicious_paths if sus in self.path),
                'severity': 'high',
                'attack_type': 'data_exfiltration_attempt'
            })
        
        # Detect SQL injection attempts in URL
        sql_patterns = ["'", '"', 'OR', 'UNION', 'SELECT', 'DROP', '--', ';']
        if any(pattern.lower() in self.path.lower() for pattern in sql_patterns):
            reporter.report({
                'event_type': 'http_sql_injection_attempt',
                'service': 'http',
                'path': self.path,
                **attacker_info,
                'severity': 'critical',
                'attack_type': 'sql_injection'
            })
        
        # Serve fake content
        if self.path in self.FAKE_STRUCTURE:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(self.FAKE_STRUCTURE[self.path].encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        """Handle POST requests (form submissions, API calls)"""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8', errors='ignore')
        
        # Extract attacker information
        attacker_info = AttackerProfiler.extract_attacker_info(
            {'headers': dict(self.headers)}, 
            self.client_address
        )
        
        # Extract credentials if present
        credentials = AttackerProfiler.extract_credentials(post_data)
        
        # Fingerprint the browser/tool
        fingerprint = AttackerProfiler.fingerprint_attacker(dict(self.headers))
        
        # Detect attack tools
        tool_detection = AttackerProfiler.detect_attack_tools(
            self.headers.get('User-Agent', '')
        )
        
        # Generate session token for tracking
        session_token = hashlib.md5(f"{self.client_address[0]}-{datetime.now(timezone.utc)}".encode()).hexdigest()[:16]
        
        event_data = {
            'event_type': 'http_post',
            'service': 'http',
            'method': 'POST',
            'path': self.path,
            **attacker_info,
            'post_data': post_data,
            'post_data_length': len(post_data),
            'user_agent': self.headers.get('User-Agent', 'unknown'),
            'content_type': self.headers.get('Content-Type', 'unknown'),
            'fingerprint': fingerprint,
            'session_token': session_token,
            'severity': 'high',
            'attack_type': 'credential_harvesting'
        }
        
        # Add extracted credentials
        if credentials:
            event_data['extracted_credentials'] = credentials
            event_data['credential_username'] = credentials.get('username', 'unknown')
            event_data['credential_captured'] = 'password' in credentials
            event_data['severity'] = 'critical'
        
        # Add tool detection if found
        if tool_detection:
            event_data['attack_tool'] = tool_detection
        
        reporter.report(event_data)
        
        # SIMULATE SUCCESSFUL LOGIN - Give them access to explore
        if '/admin' in self.path and credentials:
            # Send them a fake admin panel with session
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.send_header('Set-Cookie', f'session={session_token}; Path=/')
            self.end_headers()
            
            admin_panel = f'''
            <html>
            <head><title>Admin Panel - Logged In</title></head>
            <body>
                <h1>Welcome, {credentials.get('username', 'Admin')}!</h1>
                <h2>System Administration</h2>
                <ul>
                    <li><a href="/admin/users">User Management</a></li>
                    <li><a href="/admin/config">System Configuration</a></li>
                    <li><a href="/admin/logs">View Logs</a></li>
                    <li><a href="/admin/database">Database Access</a></li>
                    <li><a href="/admin/backup">Backup & Restore</a></li>
                    <li><a href="/files">File Manager</a></li>
                </ul>
                <h3>Quick Actions</h3>
                <form action="/admin/execute" method="POST">
                    <input name="command" placeholder="Enter command" />
                    <button>Execute</button>
                </form>
            </body>
            </html>
            '''
            self.wfile.write(admin_panel.encode())
            
            # Log successful "login"
            reporter.report({
                'event_type': 'http_successful_login',
                'service': 'http',
                **attacker_info,
                'session_token': session_token,
                'username': credentials.get('username', 'unknown'),
                'severity': 'critical',
                'attack_type': 'unauthorized_access'
            })
            
        elif '/admin/execute' in self.path:
            # They're trying to execute commands!
            command_data = dict(item.split('=') for item in post_data.split('&') if '=' in item)
            command = command_data.get('command', 'unknown')
            
            reporter.report({
                'event_type': 'http_command_execution',
                'service': 'http',
                **attacker_info,
                'command': command,
                'severity': 'critical',
                'attack_type': 'remote_code_execution'
            })
            
            # Send fake command output
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            fake_output = f'''
            <html>
            <body>
                <h2>Command Output:</h2>
                <pre>
                {command}
                Command executed successfully.
                Output: [Simulated response for honeypot]
                </pre>
                <a href="/admin">Back to Admin</a>
            </body>
            </html>
            '''
            self.wfile.write(fake_output.encode())
            
        else:
            # Generic success response
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<h1>Login Successful</h1><a href="/admin">Go to Admin Panel</a>')


class LDAPHoneypot:
    """Simulates an LDAP directory service"""
    
    def __init__(self):
        self.config = CONFIG['services']['ldap']
        self.port = self.config['port']
        self.server = None
        self.fake_users = self.config.get('fake_users', [])
    
    def handle_client(self, client_socket, addr):
        """Handle LDAP client connections"""
        try:
            # Extract attacker information
            attacker_info = AttackerProfiler.extract_attacker_info({}, addr)
            
            reporter.report({
                'event_type': 'ldap_connection',
                'service': 'ldap',
                **attacker_info,
                'action': 'connection_attempt',
                'severity': 'low',
                'protocol': 'LDAP',
                'base_dn': self.config.get('base_dn', 'unknown')
            })
            
            # Receive LDAP bind request
            try:
                data = client_socket.recv(4096)
            except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
                # Port scanner - connection closed immediately
                reporter.report({
                    'event_type': 'ldap_port_scan',
                    'service': 'ldap',
                    **attacker_info,
                    'scan_type': 'connection_reset',
                    'severity': 'low',
                    'attack_type': 'reconnaissance'
                })
                return
                
            if data:
                # Try to extract LDAP bind DN (username)
                bind_dn = "unknown"
                try:
                    # LDAP bind DN often contains CN= or uid=
                    data_str = data.decode('utf-8', errors='ignore')
                    if 'CN=' in data_str or 'uid=' in data_str:
                        # Extract potential username
                        for part in data_str.split(','):
                            if 'CN=' in part or 'uid=' in part:
                                bind_dn = part.strip()
                                break
                except:
                    pass
                
                reporter.report({
                    'event_type': 'ldap_bind_attempt',
                    'service': 'ldap',
                    **attacker_info,
                    'data_length': len(data),
                    'data_preview': base64.b64encode(data[:100]).decode('utf-8'),
                    'data_hash': hashlib.sha256(data).hexdigest(),
                    'bind_dn': bind_dn,
                    'severity': 'high',
                    'attack_type': 'credential_access'
                })
                
                # Send fake LDAP response (simplified bind response)
                try:
                    response = b'\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00'
                    client_socket.send(response)
                except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
                    pass  # Client already disconnected
                
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            # Connection reset - already logged above
            pass
        except Exception as e:
            logger.error(f"LDAP handler error: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def start(self):
        """Start LDAP honeypot server"""
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(('0.0.0.0', self.port))
        self.server.listen(5)
        logger.info(f"LDAP Honeypot listening on port {self.port}")
        
        while True:
            try:
                client, addr = self.server.accept()
                thread = threading.Thread(target=self.handle_client, args=(client, addr))
                thread.daemon = True
                thread.start()
            except Exception as e:
                logger.error(f"LDAP server error: {e}")


def start_http_server():
    """Start HTTP honeypot in a separate thread"""
    port = CONFIG['services']['http']['port']
    server = HTTPServer(('0.0.0.0', port), HTTPHoneypot)
    logger.info(f"HTTP Honeypot listening on port {port}")
    server.serve_forever()


def main():
    """Start all enabled honeypot services"""
    logger.info(f"Starting Multi-Service Honeypot System: {CONFIG['general']['honeypot_name']}")
    
    threads = []
    
    # Start SMB honeypot
    if CONFIG['services']['smb']['enabled']:
        smb = SMBHoneypot()
        t = threading.Thread(target=smb.start)
        t.daemon = True
        t.start()
        threads.append(t)
    
    # Start HTTP honeypot
    if CONFIG['services']['http']['enabled']:
        t = threading.Thread(target=start_http_server)
        t.daemon = True
        t.start()
        threads.append(t)
    
    # Start LDAP honeypot
    if CONFIG['services']['ldap']['enabled']:
        ldap = LDAPHoneypot()
        t = threading.Thread(target=ldap.start)
        t.daemon = True
        t.start()
        threads.append(t)
    
    logger.info("All honeypot services started. Press Ctrl+C to stop.")
    
    # Keep main thread alive
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        logger.info("Shutting down honeypot system...")


if __name__ == '__main__':
    main()
