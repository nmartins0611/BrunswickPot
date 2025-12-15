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
    """Simulates an SMB/CIFS file server"""
    
    def __init__(self):
        self.config = CONFIG['services']['smb']
        self.port = self.config['port']
        self.server = None
        self.fake_shares = self.config.get('fake_shares', [])
    
    def handle_client(self, client_socket, addr):
        """Handle SMB client connections"""
        try:
            # Extract attacker information
            attacker_info = AttackerProfiler.extract_attacker_info({}, addr)
            
            reporter.report({
                'event_type': 'smb_connection',
                'service': 'smb',
                **attacker_info,
                'action': 'connection_attempt',
                'severity': 'low',
                'protocol': 'SMB/CIFS',
                'protocol_version': 'unknown'
            })
            
            # Receive initial SMB negotiation
            try:
                data = client_socket.recv(4096)
            except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
                # Port scanner - connection closed immediately
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
                reporter.report({
                    'event_type': 'smb_negotiation',
                    'service': 'smb',
                    **attacker_info,
                    'data_length': len(data),
                    'data_preview': base64.b64encode(data[:100]).decode('utf-8'),
                    'data_hash': hashlib.sha256(data).hexdigest(),
                    'severity': 'medium',
                    'raw_bytes': len(data)
                })
                
                # Send fake SMB response with configured banner
                try:
                    response = b'\x00\x00\x00\x85\xffSMBr\x00\x00\x00\x00\x98\x07\xc8'
                    client_socket.send(response)
                except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
                    pass  # Client already disconnected
            
            # Wait for authentication attempt
            try:
                auth_data = client_socket.recv(4096)
            except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, socket.timeout):
                return  # Connection closed or timed out
                
            if auth_data:
                # Try to extract username from SMB auth packet
                username_attempt = "unknown"
                try:
                    # Simple extraction - SMB username often in plaintext
                    if b'\\' in auth_data:
                        parts = auth_data.split(b'\\')
                        if len(parts) > 1:
                            username_attempt = parts[1].split(b'\x00')[0].decode('utf-8', errors='ignore')
                except:
                    pass
                
                reporter.report({
                    'event_type': 'smb_auth_attempt',
                    'service': 'smb',
                    **attacker_info,
                    'data_length': len(auth_data),
                    'attempted_username': username_attempt,
                    'auth_method': 'NTLM',
                    'severity': 'high',
                    'attack_type': 'credential_access'
                })
                
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            # Connection reset - already logged above
            pass
        except Exception as e:
            logger.error(f"SMB handler error: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
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
            'severity': 'high',
            'attack_type': 'credential_harvesting'
        }
        
        # Add extracted credentials
        if credentials:
            event_data['extracted_credentials'] = credentials
            event_data['credential_username'] = credentials.get('username', 'unknown')
            # Don't log full password, just indicate it was captured
            event_data['credential_captured'] = 'password' in credentials
            event_data['severity'] = 'critical'
        
        # Add tool detection if found
        if tool_detection:
            event_data['attack_tool'] = tool_detection
        
        reporter.report(event_data)
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<h1>Login Successful</h1>')


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
