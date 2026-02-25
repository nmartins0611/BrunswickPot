"""
SSH Honeypot Service
Simulates an SSH server to capture authentication attempts and attacker behavior
"""

import socket
import threading
import logging
import os
import hashlib
from datetime import datetime, timezone

try:
    import paramiko
    from paramiko import ServerInterface, AUTH_FAILED, AUTH_SUCCESSFUL, OPEN_SUCCEEDED
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False
    print("Warning: paramiko not installed. SSH honeypot will not work. Install with: pip install paramiko")

logger = logging.getLogger(__name__)


class SSHServer(ServerInterface):
    """Paramiko SSH server interface for honeypot"""

    def __init__(self, client_address, reporter, config):
        self.client_address = client_address
        self.reporter = reporter
        self.config = config
        self.event_type_prefix = 'ssh'
        self.auth_attempts = 0
        self.max_attempts = config.get('password_attempts_before_disconnect', 3)
        self.fake_users = config.get('fake_users', ['root', 'admin', 'ubuntu', 'user'])

    def check_channel_request(self, kind, chanid):
        """Handle channel requests"""
        logger.debug(f"Channel request: {kind}")

        self.reporter.report({
            'event_type': f'{self.event_type_prefix}_channel_request',
            'service': 'ssh',
            'source_ip': self.client_address[0],
            'source_port': self.client_address[1],
            'channel_type': kind,
            'severity': 'medium',
            'attack_type': 'post_auth_activity'
        })

        return OPEN_SUCCEEDED

    def check_auth_password(self, username, password):
        """Handle password authentication attempts"""
        self.auth_attempts += 1

        self.reporter.report({
            'event_type': f'{self.event_type_prefix}_auth_attempt',
            'service': 'ssh',
            'source_ip': self.client_address[0],
            'source_port': self.client_address[1],
            'username': username,
            'password': password,  # CAUTION: Storing passwords - ensure secure handling
            'credential_captured': True,
            'auth_method': 'password',
            'auth_result': 'failed',
            'attempt_number': self.auth_attempts,
            'severity': 'high',
            'attack_type': 'credential_access'
        })

        logger.info(f"SSH password attempt from {self.client_address[0]}: {username}:{password}")

        # Always fail auth, but allow a few attempts before disconnecting
        if self.auth_attempts >= self.max_attempts:
            return AUTH_FAILED

        return AUTH_FAILED

    def check_auth_publickey(self, username, key):
        """Handle public key authentication attempts"""
        self.auth_attempts += 1

        # Get key fingerprint
        key_type = key.get_name()
        key_fingerprint = hashlib.md5(key.get_fingerprint()).hexdigest()
        key_fingerprint_formatted = ':'.join([key_fingerprint[i:i+2] for i in range(0, len(key_fingerprint), 2)])

        self.reporter.report({
            'event_type': f'{self.event_type_prefix}_pubkey_attempt',
            'service': 'ssh',
            'source_ip': self.client_address[0],
            'source_port': self.client_address[1],
            'username': username,
            'auth_method': 'publickey',
            'auth_result': 'failed',
            'key_type': key_type,
            'key_fingerprint': key_fingerprint_formatted,
            'key_bits': key.get_bits(),
            'attempt_number': self.auth_attempts,
            'severity': 'high',
            'attack_type': 'credential_access'
        })

        logger.info(f"SSH pubkey attempt from {self.client_address[0]}: {username} ({key_type}, {key_fingerprint_formatted})")

        # Always fail auth
        return AUTH_FAILED

    def get_allowed_auths(self, username):
        """Return allowed authentication methods"""
        # Advertise both password and publickey to capture both types
        return 'password,publickey'

    def check_channel_shell_request(self, channel):
        """Handle shell requests"""
        self.reporter.report({
            'event_type': f'{self.event_type_prefix}_shell_request',
            'service': 'ssh',
            'source_ip': self.client_address[0],
            'source_port': self.client_address[1],
            'severity': 'medium',
            'attack_type': 'command_execution_attempt'
        })

        return False  # Don't allow shell

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        """Handle PTY requests"""
        self.reporter.report({
            'event_type': f'{self.event_type_prefix}_pty_request',
            'service': 'ssh',
            'source_ip': self.client_address[0],
            'source_port': self.client_address[1],
            'terminal_type': term,
            'terminal_size': f'{width}x{height}',
            'severity': 'low',
        })

        return True  # Allow PTY to gather more intelligence

    def check_channel_exec_request(self, channel, command):
        """Handle command execution requests"""
        command_str = command.decode('utf-8', errors='ignore')

        self.reporter.report({
            'event_type': f'{self.event_type_prefix}_exec_request',
            'service': 'ssh',
            'source_ip': self.client_address[0],
            'source_port': self.client_address[1],
            'command': command_str,
            'severity': 'critical',
            'attack_type': 'command_execution'
        })

        logger.warning(f"SSH command attempt from {self.client_address[0]}: {command_str}")

        return False  # Don't actually execute


class SSHHoneypot:
    """SSH Honeypot Service"""

    def __init__(self, config, reporter, attacker_profiler):
        """
        Initialize SSH honeypot

        Args:
            config: SSH service configuration
            reporter: EventReporter instance
            attacker_profiler: AttackerProfiler instance
        """
        if not PARAMIKO_AVAILABLE:
            raise ImportError("paramiko library required for SSH honeypot. Install with: pip install paramiko")

        self.config = config
        self.reporter = reporter
        self.attacker_profiler = attacker_profiler
        self.port = config.get('port', 2222)
        self.banner = config.get('banner', 'SSH-2.0-OpenSSH_7.4')
        self.host_key_path = config.get('host_key_path', '/var/lib/honeypot/ssh_host_key')
        self.server = None
        self.host_key = None

        # Load or generate host key
        self._load_or_generate_host_key()

    def _load_or_generate_host_key(self):
        """Load existing SSH host key or generate a new one"""
        if os.path.exists(self.host_key_path):
            try:
                self.host_key = paramiko.RSAKey.from_private_key_file(self.host_key_path)
                logger.info(f"Loaded SSH host key from {self.host_key_path}")
            except Exception as e:
                logger.error(f"Failed to load host key: {e}, generating new key")
                self._generate_host_key()
        else:
            self._generate_host_key()

    def _generate_host_key(self):
        """Generate a new RSA host key"""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.host_key_path), exist_ok=True)

            # Generate 2048-bit RSA key
            self.host_key = paramiko.RSAKey.generate(2048)
            self.host_key.write_private_key_file(self.host_key_path)

            logger.info(f"Generated new SSH host key at {self.host_key_path}")
        except Exception as e:
            logger.error(f"Failed to generate host key: {e}")
            # Use in-memory key as fallback
            self.host_key = paramiko.RSAKey.generate(2048)
            logger.warning("Using in-memory host key (not persisted)")

    def handle_client(self, client_socket, addr):
        """Handle SSH client connections"""
        try:
            # Extract attacker information
            attacker_info = self.attacker_profiler.extract_attacker_info({}, addr)

            self.reporter.report({
                'event_type': 'ssh_connection',
                'service': 'ssh',
                **attacker_info,
                'action': 'connection_attempt',
                'severity': 'low',
                'protocol': 'SSH',
                'protocol_version': self.banner
            })

            # Set up Paramiko transport
            transport = paramiko.Transport(client_socket)
            transport.local_version = self.banner  # Custom banner
            transport.add_server_key(self.host_key)

            # Create SSH server instance
            server = SSHServer(addr, self.reporter, self.config)

            try:
                # Start SSH server
                transport.start_server(server=server)

                # Wait for authentication
                channel = transport.accept(20)  # 20 second timeout

                if channel is None:
                    logger.debug(f"SSH client {addr[0]} - no channel opened")
                else:
                    logger.info(f"SSH client {addr[0]} - channel opened")
                    channel.close()

            except paramiko.SSHException as e:
                logger.debug(f"SSH negotiation failed from {addr[0]}: {e}")
                self.reporter.report({
                    'event_type': 'ssh_negotiation_failed',
                    'service': 'ssh',
                    **attacker_info,
                    'error': str(e),
                    'severity': 'low',
                    'attack_type': 'reconnaissance'
                })
            except Exception as e:
                logger.error(f"SSH handler error from {addr[0]}: {e}")

            finally:
                try:
                    transport.close()
                except:
                    pass

        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            # Port scanner - connection closed immediately
            self.reporter.report({
                'event_type': 'ssh_port_scan',
                'service': 'ssh',
                **attacker_info,
                'scan_type': 'connection_reset',
                'severity': 'low',
                'attack_type': 'reconnaissance'
            })
        except Exception as e:
            logger.error(f"SSH handler error: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass

    def start(self):
        """Start SSH honeypot server"""
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server.bind(('0.0.0.0', self.port))
            self.server.listen(5)
            logger.info(f"SSH Honeypot listening on port {self.port}")

            while True:
                try:
                    client, addr = self.server.accept()
                    thread = threading.Thread(target=self.handle_client, args=(client, addr))
                    thread.daemon = True
                    thread.start()
                except Exception as e:
                    logger.error(f"SSH server error: {e}")

        except PermissionError:
            logger.error(f"Permission denied to bind to port {self.port}. Try using a port > 1024 or run with elevated privileges.")
        except OSError as e:
            logger.error(f"Failed to start SSH server on port {self.port}: {e}")
        except KeyboardInterrupt:
            logger.info("SSH honeypot shutting down")
        finally:
            if self.server:
                self.server.close()
