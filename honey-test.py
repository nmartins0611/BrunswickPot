#!/usr/bin/env python3
"""
Honeypot Testing Suite
Tests all honeypot services to verify they're working correctly
"""

import socket
import requests
import time
import sys
from datetime import datetime
import base64
import random

class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    END = '\033[0m'
    BOLD = '\033[1m'

class HoneypotTester:
    def __init__(self, host='localhost'):
        self.host = host
        self.results = []
        
    def log(self, message, status='info'):
        """Print colored log messages"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        if status == 'success':
            print(f"{Colors.GREEN}[✓] {timestamp} - {message}{Colors.END}")
        elif status == 'error':
            print(f"{Colors.RED}[✗] {timestamp} - {message}{Colors.END}")
        elif status == 'warning':
            print(f"{Colors.YELLOW}[!] {timestamp} - {message}{Colors.END}")
        else:
            print(f"{Colors.BLUE}[i] {timestamp} - {message}{Colors.END}")
    
    def test_smb_honeypot(self, port=4445):
        """Test SMB/File Server honeypot"""
        self.log(f"\n{Colors.BOLD}Testing SMB Honeypot on port {port}...{Colors.END}", 'info')
        
        try:
            # Test 1: Connection attempt
            self.log("Test 1: Attempting connection to SMB service...", 'info')
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.host, port))
            self.log("Successfully connected to SMB honeypot", 'success')
            
            # Test 2: Send SMB negotiation packet
            self.log("Test 2: Sending SMB negotiation packet...", 'info')
            smb_negotiate = b'\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00'
            sock.send(smb_negotiate)
            
            response = sock.recv(1024)
            if response:
                self.log(f"Received response ({len(response)} bytes)", 'success')
                self.results.append(('SMB Connection', 'PASS'))
            else:
                self.log("No response received", 'warning')
                self.results.append(('SMB Connection', 'PARTIAL'))
            
            # Test 3: Send authentication attempt
            self.log("Test 3: Sending fake authentication attempt...", 'info')
            auth_packet = b'\x00\x00\x00\x48\xff\x53\x4d\x42\x73\x00\x00\x00\x00'
            sock.send(auth_packet)
            time.sleep(0.5)
            
            sock.close()
            self.log("SMB tests completed", 'success')
            
        except ConnectionRefusedError:
            self.log(f"Connection refused - SMB honeypot not running on port {port}", 'error')
            self.results.append(('SMB Service', 'FAIL'))
        except socket.timeout:
            self.log("Connection timeout", 'error')
            self.results.append(('SMB Service', 'FAIL'))
        except Exception as e:
            self.log(f"SMB test error: {e}", 'error')
            self.results.append(('SMB Service', 'FAIL'))
    
    def test_http_honeypot(self, port=8000):
        """Test HTTP/Web Server honeypot"""
        self.log(f"\n{Colors.BOLD}Testing HTTP Honeypot on port {port}...{Colors.END}", 'info')
        base_url = f"http://{self.host}:{port}"
        
        tests = [
            ('Root page', '/'),
            ('Admin panel', '/admin'),
            ('File repository', '/files'),
            ('Sensitive config', '/files/config.ini'),
            ('Database file', '/files/database.sql'),
            ('Password file', '/files/passwords.txt'),
            ('API docs', '/api'),
            ('Non-existent page', '/nonexistent'),
        ]
        
        try:
            for test_name, path in tests:
                self.log(f"Test: Requesting {path}...", 'info')
                response = requests.get(f"{base_url}{path}", timeout=5)
                
                if response.status_code == 200:
                    self.log(f"{test_name}: Status {response.status_code} - Content length: {len(response.text)}", 'success')
                    self.results.append((f'HTTP {test_name}', 'PASS'))
                elif response.status_code == 404 and path == '/nonexistent':
                    self.log(f"{test_name}: Correctly returned 404", 'success')
                    self.results.append((f'HTTP {test_name}', 'PASS'))
                else:
                    self.log(f"{test_name}: Status {response.status_code}", 'warning')
                    self.results.append((f'HTTP {test_name}', 'PARTIAL'))
                
                time.sleep(0.2)
            
            # Test POST request (login simulation)
            self.log("Test: Sending POST request to /admin...", 'info')
            post_data = {'username': 'admin', 'password': 'password123'}
            response = requests.post(f"{base_url}/admin", data=post_data, timeout=5)
            if response.status_code == 200:
                self.log(f"POST request successful: {response.status_code}", 'success')
                self.results.append(('HTTP POST', 'PASS'))
            
            # Test with suspicious User-Agent
            self.log("Test: Sending request with suspicious User-Agent...", 'info')
            headers = {'User-Agent': 'sqlmap/1.0 (http://sqlmap.org)'}
            response = requests.get(f"{base_url}/admin", headers=headers, timeout=5)
            self.log(f"Suspicious User-Agent test: {response.status_code}", 'success')
            
        except requests.exceptions.ConnectionError:
            self.log(f"Connection refused - HTTP honeypot not running on port {port}", 'error')
            self.results.append(('HTTP Service', 'FAIL'))
        except Exception as e:
            self.log(f"HTTP test error: {e}", 'error')
            self.results.append(('HTTP Service', 'FAIL'))
    
    def test_ldap_honeypot(self, port=3389):
        """Test LDAP honeypot"""
        self.log(f"\n{Colors.BOLD}Testing LDAP Honeypot on port {port}...{Colors.END}", 'info')
        
        try:
            # Test 1: Connection attempt
            self.log("Test 1: Attempting connection to LDAP service...", 'info')
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.host, port))
            self.log("Successfully connected to LDAP honeypot", 'success')
            
            # Test 2: Send LDAP bind request
            self.log("Test 2: Sending LDAP bind request...", 'info')
            # Simple LDAP bind request (simplified)
            ldap_bind = b'\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00'
            sock.send(ldap_bind)
            
            response = sock.recv(1024)
            if response:
                self.log(f"Received LDAP response ({len(response)} bytes)", 'success')
                self.results.append(('LDAP Connection', 'PASS'))
            else:
                self.log("No response received", 'warning')
                self.results.append(('LDAP Connection', 'PARTIAL'))
            
            # Test 3: Send search request
            self.log("Test 3: Sending LDAP search request...", 'info')
            ldap_search = b'\x30\x25\x02\x01\x02\x63\x20\x04\x11\x64\x63\x3d\x63\x6f\x6d\x70\x61\x6e\x79'
            sock.send(ldap_search)
            time.sleep(0.5)
            
            sock.close()
            self.log("LDAP tests completed", 'success')
            
        except ConnectionRefusedError:
            self.log(f"Connection refused - LDAP honeypot not running on port {port}", 'error')
            self.results.append(('LDAP Service', 'FAIL'))
        except socket.timeout:
            self.log("Connection timeout", 'error')
            self.results.append(('LDAP Service', 'FAIL'))
        except Exception as e:
            self.log(f"LDAP test error: {e}", 'error')
            self.results.append(('LDAP Service', 'FAIL'))
    
    def test_port_scanner_simulation(self):
        """Simulate a port scanner hitting multiple services"""
        self.log(f"\n{Colors.BOLD}Simulating Basic Port Scanner Attack...{Colors.END}", 'info')
        
        ports_to_scan = [
            (4445, 'SMB Honeypot'),
            (8000, 'HTTP Honeypot'),
            (3389, 'LDAP Honeypot'),
            (22, 'SSH (should be closed)'),
            (23, 'Telnet (should be closed)'),
            (21, 'FTP (should be closed)'),
            (3306, 'MySQL (should be closed)'),
            (5432, 'PostgreSQL (should be closed)'),
            (1433, 'MSSQL (should be closed)'),
            (27017, 'MongoDB (should be closed)')
        ]
        
        open_ports = []
        closed_ports = []
        
        self.log("Scanning common ports...", 'info')
        
        for port, service in ports_to_scan:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.host, port))
                
                if result == 0:
                    self.log(f"Port {port} ({service}): OPEN", 'warning')
                    open_ports.append((port, service))
                else:
                    self.log(f"Port {port} ({service}): CLOSED", 'info')
                    closed_ports.append((port, service))
                
                sock.close()
                time.sleep(0.1)
                
            except Exception as e:
                self.log(f"Port scan error on {port}: {e}", 'error')
        
        # Summary
        self.log(f"\nPort scan complete:", 'info')
        self.log(f"  Open ports: {len(open_ports)}", 'warning')
        self.log(f"  Closed ports: {len(closed_ports)}", 'info')
        
        if len(open_ports) >= 3:
            self.log("Expected honeypot ports detected!", 'success')
            self.results.append(('Basic Port Scan', 'PASS'))
        else:
            self.log("Not all honeypot services detected", 'warning')
            self.results.append(('Basic Port Scan', 'PARTIAL'))
    
    def test_aggressive_port_scan(self):
        """Simulate aggressive port scanning (SYN scan style)"""
        self.log(f"\n{Colors.BOLD}Simulating Aggressive Port Scan (Rapid)...{Colors.END}", 'info')
        
        # Scan a range of ports rapidly
        start_port = 4400
        end_port = 4500
        scan_results = {'open': [], 'closed': []}
        
        self.log(f"Scanning ports {start_port}-{end_port} rapidly...", 'info')
        
        for port in range(start_port, end_port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)  # Very short timeout for aggressive scan
                result = sock.connect_ex((self.host, port))
                
                if result == 0:
                    scan_results['open'].append(port)
                    self.log(f"Found open port: {port}", 'warning')
                else:
                    scan_results['closed'].append(port)
                
                sock.close()
                # No sleep - aggressive scanning
                
            except Exception as e:
                pass  # Ignore errors in aggressive scan
        
        self.log(f"Aggressive scan complete: {len(scan_results['open'])} open ports found", 'info')
        
        if 4445 in scan_results['open']:
            self.log("SMB honeypot detected during aggressive scan!", 'success')
            self.results.append(('Aggressive Port Scan', 'PASS'))
        else:
            self.results.append(('Aggressive Port Scan', 'PARTIAL'))
    
    def test_stealth_port_scan(self):
        """Simulate stealth port scanning (slow, random intervals)"""
        self.log(f"\n{Colors.BOLD}Simulating Stealth Port Scan (Slow)...{Colors.END}", 'info')
        
        ports_to_check = [4445, 8000, 3389, 445, 80, 389, 443, 8080]
        random.shuffle(ports_to_check)  # Random order
        
        self.log("Scanning ports with random delays (stealth mode)...", 'info')
        
        detected_services = []
        
        for port in ports_to_check:
            try:
                # Random delay between 1-3 seconds
                delay = random.uniform(1.0, 3.0)
                self.log(f"Waiting {delay:.1f}s before scanning port {port}...", 'info')
                time.sleep(delay)
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.host, port))
                
                if result == 0:
                    self.log(f"Port {port}: OPEN (stealth)", 'warning')
                    detected_services.append(port)
                
                sock.close()
                
            except Exception as e:
                pass
        
        self.log(f"Stealth scan detected {len(detected_services)} services", 'info')
        
        if len(detected_services) > 0:
            self.results.append(('Stealth Port Scan', 'PASS'))
        else:
            self.results.append(('Stealth Port Scan', 'FAIL'))
    
    def test_service_banner_grabbing(self):
        """Test banner grabbing on discovered ports"""
        self.log(f"\n{Colors.BOLD}Testing Service Banner Grabbing...{Colors.END}", 'info')
        
        services = [
            (4445, 'SMB'),
            (8000, 'HTTP'),
            (3389, 'LDAP')
        ]
        
        for port, service_name in services:
            try:
                self.log(f"Attempting banner grab on port {port} ({service_name})...", 'info')
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((self.host, port))
                
                # Send generic probe
                sock.send(b'\r\n\r\n')
                time.sleep(0.5)
                
                # Try to receive banner
                try:
                    banner = sock.recv(1024)
                    if banner:
                        self.log(f"Received banner ({len(banner)} bytes) from {service_name}", 'success')
                    else:
                        self.log(f"No banner from {service_name}", 'info')
                except socket.timeout:
                    self.log(f"No banner response from {service_name}", 'info')
                
                sock.close()
                time.sleep(0.5)
                
            except ConnectionRefusedError:
                self.log(f"Port {port} refused connection", 'warning')
            except Exception as e:
                self.log(f"Banner grab error on port {port}: {e}", 'error')
        
        self.results.append(('Banner Grabbing', 'PASS'))
    
    def test_nmap_style_scan(self):
        """Simulate nmap-style comprehensive scan"""
        self.log(f"\n{Colors.BOLD}Simulating Nmap-Style Service Detection...{Colors.END}", 'info')
        
        nmap_user_agent = "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org)"
        
        # Test HTTP with nmap user agent
        self.log("Testing HTTP service with Nmap user-agent...", 'info')
        try:
            headers = {'User-Agent': nmap_user_agent}
            response = requests.get(f"http://{self.host}:8000/", headers=headers, timeout=5)
            self.log(f"HTTP responded with {response.status_code}", 'success')
            
            # Try common paths that nmap would probe
            nmap_paths = ['/', '/robots.txt', '/sitemap.xml', '/.well-known/']
            for path in nmap_paths:
                try:
                    r = requests.get(f"http://{self.host}:8000{path}", headers=headers, timeout=3)
                    self.log(f"Probed {path}: {r.status_code}", 'info')
                    time.sleep(0.3)
                except:
                    pass
            
        except Exception as e:
            self.log(f"Nmap-style scan error: {e}", 'error')
        
        # Test multiple ports in sequence (like nmap would)
        self.log("Testing port sequence...", 'info')
        nmap_common_ports = [4445, 8000, 3389, 22, 80, 443, 445]
        
        for port in nmap_common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.host, port))
                sock.close()
                time.sleep(0.2)
            except:
                pass
        
        self.log("Nmap-style scan completed", 'success')
        self.results.append(('Nmap-Style Scan', 'PASS'))
    
    def test_brute_force_simulation(self, port=8000):
        """Simulate brute force login attempts"""
        self.log(f"\n{Colors.BOLD}Simulating Brute Force Attack...{Colors.END}", 'info')
        
        base_url = f"http://{self.host}:{port}"
        credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('root', 'root'),
            ('administrator', 'password123'),
        ]
        
        try:
            for username, password in credentials:
                self.log(f"Attempting login: {username}/{password}", 'info')
                post_data = {'username': username, 'password': password}
                response = requests.post(f"{base_url}/admin", data=post_data, timeout=5)
                time.sleep(0.5)
            
            self.log("Brute force simulation completed", 'success')
            self.results.append(('Brute Force Simulation', 'PASS'))
            
        except Exception as e:
            self.log(f"Brute force test error: {e}", 'error')
            self.results.append(('Brute Force Simulation', 'FAIL'))
    
    def test_sql_injection_simulation(self, port=8000):
        """Simulate SQL injection attempts"""
        self.log(f"\n{Colors.BOLD}Simulating SQL Injection Attack...{Colors.END}", 'info')
        
        base_url = f"http://{self.host}:{port}"
        payloads = [
            "' OR '1'='1",
            "admin'--",
            "' UNION SELECT * FROM users--",
            "1'; DROP TABLE users--",
        ]
        
        try:
            for payload in payloads:
                self.log(f"Testing payload: {payload[:30]}...", 'info')
                post_data = {'username': payload, 'password': 'test'}
                response = requests.post(f"{base_url}/admin", data=post_data, timeout=5)
                time.sleep(0.3)
            
            self.log("SQL injection simulation completed", 'success')
            self.results.append(('SQL Injection Simulation', 'PASS'))
            
        except Exception as e:
            self.log(f"SQL injection test error: {e}", 'error')
            self.results.append(('SQL Injection Simulation', 'FAIL'))
    
    def print_summary(self):
        """Print test results summary"""
        self.log(f"\n{Colors.BOLD}{'='*60}{Colors.END}", 'info')
        self.log(f"{Colors.BOLD}TEST SUMMARY{Colors.END}", 'info')
        self.log(f"{Colors.BOLD}{'='*60}{Colors.END}", 'info')
        
        passed = sum(1 for _, result in self.results if result == 'PASS')
        failed = sum(1 for _, result in self.results if result == 'FAIL')
        partial = sum(1 for _, result in self.results if result == 'PARTIAL')
        
        for test_name, result in self.results:
            if result == 'PASS':
                self.log(f"{test_name}: {result}", 'success')
            elif result == 'FAIL':
                self.log(f"{test_name}: {result}", 'error')
            else:
                self.log(f"{test_name}: {result}", 'warning')
        
        self.log(f"\n{Colors.BOLD}Total: {len(self.results)} | Pass: {passed} | Fail: {failed} | Partial: {partial}{Colors.END}", 'info')
        
        if failed == 0:
            self.log(f"\n{Colors.GREEN}{Colors.BOLD}All honeypot services are working correctly!{Colors.END}", 'success')
        else:
            self.log(f"\n{Colors.YELLOW}{Colors.BOLD}Some services may not be running. Check the logs above.{Colors.END}", 'warning')
        
        self.log(f"\n{Colors.BOLD}Next Steps:{Colors.END}", 'info')
        self.log("1. Check your honeypot logs for captured events", 'info')
        self.log("2. Verify events were sent to Kafka/Webhook", 'info')
        self.log("3. Review event details and severity levels", 'info')
        self.log(f"{Colors.BOLD}{'='*60}{Colors.END}\n", 'info')


def print_menu():
    """Display the test menu"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}")
    print("HONEYPOT TESTING SUITE - TEST MENU")
    print(f"{'='*60}{Colors.END}\n")
    
    print(f"{Colors.BOLD}Service Tests:{Colors.END}")
    print(f"  {Colors.CYAN}1{Colors.END} - Test SMB Honeypot")
    print(f"  {Colors.CYAN}2{Colors.END} - Test HTTP Honeypot")
    print(f"  {Colors.CYAN}3{Colors.END} - Test LDAP Honeypot")
    
    print(f"\n{Colors.BOLD}Port Scanning Tests:{Colors.END}")
    print(f"  {Colors.CYAN}4{Colors.END} - Basic Port Scanner Simulation")
    print(f"  {Colors.CYAN}5{Colors.END} - Aggressive Port Scan (Fast)")
    print(f"  {Colors.CYAN}6{Colors.END} - Stealth Port Scan (Slow)")
    print(f"  {Colors.CYAN}7{Colors.END} - Service Banner Grabbing")
    print(f"  {Colors.CYAN}8{Colors.END} - Nmap-Style Scan")
    
    print(f"\n{Colors.BOLD}Attack Simulations:{Colors.END}")
    print(f"  {Colors.CYAN}9{Colors.END} - Brute Force Attack")
    print(f"  {Colors.CYAN}10{Colors.END} - SQL Injection Attack")
    
    print(f"\n{Colors.BOLD}All Tests:{Colors.END}")
    print(f"  {Colors.CYAN}11{Colors.END} - Run All Service Tests")
    print(f"  {Colors.CYAN}12{Colors.END} - Run All Port Scanning Tests")
    print(f"  {Colors.CYAN}13{Colors.END} - Run All Attack Simulations")
    print(f"  {Colors.CYAN}14{Colors.END} - Run ALL Tests")
    
    print(f"\n  {Colors.RED}0{Colors.END} - Exit")
    print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")


def run_interactive_menu(tester):
    """Run the interactive test menu"""
    while True:
        print_menu()
        choice = input(f"\n{Colors.BOLD}Select test number: {Colors.END}").strip()
        
        if choice == '0':
            print(f"\n{Colors.GREEN}Exiting...{Colors.END}\n")
            break
        elif choice == '1':
            tester.test_smb_honeypot()
        elif choice == '2':
            tester.test_http_honeypot()
        elif choice == '3':
            tester.test_ldap_honeypot()
        elif choice == '4':
            tester.test_port_scanner_simulation()
        elif choice == '5':
            tester.test_aggressive_port_scan()
        elif choice == '6':
            tester.test_stealth_port_scan()
        elif choice == '7':
            tester.test_service_banner_grabbing()
        elif choice == '8':
            tester.test_nmap_style_scan()
        elif choice == '9':
            tester.test_brute_force_simulation()
        elif choice == '10':
            tester.test_sql_injection_simulation()
        elif choice == '11':
            print(f"\n{Colors.MAGENTA}{Colors.BOLD}Running All Service Tests...{Colors.END}")
            tester.test_smb_honeypot()
            tester.test_http_honeypot()
            tester.test_ldap_honeypot()
        elif choice == '12':
            print(f"\n{Colors.MAGENTA}{Colors.BOLD}Running All Port Scanning Tests...{Colors.END}")
            tester.test_port_scanner_simulation()
            tester.test_aggressive_port_scan()
            tester.test_stealth_port_scan()
            tester.test_service_banner_grabbing()
            tester.test_nmap_style_scan()
        elif choice == '13':
            print(f"\n{Colors.MAGENTA}{Colors.BOLD}Running All Attack Simulations...{Colors.END}")
            tester.test_brute_force_simulation()
            tester.test_sql_injection_simulation()
        elif choice == '14':
            print(f"\n{Colors.MAGENTA}{Colors.BOLD}Running ALL Tests...{Colors.END}")
            tester.test_smb_honeypot()
            tester.test_http_honeypot()
            tester.test_ldap_honeypot()
            tester.test_port_scanner_simulation()
            tester.test_aggressive_port_scan()
            tester.test_stealth_port_scan()
            tester.test_service_banner_grabbing()
            tester.test_nmap_style_scan()
            tester.test_brute_force_simulation()
            tester.test_sql_injection_simulation()
        else:
            print(f"{Colors.RED}Invalid choice. Please try again.{Colors.END}")
            continue
        
        # Ask if user wants to see summary
        if tester.results:
            show_summary = input(f"\n{Colors.BOLD}Show test summary? (y/n): {Colors.END}").strip().lower()
            if show_summary == 'y':
                tester.print_summary()
                tester.results = []  # Reset for next test


def main():
    """Run all honeypot tests"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}")
    print("HONEYPOT TESTING SUITE")
    print(f"{'='*60}{Colors.END}\n")
    
    # Determine host
    if len(sys.argv) > 1:
        host = sys.argv[1]
        print(f"Testing honeypot at: {Colors.CYAN}{host}{Colors.END}\n")
    else:
        host = 'localhost'
        print(f"Testing honeypot at: {Colors.CYAN}{host}{Colors.END}")
        print(f"{Colors.YELLOW}(use 'python tester.py <hostname>' for remote testing){Colors.END}\n")
    
    tester = HoneypotTester(host)
    
    # Check if running in interactive mode or batch mode
    if len(sys.argv) > 2 and sys.argv[2] == '--auto':
        # Run all tests automatically
        print(f"{Colors.MAGENTA}{Colors.BOLD}Running in AUTO mode - executing all tests...{Colors.END}\n")
        tester.test_smb_honeypot(port=4445)
        tester.test_http_honeypot(port=8000)
        tester.test_ldap_honeypot(port=3389)
        tester.test_port_scanner_simulation()
        tester.test_aggressive_port_scan()
        tester.test_stealth_port_scan()
        tester.test_service_banner_grabbing()
        tester.test_nmap_style_scan()
        tester.test_brute_force_simulation(port=8000)
        tester.test_sql_injection_simulation(port=8000)
        tester.print_summary()
    else:
        # Run interactive menu
        run_interactive_menu(tester)


if __name__ == '__main__':
    main()
