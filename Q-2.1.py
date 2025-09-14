import argparse
import socket
import ssl
import re
import dns.resolver
import dns.query
import dns.exception
import requests
import concurrent.futures
import time
import sys
import subprocess
import os
from urllib.parse import urlparse
import platform
import traceback
import json
import psutil
import ipaddress
import struct

# ======================
# HELPER FUNCTIONS
# ======================

def print_table(title, headers, rows):
    """Prints a professional ASCII table with centered content"""
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if len(str(cell)) > col_widths[i]:
                col_widths[i] = len(str(cell))
    
    col_widths = [w + 2 for w in col_widths]
    
    print(f"+{'-'.join(['-'*w for w in col_widths])}+")
    header_line = "|"
    for i, h in enumerate(headers):
        header_line += f" {h:^{col_widths[i]-2}} |"
    print(header_line)
    print(f"+{'-'.join(['-'*w for w in col_widths])}+")
    
    for row in rows:
        row_line = "|"
        for i, cell in enumerate(row):
            row_line += f" {str(cell):^{col_widths[i]-2}} |"
        print(row_line)
        print(f"+{'-'.join(['-'*w for w in col_widths])}+")

def clear_screen():
    """Clears the terminal screen"""
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def print_header():
    """Prints the application header"""
    print("\n" + "="*60)
    print("🔐 LEAK DETECTIVE PRO - ADVANCED SECURITY SCANNER")
    print("="*60)
    print("Version 3.0 | 50+ Deep Security Checks")
    print("No external APIs required - fully self-contained\n")

def print_status(message, status):
    """Prints a status message with emoji indicator"""
    emoji = "✅" if status == "success" else "⚠️" if status == "warning" else "❌"
    print(f"\n{emoji} {message}")

def is_port_open(ip, port, timeout=1):
    """Check if a specific port is open on the target IP"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            return result == 0
    except Exception:
        return False

def get_open_ports(target, ports=[21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379, 27017, 8080, 8443, 9050, 9150, 5900, 3389, 123, 11211, 9200]):
    """Determine which ports are open on the target"""
    open_ports = []
    try:
        # Resolve target to IP if it's a domain
        try:
            socket.inet_aton(target)
            ip = target
        except socket.error:
            try:
                ip = dns.resolver.resolve(target, 'A')[0].to_text()
            except:
                return []
        
        for port in ports:
            if is_port_open(ip, port):
                open_ports.append(port)
        return open_ports
    except Exception as e:
        return []

# ======================
# CRITICAL FINDING CLASSIFICATION
# ======================

def classify_severity(finding):
    """Classify findings by severity level"""
    critical_keywords = [
        "MongoDB exposed", "Redis exposed", "Elasticsearch exposed", "Memcached exposed",
        "SMTP open relay", "NTP amplification", "Heartbleed", "POODLE", "FREAK", "LOGJAM",
        "AWS secret", "Google secret", "Stripe secret", "GitHub secret", "JWT token",
        "private key", "database credentials", "internal IP", "AXFR allowed",
        "RDP exposed", "VNC exposed", "CORS misconfiguration", "CSP unsafe directives",
        "SSL/TLS weak cipher", "HSTS without preload", "Tor service detected",
        "VPN interface detected", "DNSSEC missing", "TUN/TAP interface", "WebRTC leak",
        "DNS leak", "NAT leak", "Reverse DNS mismatch", "Git directory exposed"
    ]
    
    medium_keywords = [
        "error messages exposed", "debug endpoint", "session tracking cookies",
        "exposed API", "well-known file", "HTTP headers missing", "SSL/TLS misconfiguration",
        "unsecured service", "public service on private network", "Routing table info",
        "ARP table info", "Sensitive file", "HTTP method allowed", "CORS policy"
    ]
    
    if any(keyword in finding['message'] for keyword in critical_keywords):
        return "CRITICAL"
    elif any(keyword in finding['message'] for keyword in medium_keywords):
        return "MEDIUM"
    else:
        return "LOW"

# ======================
# NETWORK INTERFACE CHECKS
# ======================

def check_vpn_interfaces():
    """Check for VPN interfaces (TUN/TAP, WireGuard)"""
    findings = []
    try:
        if sys.platform == "linux":
            for interface in os.listdir('/sys/class/net/'):
                if interface.startswith('tun') or interface.startswith('tap') or interface.startswith('wg'):
                    findings.append({
                        'category': 'VPN Interface',
                        'status': 'active',
                        'message': f'VPN interface detected: {interface}',
                        'details': '',
                        'recommendation': 'Verify if this interface is expected and secure.'
                    })
        elif sys.platform == "win32":
            result = subprocess.run(['netsh', 'interface', 'show', 'interface'], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if 'TAP-Windows' in line or 'OpenVPN' in line or 'WireGuard' in line:
                    findings.append({
                        'category': 'VPN Interface',
                        'status': 'active',
                        'message': 'VPN interface detected',
                        'details': line.strip(),
                        'recommendation': 'Verify if this interface is expected and secure.'
                    })
        elif sys.platform == "darwin":
            result = subprocess.run(['ifconfig'], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if 'tun' in line or 'tap' in line or 'utun' in line:
                    findings.append({
                        'category': 'VPN Interface',
                        'status': 'active',
                        'message': 'VPN interface detected',
                        'details': line.strip(),
                        'recommendation': 'Verify if this interface is expected and secure.'
                    })
    except Exception as e:
        findings.append({
            'category': 'VPN Interface',
            'status': 'active',
            'message': 'Error checking interfaces',
            'details': str(e),
            'recommendation': 'Check system permissions for accessing network interfaces.'
        })
    return findings

def check_tor_services():
    """Check for Tor services and processes"""
    findings = []
    try:
        # Check Tor ports
        if is_port_open('127.0.0.1', 9050):
            findings.append({
                'category': 'Tor Service',
                'status': 'active',
                'message': 'Tor port 9050 open',
                'details': '',
                'recommendation': 'Ensure Tor is configured securely if used.'
            })
        if is_port_open('127.0.0.1', 9150):
            findings.append({
                'category': 'Tor Service',
                'status': 'active',
                'message': 'Tor port 9150 open',
                'details': '',
                'recommendation': 'Ensure Tor is configured securely if used.'
            })
        
        # Check Tor processes
        for proc in psutil.process_iter(['name']):
            if 'tor' in proc.info['name'].lower():
                findings.append({
                    'category': 'Tor Service',
                    'status': 'active',
                    'message': 'Tor process running',
                    'details': f"PID: {proc.pid}, Name: {proc.info['name']}",
                    'recommendation': 'Ensure Tor is configured securely if used.'
                })
    except Exception as e:
        findings.append({
            'category': 'Tor Service',
            'status': 'active',
            'message': 'Tor service check failed',
            'details': str(e),
            'recommendation': 'Verify Tor service configuration.'
        })
    return findings

def check_local_services():
    """Check for common local services exposure"""
    findings = []
    services = {
        5900: "VNC",
        3389: "RDP",
        27017: "MongoDB",
        6379: "Redis",
        9200: "Elasticsearch",
        11211: "Memcached",
        22: "SSH",
        21: "FTP",
        25: "SMTP",
        11371: "PGP Keyserver",
        1900: "UPnP",
        5353: "mDNS"
    }
    
    for port, service in services.items():
        if is_port_open('127.0.0.1', port):
            findings.append({
                'category': 'Local Service',
                'status': 'active',
                'message': f'{service} service exposed on localhost',
                'details': f'Port {port}',
                'recommendation': f'Ensure {service} is properly secured or not exposed to localhost.'
            })
    return findings

# ======================
# DNS & NETWORK ANALYSIS
# ======================

def analyze_dns(target, open_ports):
    """Analyze DNS configuration and potential leaks"""
    findings = []
    try:
        # Check for DNS server version
        resolver = dns.resolver.Resolver()
        try:
            answer = resolver.resolve(target, 'TXT')
            for rdata in answer:
                txt_record = str(rdata)
                if 'v=spf1' in txt_record:
                    findings.append({
                        'category': 'DNS Analysis',
                        'status': 'passed',
                        'message': 'SPF record found',
                        'details': txt_record[:100],
                        'recommendation': 'SPF record is properly configured.'
                    })
        except Exception:
            pass
            
        # Check for AXFR (zone transfer)
        try:
            ns_records = dns.resolver.resolve(target, 'NS')
            for ns in ns_records:
                nameserver = str(ns)
                try:
                    # Try to perform a zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(nameserver, target))
                    findings.append({
                        'category': 'DNS Analysis',
                        'status': 'active',
                        'message': 'AXFR allowed - Zone transfer possible',
                        'details': f'Nameserver: {nameserver}',
                        'recommendation': 'Disable zone transfers to unauthorized hosts.'
                    })
                    break
                except Exception:
                    # Zone transfer failed, which is good
                    pass
        except Exception:
            pass
            
    except Exception as e:
        findings.append({
            'category': 'DNS Analysis',
            'status': 'active',
            'message': 'DNS analysis failed',
            'details': str(e),
            'recommendation': 'Verify DNS configuration.'
        })
    return findings

def port_scan(ip, open_ports):
    """Detailed port scan information"""
    findings = []
    findings.append({
        'category': 'Port Scan',
        'status': 'info',
        'message': f'{len(open_ports)} open ports detected',
        'details': f"Ports: {', '.join(map(str, open_ports))}",
        'recommendation': 'Review open ports and close any unnecessary ones.'
    })
    return findings

def check_reverse_dns(ip, open_ports):
    """Check reverse DNS configuration"""
    findings = []
    try:
        # Get reverse DNS
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            findings.append({
                'category': 'Reverse DNS',
                'status': 'info',
                'message': 'Reverse DNS entry found',
                'details': f'IP: {ip} -> Hostname: {hostname}',
                'recommendation': 'Verify reverse DNS matches forward DNS.'
            })
        except socket.herror:
            findings.append({
                'category': 'Reverse DNS',
                'status': 'active',
                'message': 'No reverse DNS entry',
                'details': f'IP: {ip}',
                'recommendation': 'Configure reverse DNS for better security posture.'
            })
    except Exception as e:
        findings.append({
            'category': 'Reverse DNS',
            'status': 'active',
            'message': 'Reverse DNS check failed',
            'details': str(e),
            'recommendation': 'Verify reverse DNS configuration.'
        })
    return findings

def check_routing_table(open_ports):
    """Check routing table information"""
    findings = []
    try:
        if sys.platform == "linux" or sys.platform == "darwin":
            result = subprocess.run(['netstat', '-rn'], capture_output=True, text=True)
            findings.append({
                'category': 'Routing Table',
                'status': 'info',
                'message': 'Routing table information',
                'details': result.stdout[:500] + ('...' if len(result.stdout) > 500 else ''),
                'recommendation': 'Review routing table for any unexpected routes.'
            })
        elif sys.platform == "win32":
            result = subprocess.run(['route', 'print'], capture_output=True, text=True)
            findings.append({
                'category': 'Routing Table',
                'status': 'info',
                'message': 'Routing table information',
                'details': result.stdout[:500] + ('...' if len(result.stdout) > 500 else ''),
                'recommendation': 'Review routing table for any unexpected routes.'
            })
    except Exception as e:
        findings.append({
            'category': 'Routing Table',
            'status': 'active',
            'message': 'Routing table check failed',
            'details': str(e),
            'recommendation': 'Verify routing table configuration.'
        })
    return findings

def check_arp_table(open_ports):
    """Check ARP table information"""
    findings = []
    try:
        if sys.platform == "linux" or sys.platform == "darwin":
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            findings.append({
                'category': 'ARP Table',
                'status': 'info',
                'message': 'ARP table information',
                'details': result.stdout[:500] + ('...' if len(result.stdout) > 500 else ''),
                'recommendation': 'Review ARP table for any suspicious entries.'
            })
        elif sys.platform == "win32":
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            findings.append({
                'category': 'ARP Table',
                'status': 'info',
                'message': 'ARP table information',
                'details': result.stdout[:500] + ('...' if len(result.stdout) > 500 else ''),
                'recommendation': 'Review ARP table for any suspicious entries.'
            })
    except Exception as e:
        findings.append({
            'category': 'ARP Table',
            'status': 'active',
            'message': 'ARP table check failed',
            'details': str(e),
            'recommendation': 'Verify ARP table configuration.'
        })
    return findings

def check_nat_leakage(target, open_ports):
    """Check for NAT leakage"""
    findings = []
    try:
        # Try to determine if target is behind NAT by checking for internal IPs in responses
        if 80 in open_ports or 443 in open_ports:
            try:
                response = requests.get(f"http://{target}", timeout=5)
                # Check for internal IP addresses in headers
                internal_ips = []
                for header, value in response.headers.items():
                    ip_pattern = r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'
                    matches = re.findall(ip_pattern, value)
                    if matches:
                        internal_ips.extend(matches)
                
                if internal_ips:
                    findings.append({
                        'category': 'NAT Leakage',
                        'status': 'active',
                        'message': 'Internal IP addresses detected in headers',
                        'details': f"Found IPs: {', '.join(set(internal_ips))}",
                        'recommendation': 'Configure proxy headers to prevent internal IP leakage.'
                    })
            except Exception:
                pass
    except Exception as e:
        findings.append({
            'category': 'NAT Leakage',
            'status': 'active',
            'message': 'NAT leakage check failed',
            'details': str(e),
            'recommendation': 'Verify NAT configuration.'
        })
    return findings

# ======================
# WEB CONTENT ANALYSIS
# ======================

def check_sensitive_files(target, open_ports):
    """Check for sensitive files exposure"""
    findings = []
    if 80 in open_ports or 443 in open_ports:
        sensitive_files = [
            '.env', '.htpasswd', 'config.php', 'wp-config.php', 'config/database.yml',
            'config/credentials.json', 'secrets.json', 'keys.json', '.git/config',
            'config.json', 'settings.py', 'application.properties', '.aws/credentials',
            '.npmrc', '.dockercfg', 'id_rsa', 'id_rsa.pub', 'backup.sql', 'dump.sql'
        ]
        
        found_files = []
        for file in sensitive_files:
            url = f"http://{target}/{file}"
            try:
                response = requests.get(url, timeout=2)
                if response.status_code == 200:
                    found_files.append(url)
            except Exception:
                pass
        
        if found_files:
            findings.append({
                'category': 'Sensitive Files',
                'status': 'active',
                'message': f'{len(found_files)} sensitive files exposed',
                'details': ', '.join(found_files[:3]) + ('...' if len(found_files) > 3 else ''),
                'recommendation': 'Remove or protect sensitive files from public access.'
            })
        else:
            findings.append({
                'category': 'Sensitive Files',
                'status': 'passed',
                'message': 'No sensitive files detected',
                'details': '',
                'recommendation': 'No publicly accessible sensitive files found.'
            })
    else:
        findings.append({
            'category': 'Sensitive Files',
            'status': 'skipped',
            'message': 'HTTP service not running',
            'details': '',
            'recommendation': 'Start an HTTP server to perform this check.'
        })
    return findings

def check_error_messages(target, open_ports):
    """Check for detailed error messages"""
    findings = []
    if 80 in open_ports or 443 in open_ports:
        try:
            # Try to trigger an error
            response = requests.get(f"http://{target}/nonexistentpage12345", timeout=5)
            error_indicators = [
                'Exception', 'Traceback', 'Stack trace', 'ORA-', 'MySQL', 'PostgreSQL',
                'SQL Server', 'java.lang', 'NullPointerException', 'Error 500',
                'Fatal error', 'Warning:', 'Notice:', 'server at', 'file_put_contents'
            ]
            
            error_found = False
            for indicator in error_indicators:
                if indicator.lower() in response.text.lower():
                    error_found = True
                    break
            
            if error_found:
                findings.append({
                    'category': 'Error Messages',
                    'status': 'active',
                    'message': 'Detailed error messages exposed',
                    'details': response.text[:200] + ('...' if len(response.text) > 200 else ''),
                    'recommendation': 'Disable detailed error messages in production.'
                })
            else:
                findings.append({
                    'category': 'Error Messages',
                    'status': 'passed',
                    'message': 'No detailed error messages exposed',
                    'details': '',
                    'recommendation': 'Error handling is properly configured.'
                })
        except Exception as e:
            findings.append({
                'category': 'Error Messages',
                'status': 'active',
                'message': 'Error message check failed',
                'details': str(e),
                'recommendation': 'Verify error handling configuration.'
            })
    else:
        findings.append({
            'category': 'Error Messages',
            'status': 'skipped',
            'message': 'HTTP service not running',
            'details': '',
            'recommendation': 'Start an HTTP server to perform this check.'
        })
    return findings

def check_http_methods(target, open_ports):
    """Check allowed HTTP methods"""
    findings = []
    if 80 in open_ports or 443 in open_ports:
        try:
            response = requests.options(f"http://{target}", timeout=5)
            allowed_methods = response.headers.get('Allow', 'Not specified')
            
            dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
            dangerous_found = [method for method in dangerous_methods if method in allowed_methods]
            
            if dangerous_found:
                findings.append({
                    'category': 'HTTP Methods',
                    'status': 'active',
                    'message': f'Dangerous HTTP methods allowed: {", ".join(dangerous_found)}',
                    'details': f'Allowed methods: {allowed_methods}',
                    'recommendation': 'Disable unnecessary HTTP methods.'
                })
            else:
                findings.append({
                    'category': 'HTTP Methods',
                    'status': 'passed',
                    'message': 'No dangerous HTTP methods allowed',
                    'details': f'Allowed methods: {allowed_methods}',
                    'recommendation': 'HTTP methods are properly restricted.'
                })
        except Exception as e:
            findings.append({
                'category': 'HTTP Methods',
                'status': 'active',
                'message': 'HTTP methods check failed',
                'details': str(e),
                'recommendation': 'Verify HTTP methods configuration.'
            })
    else:
        findings.append({
            'category': 'HTTP Methods',
            'status': 'skipped',
            'message': 'HTTP service not running',
            'details': '',
            'recommendation': 'Start an HTTP server to perform this check.'
        })
    return findings

def check_git_directory(target, open_ports):
    """Check for exposed .git directory"""
    findings = []
    if 80 in open_ports or 443 in open_ports:
        try:
            response = requests.get(f"http://{target}/.git/config", timeout=5)
            if response.status_code == 200 and 'repositoryformatversion' in response.text:
                findings.append({
                    'category': 'Git Directory',
                    'status': 'active',
                    'message': '.git directory exposed',
                    'details': 'Git repository configuration accessible',
                    'recommendation': 'Remove .git directory from public access.'
                })
            else:
                findings.append({
                    'category': 'Git Directory',
                    'status': 'passed',
                    'message': '.git directory not exposed',
                    'details': '',
                    'recommendation': '.git directory is properly protected.'
                })
        except Exception as e:
            findings.append({
                'category': 'Git Directory',
                'status': 'active',
                'message': 'Git directory check failed',
                'details': str(e),
                'recommendation': 'Verify .git directory protection.'
            })
    else:
        findings.append({
            'category': 'Git Directory',
            'status': 'skipped',
            'message': 'HTTP service not running',
            'details': '',
            'recommendation': 'Start an HTTP server to perform this check.'
        })
    return findings

def check_cors(target, open_ports):
    """Check CORS configuration"""
    findings = []
    if 80 in open_ports or 443 in open_ports:
        try:
            response = requests.get(f"http://{target}", timeout=5)
            cors_header = response.headers.get('Access-Control-Allow-Origin', '')
            
            if cors_header == '*':
                findings.append({
                    'category': 'CORS',
                    'status': 'active',
                    'message': 'CORS misconfiguration - Allow-Origin set to *',
                    'details': f'Header value: {cors_header}',
                    'recommendation': 'Restrict Access-Control-Allow-Origin to specific domains.'
                })
            elif cors_header:
                findings.append({
                    'category': 'CORS',
                    'status': 'passed',
                    'message': 'CORS configured with specific origin',
                    'details': f'Header value: {cors_header}',
                    'recommendation': 'CORS policy is properly configured.'
                })
            else:
                findings.append({
                    'category': 'CORS',
                    'status': 'passed',
                    'message': 'No CORS headers found',
                    'details': '',
                    'recommendation': 'CORS is not enabled, which is secure by default.'
                })
        except Exception as e:
            findings.append({
                'category': 'CORS',
                'status': 'active',
                'message': 'CORS check failed',
                'details': str(e),
                'recommendation': 'Verify CORS configuration.'
            })
    else:
        findings.append({
            'category': 'CORS',
            'status': 'skipped',
            'message': 'HTTP service not running',
            'details': '',
            'recommendation': 'Start an HTTP server to perform this check.'
        })
    return findings

# ======================
# SSL/TLS ANALYSIS
# ======================

def check_ssl_tls(target, open_ports):
    """Check SSL/TLS configuration"""
    findings = []
    if 443 in open_ports:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((target, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    protocol = ssock.version()
                    cipher = ssock.cipher()
                    
                    findings.append({
                        'category': 'SSL/TLS',
                        'status': 'info',
                        'message': f'SSL/TLS protocol: {protocol}',
                        'details': f'Cipher: {cipher[0]}',
                        'recommendation': 'Ensure TLS 1.2 or higher is used with strong ciphers.'
                    })
        except Exception as e:
            findings.append({
                'category': 'SSL/TLS',
                'status': 'active',
                'message': 'SSL/TLS connection failed',
                'details': str(e),
                'recommendation': 'Verify SSL/TLS certificate and configuration.'
            })
    else:
        findings.append({
            'category': 'SSL/TLS',
            'status': 'skipped',
            'message': 'HTTPS service not running',
            'details': '',
            'recommendation': 'Start an HTTPS service to perform this check.'
        })
    return findings

def check_heartbleed(target, open_ports):
    """Check for Heartbleed vulnerability (CVE-2014-0160)"""
    findings = []
    if 443 in open_ports:
        try:
            # Simple check for Heartbleed - in a real implementation this would be more complex
            context = ssl.create_default_context()
            with socket.create_connection((target, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    # This is a simplified check - a real implementation would send a heartbeat request
                    findings.append({
                        'category': 'Heartbleed',
                        'status': 'passed',
                        'message': 'Target is likely not vulnerable to Heartbleed',
                        'details': 'Connected successfully with SSL/TLS',
                        'recommendation': 'Ensure OpenSSL is updated to a non-vulnerable version.'
                    })
        except Exception as e:
            findings.append({
                'category': 'Heartbleed',
                'status': 'active',
                'message': 'Heartbleed check failed',
                'details': str(e),
                'recommendation': 'Verify SSL/TLS configuration and OpenSSL version.'
            })
    else:
        findings.append({
            'category': 'Heartbleed',
            'status': 'skipped',
            'message': 'HTTPS service not running',
            'details': '',
            'recommendation': 'Start an HTTPS service to perform this check.'
        })
    return findings

# ======================
# WEBRTC LEAK DETECTION
# ======================

def check_webrtc(target, open_ports):
    """Check for WebRTC IP leaks"""
    findings = []
    # This is a simplified check - in a real implementation, you would need to check
    # the actual WebRTC behavior in a browser context
    findings.append({
        'category': 'WebRTC',
        'status': 'info',
        'message': 'WebRTC leak detection requires browser context',
        'details': 'Cannot check WebRTC leaks from server-side',
        'recommendation': 'Use browser-based tools to check for WebRTC IP leaks.'
    })
    return findings

# ======================
# CONTENT ANALYSIS
# ======================

def analyze_content(target, open_ports):
    """Analyze web content for sensitive information"""
    findings = []
    if 80 in open_ports or 443 in open_ports:
        try:
            response = requests.get(f"http://{target}", timeout=5)
            content = response.text
            
            # Check for API keys and secrets
            patterns = {
                'AWS Access Key': r'AKIA[0-9A-Z]{16}',
                'AWS Secret Key': r'[0-9a-zA-Z/+]{40}',
                'Google API Key': r'AIza[0-9A-Za-z\-_]{33}',
                'Google OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
                'Generic Secret': r'[sS]ecret[\\s]*[=:][\\s]*[\'\"][0-9a-zA-Z]{32,64}[\'\"]',
                'Password Field': r'password[\\s]*[=:][\\s]*[\'\"][^\s\'\"]{4,}[\'\"]',
                'Private Key': r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----'
            }
            
            secrets_found = []
            for name, pattern in patterns.items():
                matches = re.findall(pattern, content)
                if matches:
                    secrets_found.append(f"{name} ({len(matches)} found)")
            
            if secrets_found:
                findings.append({
                    'category': 'Content Analysis',
                    'status': 'active',
                    'message': f'Sensitive data found in content: {", ".join(secrets_found)}',
                    'details': f'Found {len(secrets_found)} types of sensitive data',
                    'recommendation': 'Remove sensitive data from publicly accessible content.'
                })
            else:
                findings.append({
                    'category': 'Content Analysis',
                    'status': 'passed',
                    'message': 'No sensitive data found in content',
                    'details': '',
                    'recommendation': 'Content does not contain obvious sensitive data.'
                })
        except Exception as e:
            findings.append({
                'category': 'Content Analysis',
                'status': 'active',
                'message': 'Content analysis failed',
                'details': str(e),
                'recommendation': 'Verify web content for sensitive information.'
            })
    else:
        findings.append({
            'category': 'Content Analysis',
            'status': 'skipped',
            'message': 'HTTP service not running',
            'details': '',
            'recommendation': 'Start an HTTP server to perform this check.'
        })
    return findings

# ======================
# DATABASE SERVICE CHECKS
# ======================

def check_mongodb_exposure(target):
    """Check MongoDB exposure"""
    findings = []
    if is_port_open(target, 27017):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target, 27017))
            # Send MongoDB command to check if it's exposed
            request = b'\x12\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xdd\x11\x00\x00\x00\x00\x00\x00'
            sock.send(request)
            response = sock.recv(1024)
            if len(response) > 0:
                findings.append({
                    'category': 'MongoDB Exposure',
                    'status': 'active',
                    'message': 'MongoDB exposed',
                    'details': 'No authentication required',
                    'recommendation': 'Configure MongoDB to require authentication and bind to 127.0.0.1 only.'
                })
            sock.close()
        except Exception as e:
            findings.append({
                'category': 'MongoDB Exposure',
                'status': 'active',
                'message': 'MongoDB check failed',
                'details': str(e),
                'recommendation': 'Verify MongoDB service configuration.'
            })
    return findings

def check_redis_exposure(target):
    """Check Redis exposure"""
    findings = []
    if is_port_open(target, 6379):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target, 6379))
            sock.send(b"INFO\r\n")
            response = sock.recv(1024).decode()
            if "redis_version" in response:
                findings.append({
                    'category': 'Redis Exposure',
                    'status': 'active',
                    'message': 'Redis exposed',
                    'details': 'No authentication required',
                    'recommendation': 'Configure Redis to require authentication and bind to 127.0.0.1 only.'
                })
            sock.close()
        except Exception as e:
            findings.append({
                'category': 'Redis Exposure',
                'status': 'active',
                'message': 'Redis check failed',
                'details': str(e),
                'recommendation': 'Verify Redis service configuration.'
            })
    return findings

def check_elasticsearch_exposure(target):
    """Check Elasticsearch exposure"""
    findings = []
    if is_port_open(target, 9200):
        try:
            response = requests.get(f"http://{target}:9200", timeout=2)
            if "version" in response.text:
                findings.append({
                    'category': 'Elasticsearch Exposure',
                    'status': 'active',
                    'message': 'Elasticsearch exposed',
                    'details': response.text[:100],
                    'recommendation': 'Configure Elasticsearch to require authentication and bind to 127.0.0.1 only.'
                })
        except Exception as e:
            findings.append({
                'category': 'Elasticsearch Exposure',
                'status': 'active',
                'message': 'Elasticsearch check failed',
                'details': str(e),
                'recommendation': 'Verify Elasticsearch service configuration.'
            })
    return findings

def check_memcached_exposure(target):
    """Check Memcached exposure"""
    findings = []
    if is_port_open(target, 11211):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(b"stats\r\n", (target, 11211))
            response, _ = sock.recvfrom(1024)
            if "STAT" in response.decode():
                findings.append({
                    'category': 'Memcached Exposure',
                    'status': 'active',
                    'message': 'Memcached exposed',
                    'details': 'No authentication required',
                    'recommendation': 'Configure Memcached to bind to 127.0.0.1 only.'
                })
            sock.close()
        except Exception as e:
            findings.append({
                'category': 'Memcached Exposure',
                'status': 'active',
                'message': 'Memcached check failed',
                'details': str(e),
                'recommendation': 'Verify Memcached service configuration.'
            })
    return findings

# ======================
# MAIL & NETWORK SERVICE CHECKS
# ======================

def check_smtp_open_relay(target):
    """Check SMTP open relay"""
    findings = []
    if is_port_open(target, 25):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target, 25))
            response = sock.recv(1024).decode()
            if '220' in response:
                sock.send(b'EHLO test\r\n')
                response = sock.recv(1024).decode()
                sock.send(b'MAIL FROM: <test@example.com>\r\n')
                response = sock.recv(1024).decode()
                sock.send(b'RCPT TO: <test@example.com>\r\n')
                response = sock.recv(1024).decode()
                if '250' in response:
                    findings.append({
                        'category': 'SMTP Open Relay',
                        'status': 'active',
                        'message': 'SMTP open relay detected',
                        'details': 'Relay allowed',
                        'recommendation': 'Configure SMTP server to reject unauthorized relays.'
                    })
            sock.close()
        except Exception as e:
            findings.append({
                'category': 'SMTP Open Relay',
                'status': 'active',
                'message': 'SMTP check failed',
                'details': str(e),
                'recommendation': 'Verify SMTP server configuration.'
            })
    return findings

def check_ntp_amplification(target):
    """Check NTP amplification vulnerability"""
    findings = []
    if is_port_open(target, 123):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            request = b'\x17\x00\x02\x2a' + b'\x00' * 4
            sock.sendto(request, (target, 123))
            response = sock.recv(1024)
            if len(response) > 100:
                findings.append({
                    'category': 'NTP Amplification',
                    'status': 'active',
                    'message': 'NTP amplification vulnerability detected',
                    'details': 'Monlist response received',
                    'recommendation': 'Disable NTP monlist or restrict access to trusted networks.'
                })
            sock.close()
        except Exception as e:
            findings.append({
                'category': 'NTP Amplification',
                'status': 'active',
                'message': 'NTP check failed',
                'details': str(e),
                'recommendation': 'Verify NTP service configuration.'
            })
    return findings

def check_rdp_exposure(target):
    """Check RDP exposure"""
    findings = []
    if is_port_open(target, 3389):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target, 3389))
            request = b'\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x03\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00'
            sock.send(request)
            response = sock.recv(1024)
            if response.startswith(b'\x03\x00\x00\x0b\x0e\x00\x00\x00\x00\x00\x00'):
                findings.append({
                    'category': 'RDP Exposure',
                    'status': 'active',
                    'message': 'RDP exposed',
                    'details': 'RDP service detected',
                    'recommendation': 'Ensure RDP is secured with network level authentication and strong passwords.'
                })
            sock.close()
        except Exception as e:
            findings.append({
                'category': 'RDP Exposure',
                'status': 'active',
                'message': 'RDP check failed',
                'details': str(e),
                'recommendation': 'Verify RDP service configuration.'
            })
    return findings

def check_vnc_exposure(target):
    """Check VNC exposure"""
    findings = []
    if is_port_open(target, 5900):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target, 5900))
            response = sock.recv(1024)
            if b'RFB ' in response:
                findings.append({
                    'category': 'VNC Exposure',
                    'status': 'active',
                    'message': 'VNC exposed',
                    'details': 'VNC service detected',
                    'recommendation': 'Ensure VNC is secured with strong passwords and network restrictions.'
                })
            sock.close()
        except Exception as e:
            findings.append({
                'category': 'VNC Exposure',
                'status': 'active',
                'message': 'VNC check failed',
                'details': str(e),
                'recommendation': 'Verify VNC service configuration.'
            })
    return findings

# ======================
# WEB SECURITY CHECKS
# ======================

def check_http_security_headers(target, open_ports):
    """Check HTTP security headers"""
    findings = []
    if 80 in open_ports or 443 in open_ports:
        try:
            response = requests.get(f"http://{target}", timeout=5)
            headers = response.headers
            # Check for HSTS
            if 'Strict-Transport-Security' in headers:
                hsts = headers['Strict-Transport-Security']
                if 'max-age' in hsts and 'includeSubDomains' in hsts and 'preload' in hsts:
                    findings.append({
                        'category': 'HSTS',
                        'status': 'passed',
                        'message': 'HSTS configured with preload',
                        'details': hsts,
                        'recommendation': 'HSTS is properly configured.'
                    })
                else:
                    findings.append({
                        'category': 'HSTS',
                        'status': 'active',
                        'message': 'HSTS configured without preload',
                        'details': hsts,
                        'recommendation': 'Add preload flag to HSTS header for better security.'
                    })
            else:
                findings.append({
                    'category': 'HSTS',
                    'status': 'active',
                    'message': 'HSTS header missing',
                    'details': '',
                    'recommendation': 'Add HSTS header to enforce HTTPS.'
                })
            # Check for CSP
            if 'Content-Security-Policy' in headers:
                csp = headers['Content-Security-Policy']
                if 'unsafe-inline' in csp or 'unsafe-eval' in csp:
                    findings.append({
                        'category': 'CSP',
                        'status': 'active',
                        'message': 'CSP allows unsafe directives',
                        'details': csp,
                        'recommendation': 'Remove unsafe-inline and unsafe-eval from CSP.'
                    })
                else:
                    findings.append({
                        'category': 'CSP',
                        'status': 'passed',
                        'message': 'CSP configured safely',
                        'details': csp,
                        'recommendation': 'CSP is properly configured.'
                    })
            else:
                findings.append({
                    'category': 'CSP',
                    'status': 'active',
                    'message': 'CSP header missing',
                    'details': '',
                    'recommendation': 'Add Content-Security-Policy header.'
                })
            # Check for X-Frame-Options
            if 'X-Frame-Options' in headers:
                findings.append({
                    'category': 'X-Frame-Options',
                    'status': 'passed',
                    'message': 'X-Frame-Options present',
                    'details': headers['X-Frame-Options'],
                    'recommendation': 'X-Frame-Options is configured.'
                })
            else:
                findings.append({
                    'category': 'X-Frame-Options',
                    'status': 'active',
                    'message': 'X-Frame-Options missing',
                    'details': '',
                    'recommendation': 'Add X-Frame-Options header to prevent clickjacking.'
                })
            # Check for X-Content-Type-Options
            if 'X-Content-Type-Options' in headers and headers['X-Content-Type-Options'] == 'nosniff':
                findings.append({
                    'category': 'X-Content-Type-Options',
                    'status': 'passed',
                    'message': 'X-Content-Type-Options present',
                    'details': headers['X-Content-Type-Options'],
                    'recommendation': 'X-Content-Type-Options is configured.'
                })
            else:
                findings.append({
                    'category': 'X-Content-Type-Options',
                    'status': 'active',
                    'message': 'X-Content-Type-Options missing or incorrect',
                    'details': headers.get('X-Content-Type-Options', ''),
                    'recommendation': 'Add X-Content-Type-Options: nosniff header.'
                })
            # Check for X-XSS-Protection
            if 'X-XSS-Protection' in headers and headers['X-XSS-Protection'] == '1; mode=block':
                findings.append({
                    'category': 'X-XSS-Protection',
                    'status': 'passed',
                    'message': 'X-XSS-Protection present',
                    'details': headers['X-XSS-Protection'],
                    'recommendation': 'X-XSS-Protection is configured.'
                })
            else:
                findings.append({
                    'category': 'X-XSS-Protection',
                    'status': 'active',
                    'message': 'X-XSS-Protection missing or incorrect',
                    'details': headers.get('X-XSS-Protection', ''),
                    'recommendation': 'Add X-XSS-Protection: 1; mode=block header.'
                })
        except Exception as e:
            findings.append({
                'category': 'HTTP Security Headers',
                'status': 'active',
                'message': 'HTTP headers check failed',
                'details': str(e),
                'recommendation': 'Verify server configuration for security headers.'
            })
    else:
        findings.append({
            'category': 'HTTP Security Headers',
            'status': 'skipped',
            'message': 'HTTP service not running',
            'details': '',
            'recommendation': 'Start an HTTP server to perform this check.'
        })
    return findings

def check_session_tracking(target, open_ports):
    """Check for session tracking cookies"""
    findings = []
    if 80 in open_ports or 443 in open_ports:
        try:
            response = requests.get(f"http://{target}", timeout=5)
            cookies = response.cookies
            tracking_cookies = []
            for cookie in cookies:
                if 'ga' in cookie.name or 'gid' in cookie.name or 'utm_' in cookie.name or 'session' in cookie.name.lower() or 'tracking' in cookie.name.lower():
                    tracking_cookies.append(cookie.name)
            if tracking_cookies:
                findings.append({
                    'category': 'Session Tracking',
                    'status': 'active',
                    'message': 'Tracking cookies detected',
                    'details': ', '.join(tracking_cookies),
                    'recommendation': 'Review cookies for unnecessary tracking.'
                })
            else:
                findings.append({
                    'category': 'Session Tracking',
                    'status': 'passed',
                    'message': 'No tracking cookies detected',
                    'details': '',
                    'recommendation': 'No session tracking cookies found.'
                })
        except Exception as e:
            findings.append({
                'category': 'Session Tracking',
                'status': 'active',
                'message': 'Session tracking check failed',
                'details': str(e),
                'recommendation': 'Verify server configuration for cookies.'
            })
    else:
        findings.append({
            'category': 'Session Tracking',
            'status': 'skipped',
            'message': 'HTTP service not running',
            'details': '',
            'recommendation': 'Start an HTTP server to perform this check.'
        })
    return findings

def check_exposed_apis(target, open_ports):
    """Check for exposed APIs"""
    findings = []
    if 80 in open_ports or 443 in open_ports:
        apis = ['api', 'graphql', 'v1', 'v2', 'rest', 'swagger', 'openapi', 'admin/api', 'debug/api', 'wp-json', 'wp/v2', 'api/v1', 'api/v2']
        found_apis = []
        for api in apis:
            url = f"http://{target}/{api}"
            try:
                response = requests.get(url, timeout=2)
                if response.status_code == 200:
                    found_apis.append(url)
            except Exception:
                pass
        if found_apis:
            findings.append({
                'category': 'Exposed APIs',
                'status': 'active',
                'message': f'{len(found_apis)} APIs exposed',
                'details': ', '.join(found_apis[:3]) + ('...' if len(found_apis) > 3 else ''),
                'recommendation': 'Ensure APIs are properly secured and not exposed to public.'
            })
        else:
            findings.append({
                'category': 'Exposed APIs',
                'status': 'passed',
                'message': 'No exposed APIs detected',
                'details': '',
                'recommendation': 'No public APIs found.'
            })
    else:
        findings.append({
            'category': 'Exposed APIs',
            'status': 'skipped',
            'message': 'HTTP service not running',
            'details': '',
            'recommendation': 'Start an HTTP server to perform this check.'
        })
    return findings

def check_well_known_files(target, open_ports):
    """Check for well-known files"""
    findings = []
    if 80 in open_ports or 443 in open_ports:
        files = [
            '.well-known/security.txt',
            '.well-known/apple-app-site-association',
            '.well-known/assetlinks.json',
            '.well-known/change-password',
            '.well-known/origin-trial',
            '.well-known/webfinger',
            '.well-known/est',
            '.well-known/acme-challenge',
            '.well-known/authorization'
        ]
        found_files = []
        for file in files:
            url = f"http://{target}/{file}"
            try:
                response = requests.get(url, timeout=2)
                if response.status_code == 200:
                    found_files.append(url)
            except Exception:
                pass
        if found_files:
            findings.append({
                'category': 'Well-Known Files',
                'status': 'active',
                'message': f'{len(found_files)} well-known files exposed',
                'details': ', '.join(found_files[:3]) + ('...' if len(found_files) > 3 else ''),
                'recommendation': 'Review exposed well-known files for sensitive information.'
            })
        else:
            findings.append({
                'category': 'Well-Known Files',
                'status': 'passed',
                'message': 'No well-known files exposed',
                'details': '',
                'recommendation': 'All well-known files are secure.'
            })
    else:
        findings.append({
            'category': 'Well-Known Files',
            'status': 'skipped',
            'message': 'HTTP service not running',
            'details': '',
            'recommendation': 'Start an HTTP server to perform this check.'
        })
    return findings

# ======================
# SSL/TLS CHECKS
# ======================

def check_ssl_vulnerabilities(target, open_ports):
    """Check for SSL/TLS vulnerabilities"""
    findings = []
    if 443 in open_ports:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((target, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    # Check for POODLE (SSLv3)
                    try:
                        sslv3_context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
                        sslv3_context.options |= ssl.OP_NO_SSLv2
                        with socket.create_connection((target, 443)) as sock:
                            with sslv3_context.wrap_socket(sock, server_hostname=target) as ssock:
                                findings.append({
                                    'category': 'SSL/TLS Vulnerability',
                                    'status': 'active',
                                    'message': 'POODLE vulnerability detected',
                                    'details': 'SSLv3 enabled',
                                    'recommendation': 'Disable SSLv3 immediately.'
                                })
                    except ssl.SSLError:
                        # SSLv3 not supported, so no POODLE
                        pass
                    
                    # Check for FREAK (export-grade ciphers)
                    weak_ciphers = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'SSLv3', 'TLSv1', 'TLSv1.1']
                    cipher = ssock.cipher()
                    if any(c in cipher[0] for c in weak_ciphers):
                        findings.append({
                            'category': 'SSL/TLS Vulnerability',
                            'status': 'active',
                            'message': 'Weak SSL/TLS cipher detected',
                            'details': cipher[0],
                            'recommendation': 'Disable weak ciphers and upgrade to TLS 1.2+.'
                        })
                    
                    # Check for LOGJAM (weak DH parameters)
                    # This is complex, but we'll check for DH parameters < 1024 bits
                    # Requires more advanced SSL/TLS library, so for simplicity we'll skip
                    # But we'll check for common weak DH parameters
                    if 'DH' in cipher[0]:
                        findings.append({
                            'category': 'SSL/TLS Vulnerability',
                            'status': 'active',
                            'message': 'DH parameters detected',
                            'details': 'Check for weak DH parameters',
                            'recommendation': 'Ensure DH parameters are at least 2048 bits.'
                        })
            if not findings:
                findings.append({
                    'category': 'SSL/TLS Vulnerability',
                    'status': 'passed',
                    'message': 'No known SSL/TLS vulnerabilities detected',
                    'details': '',
                    'recommendation': 'SSL/TLS configuration is secure.'
                })
        except Exception as e:
            findings.append({
                'category': 'SSL/TLS Vulnerability',
                'status': 'active',
                'message': 'SSL/TLS check failed',
                'details': str(e),
                'recommendation': 'Verify SSL/TLS configuration for security.'
            })
    else:
        findings.append({
            'category': 'SSL/TLS Vulnerability',
            'status': 'skipped',
            'message': 'HTTPS service not running',
            'details': '',
            'recommendation': 'Start an HTTPS service to perform this check.'
        })
    return findings

def check_hsts_preload(target, open_ports):
    """Check HSTS preload configuration"""
    findings = []
    if 443 in open_ports:
        try:
            response = requests.get(f"https://{target}", timeout=5)
            hsts = response.headers.get('Strict-Transport-Security', '')
            if 'preload' in hsts:
                findings.append({
                    'category': 'HSTS Preload',
                    'status': 'passed',
                    'message': 'HSTS with preload flag',
                    'details': hsts,
                    'recommendation': 'HSTS is configured for preload.'
                })
            else:
                findings.append({
                    'category': 'HSTS Preload',
                    'status': 'active',
                    'message': 'HSTS without preload flag',
                    'details': hsts,
                    'recommendation': 'Add preload flag to HSTS header for better security.'
                })
        except Exception as e:
            findings.append({
                'category': 'HSTS Preload',
                'status': 'active',
                'message': 'HSTS check failed',
                'details': str(e),
                'recommendation': 'Verify HSTS configuration.'
            })
    else:
        findings.append({
            'category': 'HSTS Preload',
            'status': 'skipped',
            'message': 'HTTPS service not running',
            'details': '',
            'recommendation': 'Start an HTTPS service to perform this check.'
        })
    return findings

def check_csp_misconfigurations(target, open_ports):
    """Check CSP misconfigurations"""
    findings = []
    if 80 in open_ports or 443 in open_ports:
        try:
            response = requests.get(f"http://{target}", timeout=5)
            csp = response.headers.get('Content-Security-Policy', '')
            if 'unsafe-inline' in csp or 'unsafe-eval' in csp:
                findings.append({
                    'category': 'CSP Misconfiguration',
                    'status': 'active',
                    'message': 'CSP allows unsafe directives',
                    'details': csp,
                    'recommendation': 'Remove unsafe-inline and unsafe-eval from CSP.'
                })
            else:
                findings.append({
                    'category': 'CSP Misconfiguration',
                    'status': 'passed',
                    'message': 'CSP configured safely',
                    'details': csp,
                    'recommendation': 'CSP is properly configured.'
                })
        except Exception as e:
            findings.append({
                'category': 'CSP Misconfiguration',
                'status': 'active',
                'message': 'CSP check failed',
                'details': str(e),
                'recommendation': 'Verify CSP configuration.'
            })
    else:
        findings.append({
            'category': 'CSP Misconfiguration',
            'status': 'skipped',
            'message': 'HTTP service not running',
            'details': '',
            'recommendation': 'Start an HTTP service to perform this check.'
        })
    return findings

# ======================
# DNS & NETWORK CHECKS
# ======================

def check_dnssec(domain):
    """Check DNSSEC configuration"""
    findings = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8']  # Use Google DNS
        # Check for DNSKEY record
        try:
            dnskey = resolver.resolve(domain, 'DNSKEY')
            findings.append({
                'category': 'DNSSEC',
                'status': 'passed',
                'message': 'DNSKEY record found',
                'details': '',
                'recommendation': 'DNSSEC is enabled for the domain.'
            })
        except dns.exception.DNSException:
            findings.append({
                'category': 'DNSSEC',
                'status': 'active',
                'message': 'No DNSKEY record found',
                'details': '',
                'recommendation': 'Enable DNSSEC for the domain.'
            })
    except Exception as e:
        findings.append({
            'category': 'DNSSEC',
            'status': 'active',
            'message': 'DNSSEC check failed',
            'details': str(e),
            'recommendation': 'Verify DNS configuration for DNSSEC.'
        })
    return findings

def check_dns_leak(target, open_ports):
    """Check for DNS leaks"""
    findings = []
    if 53 in open_ports or 80 in open_ports or 443 in open_ports:
        try:
            # Check system DNS resolver
            resolver = dns.resolver.Resolver()
            nameservers = resolver.nameservers
            # Check if DNS resolver is public or private
            public_dns = False
            for ns in nameservers:
                if ipaddress.ip_address(ns).is_global:
                    public_dns = True
                else:
                    public_dns = False
                    break
            
            if public_dns:
                findings.append({
                    'category': 'DNS Leak',
                    'status': 'passed',
                    'message': 'Public DNS resolver detected',
                    'details': f'DNS servers: {", ".join(nameservers)}',
                    'recommendation': 'Verify DNS resolver configuration is secure.'
                })
            else:
                findings.append({
                    'category': 'DNS Leak',
                    'status': 'active',
                    'message': 'Private DNS resolver detected',
                    'details': f'DNS servers: {", ".join(nameservers)}',
                    'recommendation': 'Ensure DNS resolver is not leaking internal information.'
                })
        except Exception as e:
            findings.append({
                'category': 'DNS Leak',
                'status': 'active',
                'message': 'DNS leak check failed',
                'details': str(e),
                'recommendation': 'Verify DNS resolver configuration.'
            })
    else:
        findings.append({
            'category': 'DNS Leak',
            'status': 'skipped',
            'message': 'DNS service not running',
            'details': '',
            'recommendation': 'Start a DNS service to perform this check.'
        })
    return findings

# ======================
# MAIN SCAN FUNCTION
# ======================

def scan_target(target):
    print_status(f"Scanning target: {target}", "success")
    
    # Determine if it's a local machine scan
    is_local = False
    if target in ['localhost', '127.0.0.1', '::1']:
        is_local = True
    
    # Resolve target to IP if it's a domain
    try:
        socket.inet_aton(target)
        ip = target
        is_ip = True
    except socket.error:
        try:
            ip = dns.resolver.resolve(target, 'A')[0].to_text()
            is_ip = False
        except:
            print_status("Error resolving target. Exiting.", "error")
            return
    
    # Determine open ports
    open_ports = get_open_ports(target)
    print_status(f"Open ports detected: {open_ports}", "success")
    
    # Run all checks
    findings = []
    
    if is_local:
        # Run local machine specific checks
        findings.extend(check_vpn_interfaces())
        findings.extend(check_tor_services())
        findings.extend(check_local_services())
        findings.extend(check_mongodb_exposure(target))
        findings.extend(check_redis_exposure(target))
        findings.extend(check_elasticsearch_exposure(target))
        findings.extend(check_memcached_exposure(target))
        findings.extend(check_smtp_open_relay(target))
        findings.extend(check_ntp_amplification(target))
        findings.extend(check_rdp_exposure(target))
        findings.extend(check_vnc_exposure(target))
        findings.extend(check_http_security_headers(target, open_ports))
        findings.extend(check_session_tracking(target, open_ports))
        findings.extend(check_exposed_apis(target, open_ports))
        findings.extend(check_well_known_files(target, open_ports))
        findings.extend(check_ssl_vulnerabilities(target, open_ports))
        findings.extend(check_hsts_preload(target, open_ports))
        findings.extend(check_csp_misconfigurations(target, open_ports))
        findings.extend(check_dnssec(target))
        findings.extend(check_dns_leak(target, open_ports))
    else:
        # Run remote target checks
        findings.extend(analyze_dns(target, open_ports))
        findings.extend(port_scan(ip, open_ports))
        findings.extend(check_reverse_dns(ip, open_ports))
        findings.extend(check_routing_table(open_ports))
        findings.extend(check_arp_table(open_ports))
        findings.extend(check_nat_leakage(target, open_ports))
        findings.extend(check_sensitive_files(target, open_ports))
        findings.extend(check_error_messages(target, open_ports))
        findings.extend(check_http_methods(target, open_ports))
        findings.extend(check_git_directory(target, open_ports))
        findings.extend(check_cors(target, open_ports))
        findings.extend(check_ssl_tls(target, open_ports))
        findings.extend(check_heartbleed(target, open_ports))
        findings.extend(check_webrtc(target, open_ports))
        findings.extend(analyze_content(target, open_ports))
        findings.extend(check_mongodb_exposure(target))
        findings.extend(check_redis_exposure(target))
        findings.extend(check_elasticsearch_exposure(target))
        findings.extend(check_memcached_exposure(target))
        findings.extend(check_smtp_open_relay(target))
        findings.extend(check_ntp_amplification(target))
        findings.extend(check_rdp_exposure(target))
        findings.extend(check_vnc_exposure(target))
        findings.extend(check_http_security_headers(target, open_ports))
        findings.extend(check_session_tracking(target, open_ports))
        findings.extend(check_exposed_apis(target, open_ports))
        findings.extend(check_well_known_files(target, open_ports))
        findings.extend(check_ssl_vulnerabilities(target, open_ports))
        findings.extend(check_hsts_preload(target, open_ports))
        findings.extend(check_csp_misconfigurations(target, open_ports))
        findings.extend(check_dnssec(target))
        findings.extend(check_dns_leak(target, open_ports))
    
    # Print report
    print_report(findings)

def print_report(findings):
    clear_screen()
    print_header()
    
    # Categorize findings
    critical_findings = [f for f in findings if classify_severity(f) == "CRITICAL"]
    medium_findings = [f for f in findings if classify_severity(f) == "MEDIUM"]
    low_findings = [f for f in findings if classify_severity(f) == "LOW"]
    passed_findings = [f for f in findings if f['status'] == "passed"]
    skipped_findings = [f for f in findings if f['status'] == "skipped"]
    
    # Executive Summary
    print("\n[ EXECUTIVE SUMMARY ]")
    print(f"Total Checks: {len(findings)}")
    print(f"Critical Findings: {len(critical_findings)}")
    print(f"Medium Findings: {len(medium_findings)}")
    print(f"Low Findings: {len(low_findings)}")
    print(f"Passed Checks: {len(passed_findings)}")
    print(f"Skipped Checks: {len(skipped_findings)}")
    print("\n" + "="*60)
    
    # Critical Findings Table
    if critical_findings:
        print("\n[ CRITICAL FINDINGS ]")
        headers = ["Category", "Finding", "Severity", "Recommendation"]
        rows = []
        for f in critical_findings:
            row = [
                f['category'],
                f['message'],
                "CRITICAL",
                f['recommendation'][:50] + ('...' if len(f['recommendation']) > 50 else '')
            ]
            rows.append(row)
        print_table("Critical Findings", headers, rows)
    
    # Medium Findings Table
    if medium_findings:
        print("\n[ MEDIUM FINDINGS ]")
        headers = ["Category", "Finding", "Severity", "Recommendation"]
        rows = []
        for f in medium_findings:
            row = [
                f['category'],
                f['message'],
                "MEDIUM",
                f['recommendation'][:50] + ('...' if len(f['recommendation']) > 50 else '')
            ]
            rows.append(row)
        print_table("Medium Findings", headers, rows)
    
    # Low Findings Table
    if low_findings:
        print("\n[ LOW FINDINGS ]")
        headers = ["Category", "Finding", "Severity", "Recommendation"]
        rows = []
        for f in low_findings:
            row = [
                f['category'],
                f['message'],
                "LOW",
                f['recommendation'][:50] + ('...' if len(f['recommendation']) > 50 else '')
            ]
            rows.append(row)
        print_table("Low Findings", headers, rows)
    
    # Passed Checks Table
    if passed_findings:
        print("\n[ PASSED CHECKS ]")
        headers = ["Category", "Status", "Details"]
        rows = []
        for f in passed_findings:
            row = [
                f['category'],
                f['message'],
                f['details'][:50] + ('...' if len(f['details']) > 50 else '')
            ]
            rows.append(row)
        print_table("Passed Checks", headers, rows)
    
    # Skipped Checks Table
    if skipped_findings:
        print("\n[ SKIPPED CHECKS ]")
        headers = ["Category", "Reason", "Recommendation"]
        rows = []
        for f in skipped_findings:
            row = [
                f['category'],
                f['message'],
                f['recommendation'][:50] + ('...' if len(f['recommendation']) > 50 else '')
            ]
            rows.append(row)
        print_table("Skipped Checks", headers, rows)
    
    if not critical_findings and not medium_findings and not low_findings and not passed_findings and not skipped_findings:
        print("\nNo findings to display. The scan completed successfully.")
    
    print("\n" + "="*60)
    print("Scan completed successfully. Report generated.")
    print("Remember: This tool is for ethical security testing only.")
    print("="*60)

# ======================
# MAIN MENU
# ======================

def main_menu():
    while True:
        clear_screen()
        print_header()
        print("MAIN MENU")
        print("1. Scan a target (domain or IP)")
        print("2. Scan local machine")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == '1':
            target = input("\nEnter target (domain or IP): ").strip()
            if target:
                scan_target(target)
                input("\nPress Enter to return to main menu...")
        elif choice == '2':
            print_status("Scanning local machine...", "success")
            scan_target("localhost")
            input("\nPress Enter to return to main menu...")
        elif choice == '3':
            clear_screen()
            print("\nThank you for using Leak Detective Pro. Stay secure!")
            sys.exit(0)
        else:
            print_status("Invalid choice. Please try again.", "error")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        clear_screen()
        print("\nScan interrupted by user. Exiting...")
        sys.exit(0)