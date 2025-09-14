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
    print("Version 2.1 | Focused on Critical Security Leaks")
    print("No external APIs required - fully self-contained\n")

def print_status(message, status):
    """Prints a status message with emoji indicator"""
    emoji = "✅" if status == "success" else "⚠️" if status == "warning" else "❌"
    print(f"\n{emoji} {message}")

def is_port_open(ip, port):
    """Check if a specific port is open on the target IP"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            return result == 0
    except Exception:
        return False

def get_open_ports(target, ports=[80, 443, 22, 25, 53, 8080, 8443]):
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
    if "AWS" in finding['message'] or "Google" in finding['message'] or "Stripe" in finding['message'] or \
       "private key" in finding['message'] or "database credentials" in finding['message'] or \
       "internal IP" in finding['message'] or "AXFR allowed" in finding['message']:
        return "CRITICAL"
    elif "CORS misconfiguration" in finding['message'] or "Weak SSL" in finding['message'] or \
         "debug endpoint" in finding['message'] or "error messages exposed" in finding['message']:
        return "MEDIUM"
    else:
        return "LOW"

# ======================
# DNS ANALYSIS FUNCTIONS
# ======================

def analyze_dns(domain, open_ports):
    findings = []
    
    # SOA Record Check
    try:
        soa = dns.resolver.resolve(domain, 'SOA')
        for rdata in soa:
            admin_email = rdata.rname.to_text().replace('.', '@', 1)[:-1]
            findings.append({
                'category': 'DNS SOA Record',
                'status': 'active',
                'message': 'SOA record found',
                'details': f'Admin email: {admin_email}',
                'recommendation': 'Verify that admin email is not a personal address.'
            })
    except dns.exception.DNSException:
        findings.append({
            'category': 'DNS SOA Record',
            'status': 'active',
            'message': 'No SOA record found',
            'details': '',
            'recommendation': 'Ensure SOA record is configured for proper DNS management.'
        })
    
    # NS Records Check
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        private_ns = []
        for ns in ns_records:
            ns_name = ns.to_text().rstrip('.')
            try:
                ns_ip = dns.resolver.resolve(ns_name, 'A')[0].to_text()
                if re.match(r'^(192\.168|10\.|172\.(1[6-9]|2[0-9]|3[0-1]))', ns_ip):
                    private_ns.append(f"{ns_name} → {ns_ip}")
            except:
                continue
        if private_ns:
            for item in private_ns:
                findings.append({
                    'category': 'DNS NS Record',
                    'status': 'active',
                    'message': 'Internal NS record detected',
                    'details': item,
                    'recommendation': 'Ensure NS records point to public IPs only.'
                })
        else:
            findings.append({
                'category': 'DNS NS Record',
                'status': 'passed',
                'message': 'No internal NS records found',
                'details': '',
                'recommendation': 'NS records are properly configured.'
            })
    except dns.exception.DNSException:
        findings.append({
            'category': 'DNS NS Record',
            'status': 'active',
            'message': 'NS check failed',
            'details': '',
            'recommendation': 'Verify DNS configuration for NS records.'
        })
    
    # SPF Record Check
    try:
        spf = dns.resolver.resolve(domain, 'TXT')
        spf_data = []
        for rdata in spf:
            txt = rdata.to_text()
            if 'v=spf1' in txt and re.search(r'192\.168|10\.|172\.', txt):
                spf_data.append(txt)
        if spf_data:
            for data in spf_data:
                findings.append({
                    'category': 'DNS SPF Record',
                    'status': 'active',
                    'message': 'SPF contains internal IPs',
                    'details': data,
                    'recommendation': 'Remove internal IPs from SPF records.'
                })
        else:
            findings.append({
                'category': 'DNS SPF Record',
                'status': 'passed',
                'message': 'SPF secure',
                'details': '',
                'recommendation': 'SPF record properly configured.'
            })
    except dns.exception.DNSException:
        findings.append({
            'category': 'DNS SPF Record',
            'status': 'active',
            'message': 'No SPF record found',
            'details': '',
            'recommendation': 'Configure SPF record to prevent email spoofing.'
        })
    
    # AXFR Check
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        axfr_allowed = False
        for ns in ns_records:
            ns_name = ns.to_text().rstrip('.')
            try:
                axfr = dns.query.axfr(ns_name, domain, timeout=3)
                if axfr:
                    axfr_allowed = True
                    break
            except:
                continue
        if axfr_allowed:
            findings.append({
                'category': 'DNS AXFR',
                'status': 'active',
                'message': 'AXFR allowed',
                'details': 'Zone transfer possible',
                'recommendation': 'Immediately block AXFR requests at DNS server.'
            })
        else:
            findings.append({
                'category': 'DNS AXFR',
                'status': 'passed',
                'message': 'AXFR blocked',
                'details': '',
                'recommendation': 'AXFR is properly restricted.'
            })
    except dns.exception.DNSException:
        findings.append({
            'category': 'DNS AXFR',
            'status': 'active',
            'message': 'AXFR check failed',
            'details': '',
            'recommendation': 'Verify DNS server configuration for AXFR restrictions.'
        })
    
    # Wildcard Check
    random_sub = f"xyz{int(time.time())}.{domain}"
    try:
        dns.resolver.resolve(random_sub, 'A')
        findings.append({
            'category': 'DNS Wildcard',
            'status': 'active',
            'message': 'Wildcard record detected',
            'details': f"Subdomain: {random_sub}",
            'recommendation': 'Review wildcard configuration for unintended exposure.'
        })
    except dns.exception.DNSException:
        findings.append({
            'category': 'DNS Wildcard',
            'status': 'passed',
            'message': 'No wildcard record',
            'details': '',
            'recommendation': 'Wildcard configuration is secure.'
        })
    
    # TXT Records for Sensitive Data
    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        patterns = {
            "AWS": r"AWS[A-Z0-9]{16,}",
            "Google": r"AIza[0-9A-Za-z\-_]{35}",
            "GitHub": r"[a-f0-9]{40}",
            "Stripe": r"sk_live_[0-9a-zA-Z]{24}",
            "JWT": r"ey[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+"
        }
        for rdata in txt_records:
            txt = rdata.to_text()
            for key, pattern in patterns.items():
                if re.search(pattern, txt):
                    findings.append({
                        'category': 'DNS TXT Record',
                        'status': 'active',
                        'message': f'{key} secret found in TXT record',
                        'details': txt[:100],
                        'recommendation': 'Immediately rotate the key and remove from DNS records.'
                    })
    except dns.exception.DNSException:
        pass
    
    return findings

# ======================
# IP ANALYSIS FUNCTIONS
# ======================

def port_scan(target_ip, open_ports):
    findings = []
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379, 27017, 8080, 8443]
    
    open_ports_list = []
    for port in common_ports:
        if is_port_open(target_ip, port):
            open_ports_list.append(port)
    
    if open_ports_list:
        findings.append({
            'category': 'Port Scan',
            'status': 'active',
            'message': f'{len(open_ports_list)} open ports detected',
            'details': f"Ports: {', '.join(map(str, open_ports_list))}",
            'recommendation': 'Verify if these ports are necessary for operations.'
        })
    else:
        findings.append({
            'category': 'Port Scan',
            'status': 'passed',
            'message': 'No open ports detected',
            'details': '',
            'recommendation': 'All ports are properly secured.'
        })
    
    return findings

def check_reverse_dns(target_ip, open_ports):
    findings = []
    try:
        hostname = socket.gethostbyaddr(target_ip)[0]
        if re.search(r'internal|local|192\.168|10\.|172\.', hostname):
            findings.append({
                'category': 'Reverse DNS',
                'status': 'active',
                'message': 'Reverse DNS leak',
                'details': f"Hostname: {hostname}",
                'recommendation': 'Configure reverse DNS to use public hostnames only.'
            })
        else:
            findings.append({
                'category': 'Reverse DNS',
                'status': 'passed',
                'message': 'Reverse DNS secure',
                'details': '',
                'recommendation': 'Reverse DNS is properly configured.'
            })
    except Exception:
        findings.append({
            'category': 'Reverse DNS',
            'status': 'active',
            'message': 'Reverse DNS check failed',
            'details': '',
            'recommendation': 'Verify reverse DNS configuration for your IP.'
        })
    return findings

def check_routing_table(open_ports):
    findings = []
    try:
        if sys.platform == "win32":
            result = subprocess.run(["route", "print"], capture_output=True, text=True)
        elif sys.platform == "linux":
            result = subprocess.run(["ip", "route"], capture_output=True, text=True)
        else:
            result = subprocess.run(["netstat", "-rn"], capture_output=True, text=True)
        
        internal_routes = []
        for line in result.stdout.splitlines():
            if re.search(r'192\.168|10\.|172\.', line):
                internal_routes.append(line.strip())
        
        if internal_routes:
            for route in internal_routes:
                findings.append({
                    'category': 'Routing Table',
                    'status': 'active',
                    'message': 'Internal route detected',
                    'details': route,
                    'recommendation': 'Review routing table for unnecessary internal routes.'
                })
        else:
            findings.append({
                'category': 'Routing Table',
                'status': 'passed',
                'message': 'No internal routes',
                'details': '',
                'recommendation': 'Routing table is properly configured.'
            })
    except Exception as e:
        findings.append({
            'category': 'Routing Table',
            'status': 'active',
            'message': 'Routing check failed',
            'details': str(e),
            'recommendation': 'Verify routing table configuration.'
        })
    return findings

def check_arp_table(open_ports):
    findings = []
    try:
        if sys.platform == "win32":
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
        else:
            result = subprocess.run(["arp", "-n"], capture_output=True, text=True)
        
        internal_ips = []
        for line in result.stdout.splitlines():
            if re.search(r'192\.168|10\.|172\.', line):
                internal_ips.append(line.strip())
        
        if internal_ips:
            for ip in internal_ips:
                findings.append({
                    'category': 'ARP Table',
                    'status': 'active',
                    'message': 'Internal device detected',
                    'details': ip,
                    'recommendation': 'Verify authorized devices on your network.'
                })
        else:
            findings.append({
                'category': 'ARP Table',
                'status': 'passed',
                'message': 'No internal devices',
                'details': '',
                'recommendation': 'ARP table is secure.'
            })
    except Exception as e:
        findings.append({
            'category': 'ARP Table',
            'status': 'active',
            'message': 'ARP check failed',
            'details': str(e),
            'recommendation': 'Verify ARP table configuration.'
        })
    return findings

def check_nat_leakage(target, open_ports):
    findings = []
    if 80 not in open_ports and 443 not in open_ports:
        findings.append({
            'category': 'NAT Leakage',
            'status': 'skipped',
            'message': 'HTTP service not running',
            'details': '',
            'recommendation': 'Start an HTTP server to perform this check.'
        })
        return findings
    
    try:
        response = requests.get(f"http://{target}", timeout=2)
        headers = response.headers
        if 'X-Forwarded-For' in headers or 'X-Real-IP' in headers:
            if re.search(r'192\.168|10\.|172\.', headers.get('X-Forwarded-For', '')):
                findings.append({
                    'category': 'NAT Leakage',
                    'status': 'active',
                    'message': 'NAT leakage detected',
                    'details': headers.get('X-Forwarded-For', ''),
                    'recommendation': 'Configure reverse proxy to remove internal IPs from headers.'
                })
        else:
            findings.append({
                'category': 'NAT Leakage',
                'status': 'passed',
                'message': 'NAT secure',
                'details': '',
                'recommendation': 'NAT configuration is secure.'
            })
    except Exception as e:
        findings.append({
            'category': 'NAT Leakage',
            'status': 'active',
            'message': 'NAT check failed',
            'details': str(e),
            'recommendation': 'Verify reverse proxy configuration.'
        })
    return findings

# ======================
# WEB SECURITY FUNCTIONS
# ======================

def check_sensitive_files(target, open_ports):
    findings = []
    if 80 not in open_ports and 443 not in open_ports:
        findings.append({
            'category': 'Sensitive File',
            'status': 'skipped',
            'message': 'HTTP service not running',
            'details': '',
            'recommendation': 'Start an HTTP server to perform this check.'
        })
        return findings
    
    paths = [
        '.env', 'phpinfo.php', 'wp-config.php', 'config.php', 
        'backup.zip', 'database.sql', 'settings.json', 
        '.git/config', '.svn/entries', '.DS_Store', 
        '.htaccess', '.user.ini', 'robots.txt', 'sitemap.xml',
        'admin/', 'cpanel/', 'phpmyadmin/', 'swagger.json',
        'debug/', 'test.php', 'info.php', 'phpinfo/index.php'
    ]
    
    found_files = []
    for path in paths:
        url = f"http://{target}/{path}"
        try:
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                found_files.append(url)
        except Exception:
            pass
    
    if found_files:
        findings.append({
            'category': 'Sensitive File',
            'status': 'active',
            'message': f'{len(found_files)} sensitive files exposed',
            'details': ', '.join(found_files[:3]) + ('...' if len(found_files) > 3 else ''),
            'recommendation': 'Immediately remove exposed files and secure server configuration.'
        })
    else:
        findings.append({
            'category': 'Sensitive File',
            'status': 'passed',
            'message': 'No sensitive files exposed',
            'details': '',
            'recommendation': 'All sensitive files are properly secured.'
        })
    
    return findings

def check_error_messages(target, open_ports):
    findings = []
    if 80 not in open_ports and 443 not in open_ports:
        findings.append({
            'category': 'Error Messages',
            'status': 'skipped',
            'message': 'HTTP service not running',
            'details': '',
            'recommendation': 'Start an HTTP server to perform this check.'
        })
        return findings
    
    try:
        url = f"http://{target}/randompath123"
        response = requests.get(url, timeout=2)
        if 'error' in response.text.lower() or 'exception' in response.text.lower() or 'stack trace' in response.text.lower():
            findings.append({
                'category': 'Error Messages',
                'status': 'active',
                'message': 'Error messages exposed',
                'details': response.text[:200],
                'recommendation': 'Disable detailed error messages in production environment.'
            })
        else:
            findings.append({
                'category': 'Error Messages',
                'status': 'passed',
                'message': 'No error messages exposed',
                'details': '',
                'recommendation': 'Error handling is properly configured.'
            })
    except Exception as e:
        findings.append({
            'category': 'Error Messages',
            'status': 'active',
            'message': 'Error check failed',
            'details': str(e),
            'recommendation': 'Verify error handling configuration.'
        })
    return findings

def check_http_methods(target, open_ports):
    findings = []
    if 80 not in open_ports and 443 not in open_ports:
        findings.append({
            'category': 'HTTP Methods',
            'status': 'skipped',
            'message': 'HTTP service not running',
            'details': '',
            'recommendation': 'Start an HTTP server to perform this check.'
        })
        return findings
    
    try:
        response = requests.options(f"http://{target}", timeout=2)
        methods = response.headers.get('Allow', '')
        if 'PUT' in methods or 'DELETE' in methods or 'TRACE' in methods:
            findings.append({
                'category': 'HTTP Methods',
                'status': 'active',
                'message': 'Dangerous HTTP methods enabled',
                'details': methods,
                'recommendation': 'Disable unnecessary HTTP methods in server configuration.'
            })
        else:
            findings.append({
                'category': 'HTTP Methods',
                'status': 'passed',
                'message': 'HTTP methods secure',
                'details': '',
                'recommendation': 'HTTP methods are properly restricted.'
            })
    except Exception as e:
        findings.append({
            'category': 'HTTP Methods',
            'status': 'active',
            'message': 'HTTP methods check failed',
            'details': str(e),
            'recommendation': 'Verify server HTTP method configuration.'
        })
    return findings

def check_git_directory(target, open_ports):
    findings = []
    if 80 not in open_ports and 443 not in open_ports:
        findings.append({
            'category': '.git Directory',
            'status': 'skipped',
            'message': 'HTTP service not running',
            'details': '',
            'recommendation': 'Start an HTTP server to perform this check.'
        })
        return findings
    
    paths = ['.git/config', '.git/index', '.git/HEAD', '.git/refs/heads/master']
    found = []
    for path in paths:
        url = f"http://{target}/{path}"
        try:
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                if 'repositoryformatversion' in response.text:
                    found.append(f"Git config exposed: {url}")
                elif 'ref: refs/heads/' in response.text:
                    found.append(f"Git index exposed: {url}")
        except Exception:
            pass
    
    if found:
        findings.append({
            'category': '.git Directory',
            'status': 'active',
            'message': f'{len(found)} .git files exposed',
            'details': found[0][:50] + ('...' if len(found) > 1 else ''),
            'recommendation': 'Immediately remove .git directory from public access.'
        })
    else:
        findings.append({
            'category': '.git Directory',
            'status': 'passed',
            'message': '.git directory secure',
            'details': '',
            'recommendation': '.git directory is properly protected.'
        })
    
    return findings

def check_cors(target, open_ports):
    findings = []
    if 80 not in open_ports and 443 not in open_ports:
        findings.append({
            'category': 'CORS Misconfiguration',
            'status': 'skipped',
            'message': 'HTTP service not running',
            'details': '',
            'recommendation': 'Start an HTTP server to perform this check.'
        })
        return findings
    
    try:
        headers = {'Origin': 'https://evil.com'}
        response = requests.get(f"http://{target}", headers=headers, timeout=5)
        allow_origin = response.headers.get('Access-Control-Allow-Origin', '')
        if allow_origin == '*' or allow_origin == 'https://evil.com':
            findings.append({
                'category': 'CORS Misconfiguration',
                'status': 'active',
                'message': 'CORS misconfiguration',
                'details': f"Access-Control-Allow-Origin: {allow_origin}",
                'recommendation': 'Restrict Access-Control-Allow-Origin to trusted domains only.'
            })
        else:
            findings.append({
                'category': 'CORS Misconfiguration',
                'status': 'passed',
                'message': 'CORS configured safely',
                'details': '',
                'recommendation': 'CORS is properly configured.'
            })
    except Exception as e:
        findings.append({
            'category': 'CORS Misconfiguration',
            'status': 'active',
            'message': 'CORS check failed',
            'details': str(e),
            'recommendation': 'Verify CORS configuration for security.'
        })
    return findings

# ======================
# SSL/TLS ANALYSIS FUNCTIONS
# ======================

def check_ssl_tls(target, open_ports):
    findings = []
    if 443 not in open_ports:
        findings.append({
            'category': 'SSL/TLS',
            'status': 'skipped',
            'message': 'HTTPS service not running',
            'details': '',
            'recommendation': 'Start an HTTPS server to perform this check.'
        })
        return findings
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                sans = cert.get('subjectAltName', [])
                internal_sans = []
                for name in sans:
                    if name[0] == 'DNS':
                        if re.search(r'internal|local|192\.168|10\.|172\.(1[6-9]|2[0-9]|3[0-1])', name[1]):
                            internal_sans.append(name[1])
                    elif name[0] == 'IP Address':
                        if re.match(r'^(192\.168|10\.|172\.(1[6-9]|2[0-9]|3[0-1]))', name[1]):
                            internal_sans.append(name[1])
                
                cipher = ssock.cipher()
                weak_ciphers = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'SSLv3', 'TLSv1', 'TLSv1.1']
                is_weak = any(c in cipher[0] for c in weak_ciphers)
                
                if internal_sans:
                    for san in internal_sans:
                        findings.append({
                            'category': 'SSL/TLS Certificate',
                            'status': 'active',
                            'message': 'Internal domain in certificate',
                            'details': san,
                            'recommendation': 'Remove internal domains from SSL certificate.'
                        })
                
                if is_weak:
                    findings.append({
                        'category': 'SSL/TLS Cipher',
                        'status': 'active',
                        'message': 'Weak SSL/TLS cipher detected',
                        'details': cipher[0],
                        'recommendation': 'Disable weak ciphers and upgrade to TLS 1.2+.'
                    })
                
                if not findings:
                    findings.append({
                        'category': 'SSL/TLS',
                        'status': 'passed',
                        'message': 'SSL/TLS secure',
                        'details': '',
                        'recommendation': 'SSL/TLS configuration is secure.'
                    })
    except Exception as e:
        findings.append({
            'category': 'SSL/TLS',
            'status': 'active',
            'message': 'SSL/TLS check failed',
            'details': str(e),
            'recommendation': 'Verify SSL/TLS configuration for security.'
        })
    return findings

def check_heartbleed(target, open_ports):
    findings = []
    if 443 not in open_ports:
        findings.append({
            'category': 'Heartbleed Vulnerability',
            'status': 'skipped',
            'message': 'HTTPS service not running',
            'details': '',
            'recommendation': 'Start an HTTPS server to perform this check.'
        })
        return findings
    
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        with socket.create_connection((target, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                heartbeat = b'\x01\x00\x00\x00'
                ssock.send(heartbeat)
                response = ssock.recv(1024)
                if response.startswith(b'\x18\x03\x01'):
                    findings.append({
                        'category': 'Heartbleed Vulnerability',
                        'status': 'active',
                        'message': 'Heartbleed vulnerability detected',
                        'details': "Heartbeat response received",
                        'recommendation': 'Immediately upgrade OpenSSL to patched version.'
                    })
        if not findings:
            findings.append({
                'category': 'Heartbleed Vulnerability',
                'status': 'passed',
                'message': 'Heartbleed not detected',
                'details': '',
                'recommendation': 'OpenSSL is up to date and secure.'
            })
    except Exception as e:
        findings.append({
            'category': 'Heartbleed Vulnerability',
            'status': 'active',
            'message': 'Heartbleed check failed',
            'details': str(e),
            'recommendation': 'Verify OpenSSL version for Heartbleed vulnerability.'
        })
    return findings

# ======================
# WEBRTC ANALYSIS FUNCTION
# ======================

def check_webrtc(target, open_ports):
    findings = []
    if 80 not in open_ports and 443 not in open_ports:
        findings.append({
            'category': 'WebRTC Leak',
            'status': 'skipped',
            'message': 'HTTP service not running',
            'details': '',
            'recommendation': 'Start an HTTP server to perform this check.'
        })
        return findings
    
    try:
        from selenium import webdriver
        from selenium.webdriver.firefox.options import Options
        
        options = Options()
        options.headless = True
        driver = webdriver.Firefox(options=options)
        driver.get(f"https://{target}")
        
        result = driver.execute_script("""
            const ips = [];
            const pc = new RTCPeerConnection({iceServers: []});
            pc.createDataChannel('');
            pc.createOffer().then(o => pc.setLocalDescription(o));
            pc.onicecandidate = e => {
                if (e.candidate) ips.push(e.candidate.address);
            };
            return new Promise(resolve => setTimeout(() => resolve(ips), 3000));
        """)
        
        driver.quit()
        
        internal_ips = [ip for ip in result if re.match(r'^(192\.168|10\.|172\.(1[6-9]|2[0-9]|3[0-1]))', ip)]
        stun_servers = re.findall(r'stun:[^"]+', str(result))
        
        if internal_ips:
            for ip in internal_ips:
                findings.append({
                    'category': 'WebRTC Leak',
                    'status': 'active',
                    'message': 'WebRTC internal IP leak',
                    'details': f'Internal IP: {ip}',
                    'recommendation': 'Disable WebRTC in browsers or use a proxy to prevent leaks.'
                })
        if stun_servers:
            for server in stun_servers:
                findings.append({
                    'category': 'WebRTC Leak',
                    'status': 'active',
                    'message': 'STUN server detected',
                    'details': f'STUN server: {server}',
                    'recommendation': 'Ensure STUN servers are not pointing to internal resources.'
                })
        if not findings:
            findings.append({
                'category': 'WebRTC Leak',
                'status': 'passed',
                'message': 'No WebRTC leaks detected',
                'details': '',
                'recommendation': 'WebRTC is configured securely.'
            })
    except Exception as e:
        findings.append({
            'category': 'WebRTC Leak',
            'status': 'active',
            'message': 'WebRTC check failed',
            'details': str(e),
            'recommendation': 'Ensure Selenium and geckodriver are properly installed.'
        })
    return findings

# ======================
# CONTENT ANALYSIS FUNCTION
# ======================

def analyze_content(target, open_ports):
    findings = []
    if 80 not in open_ports and 443 not in open_ports:
        findings.append({
            'category': 'Content Analysis',
            'status': 'skipped',
            'message': 'HTTP service not running',
            'details': '',
            'recommendation': 'Start an HTTP server to perform this check.'
        })
        return findings
    
    try:
        response = requests.get(f"http://{target}", timeout=3)
        comments = re.findall(r'<!--(.*?)-->', response.text, re.DOTALL)
        patterns = {
            "AWS": r"AWS[A-Z0-9]{16,}",
            "Google": r"AIza[0-9A-Za-z\-_]{35}",
            "GitHub": r"[a-f0-9]{40}",
            "Stripe": r"sk_live_[0-9a-zA-Z]{24}",
            "JWT": r"ey[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+",
            "SSH": r"ssh-rsa [A-Za-z0-9+/=]+",
            "PRIVATE_KEY": r"-----BEGIN (RSA|OPENSSH) PRIVATE KEY-----"
        }
        
        # Check HTML comments
        found_comments = []
        for comment in comments:
            for key, pattern in patterns.items():
                if re.search(pattern, comment):
                    found_comments.append(f"{key} in comment: {comment[:50]}")
        
        # Check JavaScript files
        found_js = []
        js_urls = re.findall(r'src="(.*?\.js)"', response.text)
        for js_url in js_urls:
            if not js_url.startswith('http'):
                js_url = f"http://{target}/{js_url.lstrip('/')}"
            try:
                js_response = requests.get(js_url, timeout=2)
                for key, pattern in patterns.items():
                    if re.search(pattern, js_response.text):
                        found_js.append(f"{key} in {js_url}")
            except Exception:
                continue
        
        # Check for exposed debug endpoints
        debug_endpoints = ['debug', 'dev', 'test', 'staging', 'admin']
        found_debug = []
        for endpoint in debug_endpoints:
            url = f"http://{target}/{endpoint}"
            try:
                resp = requests.get(url, timeout=2)
                if resp.status_code == 200 and ('debug' in resp.text.lower() or 'dev' in resp.text.lower()):
                    found_debug.append(url)
            except Exception:
                pass
        
        if found_comments or found_js or found_debug:
            findings.append({
                'category': 'Content Analysis',
                'status': 'active',
                'message': 'Sensitive data found',
                'details': f"Comments: {len(found_comments)}, JS: {len(found_js)}, Debug: {len(found_debug)}",
                'recommendation': 'Remove sensitive information from code and disable debug endpoints.'
            })
        else:
            findings.append({
                'category': 'Content Analysis',
                'status': 'passed',
                'message': 'No sensitive data found',
                'details': '',
                'recommendation': 'Content is properly secured.'
            })
    except Exception as e:
        findings.append({
            'category': 'Content Analysis',
            'status': 'active',
            'message': 'Content analysis failed',
            'details': str(e),
            'recommendation': 'Verify content security configuration.'
        })
    return findings

# ======================
# MAIN SCAN FUNCTION
# ======================

def scan_target(target):
    print_status(f"Scanning target: {target}", "success")
    
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
    
    # DNS Analysis
    findings.extend(analyze_dns(target, open_ports))
    
    # IP Analysis
    findings.extend(port_scan(ip, open_ports))
    findings.extend(check_reverse_dns(ip, open_ports))
    findings.extend(check_routing_table(open_ports))
    findings.extend(check_arp_table(open_ports))
    findings.extend(check_nat_leakage(target, open_ports))
    
    # Web Security
    findings.extend(check_sensitive_files(target, open_ports))
    findings.extend(check_error_messages(target, open_ports))
    findings.extend(check_http_methods(target, open_ports))
    findings.extend(check_git_directory(target, open_ports))
    findings.extend(check_cors(target, open_ports))
    
    # SSL/TLS Analysis
    findings.extend(check_ssl_tls(target, open_ports))
    findings.extend(check_heartbleed(target, open_ports))
    
    # WebRTC Analysis
    findings.extend(check_webrtc(target, open_ports))
    
    # Content Analysis
    findings.extend(analyze_content(target, open_ports))
    
    # Print report
    print_report(findings)

def print_report(findings):
    clear_screen()
    print_header()
    
    # Categorize findings
    active_findings = [f for f in findings if f['status'] == 'active']
    passed_findings = [f for f in findings if f['status'] == 'passed']
    skipped_findings = [f for f in findings if f['status'] == 'skipped']
    
    # Executive Summary
    print("\n[ EXECUTIVE SUMMARY ]")
    print(f"Total Checks: {len(findings)}")
    print(f"Critical Findings: {len([f for f in active_findings if classify_severity(f) == 'CRITICAL'])}")
    print(f"Medium Findings: {len([f for f in active_findings if classify_severity(f) == 'MEDIUM'])}")
    print(f"Low Findings: {len([f for f in active_findings if classify_severity(f) == 'LOW'])}")
    print(f"Passed Checks: {len(passed_findings)}")
    print(f"Skipped Checks: {len(skipped_findings)}")
    print("\n" + "="*60)
    
    # Active Findings Table
    if active_findings:
        print("\n[ CRITICAL FINDINGS ]")
        headers = ["Category", "Finding", "Severity", "Recommendation"]
        rows = []
        for f in active_findings:
            severity = classify_severity(f)
            row = [
                f['category'],
                f['message'],
                severity,
                f['recommendation']
            ]
            rows.append(row)
        print_table("Active Findings", headers, rows)
    
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
                f['recommendation']
            ]
            rows.append(row)
        print_table("Skipped Checks", headers, rows)
    
    if not active_findings and not passed_findings and not skipped_findings:
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