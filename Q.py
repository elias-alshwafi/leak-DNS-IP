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

# ======================
# HELPER FUNCTIONS
# ======================

def print_table(title, headers, rows):
    """Prints a professional ASCII table with centered content"""
    # Calculate column widths
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if len(str(cell)) > col_widths[i]:
                col_widths[i] = len(str(cell))
    
    # Add padding
    col_widths = [w + 2 for w in col_widths]
    
    # Print header
    print(f"+{'-'.join(['-'*w for w in col_widths])}+")
    header_line = "|"
    for i, h in enumerate(headers):
        header_line += f" {h:^{col_widths[i]-2}} |"
    print(header_line)
    print(f"+{'-'.join(['-'*w for w in col_widths])}+")
    
    # Print rows
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
    print("🔐 LEAK DETECTIVE - PROFESSIONAL OFFLINE SECURITY SCANNER")
    print("="*60)
    print("Version 1.1 | Developed for ethical security testing")
    print("No external APIs required - fully self-contained\n")

def print_status(message, status):
    """Prints a status message with emoji indicator"""
    emoji = "✅" if status == "success" else "⚠️" if status == "warning" else "❌"
    print(f"\n{emoji} {message}")

# ======================
# DNS ANALYSIS FUNCTIONS
# ======================

def analyze_dns(domain):
    print_status("Analyzing DNS records", "success")
    results = {}
    
    # SOA Record Check
    try:
        soa = dns.resolver.resolve(domain, 'SOA')
        for rdata in soa:
            admin_email = rdata.rname.to_text().replace('.', '@', 1)[:-1]
            results['soa'] = {
                'status': '✅ SOA record found',
                'details': [f'Admin email: {admin_email}']
            }
    except dns.exception.DNSException:
        results['soa'] = {'status': '❌ No SOA record found', 'details': []}
    
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
            results['ns'] = {
                'status': '⚠️ Internal NS records detected',
                'details': private_ns
            }
        else:
            results['ns'] = {'status': '✅ No internal NS records', 'details': []}
    except dns.exception.DNSException:
        results['ns'] = {'status': '❌ NS check failed', 'details': []}
    
    # SPF Record Check
    try:
        spf = dns.resolver.resolve(domain, 'TXT')
        spf_data = []
        for rdata in spf:
            txt = rdata.to_text()
            if 'v=spf1' in txt and re.search(r'192\.168|10\.|172\.', txt):
                spf_data.append(txt)
        if spf_data:
            results['spf'] = {
                'status': '⚠️ SPF contains internal IPs',
                'details': spf_data
            }
        else:
            results['spf'] = {'status': '✅ SPF secure', 'details': []}
    except dns.exception.DNSException:
        results['spf'] = {'status': '❌ No SPF record found', 'details': []}
    
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
            results['axfr'] = {
                'status': '⚠️ AXFR allowed',
                'details': ['Zone transfer possible']
            }
        else:
            results['axfr'] = {'status': '✅ AXFR blocked', 'details': []}
    except dns.exception.DNSException:
        results['axfr'] = {'status': '❌ AXFR check failed', 'details': []}
    
    # Wildcard Check
    random_sub = f"xyz{int(time.time())}.{domain}"
    try:
        dns.resolver.resolve(random_sub, 'A')
        results['wildcard'] = {
            'status': '⚠️ Wildcard record detected',
            'details': [f"Subdomain: {random_sub}"]
        }
    except dns.exception.DNSException:
        results['wildcard'] = {'status': '✅ No wildcard record', 'details': []}
    
    return results

# ======================
# IP ANALYSIS FUNCTIONS
# ======================

def port_scan(target_ip):
    print_status("Scanning open ports", "success")
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379, 27017, 8080, 8443]
    results = []
    
    def check_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.5)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    sock.send(b'')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    if re.search(r'192\.168|10\.|172\.(1[6-9]|2[0-9]|3[0-1])', banner):
                        return f"Port {port}: {banner[:50]} (LEAK)"
                    return f"Port {port}: open (banner: {banner[:50]})"
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(check_port, port) for port in common_ports]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
    
    return {
        'status': '⚠️ Ports with potential leaks' if results else '✅ No port leaks',
        'details': results
    }

def check_reverse_dns(target_ip):
    print_status("Checking reverse DNS", "success")
    try:
        hostname = socket.gethostbyaddr(target_ip)[0]
        if re.search(r'internal|local|192\.168|10\.|172\.', hostname):
            return {
                'status': '⚠️ Reverse DNS leak',
                'details': [f"Hostname: {hostname}"]
            }
        return {
            'status': '✅ Reverse DNS secure',
            'details': []
        }
    except Exception:
        return {
            'status': '❌ Reverse DNS check failed',
            'details': []
        }

def check_routing_table():
    print_status("Checking routing table", "success")
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
        
        return {
            'status': '⚠️ Internal routes detected' if internal_routes else '✅ No internal routes',
            'details': internal_routes
        }
    except Exception as e:
        return {
            'status': '❌ Routing check failed',
            'details': [str(e)]
        }

def check_arp_table():
    print_status("Checking ARP table", "success")
    try:
        if sys.platform == "win32":
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
        else:
            result = subprocess.run(["arp", "-n"], capture_output=True, text=True)
        
        internal_ips = []
        for line in result.stdout.splitlines():
            if re.search(r'192\.168|10\.|172\.', line):
                internal_ips.append(line.strip())
        
        return {
            'status': '⚠️ Internal devices detected' if internal_ips else '✅ No internal devices',
            'details': internal_ips
        }
    except Exception as e:
        return {
            'status': '❌ ARP check failed',
            'details': [str(e)]
        }

def check_nat_leakage(target):
    print_status("Checking NAT leakage", "success")
    try:
        response = requests.get(f"http://{target}", timeout=2)
        headers = response.headers
        if 'X-Forwarded-For' in headers or 'X-Real-IP' in headers:
            if re.search(r'192\.168|10\.|172\.', headers.get('X-Forwarded-For', '')):
                return {
                    'status': '⚠️ NAT leakage detected',
                    'details': [headers.get('X-Forwarded-For', '')]
                }
        return {
            'status': '✅ NAT secure',
            'details': []
        }
    except Exception as e:
        return {
            'status': '❌ NAT check failed',
            'details': [str(e)]
        }

# ======================
# WEB SECURITY FUNCTIONS
# ======================

def check_sensitive_files(target):
    print_status("Checking sensitive files", "success")
    paths = [
        '.env', 'phpinfo.php', 'wp-config.php', 'config.php', 
        'backup.zip', 'database.sql', 'settings.json', 
        '.git/config', '.svn/entries', '.DS_Store', 
        '.htaccess', '.user.ini', 'robots.txt', 'sitemap.xml',
        'admin/', 'cpanel/', 'phpmyadmin/', 'swagger.json'
    ]
    found = []
    for path in paths:
        url = f"http://{target}/{path}"
        try:
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                if 'secret' in response.text.lower() or 'password' in response.text.lower() or 'db_' in response.text.lower():
                    found.append(f"{url} (sensitive content)")
                else:
                    found.append(f"{url} (exists)")
        except:
            continue
    return {
        'status': '⚠️ Sensitive files exposed' if found else '✅ No sensitive files',
        'details': found
    }

def check_error_messages(target):
    print_status("Checking error messages", "success")
    try:
        url = f"http://{target}/randompath123"
        response = requests.get(url, timeout=2)
        if 'error' in response.text.lower() or 'exception' in response.text.lower() or 'stack trace' in response.text.lower():
            return {
                'status': '⚠️ Error messages exposed',
                'details': [response.text[:200]]
            }
        return {
            'status': '✅ No error messages exposed',
            'details': []
        }
    except Exception as e:
        return {
            'status': '❌ Error check failed',
            'details': [str(e)]
        }

def check_http_methods(target):
    print_status("Checking HTTP methods", "success")
    try:
        response = requests.options(f"http://{target}", timeout=2)
        methods = response.headers.get('Allow', '')
        if 'PUT' in methods or 'DELETE' in methods or 'TRACE' in methods:
            return {
                'status': '⚠️ Dangerous HTTP methods enabled',
                'details': [methods]
            }
        return {
            'status': '✅ HTTP methods secure',
            'details': []
        }
    except Exception as e:
        return {
            'status': '❌ HTTP methods check failed',
            'details': [str(e)]
        }

def check_git_directory(target):
    print_status("Checking .git directory", "success")
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
        except:
            continue
    return {
        'status': '⚠️ .git directory exposed' if found else '✅ .git directory secure',
        'details': found
    }

# ======================
# SSL/TLS ANALYSIS FUNCTIONS
# ======================

def check_ssl_tls(target):
    print_status("Analyzing SSL/TLS", "success")
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
                weak_ciphers = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT']
                is_weak = any(c in cipher[0] for c in weak_ciphers)
                
                expiry = cert.get('notAfter')
                
                return {
                    'status': '⚠️ SSL/TLS vulnerabilities detected' if internal_sans or is_weak else '✅ SSL/TLS secure',
                    'details': {
                        'SANs': internal_sans,
                        'weak_cipher': is_weak,
                        'cipher': cipher[0],
                        'expiry': expiry
                    }
                }
    except Exception as e:
        return {
            'status': '❌ SSL/TLS check failed',
            'details': [str(e)]
        }

def check_heartbleed(target):
    print_status("Checking Heartbleed vulnerability", "success")
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
                    return {
                        'status': '⚠️ Heartbleed vulnerability detected',
                        'details': ["Heartbeat response received"]
                    }
        return {
            'status': '✅ Heartbleed not detected',
            'details': []
        }
    except Exception as e:
        return {
            'status': '❌ Heartbleed check failed',
            'details': [str(e)]
        }

# ======================
# WEBRTC ANALYSIS FUNCTION
# ======================

def check_webrtc(target):
    print_status("Checking WebRTC leaks", "success")
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
        
        return {
            'status': '⚠️ WebRTC leaks detected' if internal_ips or stun_servers else '✅ WebRTC secure',
            'details': {
                'internal_ips': internal_ips,
                'stun_servers': stun_servers
            }
        }
    except Exception as e:
        return {
            'status': '❌ WebRTC check failed',
            'details': [str(e)]
        }

# ======================
# CONTENT ANALYSIS FUNCTION
# ======================

def analyze_content(target):
    print_status("Analyzing content for secrets", "success")
    try:
        response = requests.get(f"http://{target}", timeout=3)
        comments = re.findall(r'<!--(.*?)-->', response.text, re.DOTALL)
        sensitive_comments = []
        patterns = {
            "AWS": r"AWS[A-Z0-9]{16,}",
            "Google": r"AIza[0-9A-Za-z\-_]{35}",
            "GitHub": r"[a-f0-9]{40}",
            "Stripe": r"sk_live_[0-9a-zA-Z]{24}",
            "JWT": r"ey[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+"
        }
        for comment in comments:
            for key, pattern in patterns.items():
                if re.search(pattern, comment):
                    sensitive_comments.append(f"{key} in comment: {comment[:50]}")
        
        js_urls = re.findall(r'src="(.*?\.js)"', response.text)
        sensitive_js = []
        for js_url in js_urls:
            if not js_url.startswith('http'):
                js_url = f"http://{target}/{js_url.lstrip('/')}"
            try:
                js_response = requests.get(js_url, timeout=2)
                for key, pattern in patterns.items():
                    if re.search(pattern, js_response.text):
                        sensitive_js.append(f"{key} in {js_url}")
            except:
                continue
        
        return {
            'status': '⚠️ Sensitive data found' if sensitive_comments or sensitive_js else '✅ No sensitive data',
            'details': {
                'comments': sensitive_comments,
                'js': sensitive_js
            }
        }
    except Exception as e:
        return {
            'status': '❌ Content analysis failed',
            'details': [str(e)]
        }

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
    
    # Run all checks
    results = {
        "dns": analyze_dns(target),
        "ip": {
            "port_scan": port_scan(ip),
            "reverse_dns": check_reverse_dns(ip),
            "routing_table": check_routing_table(),
            "arp_table": check_arp_table(),
            "nat_leakage": check_nat_leakage(target)
        },
        "web": {
            "sensitive_files": check_sensitive_files(target),
            "error_messages": check_error_messages(target),
            "http_methods": check_http_methods(target),
            "git_directory": check_git_directory(target)
        },
        "ssl": {
            "ssl_tls": check_ssl_tls(target),
            "heartbleed": check_heartbleed(target)
        },
        "webrtc": check_webrtc(target),
        "content": analyze_content(target)
    }
    
    # Print report
    print_report(results)

def print_report(results):
    clear_screen()
    print_header()
    
    # DNS Analysis
    print("\n[ DNS ANALYSIS ]")
    dns_headers = ["Check", "Status", "Details"]
    dns_rows = []
    for check_name, check_data in results['dns'].items():
        status = check_data.get('status', 'N/A')
        details = check_data.get('details', [])
        if isinstance(details, list):
            details_str = "\n".join(details) if details else "N/A"
        else:
            details_str = str(details)
        dns_rows.append([check_name, status, details_str])
    print_table("DNS Analysis", dns_headers, dns_rows)
    
    # IP Analysis
    print("\n[ IP ANALYSIS ]")
    ip_headers = ["Check", "Status", "Details"]
    ip_rows = []
    for check_name, check_data in results['ip'].items():
        status = check_data.get('status', 'N/A')
        details = check_data.get('details', [])
        if isinstance(details, list):
            details_str = "\n".join(details) if details else "N/A"
        else:
            details_str = str(details)
        ip_rows.append([check_name, status, details_str])
    print_table("IP Analysis", ip_headers, ip_rows)
    
    # Web Security
    print("\n[ WEB SECURITY ]")
    web_headers = ["Check", "Status", "Details"]
    web_rows = []
    for check_name, check_data in results['web'].items():
        status = check_data.get('status', 'N/A')
        details = check_data.get('details', [])
        if isinstance(details, list):
            details_str = "\n".join(details) if details else "N/A"
        else:
            details_str = str(details)
        web_rows.append([check_name, status, details_str])
    print_table("Web Security", web_headers, web_rows)
    
    # SSL/TLS Analysis
    print("\n[ SSL/TLS ANALYSIS ]")
    ssl_headers = ["Check", "Status", "Details"]
    ssl_rows = []
    for check_name, check_data in results['ssl'].items():
        status = check_data.get('status', 'N/A')
        details = check_data.get('details', {})
        if isinstance(details, dict):
            details_str = "\n".join([f"{k}: {v}" for k, v in details.items()]) if details else "N/A"
        else:
            details_str = str(details)
        ssl_rows.append([check_name, status, details_str])
    print_table("SSL/TLS Analysis", ssl_headers, ssl_rows)
    
    # WebRTC Analysis
    print("\n[ WEBRTC ANALYSIS ]")
    webrtc_data = results['webrtc']
    status = webrtc_data['status']
    details = webrtc_data.get('details', [])
    
    if isinstance(details, dict):
        internal_ips = details.get('internal_ips', [])
        stun_servers = details.get('stun_servers', [])
        details_str = ""
        if internal_ips:
            details_str += "Internal IPs:\n" + "\n".join(internal_ips)
        if stun_servers:
            if details_str: details_str += "\n"
            details_str += "STUN Servers:\n" + "\n".join(stun_servers)
        if not details_str:
            details_str = "N/A"
    elif isinstance(details, list):
        details_str = "\n".join(details) if details else "N/A"
    else:
        details_str = "N/A"
    
    webrtc_rows = [["WebRTC Leaks", status, details_str]]
    print_table("WebRTC Analysis", ["WebRTC Check", "Status", "Details"], webrtc_rows)
    
    # Content Analysis
    print("\n[ CONTENT ANALYSIS ]")
    content_data = results['content']
    status = content_data.get('status', 'N/A')
    details = content_data.get('details', [])
    
    if isinstance(details, dict):
        comment_details = "\n".join(details.get('comments', [])) if details.get('comments') else "N/A"
        js_details = "\n".join(details.get('js', [])) if details.get('js') else "N/A"
        content_rows = [
            ["HTML Comments", status, comment_details],
            ["JavaScript Files", status, js_details]
        ]
    elif isinstance(details, list):
        content_rows = [["Content Analysis", status, "\n".join(details) if details else "N/A"]]
    else:
        content_rows = [["Content Analysis", status, "N/A"]]
    
    print_table("Content Analysis", ["Analysis Type", "Status", "Details"], content_rows)
    
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
            # For local machine scan, use 127.0.0.1 or localhost
            scan_target("localhost")
            input("\nPress Enter to return to main menu...")
        elif choice == '3':
            clear_screen()
            print("\nThank you for using Leak Detective. Stay secure!")
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
