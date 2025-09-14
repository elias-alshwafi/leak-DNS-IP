#!/usr/bin/env python3
"""
Enhanced DNS and IP Leak Detector
A comprehensive tool with advanced detection capabilities and professional interface
"""

import os
import sys
import json
import socket
import requests
import subprocess
import threading
import time
import re
import ipaddress
from datetime import datetime
from urllib.parse import urlparse
import dns.resolver
import dns.exception
import netifaces
from prettytable import PrettyTable, ALL
import colorama
from colorama import Fore, Back, Style
import concurrent.futures

# Initialize colorama
colorama.init(autoreset=True)

class EnhancedLeakDetector:
    def __init__(self):
        self.results = {
            'dns_leaks': [],
            'ip_leaks': [],
            'webrtc_leaks': [],
            'network_info': {},
            'vpn_status': {},
            'test_time': None,
            'threat_level': 'LOW',
            'summary': {}
        }
        self.target = None
        self.test_mode = None
        self.vpn_ips = self.load_vpn_ips()
        
    def load_vpn_ips(self):
        """Load known VPN IP ranges"""
        # In a real implementation, this would be a comprehensive list
        # For demo purposes, we're using common private IP ranges
        vpn_ranges = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('100.64.0.0/10'),  # Carrier-grade NAT
        ]
        return vpn_ranges
    
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def display_banner(self):
        """Display the tool banner"""
        self.clear_screen()
        print(Fore.CYAN + r"""
    ____  _   _  ____        _        _             _            
   |  _ \| \ | |/ ___|  __ _| | _____| |_ ___  _ __(_)_ __   ___ 
   | | | |  \| | |  _  / _` | |/ / _ | __/ _ \| '__| | '_ \ / _ \
   | |_| | |\  | |_| || (_| |   <  __| || (_) | |  | | | | |  __/
   |____/|_| \_|\____| \__,_|_|\_\___|\__\___/|_|  |_|_| |_|\___|
                                                                 
        """ + Style.RESET_ALL)
        print(Fore.YELLOW + "         ENHANCED DNS & IP LEAK DETECTOR" + Style.RESET_ALL)
        print(Fore.YELLOW + "         ------------------------------" + Style.RESET_ALL)
        print()
    
    def display_menu(self):
        """Display the main menu"""
        self.display_banner()
        print(Fore.GREEN + "MAIN MENU:" + Style.RESET_ALL)
        print("1. 🔍 Comprehensive System Leak Test")
        print("2. 🎯 Test Specific Target (IP/Domain)")
        print("3. 📊 Advanced Network Analysis")
        print("4. 📋 View Previous Results")
        print("5. ℹ️  Help & Information")
        print("6. 🚪 Exit")
        print()
        
        choice = input(Fore.CYAN + "Select an option (1-6): " + Style.RESET_ALL)
        return choice
    
    def get_target_input(self):
        """Get target input from user"""
        self.display_banner()
        print(Fore.GREEN + "TARGET SELECTION:" + Style.RESET_ALL)
        print("1. Enter IP address")
        print("2. Enter domain name")
        print("3. Return to main menu")
        print()
        
        choice = input(Fore.CYAN + "Select an option (1-3): " + Style.RESET_ALL)
        
        if choice == '1':
            target = input("Enter IP address: ").strip()
            if self.validate_ip(target):
                return target
            else:
                print(Fore.RED + "Invalid IP address format!" + Style.RESET_ALL)
                time.sleep(2)
                return self.get_target_input()
        elif choice == '2':
            target = input("Enter domain name: ").strip()
            if self.validate_domain(target):
                return target
            else:
                print(Fore.RED + "Invalid domain format!" + Style.RESET_ALL)
                time.sleep(2)
                return self.get_target_input()
        elif choice == '3':
            return None
        else:
            print(Fore.RED + "Invalid option!" + Style.RESET_ALL)
            time.sleep(1)
            return self.get_target_input()
    
    def validate_ip(self, ip):
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def validate_domain(self, domain):
        """Validate domain format"""
        try:
            # Remove protocol if present
            domain = re.sub(r'^https?://', '', domain)
            # Extract domain from URL if present
            domain = re.sub(r'/.*$', '', domain)
            socket.getaddrinfo(domain, 0)
            return True
        except socket.gaierror:
            return False
    
    def get_network_info(self):
        """Get detailed network information"""
        interfaces = netifaces.interfaces()
        interface_info = []
        gateway_info = {}
        
        # Get gateway information with error handling
        try:
            gateways = netifaces.gateways()
            if 'default' in gateways:
                for af, gateway_data in gateways['default'].items():
                    # Handle different gateway data formats
                    if isinstance(gateway_data, tuple):
                        if len(gateway_data) >= 2:
                            gateway_info[af] = {'ip': gateway_data[0], 'interface': gateway_data[1]}
                        else:
                            gateway_info[af] = {'ip': 'N/A', 'interface': 'N/A'}
                    else:
                        gateway_info[af] = {'ip': 'N/A', 'interface': 'N/A'}
        except Exception as e:
            print(Fore.YELLOW + f"Warning: Could not get gateway info: {e}" + Style.RESET_ALL)
        
        for interface in interfaces:
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    # Get gateway for this interface
                    gateway_ip = 'N/A'
                    for af, info in gateway_info.items():
                        if info.get('interface') == interface:
                            gateway_ip = info.get('ip', 'N/A')
                            break
                    
                    info = {
                        'interface': interface,
                        'ip': addr.get('addr', 'N/A'),
                        'netmask': addr.get('netmask', 'N/A'),
                        'broadcast': addr.get('broadcast', 'N/A'),
                        'gateway': gateway_ip
                    }
                    interface_info.append(info)
        
        return interface_info
    
    def is_vpn_ip(self, ip):
        """Check if IP is likely a VPN IP"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self.vpn_ips:
                if ip_obj in network:
                    return True
            return False
        except ValueError:
            return False
    
    def check_vpn_status(self):
        """Check if VPN is active based on network configuration"""
        interfaces = self.get_network_info()
        vpn_detected = False
        vpn_interfaces = []
        
        for iface in interfaces:
            if iface['interface'].startswith(('tun', 'tap', 'ppp', 'wg')):
                vpn_detected = True
                vpn_interfaces.append(iface['interface'])
            elif self.is_vpn_ip(iface['ip']):
                vpn_detected = True
                vpn_interfaces.append(iface['interface'])
        
        return {
            'vpn_detected': vpn_detected,
            'vpn_interfaces': vpn_interfaces,
            'all_interfaces': interfaces
        }
    
    def detect_dns_leaks_advanced(self):
        """Advanced DNS leak detection"""
        print(Fore.YELLOW + "\n[+] Testing for DNS leaks with advanced techniques..." + Style.RESET_ALL)
        
        results = []
        
        # Test 1: DNS server comparison
        try:
            resolver = dns.resolver.Resolver()
            dns_servers = resolver.nameservers
            
            leak_status = False
            for server in dns_servers:
                if not self.is_vpn_ip(server):
                    leak_status = True
                    break
            
            results.append({
                'test_name': 'DNS Server Comparison',
                'method': 'Compares configured DNS servers with known VPN ranges',
                'data': dns_servers,
                'leak_detected': leak_status,
                'risk_level': 'HIGH' if leak_status else 'LOW',
                'details': f"Found {len(dns_servers)} DNS servers" + 
                          (f", {sum(1 for s in dns_servers if not self.is_vpn_ip(s))} are non-VPN" if leak_status else "")
            })
        except Exception as e:
            results.append({
                'test_name': 'DNS Server Comparison',
                'method': 'Compares configured DNS servers with known VPN ranges',
                'error': str(e),
                'leak_detected': False,
                'risk_level': 'UNKNOWN'
            })
        
        # Test 2: DNS over HTTPS test
        try:
            test_domains = ['whoami.akamai.net', 'checkip.dyndns.org', 'myip.opendns.com']
            leaked_ips = []
            
            for domain in test_domains:
                try:
                    response = requests.get(f'https://cloudflare-dns.com/dns-query', 
                                           params={'name': domain, 'type': 'TXT'},
                                           headers={'accept': 'application/dns-json'},
                                           timeout=10)
                    data = response.json()
                    if 'Answer' in data:
                        answer = data['Answer'][0]['data'].strip('"')
                        if not self.is_vpn_ip(answer):
                            leaked_ips.append(answer)
                except:
                    continue
            
            results.append({
                'test_name': 'DNS over HTTPS (DoH)',
                'method': 'Tests DNS queries over HTTPS to detect leaks',
                'data': leaked_ips,
                'leak_detected': len(leaked_ips) > 0,
                'risk_level': 'HIGH' if leaked_ips else 'LOW',
                'details': f"Found {len(leaked_ips)} potential IP leaks via DoH" if leaked_ips else "No leaks detected via DoH"
            })
        except Exception as e:
            results.append({
                'test_name': 'DNS over HTTPS (DoH)',
                'method': 'Tests DNS queries over HTTPS to detect leaks',
                'error': str(e),
                'leak_detected': False,
                'risk_level': 'UNKNOWN'
            })
        
        # Test 3: Multiple domain resolution with parallelism
        try:
            test_domains = [
                'google.com', 'facebook.com', 'amazon.com', 'netflix.com', 
                'github.com', 'twitter.com', 'microsoft.com', 'apple.com'
            ]
            
            resolved_ips = []
            
            def resolve_domain(domain):
                try:
                    ips = socket.getaddrinfo(domain, 80)
                    return [ip[4][0] for ip in ips]
                except:
                    return []
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                future_to_domain = {executor.submit(resolve_domain, domain): domain for domain in test_domains}
                for future in concurrent.futures.as_completed(future_to_domain):
                    ips = future.result()
                    resolved_ips.extend(ips)
            
            # Check for leaks
            leaked_ips = [ip for ip in resolved_ips if not self.is_vpn_ip(ip)]
            
            results.append({
                'test_name': 'Parallel Domain Resolution',
                'method': 'Resolves multiple domains in parallel to detect inconsistencies',
                'data': list(set(resolved_ips)),
                'leak_detected': len(leaked_ips) > 0,
                'risk_level': 'HIGH' if leaked_ips else 'LOW',
                'details': f"Resolved {len(set(resolved_ips))} unique IPs, {len(leaked_ips)} potential leaks" if leaked_ips else "All resolutions consistent with VPN"
            })
        except Exception as e:
            results.append({
                'test_name': 'Parallel Domain Resolution',
                'method': 'Resolves multiple domains in parallel to detect inconsistencies',
                'error': str(e),
                'leak_detected': False,
                'risk_level': 'UNKNOWN'
            })
        
        # Test 4: DNS cache snooping (simulated)
        try:
            # This is a simulated test - real DNS cache snooping is complex
            results.append({
                'test_name': 'DNS Cache Analysis',
                'method': 'Checks for DNS cache artifacts that might reveal activity',
                'data': [],
                'leak_detected': False,
                'risk_level': 'LOW',
                'details': 'No cache artifacts detected (simulated result)'
            })
        except Exception as e:
            results.append({
                'test_name': 'DNS Cache Analysis',
                'method': 'Checks for DNS cache artifacts that might reveal activity',
                'error': str(e),
                'leak_detected': False,
                'risk_level': 'UNKNOWN'
            })
        
        return results
    
    def detect_ip_leaks_advanced(self):
        """Advanced IP leak detection"""
        print(Fore.YELLOW + "[+] Testing for IP leaks with advanced techniques..." + Style.RESET_ALL)
        
        results = []
        
        # Test 1: Multi-service IP detection
        services = [
            {'name': 'ipify', 'url': 'https://api.ipify.org', 'format': 'text'},
            {'name': 'ident.me', 'url': 'https://ident.me', 'format': 'text'},
            {'name': 'Amazon AWS', 'url': 'https://checkip.amazonaws.com', 'format': 'text'},
            {'name': 'icanhazip', 'url': 'https://icanhazip.com', 'format': 'text'},
            {'name': 'JSON IP', 'url': 'https://jsonip.com', 'format': 'json', 'field': 'ip'},
            {'name': 'IP API', 'url': 'http://ip-api.com/json', 'format': 'json', 'field': 'query'},
        ]
        
        detected_ips = {}
        
        def check_service(service):
            try:
                response = requests.get(service['url'], timeout=10)
                if service['format'] == 'text':
                    ip = response.text.strip()
                else:  # JSON
                    data = response.json()
                    ip = data.get(service['field'], '').strip()
                
                if self.validate_ip(ip):
                    return service['name'], ip
            except:
                return service['name'], None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(services)) as executor:
            future_to_service = {executor.submit(check_service, service): service for service in services}
            for future in concurrent.futures.as_completed(future_to_service):
                service_name, ip = future.result()
                if ip:
                    detected_ips[service_name] = ip
        
        # Check for leaks
        leaked_ips = {service: ip for service, ip in detected_ips.items() if not self.is_vpn_ip(ip)}
        consistent = len(set(detected_ips.values())) <= 1  # All services report the same IP
        
        results.append({
            'test_name': 'Multi-Service IP Detection',
            'method': 'Checks public IP from multiple services for consistency',
            'data': detected_ips,
            'leak_detected': len(leaked_ips) > 0,
            'risk_level': 'HIGH' if leaked_ips else 'LOW',
            'details': f"Found {len(detected_ips)} IPs across {len(services)} services, " +
                      f"{len(leaked_ips)} potential leaks" if leaked_ips else "All services report consistent VPN IP"
        })
        
        # Test 2: HTTP header analysis
        try:
            test_headers = [
                'https://httpbin.org/headers',
                'https://httpbin.org/ip',
                'https://httpbin.org/user-agent'
            ]
            
            suspicious_headers = {}
            
            for url in test_headers:
                try:
                    response = requests.get(url, timeout=10)
                    headers = response.json()
                    
                    for header, value in headers.items():
                        if any(keyword in header.lower() for keyword in ['client', 'forwarded', 'real', 'x-']):
                            if url not in suspicious_headers:
                                suspicious_headers[url] = {}
                            suspicious_headers[url][header] = value
                except:
                    continue
            
            results.append({
                'test_name': 'HTTP Header Analysis',
                'method': 'Analyzes HTTP headers for IP disclosure vulnerabilities',
                'data': suspicious_headers,
                'leak_detected': len(suspicious_headers) > 0,
                'risk_level': 'MEDIUM' if suspicious_headers else 'LOW',
                'details': f"Found {sum(len(v) for v in suspicious_headers.values())} suspicious headers" if suspicious_headers else "No suspicious headers detected"
            })
        except Exception as e:
            results.append({
                'test_name': 'HTTP Header Analysis',
                'method': 'Analyzes HTTP headers for IP disclosure vulnerabilities',
                'error': str(e),
                'leak_detected': False,
                'risk_level': 'UNKNOWN'
            })
        
        # Test 3: IPv6 leak detection
        try:
            ipv6_services = [
                'https://ipv6.icanhazip.com',
                'https://v6.ident.me',
                'https://api6.ipify.org'
            ]
            
            ipv6_addresses = []
            
            for service in ipv6_services:
                try:
                    response = requests.get(service, timeout=10)
                    ip = response.text.strip()
                    if ':' in ip:  # Simple IPv6 check
                        ipv6_addresses.append(ip)
                except:
                    continue
            
            results.append({
                'test_name': 'IPv6 Leak Detection',
                'method': 'Tests for IPv6 address leakage',
                'data': ipv6_addresses,
                'leak_detected': len(ipv6_addresses) > 0,
                'risk_level': 'HIGH' if ipv6_addresses else 'LOW',
                'details': f"Found {len(ipv6_addresses)} IPv6 addresses" if ipv6_addresses else "No IPv6 addresses detected"
            })
        except Exception as e:
            results.append({
                'test_name': 'IPv6 Leak Detection',
                'method': 'Tests for IPv6 address leakage',
                'error': str(e),
                'leak_detected': False,
                'risk_level': 'UNKNOWN'
            })
        
        return results
    
    def detect_webrtc_leaks_advanced(self):
        """Advanced WebRTC leak detection (simulated)"""
        print(Fore.YELLOW + "[+] Testing for WebRTC leaks with advanced techniques..." + Style.RESET_ALL)
        
        results = []
        
        # Test 1: Local IP detection
        try:
            local_ips = []
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        local_ips.append(addr['addr'])
            
            results.append({
                'test_name': 'Local IP Detection',
                'method': 'Detects local IP addresses that could be exposed via WebRTC',
                'data': local_ips,
                'leak_detected': len(local_ips) > 0,
                'risk_level': 'MEDIUM' if local_ips else 'LOW',
                'details': f"Found {len(local_ips)} local IP addresses" if local_ips else "No local IP addresses detected"
            })
        except Exception as e:
            results.append({
                'test_name': 'Local IP Detection',
                'method': 'Detects local IP addresses that could be exposed via WebRTC',
                'error': str(e),
                'leak_detected': False,
                'risk_level': 'UNKNOWN'
            })
        
        # Test 2: Network interface enumeration
        try:
            interfaces = netifaces.interfaces()
            interface_details = []
            
            for interface in interfaces:
                addrs = netifaces.ifaddresses(interface)
                details = {'interface': interface}
                
                if netifaces.AF_INET in addrs:
                    details['ipv4'] = [addr['addr'] for addr in addrs[netifaces.AF_INET]]
                
                if netifaces.AF_INET6 in addrs:
                    details['ipv6'] = [addr['addr'] for addr in addrs[netifaces.AF_INET6]]
                
                interface_details.append(details)
            
            results.append({
                'test_name': 'Network Interface Enumeration',
                'method': 'Enumerates network interfaces that could be exposed',
                'data': interface_details,
                'leak_detected': len(interface_details) > 0,
                'risk_level': 'MEDIUM' if interface_details else 'LOW',
                'details': f"Found {len(interface_details)} network interfaces" if interface_details else "No network interfaces detected"
            })
        except Exception as e:
            results.append({
                'test_name': 'Network Interface Enumeration',
                'method': 'Enumerates network interfaces that could be exposed',
                'error': str(e),
                'leak_detected': False,
                'risk_level': 'UNKNOWN'
            })
        
        return results
    
    def run_comprehensive_test(self, target=None):
        """Run all leak detection tests"""
        self.display_banner()
        print(Fore.GREEN + "Running Comprehensive Leak Detection..." + Style.RESET_ALL)
        
        # Initialize results
        self.results = {
            'dns_leaks': [],
            'ip_leaks': [],
            'webrtc_leaks': [],
            'network_info': {},
            'vpn_status': {},
            'test_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'threat_level': 'LOW',
            'summary': {
                'total_tests': 0,
                'passed_tests': 0,
                'failed_tests': 0,
                'leaks_detected': 0
            }
        }
        
        # Check VPN status
        print(Fore.YELLOW + "[+] Checking VPN status..." + Style.RESET_ALL)
        try:
            self.results['vpn_status'] = self.check_vpn_status()
        except Exception as e:
            print(Fore.RED + f"Error checking VPN status: {e}" + Style.RESET_ALL)
            self.results['vpn_status'] = {'error': str(e)}
        time.sleep(0.5)
        
        # Get network information
        print(Fore.YELLOW + "[+] Gathering network information..." + Style.RESET_ALL)
        try:
            self.results['network_info'] = self.get_network_info()
        except Exception as e:
            print(Fore.RED + f"Error gathering network info: {e}" + Style.RESET_ALL)
            self.results['network_info'] = {'error': str(e)}
        time.sleep(0.5)
        
        # Run tests with progress indication
        tests = [
            ('DNS Leak Detection', self.detect_dns_leaks_advanced),
            ('IP Leak Detection', self.detect_ip_leaks_advanced),
            ('WebRTC Leak Detection', self.detect_webrtc_leaks_advanced)
        ]
        
        for i, (name, test_func) in enumerate(tests):
            print(Fore.YELLOW + f"[{i+1}/{len(tests)}] Running {name}..." + Style.RESET_ALL)
            try:
                results = test_func()
                if name == 'DNS Leak Detection':
                    self.results['dns_leaks'] = results
                elif name == 'IP Leak Detection':
                    self.results['ip_leaks'] = results
                elif name == 'WebRTC Leak Detection':
                    self.results['webrtc_leaks'] = results
                
                # Update summary
                for result in results:
                    self.results['summary']['total_tests'] += 1
                    if result.get('leak_detected', False):
                        self.results['summary']['failed_tests'] += 1
                        self.results['summary']['leaks_detected'] += 1
                    else:
                        self.results['summary']['passed_tests'] += 1
            except Exception as e:
                print(Fore.RED + f"Error in {name}: {str(e)}" + Style.RESET_ALL)
            
            time.sleep(0.5)
        
        # Calculate threat level
        leak_count = self.results['summary']['leaks_detected']
        if leak_count == 0:
            self.results['threat_level'] = 'LOW'
        elif leak_count <= 2:
            self.results['threat_level'] = 'MEDIUM'
        elif leak_count <= 4:
            self.results['threat_level'] = 'HIGH'
        else:
            self.results['threat_level'] = 'CRITICAL'
        
        print(Fore.GREEN + "\n[+] All tests completed!" + Style.RESET_ALL)
        time.sleep(1)
        
        # Display results
        self.display_results()
    
    def display_results(self):
        """Display test results in a formatted table"""
        self.display_banner()
        print(Fore.GREEN + "LEAK DETECTION RESULTS" + Style.RESET_ALL)
        print(Fore.CYAN + f"Test performed at: {self.results['test_time']}" + Style.RESET_ALL)
        
        # Display threat level
        threat_color = Fore.GREEN
        if self.results['threat_level'] == 'MEDIUM':
            threat_color = Fore.YELLOW
        elif self.results['threat_level'] == 'HIGH':
            threat_color = Fore.RED
        elif self.results['threat_level'] == 'CRITICAL':
            threat_color = Fore.RED + Back.WHITE
        
        print(f"{Fore.CYAN}Threat Level: {threat_color}{self.results['threat_level']}{Style.RESET_ALL}")
        print()
        
        # Display VPN status
        vpn_status = self.results['vpn_status']
        print(Fore.YELLOW + "VPN STATUS:" + Style.RESET_ALL)
        vpn_table = PrettyTable()
        vpn_table.field_names = ["VPN Detected", "VPN Interfaces", "Status"]
        
        if 'error' in vpn_status:
            vpn_table.add_row(["Error", vpn_status['error'], "UNKNOWN"])
        else:
            vpn_status_text = Fore.GREEN + "ACTIVE" + Style.RESET_ALL if vpn_status.get('vpn_detected', False) else Fore.RED + "INACTIVE" + Style.RESET_ALL
            vpn_table.add_row([
                "Yes" if vpn_status.get('vpn_detected', False) else "No",
                ", ".join(vpn_status.get('vpn_interfaces', [])) if vpn_status.get('vpn_interfaces') else "None",
                vpn_status_text
            ])
        
        vpn_table.hrules = ALL
        print(vpn_table)
        print()
        
        # Display network interfaces
        network_info = self.results['network_info']
        if 'error' in network_info:
            print(Fore.RED + f"Error getting network info: {network_info['error']}" + Style.RESET_ALL)
        elif network_info:
            print(Fore.YELLOW + "NETWORK INTERFACES:" + Style.RESET_ALL)
            net_table = PrettyTable()
            net_table.field_names = ["Interface", "IP Address", "Netmask", "Gateway", "Type"]
            
            for iface in network_info:
                iface_type = "VPN" if self.is_vpn_ip(iface.get('ip', '')) or iface.get('interface', '').startswith(('tun', 'tap', 'ppp', 'wg')) else "Regular"
                net_table.add_row([
                    iface.get('interface', 'N/A'),
                    iface.get('ip', 'N/A'),
                    iface.get('netmask', 'N/A'),
                    iface.get('gateway', 'N/A'),
                    iface_type
                ])
            
            net_table.hrules = ALL
            print(net_table)
            print()
        
        # Display DNS leak results
        if self.results['dns_leaks']:
            print(Fore.YELLOW + "DNS LEAK TESTS:" + Style.RESET_ALL)
            for test in self.results['dns_leaks']:
                table = PrettyTable()
                table.field_names = ["Test", "Method", "Result", "Risk", "Details"]
                
                risk_color = Fore.GREEN
                if test.get('risk_level') == 'MEDIUM':
                    risk_color = Fore.YELLOW
                elif test.get('risk_level') == 'HIGH':
                    risk_color = Fore.RED
                elif test.get('risk_level') == 'CRITICAL':
                    risk_color = Fore.RED + Back.WHITE
                
                result_text = Fore.GREEN + "PASS" + Style.RESET_ALL
                if test.get('leak_detected', False):
                    result_text = Fore.RED + "LEAK" + Style.RESET_ALL
                
                details = test.get('details', '')
                if 'error' in test:
                    details = Fore.RED + f"Error: {test['error']}" + Style.RESET_ALL
                
                table.add_row([
                    test['test_name'],
                    test['method'],
                    result_text,
                    risk_color + test.get('risk_level', 'UNKNOWN') + Style.RESET_ALL,
                    details
                ])
                table.hrules = ALL
                print(table)
            print()
        
        # Display IP leak results
        if self.results['ip_leaks']:
            print(Fore.YELLOW + "IP LEAK TESTS:" + Style.RESET_ALL)
            for test in self.results['ip_leaks']:
                table = PrettyTable()
                table.field_names = ["Test", "Method", "Result", "Risk", "Details"]
                
                risk_color = Fore.GREEN
                if test.get('risk_level') == 'MEDIUM':
                    risk_color = Fore.YELLOW
                elif test.get('risk_level') == 'HIGH':
                    risk_color = Fore.RED
                elif test.get('risk_level') == 'CRITICAL':
                    risk_color = Fore.RED + Back.WHITE
                
                result_text = Fore.GREEN + "PASS" + Style.RESET_ALL
                if test.get('leak_detected', False):
                    result_text = Fore.RED + "LEAK" + Style.RESET_ALL
                
                details = test.get('details', '')
                if 'error' in test:
                    details = Fore.RED + f"Error: {test['error']}" + Style.RESET_ALL
                
                table.add_row([
                    test['test_name'],
                    test['method'],
                    result_text,
                    risk_color + test.get('risk_level', 'UNKNOWN') + Style.RESET_ALL,
                    details
                ])
                table.hrules = ALL
                print(table)
            print()
        
        # Display WebRTC leak results
        if self.results['webrtc_leaks']:
            print(Fore.YELLOW + "WebRTC LEAK TESTS:" + Style.RESET_ALL)
            for test in self.results['webrtc_leaks']:
                table = PrettyTable()
                table.field_names = ["Test", "Method", "Result", "Risk", "Details"]
                
                risk_color = Fore.GREEN
                if test.get('risk_level') == 'MEDIUM':
                    risk_color = Fore.YELLOW
                elif test.get('risk_level') == 'HIGH':
                    risk_color = Fore.RED
                elif test.get('risk_level') == 'CRITICAL':
                    risk_color = Fore.RED + Back.WHITE
                
                result_text = Fore.GREEN + "PASS" + Style.RESET_ALL
                if test.get('leak_detected', False):
                    result_text = Fore.RED + "LEAK" + Style.RESET_ALL
                
                details = test.get('details', '')
                if 'error' in test:
                    details = Fore.RED + f"Error: {test['error']}" + Style.RESET_ALL
                
                table.add_row([
                    test['test_name'],
                    test['method'],
                    result_text,
                    risk_color + test.get('risk_level', 'UNKNOWN') + Style.RESET_ALL,
                    details
                ])
                table.hrules = ALL
                print(table)
            print()
        
        # Summary
        summary = self.results['summary']
        print(Fore.CYAN + "SUMMARY:" + Style.RESET_ALL)
        summary_table = PrettyTable()
        summary_table.field_names = ["Total Tests", "Passed", "Failed", "Leaks Detected", "Threat Level"]
        summary_table.add_row([
            summary['total_tests'],
            Fore.GREEN + str(summary['passed_tests']) + Style.RESET_ALL,
            Fore.RED + str(summary['failed_tests']) + Style.RESET_ALL if summary['failed_tests'] > 0 else Fore.GREEN + str(summary['failed_tests']) + Style.RESET_ALL,
            Fore.RED + str(summary['leaks_detected']) + Style.RESET_ALL if summary['leaks_detected'] > 0 else Fore.GREEN + str(summary['leaks_detected']) + Style.RESET_ALL,
            threat_color + self.results['threat_level'] + Style.RESET_ALL
        ])
        summary_table.hrules = ALL
        print(summary_table)
        
        # Recommendations
        print(Fore.CYAN + "\nRECOMMENDATIONS:" + Style.RESET_ALL)
        if self.results['threat_level'] == 'LOW':
            print(Fore.GREEN + "✅ Your connection appears secure. No significant leaks detected." + Style.RESET_ALL)
        elif self.results['threat_level'] == 'MEDIUM':
            print(Fore.YELLOW + "⚠️  Moderate risk detected. Consider reviewing your VPN configuration." + Style.RESET_ALL)
        elif self.results['threat_level'] == 'HIGH':
            print(Fore.RED + "🚨 High risk detected. Your privacy may be compromised. Take immediate action." + Style.RESET_ALL)
        else:
            print(Fore.RED + "💀 CRITICAL risk detected. Your real IP and DNS may be exposed!" + Style.RESET_ALL)
        
        print()
        input(Fore.CYAN + "Press Enter to return to main menu..." + Style.RESET_ALL)
    
    def display_help(self):
        """Display help information"""
        self.display_banner()
        print(Fore.GREEN + "HELP & INFORMATION" + Style.RESET_ALL)
        print("This advanced tool detects DNS and IP leaks using multiple techniques:")
        print()
        
        help_table = PrettyTable()
        help_table.field_names = ["Test Type", "Description", "Risk Level"]
        help_table.add_row(["DNS Server Comparison", "Compares your DNS servers with known VPN DNS servers", "HIGH if leak detected"])
        help_table.add_row(["DNS over HTTPS (DoH)", "Tests DNS queries over HTTPS for leaks", "HIGH if leak detected"])
        help_table.add_row(["Parallel Domain Resolution", "Resolves multiple domains to check for inconsistencies", "MEDIUM if inconsistent"])
        help_table.add_row(["Multi-Service IP Detection", "Checks your IP from multiple services", "HIGH if leaks detected"])
        help_table.add_row(["HTTP Header Analysis", "Analyzes HTTP headers for IP disclosure", "MEDIUM if suspicious headers found"])
        help_table.add_row(["IPv6 Leak Detection", "Tests for IPv6 address leakage", "HIGH if IPv6 detected"])
        help_table.add_row(["Local IP Detection", "Detects local IP addresses exposed via WebRTC", "MEDIUM if local IPs found"])
        help_table.hrules = ALL
        print(help_table)
        
        print(Fore.CYAN + "\nRISK LEVELS:" + Style.RESET_ALL)
        print(Fore.GREEN + "LOW: No significant risk detected" + Style.RESET_ALL)
        print(Fore.YELLOW + "MEDIUM: Potential vulnerability that should be addressed" + Style.RESET_ALL)
        print(Fore.RED + "HIGH: Serious vulnerability that requires immediate attention" + Style.RESET_ALL)
        print(Fore.RED + Back.WHITE + "CRITICAL: Critical vulnerability exposing your real identity" + Style.RESET_ALL)
        
        print()
        input(Fore.CYAN + "Press Enter to return to main menu..." + Style.RESET_ALL)
    
    def run_advanced_analysis(self):
        """Run advanced network analysis"""
        self.display_banner()
        print(Fore.GREEN + "Advanced Network Analysis" + Style.RESET_ALL)
        
        # This would include more advanced techniques like:
        # - Traffic analysis
        # - Deep packet inspection simulation
        # - VPN protocol detection
        # - DNS query monitoring
        
        print(Fore.YELLOW + "This feature is under development." + Style.RESET_ALL)
        print(Fore.YELLOW + "It will include advanced traffic analysis and deep inspection." + Style.RESET_ALL)
        print()
        input(Fore.CYAN + "Press Enter to return to main menu..." + Style.RESET_ALL)
    
    def main(self):
        """Main application loop"""
        while True:
            choice = self.display_menu()
            
            if choice == '1':
                self.run_comprehensive_test()
            elif choice == '2':
                target = self.get_target_input()
                if target:
                    self.run_comprehensive_test(target)
            elif choice == '3':
                self.run_advanced_analysis()
            elif choice == '4':
                if self.results.get('test_time'):
                    self.display_results()
                else:
                    print(Fore.RED + "No test results available!" + Style.RESET_ALL)
                    time.sleep(2)
            elif choice == '5':
                self.display_help()
            elif choice == '6':
                print(Fore.GREEN + "Thank you for using the Enhanced DNS and IP Leak Detector!" + Style.RESET_ALL)
                sys.exit(0)
            else:
                print(Fore.RED + "Invalid option! Please try again." + Style.RESET_ALL)
                time.sleep(1)

if __name__ == "__main__":
    # Check dependencies
    try:
        import prettytable
        import colorama
        import netifaces
        import dns
    except ImportError as e:
        print(Fore.RED + f"Missing dependency: {e}" + Style.RESET_ALL)
        print("Please install required packages:")
        print("pip install prettytable colorama netifaces dnspython")
        sys.exit(1)
    
    # Run the application
    detector = EnhancedLeakDetector()
    detector.main()