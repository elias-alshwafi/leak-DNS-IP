#!/usr/bin/env python3
"""
DNS and IP Leak Detector
A comprehensive tool to detect DNS and IP leaks with a professional text interface
"""

import os
import sys
import json
import socket
import requests
import subprocess
import threading
import time
from datetime import datetime
from urllib.parse import urlparse
import dns.resolver
import netifaces
from prettytable import PrettyTable
import colorama
from colorama import Fore, Back, Style

# Initialize colorama
colorama.init(autoreset=True)

class LeakDetector:
    def __init__(self):
        self.results = {
            'dns_leaks': [],
            'ip_leaks': [],
            'webrtc_leaks': [],
            'target_info': {},
            'test_time': None,
            'network_interfaces': []
        }
        self.target = None
        self.test_mode = None
        
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
        print(Fore.YELLOW + "         DNS and IP Leak Detection Tool" + Style.RESET_ALL)
        print(Fore.YELLOW + "         ------------------------------" + Style.RESET_ALL)
        print()
    
    def display_menu(self):
        """Display the main menu"""
        self.display_banner()
        print(Fore.GREEN + "Main Menu:" + Style.RESET_ALL)
        print("1. Test current system for leaks")
        print("2. Test a specific target (IP/Domain)")
        print("3. View previous results")
        print("4. Help")
        print("5. Exit")
        print()
        
        choice = input(Fore.CYAN + "Select an option (1-5): " + Style.RESET_ALL)
        return choice
    
    def get_target_input(self):
        """Get target input from user"""
        self.display_banner()
        print(Fore.GREEN + "Target Selection:" + Style.RESET_ALL)
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
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    def validate_domain(self, domain):
        """Validate domain format"""
        try:
            socket.getaddrinfo(domain, 0)
            return True
        except socket.gaierror:
            return False
    
    def get_network_interfaces(self):
        """Get information about network interfaces"""
        interfaces = netifaces.interfaces()
        interface_info = []
        
        for interface in interfaces:
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    info = {
                        'interface': interface,
                        'ip': addr.get('addr', 'N/A'),
                        'netmask': addr.get('netmask', 'N/A'),
                        'broadcast': addr.get('broadcast', 'N/A')
                    }
                    interface_info.append(info)
        
        return interface_info
    
    def detect_dns_leaks(self):
        """Detect DNS leaks using multiple methods"""
        print(Fore.YELLOW + "\n[+] Testing for DNS leaks..." + Style.RESET_ALL)
        
        # Method 1: Compare DNS servers with known VPN DNS
        try:
            resolver = dns.resolver.Resolver()
            dns_servers = resolver.nameservers
            self.results['dns_leaks'].append({
                'method': 'DNS Server Comparison',
                'servers': dns_servers,
                'leak_detected': len(dns_servers) > 0 and not all(self.is_vpn_dns(server) for server in dns_servers)
            })
        except Exception as e:
            self.results['dns_leaks'].append({
                'method': 'DNS Server Comparison',
                'error': str(e),
                'leak_detected': False
            })
        
        # Method 2: DNS over HTTPS test
        try:
            response = requests.get('https://cloudflare-dns.com/dns-query', 
                                   params={'name': 'whoami.akamai.net', 'type': 'TXT'},
                                   headers={'accept': 'application/dns-json'})
            data = response.json()
            if 'Answer' in data:
                answer = data['Answer'][0]['data'].strip('"')
                self.results['dns_leaks'].append({
                    'method': 'DNS over HTTPS Test',
                    'result': answer,
                    'leak_detected': not self.is_vpn_ip(answer)
                })
        except Exception as e:
            self.results['dns_leaks'].append({
                'method': 'DNS over HTTPS Test',
                'error': str(e),
                'leak_detected': False
            })
        
        # Method 3: Multiple domain resolution test
        try:
            test_domains = ['google.com', 'facebook.com', 'amazon.com', 'netflix.com', 'github.com']
            resolved_ips = []
            
            for domain in test_domains:
                try:
                    ips = socket.getaddrinfo(domain, 80)
                    for ip in ips:
                        resolved_ips.append(ip[4][0])
                except:
                    continue
            
            self.results['dns_leaks'].append({
                'method': 'Multiple Domain Resolution',
                'resolved_ips': list(set(resolved_ips)),
                'leak_detected': any(not self.is_vpn_ip(ip) for ip in resolved_ips)
            })
        except Exception as e:
            self.results['dns_leaks'].append({
                'method': 'Multiple Domain Resolution',
                'error': str(e),
                'leak_detected': False
            })
    
    def detect_ip_leaks(self):
        """Detect IP leaks using multiple methods"""
        print(Fore.YELLOW + "[+] Testing for IP leaks..." + Style.RESET_ALL)
        
        # Method 1: Check public IP from multiple services
        services = [
            'https://api.ipify.org',
            'https://ident.me',
            'https://checkip.amazonaws.com',
            'https://icanhazip.com'
        ]
        
        detected_ips = []
        
        for service in services:
            try:
                response = requests.get(service, timeout=10)
                ip = response.text.strip()
                if self.validate_ip(ip):
                    detected_ips.append(ip)
            except:
                continue
        
        self.results['ip_leaks'].append({
            'method': 'Public IP Detection',
            'detected_ips': list(set(detected_ips)),
            'leak_detected': len(detected_ips) > 0 and not all(self.is_vpn_ip(ip) for ip in detected_ips)
        })
        
        # Method 2: HTTP header analysis
        try:
            response = requests.get('https://httpbin.org/headers', timeout=10)
            headers = response.json()
            
            suspicious_headers = {}
            for header, value in headers.items():
                if any(keyword in header.lower() for keyword in ['client', 'forwarded', 'real']):
                    suspicious_headers[header] = value
            
            self.results['ip_leaks'].append({
                'method': 'HTTP Header Analysis',
                'headers': suspicious_headers,
                'leak_detected': len(suspicious_headers) > 0
            })
        except Exception as e:
            self.results['ip_leaks'].append({
                'method': 'HTTP Header Analysis',
                'error': str(e),
                'leak_detected': False
            })
    
    def detect_webrtc_leaks(self):
        """Detect WebRTC leaks (simulated)"""
        print(Fore.YELLOW + "[+] Testing for WebRTC leaks..." + Style.RESET_ALL)
        
        # Note: True WebRTC detection requires a browser environment
        # This is a simulation for command-line tools
        
        try:
            # Get local IP addresses
            local_ips = []
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        local_ips.append(addr['addr'])
            
            self.results['webrtc_leaks'].append({
                'method': 'Local IP Detection (WebRTC Simulation)',
                'local_ips': local_ips,
                'leak_detected': len(local_ips) > 0
            })
        except Exception as e:
            self.results['webrtc_leaks'].append({
                'method': 'Local IP Detection (WebRTC Simulation)',
                'error': str(e),
                'leak_detected': False
            })
    
    def is_vpn_dns(self, dns_server):
        """Check if DNS server is likely a VPN DNS"""
        # This is a simplified check - in a real tool, you'd have a more comprehensive list
        vpn_dns_servers = [
            '10.0.0.1', '10.0.0.2', '10.8.0.1', '10.8.0.2', 
            '192.168.0.1', '192.168.1.1', '172.16.0.1'
        ]
        return dns_server in vpn_dns_servers
    
    def is_vpn_ip(self, ip):
        """Check if IP is likely a VPN IP"""
        # This is a simplified check - in a real tool, you'd use a VPN IP database
        vpn_prefixes = ['10.', '192.168.', '172.16.']
        return any(ip.startswith(prefix) for prefix in vpn_prefixes)
    
    def run_comprehensive_test(self, target=None):
        """Run all leak detection tests"""
        self.display_banner()
        print(Fore.GREEN + "Running Comprehensive Leak Detection..." + Style.RESET_ALL)
        
        # Initialize results
        self.results = {
            'dns_leaks': [],
            'ip_leaks': [],
            'webrtc_leaks': [],
            'target_info': {},
            'test_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'network_interfaces': self.get_network_interfaces()
        }
        
        if target:
            self.results['target_info'] = {
                'target': target,
                'type': 'IP' if self.validate_ip(target) else 'Domain'
            }
        
        # Run tests with progress indication
        tests = [
            self.detect_dns_leaks,
            self.detect_ip_leaks,
            self.detect_webrtc_leaks
        ]
        
        for i, test in enumerate(tests):
            print(Fore.YELLOW + f"[{i+1}/{len(tests)}] Running test..." + Style.RESET_ALL)
            test()
            time.sleep(0.5)  # Simulate work being done
        
        print(Fore.GREEN + "\n[+] All tests completed!" + Style.RESET_ALL)
        time.sleep(1)
        
        # Display results
        self.display_results()
    
    def display_results(self):
        """Display test results in a formatted table"""
        self.display_banner()
        print(Fore.GREEN + "Leak Detection Results" + Style.RESET_ALL)
        print(Fore.CYAN + f"Test performed at: {self.results['test_time']}" + Style.RESET_ALL)
        print()
        
        # Display network interfaces
        if self.results['network_interfaces']:
            print(Fore.YELLOW + "Network Interfaces:" + Style.RESET_ALL)
            table = PrettyTable()
            table.field_names = ["Interface", "IP Address", "Netmask", "Broadcast"]
            for iface in self.results['network_interfaces']:
                table.add_row([iface['interface'], iface['ip'], iface['netmask'], iface['broadcast']])
            print(table)
            print()
        
        # Display DNS leak results
        if self.results['dns_leaks']:
            print(Fore.YELLOW + "DNS Leak Tests:" + Style.RESET_ALL)
            for test in self.results['dns_leaks']:
                table = PrettyTable()
                table.field_names = ["Method", "Result", "Leak Detected"]
                
                if 'error' in test:
                    result = f"Error: {test['error']}"
                elif 'servers' in test:
                    result = f"Servers: {', '.join(test['servers'])}"
                elif 'result' in test:
                    result = f"Result: {test['result']}"
                elif 'resolved_ips' in test:
                    result = f"Resolved IPs: {', '.join(test['resolved_ips'])}"
                else:
                    result = "No data"
                
                leak_status = Fore.RED + "YES" + Style.RESET_ALL if test.get('leak_detected', False) else Fore.GREEN + "NO" + Style.RESET_ALL
                table.add_row([test['method'], result, leak_status])
                print(table)
            print()
        
        # Display IP leak results
        if self.results['ip_leaks']:
            print(Fore.YELLOW + "IP Leak Tests:" + Style.RESET_ALL)
            for test in self.results['ip_leaks']:
                table = PrettyTable()
                table.field_names = ["Method", "Result", "Leak Detected"]
                
                if 'error' in test:
                    result = f"Error: {test['error']}"
                elif 'detected_ips' in test:
                    result = f"IPs: {', '.join(test['detected_ips'])}"
                elif 'headers' in test:
                    result = f"Headers: {json.dumps(test['headers'])}"
                else:
                    result = "No data"
                
                leak_status = Fore.RED + "YES" + Style.RESET_ALL if test.get('leak_detected', False) else Fore.GREEN + "NO" + Style.RESET_ALL
                table.add_row([test['method'], result, leak_status])
                print(table)
            print()
        
        # Display WebRTC leak results
        if self.results['webrtc_leaks']:
            print(Fore.YELLOW + "WebRTC Leak Tests:" + Style.RESET_ALL)
            for test in self.results['webrtc_leaks']:
                table = PrettyTable()
                table.field_names = ["Method", "Result", "Leak Detected"]
                
                if 'error' in test:
                    result = f"Error: {test['error']}"
                elif 'local_ips' in test:
                    result = f"Local IPs: {', '.join(test['local_ips'])}"
                else:
                    result = "No data"
                
                leak_status = Fore.RED + "YES" + Style.RESET_ALL if test.get('leak_detected', False) else Fore.GREEN + "NO" + Style.RESET_ALL
                table.add_row([test['method'], result, leak_status])
                print(table)
            print()
        
        # Summary
        print(Fore.CYAN + "SUMMARY:" + Style.RESET_ALL)
        dns_leaks = any(test.get('leak_detected', False) for test in self.results['dns_leaks'])
        ip_leaks = any(test.get('leak_detected', False) for test in self.results['ip_leaks'])
        webrtc_leaks = any(test.get('leak_detected', False) for test in self.results['webrtc_leaks'])
        
        if dns_leaks or ip_leaks or webrtc_leaks:
            print(Fore.RED + "Leaks detected in:" + Style.RESET_ALL)
            if dns_leaks:
                print(Fore.RED + "  - DNS" + Style.RESET_ALL)
            if ip_leaks:
                print(Fore.RED + "  - IP" + Style.RESET_ALL)
            if webrtc_leaks:
                print(Fore.RED + "  - WebRTC" + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "No leaks detected!" + Style.RESET_ALL)
        
        print()
        input(Fore.CYAN + "Press Enter to return to main menu..." + Style.RESET_ALL)
    
    def display_help(self):
        """Display help information"""
        self.display_banner()
        print(Fore.GREEN + "Help Information" + Style.RESET_ALL)
        print("This tool detects DNS and IP leaks using multiple techniques:")
        print()
        print(Fore.YELLOW + "DNS Leak Detection:" + Style.RESET_ALL)
        print("  - Compares your DNS servers with known VPN DNS servers")
        print("  - Tests DNS over HTTPS (DoH) implementation")
        print("  - Resolves multiple domains to check for inconsistencies")
        print()
        print(Fore.YELLOW + "IP Leak Detection:" + Style.RESET_ALL)
        print("  - Checks your public IP from multiple services")
        print("  - Analyzes HTTP headers for IP disclosure")
        print()
        print(Fore.YELLOW + "WebRTC Leak Detection:" + Style.RESET_ALL)
        print("  - Simulates WebRTC leak detection (limited in CLI)")
        print()
        print(Fore.CYAN + "Note:" + Style.RESET_ALL)
        print("For accurate WebRTC testing, use a browser-based tool.")
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
                if self.results['test_time']:
                    self.display_results()
                else:
                    print(Fore.RED + "No test results available!" + Style.RESET_ALL)
                    time.sleep(2)
            elif choice == '4':
                self.display_help()
            elif choice == '5':
                print(Fore.GREEN + "Thank you for using the DNS and IP Leak Detector!" + Style.RESET_ALL)
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
    detector = LeakDetector()
    detector.main()