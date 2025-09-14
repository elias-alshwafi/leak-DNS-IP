#!/usr/bin/env python3
"""
DNS & IP Leak Scanner - Terminal UI (single-file)

A comprehensive terminal-based tool to check for DNS and IP leaks.
"""

import curses
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Configuration
PUBLIC_IP_SERVICES = [
    "https://ifconfig.me/ip",
    "https://ipinfo.io/ip",
    "https://icanhazip.com"
]

DEFAULT_PCAP = "dns_capture.pcap"

# Tool detection
TCPDUMP_BIN = shutil.which("tcpdump")
DIG_BIN = shutil.which("dig") or shutil.which("nslookup")
CURL_BIN = shutil.which("curl") or shutil.which("wget")
TRACEROUTE_BIN = shutil.which("traceroute") or shutil.which("tracert")

# Playwright availability
PLAYWRIGHT_AVAILABLE = False
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# ---------------- Utilities ----------------

def run_cmd(cmd: List[str], timeout: int = 20) -> Tuple[int, str, str]:
    """Run system command with timeout and return code, stdout, stderr"""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", "not found"


def http_get_simple(url: str, timeout: int = 8) -> Optional[str]:
    """Simple HTTP GET with fallback between curl/wget and urllib"""
    if CURL_BIN:
        cmd = [CURL_BIN, '-s', '--max-time', str(timeout), url]
        rc, out, err = run_cmd(cmd, timeout=timeout + 2)
        if rc == 0 and out:
            return out.strip()
    try:
        import urllib.request
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.read().decode().strip()
    except Exception:
        return None

# ---------------- Detection modules ----------------

def check_public_ip() -> Dict[str, Optional[str]]:
    """Check multiple services for public IP address"""
    results = {}
    for svc in PUBLIC_IP_SERVICES:
        results[svc] = http_get_simple(svc, timeout=6)
    return results


def get_system_resolvers() -> Dict[str, List[str]]:
    """Get system DNS resolvers from OS-specific sources"""
    system = platform.system()
    resolvers = {}
    try:
        if system == 'Linux':
            rc, out, err = run_cmd(['resolvectl', 'status'], timeout=3)
            if rc == 0 and out:
                cur = 'system'
                for line in out.splitlines():
                    line = line.strip()
                    if line.startswith('DNS Servers:'):
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            vals = [p.strip() for p in parts[1].split()] if parts[1].strip() else []
                            resolvers.setdefault(cur, []).extend(vals)
            # Fallback to /etc/resolv.conf
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    vals = [l.split()[1] for l in f.readlines() if l.strip().startswith('nameserver')]
                    if vals:
                        resolvers.setdefault('resolv.conf', []).extend(vals)
            except Exception:
                pass
        elif system == 'Darwin':
            rc, out, err = run_cmd(['scutil', '--dns'], timeout=3)
            if rc == 0 and out:
                cur = 'system'
                for line in out.splitlines():
                    line = line.strip()
                    if line.startswith('nameserver'):
                        parts = line.split()
                        if len(parts) > 1:
                            resolvers.setdefault(cur, []).append(parts[1])
        elif system == 'Windows':
            rc, out, err = run_cmd(['ipconfig', '/all'], timeout=4)
            if rc == 0 and out:
                cur = 'system'
                for line in out.splitlines():
                    if 'DNS Servers' in line:
                        parts = line.split(':', 1)
                        if len(parts) > 1 and parts[1].strip():
                            resolvers.setdefault(cur, []).append(parts[1].strip())
        else:
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    vals = [l.split()[1] for l in f.readlines() if l.strip().startswith('nameserver')]
                    if vals:
                        resolvers['resolv.conf'] = vals
            except Exception:
                pass
    except Exception:
        pass
    # Clean empty values
    for k in list(resolvers.keys()):
        resolvers[k] = [v for v in resolvers[k] if v]
    return resolvers


def check_ipv6_enabled() -> bool:
    """Check if IPv6 is enabled on the system"""
    system = platform.system()
    try:
        if system in ('Linux', 'Darwin'):
            rc, out, err = run_cmd(['ip', '-6', 'addr'], timeout=3)
            return (rc == 0 and out.strip() != '')
        elif system == 'Windows':
            rc, out, err = run_cmd(['ipconfig'], timeout=3)
            return 'IPv6' in out
    except Exception:
        return False


def dns_query_via_resolver(target: str, resolver: Optional[str] = None) -> Dict[str, str]:
    """Perform DNS query via specified resolver"""
    out = {'resolver': resolver or 'system', 'answer': '', 'raw': ''}
    if DIG_BIN and DIG_BIN.endswith('dig'):
        cmd = [DIG_BIN, '+short', target]
        if resolver:
            cmd.insert(1, '@' + resolver)
        rc, o, e = run_cmd(cmd, timeout=6)
        out['answer'] = o if o else e
        out['raw'] = o if o else e
    else:
        try:
            info = socket.getaddrinfo(target, None)
            ips = sorted({i[4][0] for i in info})
            out['answer'] = ','.join(ips)
        except Exception as ex:
            out['answer'] = f'error: {ex}'
    return out


def run_tcpdump_text(duration: int = 6) -> List[Dict[str, str]]:
    """Run short tcpdump capture and return parsed results"""
    if not TCPDUMP_BIN:
        return []
    cmd = [TCPDUMP_BIN, '-n', '-i', 'any', 'port', '53', '-l']
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except Exception:
        return []
    start = time.time()
    results = []
    try:
        while time.time() - start < duration:
            line = proc.stdout.readline()
            if not line:
                time.sleep(0.02)
                continue
            ts = datetime.utcnow().isoformat() + 'Z'
            raw = line.strip()
            # rough parse
            src = ''
            dst = ''
            try:
                parts = raw.split()
                if '>' in parts:
                    idx = parts.index('>')
                    src = parts[idx-1]
                    dst = parts[idx+1].rstrip(':')
            except Exception:
                pass
            results.append({'ts': ts, 'raw': raw, 'src': src, 'dst': dst})
    finally:
        try:
            proc.terminate()
            proc.wait(1)
        except Exception:
            pass
    return results


def capture_pcap(duration: int = 8, out_path: str = DEFAULT_PCAP) -> Dict[str, str]:
    """Capture DNS traffic to PCAP file"""
    if not TCPDUMP_BIN:
        return {'status': 'missing', 'msg': 'tcpdump not available'}
    cmd = [TCPDUMP_BIN, '-n', '-i', 'any', 'port', '53', '-w', out_path]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as e:
        return {'status': 'error', 'msg': str(e)}
    time.sleep(duration)
    try:
        proc.terminate()
        proc.wait(2)
    except Exception:
        proc.kill()
    return {'status': 'ok', 'path': out_path}


def playwright_webrtc_ice_candidates(timeout: int = 6) -> List[str]:
    """Get WebRTC ICE candidates via Playwright"""
    if not PLAYWRIGHT_AVAILABLE:
        return []
    candidates = []
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, args=['--no-sandbox'])
            context = browser.new_context()
            page = context.new_page()
            html = """
            <!doctype html>
            <script>
            async function getCandidates(timeout) {
              const pc = new RTCPeerConnection();
              const cands = [];
              pc.onicecandidate = e => {
                if (e.candidate) cands.push(e.candidate.candidate);
              };
              pc.createDataChannel('d');
              const offer = await pc.createOffer();
              await pc.setLocalDescription(offer);
              await new Promise(r => setTimeout(r, timeout * 1000));
              document.title = JSON.stringify(cands);
            }
            getCandidates(6000).then(() => {}).catch(() => {});
            </script>
            """
            page.set_content(html)
            page.wait_for_timeout(timeout*1000 + 500)
            title = page.title()
            try:
                candidates = json.loads(title)
            except Exception:
                candidates = []
            browser.close()
    except Exception:
        candidates = []
    return candidates


def traceroute_target(target: str, maxhops: int = 30) -> List[str]:
    """Run traceroute to target"""
    if not TRACEROUTE_BIN:
        return []
    try:
        if TRACEROUTE_BIN.endswith('traceroute'):
            rc, out, err = run_cmd([TRACEROUTE_BIN, '-m', str(maxhops), target], timeout=30)
        else:
            rc, out, err = run_cmd([TRACEROUTE_BIN, target], timeout=30)
        if out:
            return out.splitlines()
    except Exception:
        return []

# ---------------- Reporting ----------------

def create_report() -> Dict:
    """Create initial report structure"""
    return {
        'meta': {'created': datetime.utcnow().isoformat() + 'Z'}, 
        'scans': {}
    }


def render_table(headers: List[str], rows: List[List[str]], maxw: int) -> List[str]:
    """Render a table as text with proper column widths"""
    col_count = len(headers)
    col_widths = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            col_widths[i] = max(col_widths[i], min(len(str(c)), maxw // col_count))
    
    lines = []
    sep = ' | '
    header_line = sep.join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    divider = '-+-'.join('-' * col_widths[i] for i in range(col_count))
    lines.append(header_line)
    lines.append(divider)
    for r in rows:
        lines.append(sep.join(str(r[i]).ljust(col_widths[i]) for i in range(col_count)))
    return lines

# ---------------- TUI ----------------

class LeakScannerUI:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.height, self.width = self.stdscr.getmaxyx()
        self.setup_screen()
        self.report = create_report()

    def setup_screen(self):
        # Initialize colors
        curses.start_color()
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)   # Header
        curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_WHITE)  # Info
        curses.init_pair(3, curses.COLOR_BLACK, curses.COLOR_YELLOW) # Warning
        curses.init_pair(4, curses.COLOR_BLACK, curses.COLOR_CYAN)   # Section
        curses.curs_set(0)  # Hide cursor
        self.stdscr.clear()
        self.stdscr.refresh()

    def safe_addstr(self, y, x, text, attr=0):
        """Safely add string to screen, handling edge cases"""
        try:
            if y < self.height and x < self.width:
                # Truncate text to fit screen width
                max_len = self.width - x - 1
                if len(text) > max_len:
                    text = text[:max_len-3] + "..."
                self.stdscr.addstr(y, x, text, attr)
        except curses.error:
            pass  # Ignore display errors

    def center_text(self, y, text, attr=0):
        """Center text on screen"""
        try:
            x = max(0, (self.width - len(text)) // 2)
            self.safe_addstr(y, x, text, attr)
        except curses.error:
            pass

    def show_welcome(self) -> str:
        """Show welcome screen and get target input"""
        self.stdscr.clear()
        self.center_text(1, "DNS & IP Leak Scanner", curses.A_BOLD | curses.color_pair(1))
        
        # Show tool status
        tool_status = []
        tool_status.append(f"tcpdump: {'Available' if TCPDUMP_BIN else 'Not found'}")
        tool_status.append(f"DNS tools: {'Available' if DIG_BIN else 'Not found'}")
        tool_status.append(f"Traceroute: {'Available' if TRACEROUTE_BIN else 'Not found'}")
        tool_status.append(f"WebRTC (Playwright): {'Available' if PLAYWRIGHT_AVAILABLE else 'Not found'}")
        
        self.center_text(3, "Enter target (domain/IP) or 'self' to scan this host:")
        for i, status in enumerate(tool_status):
            self.center_text(5 + i, status)
        
        # Get user input
        curses.echo()
        self.safe_addstr(10, 4, "> ")
        target = self.stdscr.getstr(10, 6, 60).decode().strip()
        curses.noecho()
        
        return target or 'self'

    def show_lines(self, start_y: int, lines: List[str], max_lines: Optional[int] = None):
        """Display multiple lines of text with proper positioning"""
        if max_lines is None:
            max_lines = self.height - start_y - 2
            
        for i, line in enumerate(lines[:max_lines]):
            self.safe_addstr(start_y + i, 2, line)

    def run_scan_sequence(self, target: str):
        """Run the complete scan sequence"""
        self.stdscr.clear()
        self.center_text(1, "Running Scan Sequence...", curses.A_BOLD | curses.color_pair(1))
        self.stdscr.refresh()
        
        # 1. Public IP check
        self.safe_addstr(3, 2, "1. Checking public IP addresses...")
        self.stdscr.refresh()
        public_ips = check_public_ip()
        self.report['scans']['public_ip'] = public_ips
        
        # Display results
        ip_lines = []
        for svc, ip in public_ips.items():
            ip_lines.append(f"{svc}: {ip or 'No response'}")
        self.show_lines(5, ip_lines, 5)
        self.stdscr.refresh()
        time.sleep(1)
        
        # 2. System resolvers
        self.safe_addstr(11, 2, "2. Detecting system DNS resolvers...")
        self.stdscr.refresh()
        resolvers = get_system_resolvers()
        self.report['scans']['system_resolvers'] = resolvers
        
        resolver_lines = []
        for source, resolver_list in resolvers.items():
            resolver_lines.append(f"{source}: {', '.join(resolver_list) if resolver_list else 'None'}")
        self.show_lines(13, resolver_lines, 5)
        self.stdscr.refresh()
        time.sleep(1)
        
        # 3. IPv6 check
        self.safe_addstr(19, 2, "3. Checking IPv6 status...")
        self.stdscr.refresh()
        ipv6_enabled = check_ipv6_enabled()
        self.report['scans']['ipv6_enabled'] = ipv6_enabled
        self.safe_addstr(21, 2, f"IPv6 enabled: {ipv6_enabled}")
        self.stdscr.refresh()
        time.sleep(1)
        
        # 4. DNS resolution
        self.safe_addstr(23, 2, "4. Testing DNS resolution...")
        self.stdscr.refresh()
        dns_results = []
        
        # System resolver
        sys_result = dns_query_via_resolver(target)
        dns_results.append([sys_result['resolver'], sys_result['answer']])
        
        # Each discovered resolver
        for source, resolver_list in resolvers.items():
            for resolver in resolver_list:
                result = dns_query_via_resolver(target, resolver)
                dns_results.append([result['resolver'], result['answer']])
        
        self.report['scans']['dns_queries'] = dns_results
        dns_lines = render_table(['Resolver', 'Answer'], dns_results, self.width - 4)
        self.show_lines(25, dns_lines, 10)
        self.stdscr.refresh()
        time.sleep(1)
        
        # 5. Traceroute (if available)
        self.safe_addstr(36, 2, "5. Running traceroute...")
        self.stdscr.refresh()
        traceroute_lines = traceroute_target(target)[:10]  # Limit output
        self.report['scans']['traceroute'] = traceroute_lines
        self.show_lines(38, traceroute_lines, 10)
        self.stdscr.refresh()
        time.sleep(1)
        
        # 6. TCPDump capture (if available)
        self.safe_addstr(49, 2, "6. Capturing DNS packets...")
        self.stdscr.refresh()
        if TCPDUMP_BIN:
            capture_lines = run_tcpdump_text(duration=5)
            self.report['scans']['tcpdump_text'] = capture_lines
            if capture_lines:
                parsed_lines = []
                for line in capture_lines[:10]:  # Limit output
                    parsed_lines.append(f"{line['src']} -> {line['dst']}")
                self.show_lines(51, parsed_lines, 10)
            else:
                self.safe_addstr(51, 2, "No DNS packets captured")
        else:
            self.safe_addstr(51, 2, "tcpdump not available")
        self.stdscr.refresh()
        time.sleep(1)
        
        # Save report
        try:
            report_path = 'dns_ip_leak_report.json'
            with open(report_path, 'w') as f:
                json.dump(self.report, f, indent=2)
            self.safe_addstr(self.height - 2, 2, f"Report saved to {report_path}")
        except Exception:
            self.safe_addstr(self.height - 2, 2, "Failed to save report")
        
        self.center_text(self.height - 1, "Press any key to exit...")
        self.stdscr.refresh()
        self.stdscr.getch()

    def run(self):
        """Run the complete application"""
        target = self.show_welcome()
        if target.lower() == 'self':
            try:
                target = socket.gethostname()
            except Exception:
                target = 'localhost'
        
        self.run_scan_sequence(target)


def main(stdscr):
    """Main entry point"""
    try:
        scanner = LeakScannerUI(stdscr)
        scanner.run()
    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    # Check if running as root for tcpdump
    if os.geteuid() != 0 and TCPDUMP_BIN:
        print("Note: tcpdump detected but not running as root - capture will be limited.")
        time.sleep(1)
    
    try:
        curses.wrapper(main)
    except KeyboardInterrupt:
        print("\nScan cancelled by user.")
        sys.exit(0)