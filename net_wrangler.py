#!/usr/bin/env python3
"""
NET-WRANGLER v2.0 - Modern Network Analysis & Security Tool
A comprehensive networking toolkit for network administrators and security professionals.

Features:
- Network Discovery & Scanning
- Port Scanning (TCP/UDP)
- DNS Analysis
- WHOIS Lookup
- Ping Sweep
- Traceroute
- Bandwidth Monitoring
- SSL/TLS Certificate Analysis
- HTTP Header Analysis
- MAC Address Lookup
- Subnet Calculator
- Network Interface Information
- ARP Table Viewer
- Connection Monitor
- Packet Sniffer
- Geolocation Lookup
"""

import socket
import struct
import subprocess
import sys
import os
import json
import time
import threading
import re
import ssl
import ipaddress
import platform
import urllib.request
import urllib.error
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Optional, List, Dict, Tuple, Any
from educational_features import EducationalFeatures  # Import educational features

# Check and install required packages
def check_dependencies():
    """Check and install required dependencies."""
    required = {
        'rich': 'rich',
        'scapy': 'scapy',
        'psutil': 'psutil',
        'requests': 'requests',
        'python-whois': 'whois',
        'dnspython': 'dns',
    }
    
    missing = []
    for package, import_name in required.items():
        try:
            __import__(import_name.split('.')[0] if '.' in import_name else import_name)
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"Installing missing packages: {', '.join(missing)}")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--quiet'] + missing)

# Check dependencies on first run
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.prompt import Prompt, Confirm
    from rich.layout import Layout
    from rich.live import Live
    from rich import box
    from rich.markdown import Markdown
    from rich.syntax import Syntax
    import psutil
    import requests
    from educational_features import EducationalFeatures  # Import educational features

    import whois
    import dns.resolver
    import dns.reversename
    from scapy.all import ARP, Ether, srp, IP, ICMP, TCP, UDP, sr1, sniff, conf
    conf.verb = 0  # Suppress scapy output
except ImportError:
    check_dependencies()
    # Re-import after installation
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.prompt import Prompt, Confirm
    from rich.layout import Layout
    from rich.live import Live
    from rich import box
    from rich.markdown import Markdown
    from rich.syntax import Syntax
    import psutil
    import requests
    from educational_features import EducationalFeatures  # Import educational features

    import whois
    import dns.resolver
    import dns.reversename
    from scapy.all import ARP, Ether, srp, IP, ICMP, TCP, UDP, sr1, sniff, conf
    conf.verb = 0

console = Console()

# ===================== UTILITY CLASSES =====================

@dataclass
class ScanResult:
    """Data class for scan results."""
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    ports: Optional[List[int]] = None
    os_guess: Optional[str] = None
    latency: Optional[float] = None

@dataclass
class PortInfo:
    """Data class for port information."""
    port: int
    state: str
    service: str
    banner: Optional[str] = None

# ===================== CORE FUNCTIONS =====================

class NetWrangler:
    """Main NET-WRANGLER class with all networking tools."""
    
    COMMON_PORTS = [
        20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
        993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888
    ]
    
    PORT_SERVICES = {
        20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC",
        139: "NETBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
        995: "POP3S", 1433: "MSSQL", 1521: "ORACLE", 1723: "PPTP", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
        8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt", 27017: "MongoDB"
    }

    def __init__(self):
        self.console = Console()
        
    # ===================== NETWORK DISCOVERY =====================
    
    def get_local_ip(self) -> str:
        """Get the local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    def get_network_range(self) -> str:
        """Get the network range for scanning."""
        local_ip = self.get_local_ip()
        # Assume /24 network
        return f"{'.'.join(local_ip.split('.')[:-1])}.0/24"
    
    def arp_scan(self, network: str = None) -> List[ScanResult]:
        """Perform ARP scan to discover hosts on the network."""
        if network is None:
            network = self.get_network_range()
        
        results = []
        try:
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            answered, _ = srp(packet, timeout=3, verbose=False)
            
            for sent, received in answered:
                try:
                    hostname = socket.gethostbyaddr(received.psrc)[0]
                except socket.herror:
                    hostname = "Unknown"
                
                results.append(ScanResult(
                    ip=received.psrc,
                    mac=received.hwsrc,
                    hostname=hostname
                ))
        except Exception as e:
            self.console.print(f"[red]ARP Scan Error: {e}[/red]")
        
        return results
    
    def ping_sweep(self, network: str = None, timeout: float = 1) -> List[ScanResult]:
        """Perform ping sweep to discover active hosts."""
        if network is None:
            network = self.get_network_range()
        
        results = []
        net = ipaddress.ip_network(network, strict=False)
        
        def ping_host(ip: str) -> Optional[ScanResult]:
            try:
                start = time.time()
                packet = IP(dst=ip)/ICMP()
                reply = sr1(packet, timeout=timeout, verbose=False)
                if reply:
                    latency = (time.time() - start) * 1000
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except socket.herror:
                        hostname = "Unknown"
                    return ScanResult(ip=ip, hostname=hostname, latency=round(latency, 2))
            except Exception:
                pass
            return None
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=self.console
        ) as progress:
            task = progress.add_task("[cyan]Ping sweep...", total=net.num_addresses)
            
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(ping_host, str(ip)): ip for ip in net.hosts()}
                
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results.append(result)
                    progress.advance(task)
        
        return sorted(results, key=lambda x: ipaddress.ip_address(x.ip))
    
    # ===================== PORT SCANNING =====================
    
    def tcp_connect_scan(self, target: str, ports: List[int] = None, timeout: float = 1) -> List[PortInfo]:
        """Perform TCP connect scan on target."""
        if ports is None:
            ports = self.COMMON_PORTS
        
        results = []
        
        def scan_port(port: int) -> Optional[PortInfo]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                if result == 0:
                    service = self.PORT_SERVICES.get(port, "Unknown")
                    banner = self.grab_banner(target, port)
                    sock.close()
                    return PortInfo(port=port, state="open", service=service, banner=banner)
                sock.close()
            except Exception:
                pass
            return None
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=self.console
        ) as progress:
            task = progress.add_task(f"[cyan]Scanning {target}...", total=len(ports))
            
            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = {executor.submit(scan_port, port): port for port in ports}
                
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        results.append(result)
                    progress.advance(task)
        
        return sorted(results, key=lambda x: x.port)
    
    def syn_scan(self, target: str, ports: List[int] = None, timeout: float = 2) -> List[PortInfo]:
        """Perform SYN scan (requires root/admin)."""
        if ports is None:
            ports = self.COMMON_PORTS
        
        results = []
        
        for port in ports:
            try:
                packet = IP(dst=target)/TCP(dport=port, flags="S")
                response = sr1(packet, timeout=timeout, verbose=False)
                
                if response and response.haslayer(TCP):
                    if response[TCP].flags == 0x12:  # SYN-ACK
                        service = self.PORT_SERVICES.get(port, "Unknown")
                        results.append(PortInfo(port=port, state="open", service=service))
                        # Send RST to close connection
                        sr1(IP(dst=target)/TCP(dport=port, flags="R"), timeout=1, verbose=False)
            except Exception:
                pass
        
        return sorted(results, key=lambda x: x.port)
    
    def grab_banner(self, target: str, port: int, timeout: float = 2) -> Optional[str]:
        """Grab service banner from port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            # Send probe based on port
            if port in [80, 8080, 8888]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 443:
                return "HTTPS"
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            # Truncate long banners
            if len(banner) > 100:
                banner = banner[:100] + "..."
            
            return banner if banner else None
        except Exception:
            return None
    
    def full_port_scan(self, target: str, start_port: int = 1, end_port: int = 65535) -> List[PortInfo]:
        """Scan all ports on target."""
        ports = list(range(start_port, end_port + 1))
        return self.tcp_connect_scan(target, ports)
    
    # ===================== DNS TOOLS =====================
    
    def dns_lookup(self, domain: str) -> Dict[str, Any]:
        """Perform comprehensive DNS lookup."""
        results = {"domain": domain, "records": {}}
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                results["records"][record_type] = [str(rdata) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass
            except Exception:
                pass
        
        return results
    
    def reverse_dns(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup."""
        try:
            addr = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(addr, "PTR")
            return str(answers[0])
        except Exception:
            return None
    
    def dns_zone_transfer(self, domain: str, nameserver: str = None) -> List[str]:
        """Attempt DNS zone transfer."""
        results = []
        
        try:
            if nameserver is None:
                ns_answers = dns.resolver.resolve(domain, 'NS')
                nameservers = [str(ns) for ns in ns_answers]
            else:
                nameservers = [nameserver]
            
            for ns in nameservers:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, domain))
                    for name, node in zone.nodes.items():
                        results.append(str(name) + "." + domain)
                except Exception:
                    pass
        except Exception:
            pass
        
        return results
    
    # ===================== WHOIS =====================
    
    def whois_lookup(self, target: str) -> Dict[str, Any]:
        """Perform WHOIS lookup."""
        try:
            w = whois.whois(target)
            return {
                "domain_name": w.domain_name,
                "registrar": w.registrar,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                "name_servers": w.name_servers,
                "registrant": w.registrant_name,
                "org": w.org,
                "country": w.country,
                "emails": w.emails,
            }
        except Exception as e:
            return {"error": str(e)}
    
    # ===================== TRACEROUTE =====================
    
    def traceroute(self, target: str, max_hops: int = 30) -> List[Dict[str, Any]]:
        """Perform traceroute to target."""
        results = []
        
        try:
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            return [{"error": f"Could not resolve {target}"}]
        
        for ttl in range(1, max_hops + 1):
            try:
                packet = IP(dst=target_ip, ttl=ttl)/ICMP()
                start = time.time()
                reply = sr1(packet, timeout=2, verbose=False)
                rtt = (time.time() - start) * 1000
                
                if reply is None:
                    results.append({"hop": ttl, "ip": "*", "hostname": "*", "rtt": None})
                else:
                    try:
                        hostname = socket.gethostbyaddr(reply.src)[0]
                    except socket.herror:
                        hostname = reply.src
                    
                    results.append({
                        "hop": ttl,
                        "ip": reply.src,
                        "hostname": hostname,
                        "rtt": round(rtt, 2)
                    })
                    
                    if reply.src == target_ip:
                        break
            except Exception as e:
                results.append({"hop": ttl, "ip": "error", "hostname": str(e), "rtt": None})
        
        return results
    
    # ===================== SSL/TLS ANALYSIS =====================
    
    def ssl_analysis(self, target: str, port: int = 443) -> Dict[str, Any]:
        """Analyze SSL/TLS certificate and configuration."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Get certificate details
                    peer_cert = ssock.getpeercert()
                    
                    return {
                        "version": version,
                        "cipher": cipher[0] if cipher else None,
                        "cipher_bits": cipher[2] if cipher else None,
                        "subject": dict(x[0] for x in peer_cert.get('subject', [])) if peer_cert else {},
                        "issuer": dict(x[0] for x in peer_cert.get('issuer', [])) if peer_cert else {},
                        "not_before": peer_cert.get('notBefore') if peer_cert else None,
                        "not_after": peer_cert.get('notAfter') if peer_cert else None,
                        "san": peer_cert.get('subjectAltName', []) if peer_cert else [],
                    }
        except ssl.SSLError as e:
            return {"error": f"SSL Error: {e}"}
        except Exception as e:
            return {"error": str(e)}
    
    # ===================== HTTP ANALYSIS =====================
    
    def http_headers(self, url: str) -> Dict[str, Any]:
        """Analyze HTTP headers of a URL."""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            response = requests.head(url, timeout=10, allow_redirects=True, verify=False)
            
            # Security headers to check
            security_headers = [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Referrer-Policy',
                'Permissions-Policy'
            ]
            
            return {
                "url": response.url,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "security_headers": {h: response.headers.get(h, "Missing") for h in security_headers},
                "server": response.headers.get('Server', 'Unknown'),
                "cookies": len(response.cookies),
            }
        except Exception as e:
            return {"error": str(e)}
    
    # ===================== GEOLOCATION =====================
    
    def geolocate_ip(self, ip: str) -> Dict[str, Any]:
        """Get geolocation information for an IP address."""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
    # ===================== SUBNET CALCULATOR =====================
    
    def subnet_calculator(self, cidr: str) -> Dict[str, Any]:
        """Calculate subnet information."""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return {
                "network": str(network.network_address),
                "broadcast": str(network.broadcast_address),
                "netmask": str(network.netmask),
                "hostmask": str(network.hostmask),
                "num_hosts": network.num_addresses - 2 if network.num_addresses > 2 else network.num_addresses,
                "prefix_length": network.prefixlen,
                "is_private": network.is_private,
                "first_host": str(list(network.hosts())[0]) if network.num_addresses > 2 else str(network.network_address),
                "last_host": str(list(network.hosts())[-1]) if network.num_addresses > 2 else str(network.network_address),
            }
        except Exception as e:
            return {"error": str(e)}
    
    # ===================== NETWORK INTERFACES =====================
    
    def get_interfaces(self) -> List[Dict[str, Any]]:
        """Get information about network interfaces using psutil."""
        interfaces = []
        
        # Get network interface addresses
        if_addrs = psutil.net_if_addrs()
        if_stats = psutil.net_if_stats()
        
        for iface_name, addrs in if_addrs.items():
            info = {
                "name": iface_name,
                "addresses": {"ipv4": [], "ipv6": [], "mac": []},
                "is_up": if_stats.get(iface_name, None).isup if iface_name in if_stats else False
            }
            
            for addr in addrs:
                if addr.family == socket.AF_INET:  # IPv4
                    info["addresses"]["ipv4"].append({
                        "addr": addr.address,
                        "netmask": addr.netmask,
                        "broadcast": addr.broadcast
                    })
                elif addr.family == socket.AF_INET6:  # IPv6
                    info["addresses"]["ipv6"].append({
                        "addr": addr.address
                    })
                elif addr.family == psutil.AF_LINK:  # MAC (on Linux)
                    info["addresses"]["mac"].append({"addr": addr.address})
                elif addr.family == -1:  # MAC (on Windows, uses -1)
                    info["addresses"]["mac"].append({"addr": addr.address})
            
            interfaces.append(info)
        
        return interfaces
    
    # ===================== BANDWIDTH MONITORING =====================
    
    def bandwidth_monitor(self, duration: int = 10, interval: float = 1) -> List[Dict[str, Any]]:
        """Monitor bandwidth usage."""
        results = []
        start_counters = psutil.net_io_counters()
        
        for i in range(int(duration / interval)):
            time.sleep(interval)
            current = psutil.net_io_counters()
            
            bytes_sent = current.bytes_sent - start_counters.bytes_sent
            bytes_recv = current.bytes_recv - start_counters.bytes_recv
            
            results.append({
                "timestamp": datetime.now().isoformat(),
                "bytes_sent_per_sec": bytes_sent / interval,
                "bytes_recv_per_sec": bytes_recv / interval,
                "mbps_sent": (bytes_sent * 8 / 1_000_000) / interval,
                "mbps_recv": (bytes_recv * 8 / 1_000_000) / interval,
                "packets_sent": current.packets_sent,
                "packets_recv": current.packets_recv,
            })
            
            start_counters = current
        
        return results
    
    # ===================== CONNECTION MONITOR =====================
    
    def get_connections(self) -> List[Dict[str, Any]]:
        """Get active network connections."""
        connections = []
        
        for conn in psutil.net_connections(kind='inet'):
            try:
                process_name = psutil.Process(conn.pid).name() if conn.pid else "Unknown"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                process_name = "Unknown"
            
            connections.append({
                "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                "status": conn.status,
                "pid": conn.pid,
                "process": process_name,
                "type": "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            })
        
        return connections
    
    # ===================== MAC ADDRESS LOOKUP =====================
    
    def mac_lookup(self, mac: str) -> Dict[str, Any]:
        """Lookup MAC address vendor."""
        try:
            # Normalize MAC address
            mac = mac.replace(":", "").replace("-", "").replace(".", "").upper()[:6]
            
            response = requests.get(f"https://api.macvendors.com/{mac}", timeout=10)
            if response.status_code == 200:
                return {"mac": mac, "vendor": response.text}
            else:
                return {"mac": mac, "vendor": "Unknown"}
        except Exception as e:
            return {"error": str(e)}
    
    # ===================== PACKET SNIFFER =====================
    
    def packet_sniffer(self, count: int = 10, interface: str = None, filter_str: str = None) -> List[Dict[str, Any]]:
        """Capture network packets."""
        packets_info = []
        
        def packet_callback(packet):
            info = {
                "timestamp": datetime.now().isoformat(),
                "size": len(packet)
            }
            
            if IP in packet:
                info["src_ip"] = packet[IP].src
                info["dst_ip"] = packet[IP].dst
                info["protocol"] = packet[IP].proto
            
            if TCP in packet:
                info["src_port"] = packet[TCP].sport
                info["dst_port"] = packet[TCP].dport
                info["flags"] = str(packet[TCP].flags)
            elif UDP in packet:
                info["src_port"] = packet[UDP].sport
                info["dst_port"] = packet[UDP].dport
            
            packets_info.append(info)
        
        try:
            sniff(prn=packet_callback, count=count, iface=interface, 
                  filter=filter_str, timeout=30, store=False)
        except Exception as e:
            return [{"error": str(e)}]
        
        return packets_info
    
    # ===================== VULNERABILITY CHECKS =====================
    
    def check_common_vulnerabilities(self, target: str) -> Dict[str, Any]:
        """Check for common vulnerabilities."""
        results = {
            "target": target,
            "checks": []
        }
        
        # Check for open risky ports
        risky_ports = {
            21: "FTP (unencrypted)",
            23: "Telnet (unencrypted)",
            445: "SMB (ransomware target)",
            3389: "RDP (common attack vector)",
            5900: "VNC (often unsecured)",
        }
        
        open_risky = []
        for port, desc in risky_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                if sock.connect_ex((target, port)) == 0:
                    open_risky.append({"port": port, "service": desc})
                sock.close()
            except Exception:
                pass
        
        results["checks"].append({
            "name": "Risky Open Ports",
            "status": "warning" if open_risky else "ok",
            "findings": open_risky
        })
        
        # Check HTTP security headers
        for protocol in ['http', 'https']:
            try:
                resp = requests.head(f"{protocol}://{target}", timeout=5, verify=False)
                missing_headers = []
                security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 
                                  'Strict-Transport-Security', 'Content-Security-Policy']
                
                for header in security_headers:
                    if header not in resp.headers:
                        missing_headers.append(header)
                
                if missing_headers:
                    results["checks"].append({
                        "name": f"Missing Security Headers ({protocol.upper()})",
                        "status": "warning",
                        "findings": missing_headers
                    })
            except Exception:
                pass
        
        return results


# ===================== CLI INTERFACE =====================

class CLI:
    """Command Line Interface for NET-WRANGLER."""
    
    def __init__(self):
        self.console = Console()
        self.nw = NetWrangler()
        self.edu = EducationalFeatures()
    
    def print_banner(self):
        """Print the tool banner."""
        banner = r"""
[bold cyan]
 _   _ _____ _____    __        ______      _    _   _  ____ _     _____ ____  
| \ | | ____|_   _|   \ \      / /  _ \    / \  | \ | |/ ___| |   | ____|  _ \ 
|  \| |  _|   | |      \ \ /\ / /| |_) |  / _ \ |  \| | |  _| |   |  _| | |_) |
| |\  | |___  | |       \ V  V / |  _ <  / ___ \| |\  | |_| | |___| |___|  _ < 
|_| \_|_____| |_|        \_/\_/  |_| \_\/_/   \_\_| \_|\____|_____|_____|_| \_\

[/bold cyan]
[yellow]v2.0 - Modern Network Analysis & Security Tool[/yellow]
[dim]Created with ❤️ for Network Administrators & Security Professionals[/dim]
        """
        self.console.print(Panel(banner, border_style="cyan"))
    
    def main_menu(self):
        """Display main menu."""
        menu = """
[bold green]Available Tools:[/bold green]

[cyan]1.[/cyan]  Network Discovery (ARP Scan)
[cyan]2.[/cyan]  Ping Sweep
[cyan]3.[/cyan]  Port Scan (TCP Connect)
[cyan]4.[/cyan]  Full Port Scan (1-65535)
[cyan]5.[/cyan]  DNS Lookup
[cyan]6.[/cyan]  Reverse DNS
[cyan]7.[/cyan]  WHOIS Lookup
[cyan]8.[/cyan]  Traceroute
[cyan]9.[/cyan]  SSL/TLS Analysis
[cyan]10.[/cyan] HTTP Header Analysis
[cyan]11.[/cyan] Geolocation Lookup
[cyan]12.[/cyan] Subnet Calculator
[cyan]13.[/cyan] Network Interfaces
[cyan]14.[/cyan] Bandwidth Monitor
[cyan]15.[/cyan] Active Connections
[cyan]16.[/cyan] MAC Address Lookup
[cyan]17.[/cyan] Packet Sniffer
[cyan]18.[/cyan] Vulnerability Check
[cyan]19.[/cyan] Quick Scan (All-in-One)

[cyan]H.[/cyan]  Help / Educational Guide
[cyan]D.[/cyan]  Define Term (Glossary)
[cyan]T.[/cyan]  Tutorial Mode
[red]0.[/red]  Exit
        """
        self.console.print(Panel(menu, title="Main Menu", border_style="green"))

    def run_define(self):
        """Run the glossary definition tool."""
        self.console.print("\n[bold cyan]📚 NET-WRANGLER Glossary[/bold cyan]")
        self.console.print("Available terms: " + ", ".join(self.edu.GLOSSARY.keys()))
        
        term = Prompt.ask("\n[cyan]Enter term to define[/cyan]")
        definition = self.edu.get_glossary_term(term)
        
        if definition:
            panel = Panel(
                f"[bold]Definition:[/bold] {definition['definition']}\n\n"
                f"[bold yellow]Analogy:[/bold yellow] {definition['analogy']}\n\n"
                f"[bold red]Security Context:[/bold red] {definition['security']}",
                title=f"📖 {definition['term']}",
                border_style="cyan"
            )
            self.console.print(panel)
        else:
            self.console.print(f"[red]Term '{term}' not found.[/red]")

    def run_tutorial(self):
        """Run interactive tutorial."""
        self.console.print("\n[bold cyan]🎓 Interactive Tutorials[/bold cyan]")
        self.console.print("1. Network Discovery (ARP)")
        self.console.print("3. Port Scanning")
        
        choice = Prompt.ask("\n[cyan]Select tutorial[/cyan]")
        tutorial = self.edu.get_tutorial(choice)
        
        if tutorial:
            self.console.print(f"\n[bold green]Starting Tutorial: {tutorial['title']}[/bold green]\n")
            for i, step in enumerate(tutorial['steps'], 1):
                self.console.print(f"[yellow]Step {i}:[/yellow] {step}")
                if i < len(tutorial['steps']):
                    input("Press Enter to continue...")
            
            self.console.print("\n[green]Tutorial Complete! Now try the real tool.[/green]")
            if Confirm.ask("Run this tool now?"):
                if choice == "1":
                    self.run_network_discovery()
                elif choice == "3":
                    self.run_port_scan()
        else:
            self.console.print("[red]Tutorial not found.[/red]")

    def run_help(self):
        """Display the educational manual."""
        try:
            # Try to find the manual in the current directory
            manual_path = "NET_WRANGLER_MANUAL.md"
            if not os.path.exists(manual_path):
                # Fallback to checking if we are in a subdirectory
                manual_path = os.path.join("..", "NET_WRANGLER_MANUAL.md")
            
            if os.path.exists(manual_path):
                with open(manual_path, "r", encoding="utf-8") as f:
                    content = f.read()
                
                self.console.print(Markdown(content))
            else:
                self.console.print("[red]Manual file (NET_WRANGLER_MANUAL.md) not found![/red]")
                self.console.print("[yellow]Please ensure the manual file is in the same directory.[/yellow]")
        except Exception as e:
            self.console.print(f"[red]Error reading manual: {e}[/red]")

    def display_table(self, title: str, columns: List[str], rows: List[List[str]]):
        """Display data in a formatted table."""
        table = Table(title=title, box=box.ROUNDED, show_header=True, header_style="bold magenta")
        
        for col in columns:
            table.add_column(col)
        
        for row in rows:
            table.add_row(*[str(item) for item in row])
        
        self.console.print(table)
    
    def run_network_discovery(self):
        """Run network discovery scan."""
        network = Prompt.ask("[cyan]Enter network range[/cyan]", default=self.nw.get_network_range())
        
        self.console.print(f"\n[yellow]Scanning network: {network}[/yellow]\n")
        results = self.nw.arp_scan(network)
        
        if results:
            rows = [[r.ip, r.mac, r.hostname] for r in results]
            self.display_table("Network Discovery Results", ["IP Address", "MAC Address", "Hostname"], rows)
            self.console.print(f"\n[green]Found {len(results)} active hosts[/green]")
            
            if Confirm.ask("\n[bold cyan]?[/bold cyan] Explain these results?"):
                self.console.print("\n[bold yellow]Analysis:[/bold yellow]")
                self.console.print(f"• Found {len(results)} devices on your local network.")
                self.console.print("• [cyan]Security Check:[/cyan] Review the list for any unknown devices.")
                self.console.print("• [cyan]MAC Addresses:[/cyan] The first 3 bytes (e.g., AA:BB:CC) identify the manufacturer.")
                
                unknown_count = 0
                for r in results:
                    if "Unknown" in r.hostname or not r.hostname:
                        unknown_count += 1
                
                if unknown_count > 0:
                    self.console.print(f"• [yellow]Warning:[/yellow] {unknown_count} devices have unknown hostnames. Investigate them.")
        else:
            self.console.print("[red]No hosts found or scan failed[/red]")
    
    def run_ping_sweep(self):
        """Run ping sweep."""
        network = Prompt.ask("[cyan]Enter network range[/cyan]", default=self.nw.get_network_range())
        
        self.console.print(f"\n[yellow]Ping sweeping: {network}[/yellow]\n")
        results = self.nw.ping_sweep(network)
        
        if results:
            rows = [[r.ip, r.hostname, f"{r.latency} ms" if r.latency else "N/A"] for r in results]
            self.display_table("Ping Sweep Results", ["IP Address", "Hostname", "Latency"], rows)
            self.console.print(f"\n[green]Found {len(results)} responding hosts[/green]")
        else:
            self.console.print("[red]No hosts responding or scan failed[/red]")
    
    def run_port_scan(self):
        """Run port scan."""
        target = Prompt.ask("[cyan]Enter target IP/hostname[/cyan]")
        port_input = Prompt.ask("[cyan]Enter ports (comma-separated or 'common')[/cyan]", default="common")
        
        if port_input.lower() == "common":
            ports = self.nw.COMMON_PORTS
        else:
            ports = [int(p.strip()) for p in port_input.split(",")]
        
        self.console.print(f"\n[yellow]Scanning {target}...[/yellow]\n")
        results = self.nw.tcp_connect_scan(target, ports)
        
        if results:
            rows = [[str(r.port), r.state, r.service, r.banner or "N/A"] for r in results]
            self.display_table(f"Port Scan Results - {target}", ["Port", "State", "Service", "Banner"], rows)
            self.console.print(f"\n[green]Found {len(results)} open ports[/green]")
            
            if Confirm.ask("\n[bold cyan]?[/bold cyan] Explain these results?"):
                self.console.print("\n[bold yellow]Analysis:[/bold yellow]")
                for r in results:
                    risk = "Low"
                    details = "Standard service."
                    
                    if r.port == 21: 
                        risk = "High"; details = "FTP sends passwords in clear text."
                    elif r.port == 23: 
                        risk = "High"; details = "Telnet is unencrypted. Use SSH instead."
                    elif r.port == 80: 
                        risk = "Medium"; details = "HTTP is unencrypted. Prefer HTTPS."
                    elif r.port == 445: 
                        risk = "Critical"; details = "SMB is a frequent target for ransomware (EternalBlue)."
                    elif r.port == 3389: 
                        risk = "High"; details = "RDP should not be exposed to the internet."
                    
                    color = "red" if risk in ["High", "Critical"] else "green"
                    self.console.print(f"• [cyan]Port {r.port} ({r.service})[/cyan]: [{color}]{risk} Risk[/{color}]. {details}")
        else:
            self.console.print("[yellow]No open ports found[/yellow]")
    
    def run_full_port_scan(self):
        """Run full port scan."""
        target = Prompt.ask("[cyan]Enter target IP/hostname[/cyan]")
        start = int(Prompt.ask("[cyan]Start port[/cyan]", default="1"))
        end = int(Prompt.ask("[cyan]End port[/cyan]", default="65535"))
        
        self.console.print(f"\n[yellow]Full scan on {target} (ports {start}-{end})...[/yellow]")
        self.console.print("[dim]This may take a while...[/dim]\n")
        
        ports = list(range(start, end + 1))
        results = self.nw.tcp_connect_scan(target, ports)
        
        if results:
            rows = [[str(r.port), r.state, r.service, r.banner or "N/A"] for r in results]
            self.display_table(f"Full Port Scan - {target}", ["Port", "State", "Service", "Banner"], rows)
            self.console.print(f"\n[green]Found {len(results)} open ports[/green]")
        else:
            self.console.print("[yellow]No open ports found[/yellow]")
    
    def run_dns_lookup(self):
        """Run DNS lookup."""
        domain = Prompt.ask("[cyan]Enter domain name[/cyan]")
        
        self.console.print(f"\n[yellow]Looking up DNS records for: {domain}[/yellow]\n")
        results = self.nw.dns_lookup(domain)
        
        if "records" in results and results["records"]:
            for record_type, values in results["records"].items():
                table = Table(title=f"{record_type} Records", box=box.SIMPLE)
                table.add_column("Value")
                for value in values:
                    table.add_row(value)
                self.console.print(table)
            
            if Confirm.ask("\n[bold cyan]?[/bold cyan] Explain these results?"):
                self.console.print("\n[bold yellow]Analysis:[/bold yellow]")
                if "A" in results["records"]:
                    self.console.print("• [cyan]A Records:[/cyan] These are the IPv4 addresses of the server.")
                if "MX" in results["records"]:
                    self.console.print("• [cyan]MX Records:[/cyan] These servers handle email for this domain.")
                if "TXT" in results["records"]:
                    self.console.print("• [cyan]TXT Records:[/cyan] Often used for verification (Google, MS) or security (SPF/DMARC).")
                    for txt in results["records"]["TXT"]:
                        if "v=spf1" in txt:
                            self.console.print(f"  - Found SPF Record: [green]{txt}[/green] (Helps prevent email spoofing)")
        else:
            self.console.print("[red]No DNS records found[/red]")
    
    def run_reverse_dns(self):
        """Run reverse DNS lookup."""
        ip = Prompt.ask("[cyan]Enter IP address[/cyan]")
        
        result = self.nw.reverse_dns(ip)
        if result:
            self.console.print(f"\n[green]Reverse DNS: {ip} → {result}[/green]")
        else:
            self.console.print(f"\n[red]No reverse DNS record found for {ip}[/red]")
    
    def run_whois(self):
        """Run WHOIS lookup."""
        target = Prompt.ask("[cyan]Enter domain or IP[/cyan]")
        
        self.console.print(f"\n[yellow]WHOIS lookup for: {target}[/yellow]\n")
        results = self.nw.whois_lookup(target)
        
        if "error" not in results:
            table = Table(title="WHOIS Information", box=box.ROUNDED)
            table.add_column("Field", style="cyan")
            table.add_column("Value")
            
            for key, value in results.items():
                if value:
                    table.add_row(key.replace("_", " ").title(), str(value))
            
            self.console.print(table)
        else:
            self.console.print(f"[red]WHOIS lookup failed: {results['error']}[/red]")
    
    def run_traceroute(self):
        """Run traceroute."""
        target = Prompt.ask("[cyan]Enter target IP/hostname[/cyan]")
        max_hops = int(Prompt.ask("[cyan]Max hops[/cyan]", default="30"))
        
        self.console.print(f"\n[yellow]Traceroute to {target}...[/yellow]\n")
        results = self.nw.traceroute(target, max_hops)
        
        if results and "error" not in results[0]:
            rows = [[str(r["hop"]), r["ip"], r["hostname"], 
                    f"{r['rtt']} ms" if r["rtt"] else "*"] for r in results]
            self.display_table(f"Traceroute to {target}", ["Hop", "IP", "Hostname", "RTT"], rows)
        else:
            self.console.print(f"[red]Traceroute failed[/red]")
    
    def run_ssl_analysis(self):
        """Run SSL/TLS analysis."""
        target = Prompt.ask("[cyan]Enter hostname[/cyan]")
        port = int(Prompt.ask("[cyan]Port[/cyan]", default="443"))
        
        self.console.print(f"\n[yellow]Analyzing SSL/TLS on {target}:{port}...[/yellow]\n")
        results = self.nw.ssl_analysis(target, port)
        
        if "error" not in results:
            table = Table(title="SSL/TLS Analysis", box=box.ROUNDED)
            table.add_column("Property", style="cyan")
            table.add_column("Value")
            
            table.add_row("Protocol Version", results.get("version", "N/A"))
            table.add_row("Cipher Suite", results.get("cipher", "N/A"))
            table.add_row("Key Bits", str(results.get("cipher_bits", "N/A")))
            table.add_row("Valid From", results.get("not_before", "N/A"))
            table.add_row("Valid Until", results.get("not_after", "N/A"))
            
            if results.get("subject"):
                table.add_row("Subject", str(results["subject"]))
            if results.get("issuer"):
                table.add_row("Issuer", str(results["issuer"]))
            
            self.console.print(table)
            
            if Confirm.ask("\n[bold cyan]?[/bold cyan] Explain these results?"):
                self.console.print("\n[bold yellow]Analysis:[/bold yellow]")
                
                # Protocol Check
                version = results.get("version", "")
                if "TLSv1.3" in version or "TLSv1.2" in version:
                    self.console.print(f"• [green]Protocol ({version}):[/green] Secure. Modern standard.")
                else:
                    self.console.print(f"• [red]Protocol ({version}):[/red] Obsolete. Vulnerable to attacks like POODLE.")
                
                # Expiration Check
                try:
                    not_after = datetime.strptime(results.get("not_after", ""), "%b %d %H:%M:%S %Y %Z")
                    days_left = (not_after - datetime.now()).days
                    if days_left < 0:
                        self.console.print(f"• [red]Expiration:[/red] Certificate is EXPIRED! Users will see warnings.")
                    elif days_left < 30:
                        self.console.print(f"• [yellow]Expiration:[/yellow] Expiring soon ({days_left} days). Renew immediately.")
                    else:
                        self.console.print(f"• [green]Expiration:[/green] Valid for {days_left} more days.")
                except:
                    pass
        else:
            self.console.print(f"[red]SSL Analysis failed: {results['error']}[/red]")
    
    def run_http_headers(self):
        """Run HTTP header analysis."""
        url = Prompt.ask("[cyan]Enter URL[/cyan]")
        
        self.console.print(f"\n[yellow]Analyzing HTTP headers for: {url}[/yellow]\n")
        results = self.nw.http_headers(url)
        
        if "error" not in results:
            # General info
            table = Table(title="HTTP Response", box=box.ROUNDED)
            table.add_column("Property", style="cyan")
            table.add_column("Value")
            table.add_row("Final URL", results.get("url", "N/A"))
            table.add_row("Status Code", str(results.get("status_code", "N/A")))
            table.add_row("Server", results.get("server", "N/A"))
            self.console.print(table)
            
            # Security headers
            sec_table = Table(title="Security Headers", box=box.ROUNDED)
            sec_table.add_column("Header", style="cyan")
            sec_table.add_column("Value")
            
            for header, value in results.get("security_headers", {}).items():
                style = "red" if value == "Missing" else "green"
                sec_table.add_row(header, f"[{style}]{value}[/{style}]")
            
            self.console.print(sec_table)
            
            if Confirm.ask("\n[bold cyan]?[/bold cyan] Explain these results?"):
                self.console.print("\n[bold yellow]Analysis:[/bold yellow]")
                headers = results.get("security_headers", {})
                
                if headers.get("Strict-Transport-Security") == "Missing":
                    self.console.print("• [red]HSTS Missing:[/red] Users can be downgraded to HTTP (unencrypted).")
                else:
                    self.console.print("• [green]HSTS Present:[/green] Forces users to use HTTPS.")
                    
                if headers.get("X-Frame-Options") == "Missing":
                    self.console.print("• [red]X-Frame-Options Missing:[/red] Site can be embedded in an iframe (Clickjacking risk).")
                
                if headers.get("Content-Security-Policy") == "Missing":
                    self.console.print("• [red]CSP Missing:[/red] No protection against XSS (Cross-Site Scripting).")
        else:
            self.console.print(f"[red]HTTP Analysis failed: {results['error']}[/red]")
    
    def run_geolocation(self):
        """Run geolocation lookup."""
        ip = Prompt.ask("[cyan]Enter IP address[/cyan]", default=self.nw.get_local_ip())
        
        self.console.print(f"\n[yellow]Geolocating: {ip}[/yellow]\n")
        results = self.nw.geolocate_ip(ip)
        
        if "error" not in results and results.get("status") != "fail":
            table = Table(title="IP Geolocation", box=box.ROUNDED)
            table.add_column("Property", style="cyan")
            table.add_column("Value")
            
            fields = [
                ("IP", "query"), ("Country", "country"), ("Region", "regionName"),
                ("City", "city"), ("ZIP", "zip"), ("Latitude", "lat"),
                ("Longitude", "lon"), ("Timezone", "timezone"), ("ISP", "isp"),
                ("Organization", "org"), ("AS", "as")
            ]
            
            for label, key in fields:
                if key in results:
                    table.add_row(label, str(results[key]))
            
            self.console.print(table)
        else:
            self.console.print(f"[red]Geolocation failed[/red]")
    
    def run_subnet_calc(self):
        """Run subnet calculator."""
        cidr = Prompt.ask("[cyan]Enter CIDR notation (e.g., 192.168.1.0/24)[/cyan]")
        
        results = self.nw.subnet_calculator(cidr)
        
        if "error" not in results:
            table = Table(title="Subnet Information", box=box.ROUNDED)
            table.add_column("Property", style="cyan")
            table.add_column("Value")
            
            table.add_row("Network Address", results["network"])
            table.add_row("Broadcast Address", results["broadcast"])
            table.add_row("Netmask", results["netmask"])
            table.add_row("Wildcard Mask", results["hostmask"])
            table.add_row("CIDR Prefix", f"/{results['prefix_length']}")
            table.add_row("Usable Hosts", str(results["num_hosts"]))
            table.add_row("First Usable Host", results["first_host"])
            table.add_row("Last Usable Host", results["last_host"])
            table.add_row("Private Network", "Yes" if results["is_private"] else "No")
            
            self.console.print(table)
        else:
            self.console.print(f"[red]Invalid CIDR: {results['error']}[/red]")
    
    def run_interfaces(self):
        """Display network interfaces."""
        interfaces = self.nw.get_interfaces()
        
        for iface in interfaces:
            status = "[green]UP[/green]" if iface.get("is_up") else "[red]DOWN[/red]"
            table = Table(title=f"Interface: {iface['name']} ({status})", box=box.ROUNDED)
            table.add_column("Type", style="cyan")
            table.add_column("Address")
            
            addrs = iface.get("addresses", {})
            
            if addrs.get("ipv4"):
                for addr in addrs["ipv4"]:
                    table.add_row("IPv4", f"{addr.get('addr', 'N/A')} / {addr.get('netmask', 'N/A')}")
            
            if addrs.get("ipv6"):
                for addr in addrs["ipv6"]:
                    table.add_row("IPv6", addr.get('addr', 'N/A'))
            
            if addrs.get("mac"):
                for addr in addrs["mac"]:
                    if addr.get('addr'):
                        table.add_row("MAC", addr.get('addr', 'N/A'))
            
            self.console.print(table)
    
    def run_bandwidth_monitor(self):
        """Run bandwidth monitor."""
        duration = int(Prompt.ask("[cyan]Monitor duration (seconds)[/cyan]", default="10"))
        
        self.console.print(f"\n[yellow]Monitoring bandwidth for {duration} seconds...[/yellow]\n")
        
        with Live(console=self.console, refresh_per_second=1) as live:
            start_counters = psutil.net_io_counters()
            
            for i in range(duration):
                time.sleep(1)
                current = psutil.net_io_counters()
                
                bytes_sent = current.bytes_sent - start_counters.bytes_sent
                bytes_recv = current.bytes_recv - start_counters.bytes_recv
                
                table = Table(title=f"Bandwidth Monitor ({i+1}/{duration}s)", box=box.ROUNDED)
                table.add_column("Metric", style="cyan")
                table.add_column("Value")
                
                table.add_row("Download Speed", f"{bytes_recv / 1024:.2f} KB/s")
                table.add_row("Upload Speed", f"{bytes_sent / 1024:.2f} KB/s")
                table.add_row("Total Downloaded", f"{current.bytes_recv / 1024 / 1024:.2f} MB")
                table.add_row("Total Uploaded", f"{current.bytes_sent / 1024 / 1024:.2f} MB")
                table.add_row("Packets Received", str(current.packets_recv))
                table.add_row("Packets Sent", str(current.packets_sent))
                
                live.update(table)
                start_counters = current
    
    def run_connections(self):
        """Display active connections."""
        self.console.print("\n[yellow]Fetching active connections...[/yellow]\n")
        connections = self.nw.get_connections()
        
        # Filter to show only ESTABLISHED connections
        established = [c for c in connections if c["status"] == "ESTABLISHED"]
        
        if established:
            rows = [[c["local_address"] or "N/A", c["remote_address"] or "N/A", 
                    c["status"], c["type"], c["process"]] for c in established[:50]]
            self.display_table("Active Connections (ESTABLISHED)", 
                              ["Local Address", "Remote Address", "Status", "Type", "Process"], rows)
            self.console.print(f"\n[green]Showing {len(rows)} of {len(established)} connections[/green]")
        else:
            self.console.print("[yellow]No established connections found[/yellow]")
    
    def run_mac_lookup(self):
        """Run MAC address lookup."""
        mac = Prompt.ask("[cyan]Enter MAC address[/cyan]")
        
        result = self.nw.mac_lookup(mac)
        
        if "error" not in result:
            self.console.print(f"\n[green]MAC: {mac}[/green]")
            self.console.print(f"[green]Vendor: {result['vendor']}[/green]")
        else:
            self.console.print(f"[red]Lookup failed: {result['error']}[/red]")
    
    def run_packet_sniffer(self):
        """Run packet sniffer."""
        count = int(Prompt.ask("[cyan]Number of packets to capture[/cyan]", default="10"))
        filter_str = Prompt.ask("[cyan]BPF filter (optional, press Enter to skip)[/cyan]", default="")
        
        self.console.print(f"\n[yellow]Capturing {count} packets...[/yellow]\n")
        
        filter_arg = filter_str if filter_str else None
        packets = self.nw.packet_sniffer(count=count, filter_str=filter_arg)
        
        if packets and "error" not in packets[0]:
            rows = []
            for p in packets:
                src = f"{p.get('src_ip', 'N/A')}:{p.get('src_port', 'N/A')}"
                dst = f"{p.get('dst_ip', 'N/A')}:{p.get('dst_port', 'N/A')}"
                rows.append([p.get("timestamp", "N/A")[:19], src, dst, str(p.get("size", 0))])
            
            self.display_table("Captured Packets", ["Timestamp", "Source", "Destination", "Size"], rows)
        else:
            self.console.print("[red]Packet capture failed (may require admin privileges)[/red]")
    
    def run_vuln_check(self):
        """Run vulnerability check."""
        target = Prompt.ask("[cyan]Enter target IP/hostname[/cyan]")
        
        self.console.print(f"\n[yellow]Checking {target} for common vulnerabilities...[/yellow]\n")
        results = self.nw.check_common_vulnerabilities(target)
        
        for check in results["checks"]:
            status_color = "green" if check["status"] == "ok" else "yellow"
            self.console.print(f"\n[{status_color}]► {check['name']}: {check['status'].upper()}[/{status_color}]")
            
            if check["findings"]:
                for finding in check["findings"]:
                    if isinstance(finding, dict):
                        self.console.print(f"  [red]• Port {finding['port']}: {finding['service']}[/red]")
                    else:
                        self.console.print(f"  [red]• {finding}[/red]")
    
    def run_quick_scan(self):
        """Run quick all-in-one scan."""
        target = Prompt.ask("[cyan]Enter target IP/hostname[/cyan]")
        
        self.console.print(f"\n[bold yellow]═══ Quick Scan: {target} ═══[/bold yellow]\n")
        
        # Resolve hostname
        try:
            ip = socket.gethostbyname(target)
            self.console.print(f"[green]✓ Resolved to: {ip}[/green]\n")
        except socket.gaierror:
            self.console.print(f"[red]✗ Could not resolve hostname[/red]")
            return
        
        # Port scan
        self.console.print("[cyan]► Port Scan (Common Ports)...[/cyan]")
        ports = self.nw.tcp_connect_scan(target, self.nw.COMMON_PORTS[:10])
        if ports:
            for p in ports:
                self.console.print(f"  [green]• {p.port}/tcp - {p.service}[/green]")
        else:
            self.console.print("  [yellow]No common ports open[/yellow]")
        
        # DNS
        self.console.print("\n[cyan]► DNS Records...[/cyan]")
        dns_results = self.nw.dns_lookup(target)
        if dns_results.get("records"):
            for rtype, values in list(dns_results["records"].items())[:3]:
                self.console.print(f"  [green]• {rtype}: {', '.join(values[:2])}[/green]")
        
        # Geolocation
        self.console.print("\n[cyan]► Geolocation...[/cyan]")
        geo = self.nw.geolocate_ip(ip)
        if geo.get("status") != "fail":
            self.console.print(f"  [green]• Location: {geo.get('city', 'N/A')}, {geo.get('country', 'N/A')}[/green]")
            self.console.print(f"  [green]• ISP: {geo.get('isp', 'N/A')}[/green]")
        
        # HTTP
        self.console.print("\n[cyan]► HTTP Analysis...[/cyan]")
        for proto in ['https', 'http']:
            try:
                http = self.nw.http_headers(f"{proto}://{target}")
                if "error" not in http:
                    self.console.print(f"  [green]• {proto.upper()} Server: {http.get('server', 'N/A')}[/green]")
                    break
            except Exception:
                pass
        
        self.console.print(f"\n[bold green]═══ Quick Scan Complete ═══[/bold green]")
    
    def run(self):
        """Main CLI loop."""
        self.print_banner()
        
        while True:
            self.main_menu()
            
            choice = Prompt.ask("\n[bold cyan]Select option[/bold cyan]")
            
            try:
                if choice == "0":
                    self.console.print("\n[yellow]Goodbye! Stay secure! 🛡️[/yellow]\n")
                    break
                elif choice == "1":
                    self.run_network_discovery()
                elif choice == "2":
                    self.run_ping_sweep()
                elif choice == "3":
                    self.run_port_scan()
                elif choice == "4":
                    self.run_full_port_scan()
                elif choice == "5":
                    self.run_dns_lookup()
                elif choice == "6":
                    self.run_reverse_dns()
                elif choice == "7":
                    self.run_whois()
                elif choice == "8":
                    self.run_traceroute()
                elif choice == "9":
                    self.run_ssl_analysis()
                elif choice == "10":
                    self.run_http_headers()
                elif choice == "11":
                    self.run_geolocation()
                elif choice == "12":
                    self.run_subnet_calc()
                elif choice == "13":
                    self.run_interfaces()
                elif choice == "14":
                    self.run_bandwidth_monitor()
                elif choice == "15":
                    self.run_connections()
                elif choice == "16":
                    self.run_mac_lookup()
                elif choice == "17":
                    self.run_packet_sniffer()
                elif choice == "18":
                    self.run_vuln_check()
                elif choice == "19":
                    self.run_quick_scan()
                elif choice.lower() in ["h", "help"]:
                    self.run_help()
                elif choice.lower() in ["d", "define"]:
                    self.run_define()
                elif choice.lower() in ["t", "tutorial"]:
                    self.run_tutorial()
                else:
                    self.console.print("[red]Invalid option. Please try again.[/red]")
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Operation cancelled[/yellow]")
            except Exception as e:
                self.console.print(f"[red]Error: {e}[/red]")
            
            input("\nPress Enter to continue...")


if __name__ == "__main__":
    # Check for admin/root privileges for certain features
    if platform.system() == "Windows":
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        is_admin = os.geteuid() == 0
    
    if not is_admin:
        console.print("[yellow]⚠ Running without admin privileges. Some features may be limited.[/yellow]")
    
    cli = CLI()
    cli.run()
