#!/usr/bin/env python3
"""
NET-WRANGLER v2.0 - Feature Test Script
Tests each feature of the networking tool to ensure proper functionality.
"""

import sys
import socket
import time

# Add parent directory to path
sys.path.insert(0, '.')

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

def test_header(name: str):
    """Print test header."""
    console.print(f"\n[bold cyan]{'='*60}[/bold cyan]")
    console.print(f"[bold yellow]Testing: {name}[/bold yellow]")
    console.print(f"[bold cyan]{'='*60}[/bold cyan]\n")

def test_result(name: str, success: bool, message: str = ""):
    """Print test result."""
    status = "[green]✓ PASS[/green]" if success else "[red]✗ FAIL[/red]"
    console.print(f"{status} {name}: {message}")
    return success

def run_tests():
    """Run all feature tests."""
    console.print(Panel("[bold magenta]NET-WRANGLER v2.0 - Feature Tests[/bold magenta]", border_style="magenta"))
    
    # Import the main module
    try:
        from net_wrangler import NetWrangler
        nw = NetWrangler()
        test_result("Module Import", True, "NetWrangler loaded successfully")
    except Exception as e:
        test_result("Module Import", False, str(e))
        return
    
    results = []
    
    # ==================== TEST 1: Get Local IP ====================
    test_header("1. Get Local IP")
    try:
        local_ip = nw.get_local_ip()
        success = local_ip and local_ip != "127.0.0.1"
        results.append(test_result("Get Local IP", success, f"Local IP: {local_ip}"))
    except Exception as e:
        results.append(test_result("Get Local IP", False, str(e)))
    
    # ==================== TEST 2: Get Network Range ====================
    test_header("2. Get Network Range")
    try:
        network = nw.get_network_range()
        success = network and "/24" in network
        results.append(test_result("Get Network Range", success, f"Network: {network}"))
    except Exception as e:
        results.append(test_result("Get Network Range", False, str(e)))
    
    # ==================== TEST 3: DNS Lookup ====================
    test_header("3. DNS Lookup")
    try:
        dns_result = nw.dns_lookup("google.com")
        success = "records" in dns_result and len(dns_result["records"]) > 0
        results.append(test_result("DNS Lookup", success, f"Found {len(dns_result.get('records', {}))} record types"))
        if success:
            for rtype, values in list(dns_result["records"].items())[:3]:
                console.print(f"  [dim]• {rtype}: {values[0] if values else 'N/A'}[/dim]")
    except Exception as e:
        results.append(test_result("DNS Lookup", False, str(e)))
    
    # ==================== TEST 4: Reverse DNS ====================
    test_header("4. Reverse DNS")
    try:
        reverse = nw.reverse_dns("8.8.8.8")
        success = reverse is not None
        results.append(test_result("Reverse DNS", success, f"8.8.8.8 → {reverse}"))
    except Exception as e:
        results.append(test_result("Reverse DNS", False, str(e)))
    
    # ==================== TEST 5: WHOIS Lookup ====================
    test_header("5. WHOIS Lookup")
    try:
        whois_result = nw.whois_lookup("google.com")
        success = "error" not in whois_result and whois_result.get("registrar")
        results.append(test_result("WHOIS Lookup", success, f"Registrar: {whois_result.get('registrar', 'N/A')}"))
    except Exception as e:
        results.append(test_result("WHOIS Lookup", False, str(e)))
    
    # ==================== TEST 6: Port Scan (Quick) ====================
    test_header("6. TCP Port Scan (Quick)")
    try:
        # Scan only a few ports on google.com
        ports = nw.tcp_connect_scan("google.com", [80, 443], timeout=3)
        success = len(ports) > 0
        results.append(test_result("Port Scan", success, f"Found {len(ports)} open ports"))
        for p in ports:
            console.print(f"  [dim]• Port {p.port}: {p.service}[/dim]")
    except Exception as e:
        results.append(test_result("Port Scan", False, str(e)))
    
    # ==================== TEST 7: Subnet Calculator ====================
    test_header("7. Subnet Calculator")
    try:
        subnet = nw.subnet_calculator("192.168.1.0/24")
        success = "error" not in subnet
        results.append(test_result("Subnet Calculator", success, 
            f"Network: {subnet.get('network', 'N/A')}, Hosts: {subnet.get('num_hosts', 'N/A')}"))
    except Exception as e:
        results.append(test_result("Subnet Calculator", False, str(e)))
    
    # ==================== TEST 8: Geolocation ====================
    test_header("8. IP Geolocation")
    try:
        geo = nw.geolocate_ip("8.8.8.8")
        success = geo.get("status") != "fail" and "country" in geo
        results.append(test_result("Geolocation", success, 
            f"8.8.8.8 → {geo.get('city', 'N/A')}, {geo.get('country', 'N/A')}"))
    except Exception as e:
        results.append(test_result("Geolocation", False, str(e)))
    
    # ==================== TEST 9: HTTP Headers ====================
    test_header("9. HTTP Header Analysis")
    try:
        headers = nw.http_headers("https://google.com")
        success = "error" not in headers
        results.append(test_result("HTTP Headers", success, 
            f"Status: {headers.get('status_code', 'N/A')}, Server: {headers.get('server', 'N/A')}"))
        if success and "security_headers" in headers:
            missing = sum(1 for v in headers["security_headers"].values() if v == "Missing")
            console.print(f"  [dim]• Security headers missing: {missing}/{len(headers['security_headers'])}[/dim]")
    except Exception as e:
        results.append(test_result("HTTP Headers", False, str(e)))
    
    # ==================== TEST 10: SSL/TLS Analysis ====================
    test_header("10. SSL/TLS Analysis")
    try:
        ssl_info = nw.ssl_analysis("google.com", 443)
        success = "error" not in ssl_info
        results.append(test_result("SSL Analysis", success, 
            f"Protocol: {ssl_info.get('version', 'N/A')}, Cipher: {ssl_info.get('cipher', 'N/A')}"))
    except Exception as e:
        results.append(test_result("SSL Analysis", False, str(e)))
    
    # ==================== TEST 11: Network Interfaces ====================
    test_header("11. Network Interfaces")
    try:
        interfaces = nw.get_interfaces()
        success = len(interfaces) > 0
        results.append(test_result("Network Interfaces", success, f"Found {len(interfaces)} interfaces"))
        for iface in interfaces[:3]:
            ipv4 = iface.get("addresses", {}).get("ipv4", [])
            ip = ipv4[0].get("addr") if ipv4 else "N/A"
            console.print(f"  [dim]• {iface['name']}: {ip}[/dim]")
    except Exception as e:
        results.append(test_result("Network Interfaces", False, str(e)))
    
    # ==================== TEST 12: Active Connections ====================
    test_header("12. Active Connections")
    try:
        connections = nw.get_connections()
        established = [c for c in connections if c["status"] == "ESTABLISHED"]
        success = True  # This always works, may have 0 connections
        results.append(test_result("Connections", success, 
            f"Total: {len(connections)}, Established: {len(established)}"))
    except Exception as e:
        results.append(test_result("Connections", False, str(e)))
    
    # ==================== TEST 13: MAC Lookup ====================
    test_header("13. MAC Address Lookup")
    try:
        mac_info = nw.mac_lookup("00:00:5E:00:53:AF")
        success = "error" not in mac_info
        results.append(test_result("MAC Lookup", success, f"Vendor: {mac_info.get('vendor', 'N/A')}"))
    except Exception as e:
        results.append(test_result("MAC Lookup", False, str(e)))
    
    # ==================== TEST 14: Banner Grab ====================
    test_header("14. Banner Grabbing")
    try:
        banner = nw.grab_banner("google.com", 80)
        success = banner is not None
        results.append(test_result("Banner Grab", success, f"Banner: {banner[:50] if banner else 'N/A'}..."))
    except Exception as e:
        results.append(test_result("Banner Grab", False, str(e)))
    
    # ==================== TEST 15: Vulnerability Check ====================
    test_header("15. Vulnerability Check")
    try:
        vuln = nw.check_common_vulnerabilities("google.com")
        success = "checks" in vuln
        results.append(test_result("Vuln Check", success, f"Performed {len(vuln.get('checks', []))} checks"))
    except Exception as e:
        results.append(test_result("Vuln Check", False, str(e)))
    
    # ==================== SUMMARY ====================
    console.print("\n")
    console.print(Panel("[bold magenta]Test Summary[/bold magenta]", border_style="magenta"))
    
    passed = sum(1 for r in results if r)
    failed = len(results) - passed
    
    table = Table(box=box.ROUNDED)
    table.add_column("Status", style="cyan")
    table.add_column("Count")
    table.add_row("[green]Passed[/green]", str(passed))
    table.add_row("[red]Failed[/red]", str(failed))
    table.add_row("[yellow]Total[/yellow]", str(len(results)))
    
    console.print(table)
    
    if failed == 0:
        console.print("\n[bold green]🎉 All tests passed! NET-WRANGLER is working correctly.[/bold green]")
    else:
        console.print(f"\n[bold yellow]⚠ {failed} test(s) failed. Some features may require admin privileges.[/bold yellow]")
    
    # Note about features that need special permissions
    console.print("\n[dim]Note: Some features (ARP Scan, Packet Sniffer, Traceroute) require admin/root privileges.[/dim]")
    console.print("[dim]Run as Administrator/root for full functionality.[/dim]")

if __name__ == "__main__":
    run_tests()
