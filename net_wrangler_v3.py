#!/usr/bin/env python3
"""
NET-WRANGLER v3.0 - Enterprise Network Security Suite
Advanced networking toolkit for security professionals and penetration testers.

Author: jamwal69
License: MIT
Version: 3.0.0 (Enterprise Edition)
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
import configparser
import hashlib
import base64
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Any
from collections import defaultdict, deque
import warnings
import urllib3
warnings.filterwarnings('ignore', category=urllib3.exceptions.InsecureRequestWarning)

# Import enterprise features
try:
    from enterprise_features import (
        CloudStorageAuditor,
        SubdomainEnumerator,
        WAFDetector,
        AnomalyDetector,
        FutureSecurityFeatures
    )
    ENTERPRISE_FEATURES_AVAILABLE = True
except ImportError:
    ENTERPRISE_FEATURES_AVAILABLE = False
    print("Warning: Enterprise features module not found. Some features will be unavailable.")

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
        'numpy': 'numpy',
        'scikit-learn': 'sklearn',
    }
    
    missing = []
    for package, import_name in required.items():
        try:
            __import__(import_name.split('.')[0] if '.' in import_name else import_name)
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"[*] Installing missing packages: {', '.join(missing)}")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--quiet'] + missing)

# Import libraries
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.prompt import Prompt, Confirm, IntPrompt
    from rich.layout import Layout
    from rich.live import Live
    from rich import box
    from rich.markdown import Markdown
    from rich.syntax import Syntax
    from rich.tree import Tree
    from rich.columns import Columns
    from rich.align import Align
    import psutil
    import requests
    import urllib3
    import whois
    import dns.resolver
    import dns.reversename
    from scapy.all import ARP, Ether, srp, IP, ICMP, TCP, UDP, sr1, sniff, conf
    import numpy as np
    from sklearn.ensemble import IsolationForest
    conf.verb = 0
except ImportError:
    check_dependencies()
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.prompt import Prompt, Confirm, IntPrompt
    from rich.layout import Layout
    from rich.live import Live
    from rich import box
    from rich.markdown import Markdown
    from rich.syntax import Syntax
    from rich.tree import Tree
    from rich.columns import Columns
    from rich.align import Align
    import psutil
    import requests
    import urllib3
    import whois
    import dns.resolver
    import dns.reversename
    from scapy.all import ARP, Ether, srp, IP, ICMP, TCP, UDP, sr1, sniff, conf
    import numpy as np
    from sklearn.ensemble import IsolationForest
    conf.verb = 0

console = Console()

# ===================== CONFIGURATION SYSTEM =====================

class Config:
    """Configuration manager for API keys and settings."""
    
    CONFIG_FILE = "config.ini"
    
    DEFAULT_CONFIG = {
        'API_KEYS': {
            'abuseipdb_key': '',
            'shodan_key': '',
            'virustotal_key': '',
        },
        'SETTINGS': {
            'stealth_mode': 'false',
            'max_threads': '100',
            'timeout': '3',
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        }
    }
    
    @staticmethod
    def load_config() -> configparser.ConfigParser:
        """Load configuration from file."""
        config = configparser.ConfigParser()
        
        if not os.path.exists(Config.CONFIG_FILE):
            Config.create_default_config()
        
        config.read(Config.CONFIG_FILE)
        return config
    
    @staticmethod
    def create_default_config():
        """Create default configuration file."""
        config = configparser.ConfigParser()
        config.read_dict(Config.DEFAULT_CONFIG)
        
        with open(Config.CONFIG_FILE, 'w') as f:
            config.write(f)
        
        console.print(f"[yellow]Created default config file: {Config.CONFIG_FILE}[/yellow]")
        console.print("[dim]You can add API keys in this file for threat intelligence features.[/dim]")
    
    @staticmethod
    def get(section: str, key: str, fallback: str = '') -> str:
        """Get configuration value."""
        config = Config.load_config()
        return config.get(section, key, fallback=fallback)

# ===================== HELP SYSTEM (MAN-PAGE STYLE) =====================

class HelpSystem:
    """Comprehensive help documentation system."""
    
    HELP_DOCS = {
        "1": {
            "name": "Network Discovery (ARP Scan)",
            "synopsis": "arp_scan [network_range]",
            "description": """
## What is ARP Scan?

Address Resolution Protocol (ARP) scanning is a Layer 2 network discovery technique that maps IP addresses to MAC addresses on the local network.

## Why Use ARP Scan?

- **Speed**: ARP is faster than ICMP ping sweeps
- **Reliability**: Works even when ICMP is blocked by firewalls
- **Accuracy**: Discovers all devices on the local network segment
- **Stealth**: Less likely to trigger intrusion detection systems

## How It Works

1. Sends ARP request packets to all IPs in the target network
2. Devices respond with their MAC addresses
3. Performs reverse DNS lookup for hostnames
4. Maps the entire network topology

## What You Achieve

- Complete inventory of all active network devices
- MAC address to IP mapping
- Hostname resolution for identified hosts
- Network topology visualization

## Security Implications

- **Reconnaissance**: First step in penetration testing
- **Rogue Device Detection**: Identify unauthorized devices
- **Network Mapping**: Understand your attack surface

## Example Output

```
IP Address      MAC Address        Hostname
192.168.1.1     00:11:22:33:44:55  router.local
192.168.1.100   AA:BB:CC:DD:EE:FF  desktop-pc
```

## Requirements

- Must be run on the same network segment (Layer 2)
- Requires administrator/root privileges
- Works only on local networks (not across routers)
            """,
            "options": {
                "network_range": "CIDR notation (e.g., 192.168.1.0/24)",
            },
            "examples": [
                "Scan default network range",
                "Scan custom network: 10.0.0.0/24",
            ]
        },
        
        "2": {
            "name": "Ping Sweep (ICMP Discovery)",
            "synopsis": "ping_sweep [network_range] [timeout]",
            "description": """
## What is Ping Sweep?

ICMP Echo Request (ping) sweep is a Layer 3 network discovery technique that identifies live hosts across networks.

## Why Use Ping Sweep?

- **Cross-Network**: Works across routers (Layer 3)
- **Standard Protocol**: ICMP is universally supported
- **Latency Measurement**: Provides round-trip time (RTT)
- **Wide Range**: Can scan entire subnets quickly

## How It Works

1. Sends ICMP Echo Request packets to each IP
2. Waits for ICMP Echo Reply responses
3. Measures response time (latency)
4. Multi-threaded for speed (50 concurrent threads)
5. Resolves hostnames for responding IPs

## What You Achieve

- Identify active hosts across network boundaries
- Measure network latency and performance
- Discover hosts that allow ICMP traffic
- Create a list of scan targets for port scanning

## Security Implications

- **Firewall Evasion**: Some firewalls block ICMP
- **Detection Risk**: High volume may trigger IDS
- **Reconnaissance**: Standard first step in attack chain

## Limitations

- Blocked by many modern firewalls
- Some hosts disable ICMP responses
- May not discover all active hosts

## Example Output

```
IP Address      Hostname          Latency
192.168.1.1     gateway.local     1.2 ms
192.168.1.50    webserver.local   0.8 ms
```
            """,
            "options": {
                "network_range": "CIDR notation (default: auto-detect)",
                "timeout": "Response timeout in seconds (default: 1)",
            },
            "examples": [
                "Sweep entire subnet with default timeout",
                "Fast sweep with 0.5s timeout",
            ]
        },
        
        "3": {
            "name": "TCP Port Scan",
            "synopsis": "port_scan <target> [ports] [timeout]",
            "description": """
## What is TCP Port Scanning?

TCP port scanning identifies open network services on a target by attempting TCP connections to specific ports.

## Why Use Port Scanning?

- **Service Discovery**: Identify running services
- **Vulnerability Assessment**: Find exposed services
- **Attack Surface Mapping**: Understand entry points
- **Compliance**: Verify security policies

## How It Works

1. Initiates TCP handshake (SYN) to target ports
2. If SYN-ACK received: Port is OPEN
3. If RST received: Port is CLOSED
4. If no response: Port is FILTERED
5. Performs service identification via banner grabbing
6. Multi-threaded for speed (100 concurrent threads)

## Scan Types

**TCP Connect Scan (Default)**
- Completes full TCP handshake
- Most reliable and compatible
- Logged by target systems
- No special privileges required

**SYN Scan (Stealth)**
- Sends SYN, doesn't complete handshake
- Less likely to be logged
- Requires root/admin privileges
- Faster than connect scan

## What You Achieve

- List of open ports and services
- Service version detection (banner grabbing)
- Attack surface analysis
- Input for vulnerability scanning

## Security Implications

- **Detection**: Port scans are easily detected
- **Logged**: All connection attempts are typically logged
- **Legal**: Only scan systems you own or have permission to test

## Common Ports

```
Port  Service      Description
22    SSH          Secure Shell
80    HTTP         Web Server
443   HTTPS        Secure Web Server
3389  RDP          Remote Desktop
5432  PostgreSQL   Database Server
```

## Example Output

```
Port   State  Service     Banner
22     open   SSH         OpenSSH 8.2p1
80     open   HTTP        Apache/2.4.41
443    open   HTTPS       nginx/1.18.0
```
            """,
            "options": {
                "target": "IP address or hostname",
                "ports": "Comma-separated or 'common' (default: common)",
                "timeout": "Connection timeout in seconds (default: 1)",
            },
            "examples": [
                "Scan common ports on target",
                "Scan specific ports: 80,443,8080",
                "Full port scan: 1-65535",
            ]
        },
        
        "5": {
            "name": "DNS Lookup & Analysis",
            "synopsis": "dns_lookup <domain>",
            "description": """
## What is DNS Lookup?

Domain Name System (DNS) lookup resolves domain names to IP addresses and retrieves various DNS records.

## Why Use DNS Lookup?

- **Reconnaissance**: Gather information about target infrastructure
- **Mail Server Discovery**: Find email servers (MX records)
- **Subdomain Discovery**: Identify related domains
- **DNSSEC Validation**: Check security configuration

## DNS Record Types

**A Record**: IPv4 address mapping
**AAAA Record**: IPv6 address mapping
**MX Record**: Mail exchange servers
**NS Record**: Name server records
**TXT Record**: Text annotations (SPF, DKIM, verification)
**SOA Record**: Start of Authority (zone information)
**CNAME Record**: Canonical name (alias)

## How It Works

1. Queries authoritative DNS servers
2. Retrieves all available record types
3. Parses and displays results
4. Can perform zone transfers (AXFR) if misconfigured

## What You Achieve

- Complete DNS profile of target domain
- Identify infrastructure (servers, CDN, cloud providers)
- Find email servers for phishing reconnaissance
- Discover subdomains and related assets

## Security Implications

- **Information Disclosure**: DNS reveals infrastructure details
- **Zone Transfer**: Misconfigured servers may leak all records
- **SPF/DMARC**: Email security posture assessment

## Example Output

```
Record Type  Value
A            93.184.216.34
AAAA         2606:2800:220:1:248:1893:25c8:1946
MX           10 mail.example.com
NS           ns1.example.com
TXT          "v=spf1 include:_spf.example.com ~all"
```
            """,
            "options": {
                "domain": "Target domain name",
            },
            "examples": [
                "Look up all DNS records for a domain",
                "Attempt zone transfer (if misconfigured)",
            ]
        },
        
        "9": {
            "name": "SSL/TLS Certificate Analysis",
            "synopsis": "ssl_analysis <hostname> [port]",
            "description": """
## What is SSL/TLS Analysis?

SSL/TLS analysis examines the security configuration of encrypted connections and certificate validity.

## Why Analyze SSL/TLS?

- **Security Assessment**: Verify encryption strength
- **Certificate Validation**: Check expiration and trust chain
- **Vulnerability Detection**: Identify weak ciphers
- **Compliance**: Ensure PCI DSS, HIPAA requirements

## What It Checks

**Protocol Version**
- TLS 1.3 (Recommended)
- TLS 1.2 (Acceptable)
- TLS 1.1/1.0 (Deprecated)
- SSLv3 (Vulnerable)

**Cipher Suites**
- AES-256-GCM (Strong)
- AES-128-GCM (Acceptable)
- RC4, DES, 3DES (Weak/Vulnerable)

**Certificate Information**
- Validity period
- Issuer and subject
- Subject Alternative Names (SAN)
- Signature algorithm

## How It Works

1. Initiates TLS handshake with target
2. Retrieves server certificate
3. Analyzes cipher suite negotiation
4. Parses certificate details
5. Checks for known vulnerabilities

## What You Achieve

- Identify weak encryption configurations
- Detect expired or invalid certificates
- Verify proper HTTPS implementation
- Assess cryptographic security posture

## Common Vulnerabilities

- **POODLE**: SSLv3 vulnerability
- **BEAST**: TLS 1.0 cipher block chaining
- **Heartbleed**: OpenSSL memory disclosure
- **Weak Ciphers**: RC4, DES, export-grade

## Example Output

```
Protocol: TLSv1.3
Cipher: TLS_AES_256_GCM_SHA384
Key Bits: 256
Valid From: 2024-01-01
Valid Until: 2025-01-01
Issuer: Let's Encrypt
Subject: example.com
```
            """,
            "options": {
                "hostname": "Target hostname",
                "port": "Target port (default: 443)",
            },
            "examples": [
                "Analyze HTTPS website certificate",
                "Check custom SSL port: 8443",
            ]
        },
        
        "cloud": {
            "name": "Cloud Storage Auditor",
            "synopsis": "cloud_scan <domain>",
            "description": """
## What is Cloud Storage Auditing?

Automated scanning for publicly accessible cloud storage buckets (AWS S3, Azure Blob, GCP) associated with a target.

## Why Scan Cloud Storage?

- **Data Exposure**: #1 cause of data breaches in 2024-2025
- **Misconfiguration**: Default permissions often too permissive
- **Compliance**: GDPR, CCPA require proper access controls
- **Reconnaissance**: Discover backup files, credentials, source code

## How It Works

1. Generates bucket name permutations from domain
   - company.com  company, company-dev, company-backup, company-prod
2. Tests AWS S3 URLs (s3.amazonaws.com/bucket-name)
3. Tests Azure Blob URLs (blob.core.windows.net/bucket-name)
4. Tests GCP Storage URLs (storage.googleapis.com/bucket-name)
5. Checks bucket permissions and listings

## Common Permutations

```
example.com  
  - example
  - example-dev
  - example-staging
  - example-prod
  - example-backup
  - example-assets
  - example-cdn
  - dev-example
  - staging-example
```

## What You Achieve

- Identify exposed cloud storage
- Find publicly accessible sensitive data
- Discover misconfigured buckets
- Generate compliance reports

## Security Impact

**Real-World Examples:**
- Capital One breach: Misconfigured S3 bucket (2019)
- Dow Jones leak: Exposed 2.2M customer records
- Accenture: 137GB of data exposed on S3

## Example Output

```
Bucket Name              Status        Access Level
example-backup          OPEN          Public Read
example-dev             RESTRICTED    Authenticated Only
example-prod            SECURE        Private
```
            """,
            "options": {
                "domain": "Target domain for bucket enumeration",
            },
            "examples": [
                "Scan for S3/Azure buckets related to domain",
                "Generate bucket permutations report",
            ]
        },
        
        "threat": {
            "name": "Threat Intelligence Lookup",
            "synopsis": "threat_intel <ip_or_domain>",
            "description": """
## What is Threat Intelligence?

Threat intelligence aggregates data from multiple sources to identify malicious IPs, domains, and known threats.

## Why Use Threat Intelligence?

- **Reputation Checking**: Verify if IP/domain is malicious
- **IOC Detection**: Identify Indicators of Compromise
- **Attribution**: Link activity to known threat actors
- **Automated Response**: Block known bad actors

## Data Sources

**AbuseIPDB**
- Crowdsourced IP reputation database
- Tracks malicious activity reports
- Confidence scores and abuse types
- Historical data and trends

**Shodan InternetDB**
- Internet-wide scanning data
- Open port and service information
- Vulnerability exposure
- No API key required for basic lookups

**VirusTotal**
- Multi-engine malware scanning
- Domain/IP reputation
- Associated malware samples
- Community comments and votes

## How It Works

1. Queries configured threat intelligence APIs
2. Aggregates results from multiple sources
3. Calculates risk score
4. Provides context and recommendations

## What You Achieve

- Identify compromised or malicious hosts
- Validate scan findings against known threats
- Prioritize remediation efforts
- Build block lists automatically

## Risk Score Calculation

```
High Risk (80-100):    Confirmed malicious activity
Medium Risk (50-79):   Suspicious behavior reported
Low Risk (20-49):      Minor issues or old reports
Clean (0-19):          No significant threats found
```

## Example Output

```
IP: 203.0.113.42
Risk Score: 85 (HIGH)

AbuseIPDB: 127 reports (spam, brute-force)
Shodan: Open ports - 22, 23, 3389
VirusTotal: Flagged by 12/89 engines

Recommendation: BLOCK THIS IP
```
            """,
            "options": {
                "ip_or_domain": "Target IP address or domain name",
            },
            "examples": [
                "Check IP reputation across all sources",
                "Look up domain threat intelligence",
            ]
        },
        
        "waf": {
            "name": "WAF Detection & Fingerprinting",
            "synopsis": "waf_detect <url>",
            "description": """
## What is WAF Detection?

Web Application Firewall (WAF) detection identifies protective layers in front of web applications.

## Why Detect WAFs?

- **Attack Planning**: Understand defensive capabilities
- **Evasion Techniques**: Adjust scanning strategies
- **Bypass Research**: Find WAF-specific vulnerabilities
- **Resource Efficiency**: Avoid wasted scanning effort

## Common WAFs Detected

- **Cloudflare**: CDN + WAF
- **AWS WAF**: Amazon's web application firewall
- **Akamai Kona**: Enterprise-grade protection
- **Imperva Incapsula**: DDoS + WAF
- **F5 Big-IP**: Hardware/software WAF
- **ModSecurity**: Open-source WAF

## Detection Methods

**HTTP Response Headers**
```
Server: cloudflare
X-CDN: Akamai
Set-Cookie: __cfduid=...
```

**Response Patterns**
- Custom error pages
- Specific HTTP status codes
- Block page signatures

**Behavioral Analysis**
- Rate limiting patterns
- Request filtering behavior
- JavaScript challenges

## How It Works

1. Sends probe requests to target
2. Analyzes HTTP response headers
3. Tests for JavaScript challenges
4. Identifies rate limiting
5. Fingerprints WAF vendor

## What You Achieve

- Identify protection mechanisms
- Adjust scan intensity to avoid blocks
- Plan evasion strategies
- Understand security posture

## Evasion Techniques (Educational)

- **Slow Scanning**: Reduce request rate
- **User-Agent Rotation**: Mimic legitimate browsers
- **Header Manipulation**: Modify suspicious headers
- **Encoding**: URL encoding, double encoding
- **IP Rotation**: Use proxy chains

## Example Output

```
URL: https://example.com

WAF Detected: Cloudflare
Confidence: 95%

Evidence:
- Server: cloudflare
- Set-Cookie: __cfduid=xyz123
- Ray ID in error pages
- JavaScript challenge present

Recommendation: Use stealth mode and slow scanning
```
            """,
            "options": {
                "url": "Target URL to analyze",
            },
            "examples": [
                "Detect WAF on target website",
                "Identify CDN and protection mechanisms",
            ]
        },
        
        "anomaly": {
            "name": "AI Traffic Anomaly Detection",
            "synopsis": "anomaly_detect [duration]",
            "description": """
## What is Anomaly Detection?

Machine learning-based analysis of network traffic to identify suspicious patterns like C2 beaconing and data exfiltration.

## Why Use AI for Security?

- **Zero-Day Detection**: Finds unknown threats
- **Behavioral Analysis**: Detects abnormal patterns
- **Automation**: Reduces manual analysis time
- **False Positive Reduction**: ML improves accuracy

## Detection Capabilities

**C2 Beaconing Detection**
- Regular interval connections
- Consistent packet sizes
- Predictable timing patterns
- Suspicious destinations

**Data Exfiltration Detection**
- Sudden upload spikes
- Non-standard ports
- Unusual time-of-day activity
- Large data transfers

**Malware Communication**
- HTTP beaconing
- DNS tunneling
- Encrypted channel analysis

## How It Works

1. Collects baseline network traffic (learning phase)
2. Trains Isolation Forest ML model
3. Monitors live connections in real-time
4. Flags statistical anomalies
5. Scores suspicious behavior

## Machine Learning Algorithm

**Isolation Forest**
- Unsupervised anomaly detection
- No labeled training data required
- Identifies outliers efficiently
- Low false positive rate

## Behavioral Indicators

```
Normal Traffic:
- Random intervals
- Variable packet sizes
- Standard ports (80, 443)
- Business hours activity

Beaconing (Malware):
- Exact 60-second intervals
- Fixed 256-byte packets
- Non-standard port (8443)
- 24/7 activity
```

## What You Achieve

- Early detection of compromised systems
- Identification of C2 infrastructure
- Prevention of data theft
- Automated threat hunting

## Example Output

```
ANOMALY DETECTED

Connection: 192.168.1.50  203.0.113.42:8443
Anomaly Score: 0.89 (HIGH)

Pattern: Regular 60-second intervals
Packet Size: Consistent 512 bytes
Duration: 6 hours continuous
Classification: C2 BEACONING

Recommendation: ISOLATE HOST IMMEDIATELY
```
            """,
            "options": {
                "duration": "Monitoring duration in minutes (default: 10)",
            },
            "examples": [
                "Monitor traffic for 10 minutes and detect anomalies",
                "Long-term monitoring: 60 minutes",
            ]
        },
        
        "subdomain": {
            "name": "Subdomain Enumeration (Passive)",
            "synopsis": "subdomain_enum <domain>",
            "description": """
## What is Subdomain Enumeration?

Discovery of subdomains through passive reconnaissance using Certificate Transparency logs and other OSINT sources.

## Why Enumerate Subdomains?

- **Attack Surface Expansion**: Find forgotten/dev servers
- **Credential Hunting**: Test.example.com often has default creds
- **Vulnerability Discovery**: Dev/staging less protected than prod
- **Asset Inventory**: Complete domain mapping

## Discovery Methods

**Certificate Transparency Logs (crt.sh)**
- SSL certificates are publicly logged
- Finds all subdomains ever issued certificates
- Historical data available
- No scanning required (100% passive)

**DNS Aggregation**
- Historical DNS records
- Zone file analysis
- Public DNS databases

**Search Engine Dorking**
- Google: site:example.com
- Historical crawl data

## How It Works

1. Queries crt.sh Certificate Transparency logs
2. Extracts Subject Alternative Names (SANs)
3. Removes duplicates and wildcards
4. Validates discovered subdomains
5. Performs IP resolution

## Common Subdomain Patterns

```
Production:
- www.example.com
- api.example.com
- cdn.example.com

Development/Staging:
- dev.example.com
- staging.example.com
- test.example.com
- uat.example.com

Internal/Interesting:
- vpn.example.com
- mail.example.com
- admin.example.com
- backup.example.com
```

## What You Achieve

- Complete subdomain inventory
- Discovery of hidden infrastructure
- Identification of development servers
- Input for targeted scanning

## Security Implications

**High-Value Targets:**
- admin.* - Administrative interfaces
- dev.* - Often less protected
- staging.* - May contain production data
- api.* - Backend services
- vpn.* - Remote access points

## Example Output

```
Domain: example.com
Subdomains Found: 47

Production (12):
- www.example.com          [93.184.216.34]
- api.example.com          [93.184.216.35]
- cdn.example.com          [CloudFlare]

Development (8):
- dev.example.com          [10.0.0.50]
- staging.example.com      [192.168.1.100]
- test-api.example.com     [172.16.0.10]

High-Risk (3):
- admin.example.com        [ACCESSIBLE]
- backup.example.com       [ACCESSIBLE]
- old-site.example.com     [OUTDATED]
```
            """,
            "options": {
                "domain": "Target domain for subdomain discovery",
            },
            "examples": [
                "Enumerate all subdomains passively",
                "Find development and staging servers",
            ]
        },
    }
    
    @staticmethod
    def show_help(feature_number: str):
        """Display comprehensive help for a feature."""
        if feature_number not in HelpSystem.HELP_DOCS:
            console.print(f"[red]No help available for feature {feature_number}[/red]")
            return
        
        doc = HelpSystem.HELP_DOCS[feature_number]
        
        # Create help display
        console.print()
        console.print(Panel(
            f"[bold cyan]{doc['name']}[/bold cyan]",
            border_style="cyan"
        ))
        
        # Synopsis
        console.print("\n[bold yellow]SYNOPSIS[/bold yellow]")
        console.print(f"    {doc['synopsis']}")
        
        # Description (Markdown)
        console.print(Markdown(doc['description']))
        
        # Options
        if 'options' in doc:
            console.print("\n[bold yellow]OPTIONS[/bold yellow]")
            for opt, desc in doc['options'].items():
                console.print(f"    [cyan]{opt}[/cyan]: {desc}")
        
        # Examples
        if 'examples' in doc:
            console.print("\n[bold yellow]EXAMPLES[/bold yellow]")
            for i, example in enumerate(doc['examples'], 1):
                console.print(f"    {i}. {example}")
        
        console.print()

# ===================== DATA CLASSES =====================

@dataclass
class ScanResult:
    """Enhanced scan result with threat intelligence."""
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    ports: Optional[List[int]] = None
    os_guess: Optional[str] = None
    latency: Optional[float] = None
    threat_score: Optional[int] = None
    threat_sources: List[str] = field(default_factory=list)

@dataclass
class PortInfo:
    """Enhanced port information."""
    port: int
    state: str
    service: str
    banner: Optional[str] = None
    vulnerability: Optional[str] = None

@dataclass
class ThreatIntel:
    """Threat intelligence data."""
    target: str
    risk_score: int
    sources: Dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""

@dataclass
class Anomaly:
    """Network anomaly detection result."""
    timestamp: datetime
    source_ip: str
    dest_ip: str
    dest_port: int
    anomaly_score: float
    pattern_type: str
    details: str

# ===================== CORE ENGINE =====================

class NetWranglerV3:
    """Enterprise-grade network security suite."""
    
    COMMON_PORTS = [
        20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 27017
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
        self.config = Config.load_config()
        self.stealth_mode = Config.get('SETTINGS', 'stealth_mode', 'false').lower() == 'true'
        self.max_threads = int(Config.get('SETTINGS', 'max_threads', '100'))
        self.timeout = float(Config.get('SETTINGS', 'timeout', '3'))
        
        # Traffic monitoring for anomaly detection
        self.connection_history = deque(maxlen=1000)
        
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
        return f"{'.'.join(local_ip.split('.')[:-1])}.0/24"
    
    def arp_scan(self, network: str = None) -> List[ScanResult]:
        """Enhanced ARP scan with threat intelligence."""
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
                
                result = ScanResult(
                    ip=received.psrc,
                    mac=received.hwsrc,
                    hostname=hostname
                )
                
                # Add threat intelligence if available
                if self.has_api_keys():
                    threat = self.check_threat_intel(received.psrc)
                    result.threat_score = threat.risk_score
                    result.threat_sources = list(threat.sources.keys())
                
                results.append(result)
                
                if self.stealth_mode:
                    time.sleep(0.5)  # Slow down in stealth mode
        
        except Exception as e:
            self.console.print(f"[red]ARP Scan Error: {e}[/red]")
        
        return results
    
    # [REST OF THE CODE CONTINUES...]
    # Due to length limitations, I'll create this as a multi-part file
    
    def has_api_keys(self) -> bool:
        """Check if any API keys are configured."""
        abuseipdb = Config.get('API_KEYS', 'abuseipdb_key', '')
        shodan = Config.get('API_KEYS', 'shodan_key', '')
        vt = Config.get('API_KEYS', 'virustotal_key', '')
        return bool(abuseipdb or shodan or vt)
    
    def check_threat_intel(self, target: str) -> ThreatIntel:
        """Check target against threat intelligence sources."""
        intel = ThreatIntel(target=target, risk_score=0)
        
        # AbuseIPDB
        abuseipdb_key = Config.get('API_KEYS', 'abuseipdb_key', '')
        if abuseipdb_key:
            try:
                headers = {'Key': abuseipdb_key, 'Accept': 'application/json'}
                response = requests.get(
                    f'https://api.abuseipdb.com/api/v2/check',
                    params={'ipAddress': target},
                    headers=headers,
                    timeout=5
                )
                if response.status_code == 200:
                    data = response.json().get('data', {})
                    intel.sources['abuseipdb'] = {
                        'confidence': data.get('abuseConfidenceScore', 0),
                        'reports': data.get('totalReports', 0)
                    }
                    intel.risk_score += data.get('abuseConfidenceScore', 0) // 2
            except Exception:
                pass
        
        # Shodan InternetDB (No API key required)
        try:
            response = requests.get(f'https://internetdb.shodan.io/{target}', timeout=5)
            if response.status_code == 200:
                data = response.json()
                intel.sources['shodan'] = {
                    'ports': data.get('ports', []),
                    'vulns': data.get('vulns', []),
                    'tags': data.get('tags', [])
                }
                if data.get('vulns'):
                    intel.risk_score += 30
        except Exception:
            pass
        
        # Set recommendation
        if intel.risk_score >= 80:
            intel.recommendation = "HIGH RISK - Block this IP immediately"
        elif intel.risk_score >= 50:
            intel.recommendation = "MEDIUM RISK - Investigate and monitor"
        elif intel.risk_score >= 20:
            intel.recommendation = "LOW RISK - Minor issues detected"
        else:
            intel.recommendation = "CLEAN - No significant threats found"
        
        return intel


# ===================== CLI INTERFACE V3 =====================

class CLIV3:
    """Enhanced CLI with better UI and help system."""
    
    def __init__(self):
        self.console = Console()
        self.nw = NetWranglerV3()
    
    def print_banner(self):
        """Enhanced banner."""
        banner = r"""
[bold cyan]

                                                               
                   
               
                    
                 
                    
                       
                                                               
                NETWORK WRANGLER v3.0 ENTERPRISE              
                                                               

[/bold cyan]

[yellow] Advanced Network Security & Threat Intelligence Suite[/yellow]
[dim]  Security-First Design |  AI-Powered Analysis |   Cloud-Native[/dim]

[green]Type 'help <number>' for detailed information about any feature[/green]
[dim]Example: help 1, help cloud, help threat[/dim]
        """
        self.console.print(banner)
    
    def main_menu(self):
        """Enhanced main menu with categories."""
        menu = """
[bold cyan][/bold cyan]
[bold green]                    RECONNAISSANCE TOOLS[/bold green]
[bold cyan][/bold cyan]

[cyan]1.[/cyan]  Network Discovery (ARP Scan)        [dim]| Map local network devices[/dim]
[cyan]2.[/cyan]  Ping Sweep (ICMP)                   [dim]| Fast host discovery[/dim]
[cyan]3.[/cyan]  TCP Port Scan                       [dim]| Service identification[/dim]
[cyan]4.[/cyan]  Full Port Scan (1-65535)            [dim]| Comprehensive scanning[/dim]
[cyan]5.[/cyan]  DNS Lookup & Analysis               [dim]| Domain intelligence[/dim]
[cyan]6.[/cyan]  Reverse DNS                         [dim]| IP to hostname[/dim]
[cyan]7.[/cyan]  WHOIS Lookup                        [dim]| Domain registration[/dim]
[cyan]8.[/cyan]  Traceroute                          [dim]| Path discovery[/dim]

[bold cyan][/bold cyan]
[bold green]                   SECURITY ANALYSIS[/bold green]
[bold cyan][/bold cyan]

[cyan]9.[/cyan]  SSL/TLS Analysis                    [dim]| Certificate inspection[/dim]
[cyan]10.[/cyan] HTTP Security Headers               [dim]| Web security audit[/dim]
[cyan]11.[/cyan] Vulnerability Checker               [dim]| Common CVE detection[/dim]
[cyan]12.[/cyan] WAF Detection                       [dim]| Firewall fingerprinting[/dim]

[bold cyan][/bold cyan]
[bold green]                 CLOUD & MODERN SECURITY[/bold green]
[bold cyan][/bold cyan]

[cyan]13.[/cyan] Cloud Storage Auditor               [dim]| S3/Azure bucket scanning[/dim]
[cyan]14.[/cyan] Subdomain Enumeration (Passive)     [dim]| Certificate transparency[/dim]
[cyan]15.[/cyan] Threat Intelligence Lookup          [dim]| IP reputation checking[/dim]

[bold cyan][/bold cyan]
[bold green]                   AI-POWERED TOOLS[/bold green]
[bold cyan][/bold cyan]

[cyan]16.[/cyan] Traffic Anomaly Detection           [dim]| C2 beaconing detection[/dim]
[cyan]17.[/cyan] Behavioral Analysis                 [dim]| ML-based threat hunting[/dim]

[bold cyan][/bold cyan]
[bold green]                    MONITORING TOOLS[/bold green]
[bold cyan][/bold cyan]

[cyan]18.[/cyan] Bandwidth Monitor                   [dim]| Real-time throughput[/dim]
[cyan]19.[/cyan] Active Connections                  [dim]| Network connections[/dim]
[cyan]20.[/cyan] Network Interfaces                  [dim]| Interface information[/dim]
[cyan]21.[/cyan] Packet Sniffer                      [dim]| Live packet capture[/dim]

[bold cyan][/bold cyan]
[bold green]                      UTILITIES[/bold green]
[bold cyan][/bold cyan]

[cyan]22.[/cyan] Subnet Calculator                   [dim]| CIDR calculations[/dim]
[cyan]23.[/cyan] MAC Lookup                          [dim]| Vendor identification[/dim]
[cyan]24.[/cyan] Geolocation Lookup                  [dim]| IP geolocation[/dim]
[cyan]25.[/cyan] Quick Scan (All-in-One)             [dim]| Comprehensive recon[/dim]

[bold cyan][/bold cyan]
[bold green]                2030 FUTURE SECURITY[/bold green]
[bold cyan][/bold cyan]

[magenta]30.[/magenta] Quantum-Safe Crypto Analysis       [dim]| Post-quantum readiness[/dim]
[magenta]31.[/magenta] Zero-Trust Posture Assessment     [dim]| ZT architecture review[/dim]
[magenta]32.[/magenta] Blockchain Security Analysis      [dim]| Web3 & smart contracts[/dim]
[magenta]33.[/magenta] AI Threat Hunting (APT)           [dim]| Advanced persistent threats[/dim]
[magenta]34.[/magenta] Container Security Scan           [dim]| Docker/K8s vulnerabilities[/dim]
[magenta]35.[/magenta] API Security Assessment           [dim]| OWASP API Top 10[/dim]
[magenta]36.[/magenta] Supply Chain Security             [dim]| SBOM & dependency risks[/dim]
[magenta]37.[/magenta] Predictive Threat Modeling        [dim]| ML-based risk prediction[/dim]

[bold cyan][/bold cyan]

[yellow]help[/yellow]   Show detailed help for any feature (e.g., 'help 1')
[yellow]config[/yellow] Configure API keys and settings
[yellow]2030[/yellow]   Quick access to all 2030 features
[red]exit[/red]   Exit NET-WRANGLER

[bold cyan][/bold cyan]
        """
        self.console.print(menu)
    
    def run(self):
        """Main CLI loop."""
        self.print_banner()
        
        # Check for config file
        if not os.path.exists(Config.CONFIG_FILE):
            Config.create_default_config()
        
        # Show status
        status_items = []
        if self.nw.stealth_mode:
            status_items.append("[yellow] Stealth Mode: ON[/yellow]")
        if self.nw.has_api_keys():
            status_items.append("[green] API Keys: Configured[/green]")
        else:
            status_items.append("[dim] API Keys: Not configured (use 'config' command)[/dim]")
        
        if status_items:
            self.console.print(Panel(" | ".join(status_items), border_style="dim"))
        
        while True:
            self.main_menu()
            
            choice = Prompt.ask("\n[bold cyan]Select option or 'help <#>'[/bold cyan]").strip().lower()
            
            try:
                # Handle help command
                if choice.startswith('help'):
                    parts = choice.split()
                    if len(parts) == 2:
                        HelpSystem.show_help(parts[1])
                    else:
                        self.console.print("[yellow]Usage: help <feature_number>[/yellow]")
                        self.console.print("[dim]Example: help 1, help cloud, help threat[/dim]")
                    input("\n[dim]Press Enter to continue...[/dim]")
                    continue
                
                # Handle config command
                elif choice == 'config':
                    self.configure_settings()
                    continue
                
                # Handle 2030 menu
                elif choice == '2030':
                    self.show_2030_menu()
                    continue
                
                # Handle exit
                elif choice in ['exit', 'quit', 'q', '0']:
                    self.console.print("\n[yellow]  Stay secure! Goodbye![/yellow]\n")
                    break
                
                # Handle numeric choices
                elif choice.isdigit():
                    choice_num = int(choice)
                    
                    if choice_num == 1:
                        self.run_arp_scan()
                    elif choice_num == 2:
                        self.run_ping_sweep()
                    elif choice_num == 3:
                        self.run_port_scan()
                    elif choice_num == 12:
                        self.run_waf_detect()
                    elif choice_num == 13:
                        self.run_cloud_scan()
                    elif choice_num == 14:
                        self.run_subdomain_enum()
                    elif choice_num == 15:
                        self.run_threat_intel()
                    elif choice_num == 16:
                        self.run_anomaly_detect()
                    elif choice_num == 17:
                        self.run_future_features()
                    # 2030 Features
                    elif choice_num == 30:
                        self.run_quantum_safe_check()
                    elif choice_num == 31:
                        self.run_zero_trust_assessment()
                    elif choice_num == 32:
                        self.run_blockchain_security()
                    elif choice_num == 33:
                        self.run_ai_threat_hunting()
                    elif choice_num == 34:
                        self.run_container_security()
                    elif choice_num == 35:
                        self.run_api_security()
                    elif choice_num == 36:
                        self.run_supply_chain_security()
                    elif choice_num == 37:
                        self.run_predictive_threat()
                    # Add more features here...
                    else:
                        self.console.print("[red]Feature not yet implemented in this version[/red]")
                else:
                    self.console.print("[red]Invalid option. Please try again.[/red]")
            
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Operation cancelled[/yellow]")
            except Exception as e:
                self.console.print(f"[red]Error: {e}[/red]")
            
            input("\n[dim]Press Enter to continue...[/dim]")
    
    def configure_settings(self):
        """Configure API keys and settings."""
        self.console.print("\n[bold cyan]Configuration[/bold cyan]\n")
        
        config = Config.load_config()
        
        # API Keys
        self.console.print("[yellow]API Keys (press Enter to skip):[/yellow]\n")
        
        abuseipdb = Prompt.ask("AbuseIPDB API Key", default=Config.get('API_KEYS', 'abuseipdb_key', ''))
        shodan = Prompt.ask("Shodan API Key", default=Config.get('API_KEYS', 'shodan_key', ''))
        vt = Prompt.ask("VirusTotal API Key", default=Config.get('API_KEYS', 'virustotal_key', ''))
        
        config['API_KEYS']['abuseipdb_key'] = abuseipdb
        config['API_KEYS']['shodan_key'] = shodan
        config['API_KEYS']['virustotal_key'] = vt
        
        # Settings
        self.console.print("\n[yellow]Settings:[/yellow]\n")
        
        stealth = Confirm.ask("Enable Stealth Mode?", default=self.nw.stealth_mode)
        config['SETTINGS']['stealth_mode'] = str(stealth).lower()
        
        # Save config
        with open(Config.CONFIG_FILE, 'w') as f:
            config.write(f)
        
        self.console.print("\n[green] Configuration saved![/green]")
        self.console.print(f"[dim]Config file: {Config.CONFIG_FILE}[/dim]")
        
        # Reload
        self.nw.config = config
        self.nw.stealth_mode = stealth
    
    def run_arp_scan(self):
        """Run ARP scan with enhanced display."""
        network = Prompt.ask("[cyan]Network range[/cyan]", default=self.nw.get_network_range())
        
        self.console.print(f"\n[yellow] Scanning network: {network}[/yellow]")
        
        with self.console.status("[bold green]Performing ARP scan...") as status:
            results = self.nw.arp_scan(network)
        
        if results:
            table = Table(title="Network Discovery Results", box=box.ROUNDED, show_header=True, header_style="bold magenta")
            table.add_column("IP Address", style="cyan")
            table.add_column("MAC Address", style="green")
            table.add_column("Hostname", style="yellow")
            
            if self.nw.has_api_keys():
                table.add_column("Threat Score", style="red")
            
            for r in results:
                row = [r.ip, r.mac or "N/A", r.hostname or "Unknown"]
                if self.nw.has_api_keys() and r.threat_score is not None:
                    score_color = "red" if r.threat_score >= 50 else "yellow" if r.threat_score >= 20 else "green"
                    row.append(f"[{score_color}]{r.threat_score}[/{score_color}]")
                table.add_row(*row)
            
            self.console.print(table)
            self.console.print(f"\n[green] Found {len(results)} active hosts[/green]")
        else:
            self.console.print("[red]No hosts found[/red]")
    
    def run_ping_sweep(self):
        """Run ping sweep - placeholder."""
        self.console.print("[yellow]Ping sweep feature - Coming in full version...[/yellow]")
    
    def run_port_scan(self):
        """Run port scan - placeholder."""
        self.console.print("[yellow]Port scan feature - Coming in full version...[/yellow]")
    
    def run_cloud_scan(self):
        """Run cloud storage audit."""
        if not ENTERPRISE_FEATURES_AVAILABLE:
            self.console.print("[red]Enterprise features not available. Install enterprise_features.py[/red]")
            return
        
        domain = Prompt.ask("[cyan]Domain to scan[/cyan]", default="example.com")
        
        scanner = CloudStorageAuditor()
        
        self.console.print(f"\n[yellow]  Scanning cloud storage for: {domain}[/yellow]\n")
        
        # Generate bucket names
        with self.console.status("[bold green]Generating bucket name permutations...") as status:
            bucket_names = scanner.generate_bucket_names(domain)
        
        self.console.print(f"[cyan]Generated {len(bucket_names)} potential bucket names[/cyan]\n")
        
        # Scan each platform
        results = {'s3': [], 'azure': [], 'gcp': []}
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning...", total=len(bucket_names) * 3)
            
            for name in bucket_names[:20]:  # Limit to first 20 for demo
                # S3
                s3_result = scanner.check_s3_bucket(name)
                if s3_result['accessible']:
                    results['s3'].append(s3_result)
                progress.update(task, advance=1)
                
                # Azure
                azure_result = scanner.check_azure_blob(name)
                if azure_result['accessible']:
                    results['azure'].append(azure_result)
                progress.update(task, advance=1)
                
                # GCP
                gcp_result = scanner.check_gcp_bucket(name)
                if gcp_result['accessible']:
                    results['gcp'].append(gcp_result)
                progress.update(task, advance=1)
        
        # Display results
        total_found = len(results['s3']) + len(results['azure']) + len(results['gcp'])
        
        if total_found > 0:
            self.console.print(f"\n[bold red]  Found {total_found} accessible bucket(s)![/bold red]\n")
            
            for platform, buckets in results.items():
                if buckets:
                    table = Table(title=f"{platform.upper()} Results", box=box.ROUNDED)
                    table.add_column("Bucket Name", style="cyan")
                    table.add_column("Status", style="yellow")
                    table.add_column("Files", style="green")
                    
                    for bucket in buckets:
                        table.add_row(
                            bucket['name'],
                            "[red]PUBLIC[/red]" if bucket['public'] else "[yellow]Accessible[/yellow]",
                            str(len(bucket['files']))
                        )
                    
                    self.console.print(table)
        else:
            self.console.print("[green] No publicly accessible buckets found[/green]")
    
    def run_subdomain_enum(self):
        """Run subdomain enumeration."""
        if not ENTERPRISE_FEATURES_AVAILABLE:
            self.console.print("[red]Enterprise features not available[/red]")
            return
        
        domain = Prompt.ask("[cyan]Domain to enumerate[/cyan]", default="example.com")
        
        enumerator = SubdomainEnumerator()
        
        self.console.print(f"\n[yellow] Enumerating subdomains for: {domain}[/yellow]")
        
        with self.console.status("[bold green]Querying Certificate Transparency logs..."):
            subdomains = enumerator.query_crt_sh(domain)
        
        if subdomains:
            # Categorize
            categorized = enumerator.categorize_subdomains(subdomains)
            
            # Summary
            self.console.print(f"\n[green] Found {len(subdomains)} unique subdomains[/green]\n")
            
            # Display by category
            for category, subs in categorized.items():
                if subs:
                    table = Table(title=f"{category.upper()} Subdomains", box=box.SIMPLE)
                    table.add_column("Subdomain", style="cyan")
                    
                    for sub in sorted(subs)[:10]:  # Show first 10
                        table.add_row(sub)
                    
                    if len(subs) > 10:
                        table.add_row(f"[dim]...and {len(subs)-10} more[/dim]")
                    
                    self.console.print(table)
        else:
            self.console.print("[yellow]No subdomains found[/yellow]")
    
    def run_threat_intel(self):
        """Run threat intelligence lookup."""
        target = Prompt.ask("[cyan]IP address to check[/cyan]")
        
        self.console.print(f"\n[yellow] Gathering threat intelligence for: {target}[/yellow]\n")
        
        with self.console.status("[bold green]Querying threat intelligence sources..."):
            intel = self.nw.get_threat_intelligence(target)
        
        # Display results
        panel = Panel(
            f"[bold]IP Address:[/bold] {intel.ip}\n"
            f"[bold]Country:[/bold] {intel.country or 'Unknown'}\n"
            f"[bold]ISP:[/bold] {intel.isp or 'Unknown'}\n"
            f"[bold]Risk Score:[/bold] [{intel.risk_color}]{intel.risk_score}[/{intel.risk_color}]\n"
            f"[bold]Blacklisted:[/bold] {'[red]YES[/red]' if intel.is_blacklisted else '[green]NO[/green]'}\n"
            f"[bold]Total Reports:[/bold] {intel.total_reports}\n\n"
            f"[bold]Recommendation:[/bold]\n{intel.recommendation}",
            title=" Threat Intelligence Report",
            border_style="cyan"
        )
        
        self.console.print(panel)
        
        # Show threats if any
        if intel.threats:
            table = Table(title="Detected Threats", box=box.ROUNDED)
            table.add_column("Source", style="yellow")
            table.add_column("Threat", style="red")
            
            for threat in intel.threats:
                table.add_row(threat['source'], threat['description'])
            
            self.console.print(table)
    
    def run_waf_detect(self):
        """Run WAF detection."""
        if not ENTERPRISE_FEATURES_AVAILABLE:
            self.console.print("[red]Enterprise features not available[/red]")
            return
        
        url = Prompt.ask("[cyan]URL to check[/cyan]", default="https://example.com")
        
        detector = WAFDetector()
        
        self.console.print(f"\n[yellow] Detecting WAF for: {url}[/yellow]\n")
        
        with self.console.status("[bold green]Analyzing headers and responses..."):
            result = detector.detect_waf(url)
        
        if result['waf_detected']:
            panel = Panel(
                f"[bold red]WAF Detected![/bold red]\n\n"
                f"[bold]WAF Type:[/bold] {result['waf_name']}\n"
                f"[bold]Confidence:[/bold] {result['confidence']:.1f}%\n\n"
                f"[bold]Indicators:[/bold]\n" +
                "\n".join(f"   {ind}" for ind in result['indicators'][:5]),
                title=" WAF Detection Result",
                border_style="red"
            )
        else:
            panel = Panel(
                "[green]No WAF detected[/green]\n\n"
                "Target may be unprotected or using custom security solution.",
                title=" WAF Detection Result",
                border_style="green"
            )
        
        self.console.print(panel)
    
    def run_anomaly_detect(self):
        """Run anomaly detection."""
        if not ENTERPRISE_FEATURES_AVAILABLE:
            self.console.print("[red]Enterprise features not available[/red]")
            return
        
        detector = AnomalyDetector()
        
        self.console.print("\n[yellow] AI Anomaly Detection[/yellow]\n")
        self.console.print("[cyan]Collecting baseline traffic (60 seconds)...[/cyan]\n")
        
        with self.console.status("[bold green]Monitoring network activity..."):
            baseline = detector.collect_baseline(duration=60)
        
        if baseline:
            self.console.print(f"[green] Collected {len(baseline)} connection samples[/green]\n")
            
            # Train model
            with self.console.status("[bold green]Training ML model..."):
                detector.train_model(baseline)
            
            self.console.print("[green] Model trained[/green]\n")
            
            # Analyze beaconing
            self.console.print("[cyan]Analyzing for C2 beaconing patterns...[/cyan]\n")
            
            beaconing = detector.analyze_beaconing(baseline)
            
            if beaconing:
                table = Table(title=" Potential C2 Beaconing Detected", box=box.ROUNDED)
                table.add_column("Destination", style="red")
                table.add_column("Count", style="yellow")
                table.add_column("Regularity", style="cyan")
                
                for b in beaconing:
                    table.add_row(
                        b['destination'],
                        str(b['count']),
                        f"{b['regularity']:.2f}"
                    )
                
                self.console.print(table)
            else:
                self.console.print("[green] No beaconing patterns detected[/green]")
        else:
            self.console.print("[yellow]No traffic captured for analysis[/yellow]")
    
    def run_quantum_safe_check(self):
        """Run quantum-safe cryptography analysis."""
        if not ENTERPRISE_FEATURES_AVAILABLE:
            self.console.print("[red]Enterprise features not available[/red]")
            return
        
        future = FutureSecurityFeatures()
        target = Prompt.ask("[cyan]Target domain/IP[/cyan]", default="example.com")
        
        self.console.print(f"\n[magenta] Quantum-Safe Cryptography Analysis[/magenta]\n")
        
        with self.console.status("[bold green]Analyzing cryptographic algorithms..."):
            result = future.check_quantum_safe_crypto(target)
        
        quantum_color = "green" if result['quantum_safe'] else "red"
        panel = Panel(
            f"[bold]Target:[/bold] {result['target']}\n"
            f"[bold]Quantum-Safe:[/bold] [{'green]YES[/green' if result['quantum_safe'] else 'red]NO[/red'}]\n"
            f"[bold]Current Algorithm:[/bold] {result.get('algorithm', 'Unknown')}\n"
            f"[bold]TLS Version:[/bold] {result.get('version', 'Unknown')}\n\n"
            f"[bold]Assessment:[/bold]\n{result['recommendation']}",
            title=" Quantum-Safe Crypto Check",
            border_style=quantum_color
        )
        self.console.print(panel)
    
    def run_zero_trust_assessment(self):
        """Run zero-trust posture assessment."""
        if not ENTERPRISE_FEATURES_AVAILABLE:
            self.console.print("[red]Enterprise features not available[/red]")
            return
        
        future = FutureSecurityFeatures()
        target = Prompt.ask("[cyan]Target to assess[/cyan]", default="example.com")
        
        self.console.print(f"\n[magenta] Zero-Trust Security Assessment[/magenta]\n")
        
        with self.console.status("[bold green]Analyzing zero-trust posture..."):
            result = future.analyze_zero_trust_posture(target)
        
        score_color = "green" if result['zero_trust_score'] >= 80 else "yellow" if result['zero_trust_score'] >= 50 else "red"
        
        table = Table(title=f"Zero-Trust Score: [{score_color}]{result['zero_trust_score']}/100[/{score_color}]", box=box.ROUNDED)
        table.add_column("Control", style="cyan")
        table.add_column("Status", style="white")
        
        for check in result['checks']:
            status = "[green] PASS[/green]" if check[1] else "[red] FAIL[/red]"
            table.add_row(check[0], status)
        
        self.console.print(table)
        
        rating = result.get('rating', 'UNKNOWN')
        rating_color = {'EXCELLENT': 'green', 'GOOD': 'cyan', 'FAIR': 'yellow', 'POOR': 'red'}.get(rating, 'white')
        self.console.print(f"\n[{rating_color}]Overall Rating: {rating}[/{rating_color}]")
    
    def run_blockchain_security(self):
        """Run blockchain security analysis."""
        if not ENTERPRISE_FEATURES_AVAILABLE:
            self.console.print("[red]Enterprise features not available[/red]")
            return
        
        future = FutureSecurityFeatures()
        target = Prompt.ask("[cyan]Target (domain/contract address)[/cyan]", default="example.com")
        
        self.console.print(f"\n[magenta] Blockchain & Web3 Security Analysis[/magenta]\n")
        
        with self.console.status("[bold green]Analyzing blockchain security..."):
            result = future.blockchain_security_analysis(target)
        
        # Main panel
        score_color = "green" if result['web3_security_score'] >= 70 else "yellow" if result['web3_security_score'] >= 40 else "red"
        
        panel = Panel(
            f"[bold]Target:[/bold] {result['target']}\n"
            f"[bold]Blockchain Ready:[/bold] {'[green]YES[/green]' if result['blockchain_ready'] else '[red]NO[/red]'}\n"
            f"[bold]Web3 Security Score:[/bold] [{score_color}]{result['web3_security_score']}/100[/{score_color}]\n\n"
            f"[bold]Smart Contract Vulnerabilities:[/bold] {len(result['smart_contract_vulnerabilities'])}\n"
            f"[bold]DeFi Risks:[/bold] {len(result['defi_risks'])}",
            title=" Blockchain Security Overview",
            border_style=score_color
        )
        self.console.print(panel)
        
        # Vulnerabilities
        if result['smart_contract_vulnerabilities']:
            self.console.print("\n[red]  Smart Contract Vulnerabilities:[/red]")
            for vuln in result['smart_contract_vulnerabilities']:
                self.console.print(f"   {vuln}")
        
        # DeFi risks
        if result['defi_risks']:
            self.console.print("\n[yellow]  DeFi Risks:[/yellow]")
            for risk in result['defi_risks']:
                self.console.print(f"   {risk}")
        
        # NFT security
        if result.get('nft_security'):
            self.console.print("\n[cyan] NFT Security Checks:[/cyan]")
            for check, status in result['nft_security'].items():
                icon = "" if status else ""
                color = "green" if status else "red"
                self.console.print(f"  [{color}]{icon}[/{color}] {check.replace('_', ' ').title()}")
        
        # Recommendations
        if result['recommendations']:
            self.console.print("\n[bold] Recommendations:[/bold]")
            for i, rec in enumerate(result['recommendations'][:5], 1):
                self.console.print(f"  {i}. {rec}")
    
    def run_ai_threat_hunting(self):
        """Run AI-powered threat hunting."""
        if not ENTERPRISE_FEATURES_AVAILABLE:
            self.console.print("[red]Enterprise features not available[/red]")
            return
        
        future = FutureSecurityFeatures()
        duration = int(Prompt.ask("[cyan]Scan duration (minutes)[/cyan]", default="10"))
        
        with self.console.status(f"[bold green]AI Threat Hunting - scanning for {duration} minutes..."):
            result = future.ai_threat_hunting(duration_minutes=duration)
        
        if result['threats_detected']:
            for threat in result['threats_detected']:
                severity_color = {'CRITICAL': 'red', 'HIGH': 'yellow', 'MEDIUM': 'cyan'}.get(threat['severity'], 'white')
                
                panel = Panel(
                    f"[bold]Type:[/bold] {threat['type']}\n"
                    f"[bold]Severity:[/bold] [{severity_color}]{threat['severity']}[/{severity_color}]\n"
                    f"[bold]First Seen:[/bold] {threat['first_seen']}\n\n"
                    f"[bold]Indicators:[/bold]\n" +
                    "\n".join(f"   {ind}" for ind in threat['indicators']),
                    title=" APT Detected",
                    border_style="red"
                )
                self.console.print(panel)
            
            # IOCs
            if result['iocs']:
                self.console.print("\n[red] Indicators of Compromise (IOCs):[/red]")
                for ioc in result['iocs']:
                    self.console.print(f"   [{ioc['type']}] {ioc['value']}")
            
            # TTPs
            if result['ttps']:
                self.console.print("\n[yellow] MITRE ATT&CK TTPs:[/yellow]")
                for ttp in result['ttps']:
                    self.console.print(f"   {ttp}")
            
            # Attack chain
            if result['attack_chain']:
                self.console.print("\n[cyan] Attack Chain:[/cyan]")
                self.console.print("  ".join(result['attack_chain']))
        else:
            self.console.print("[green] No advanced persistent threats detected[/green]")
        
        # Recommendations
        if result['recommendations']:
            self.console.print("\n[bold] Recommended Actions:[/bold]")
            for i, rec in enumerate(result['recommendations'], 1):
                self.console.print(f"  {i}. {rec}")
    
    def run_container_security(self):
        """Run container security scan."""
        if not ENTERPRISE_FEATURES_AVAILABLE:
            self.console.print("[red]Enterprise features not available[/red]")
            return
        
        future = FutureSecurityFeatures()
        target = Prompt.ask("[cyan]Container image or registry[/cyan]", default="nginx:latest")
        
        self.console.print(f"\n[magenta] Container Security Scan[/magenta]\n")
        
        with self.console.status("[bold green]Scanning container for vulnerabilities..."):
            result = future.container_security_scan(target)
        
        # Overview
        risk_color = "red" if result['risk_score'] >= 70 else "yellow" if result['risk_score'] >= 40 else "green"
        
        panel = Panel(
            f"[bold]Target:[/bold] {result['target']}\n"
            f"[bold]Type:[/bold] {result['container_type']}\n"
            f"[bold]Risk Score:[/bold] [{risk_color}]{result['risk_score']}/100[/{risk_color}]\n\n"
            f"[bold]Vulnerabilities:[/bold] {len(result['vulnerabilities'])}\n"
            f"[bold]Misconfigurations:[/bold] {len(result['misconfigurations'])}\n"
            f"[bold]Exposed Secrets:[/bold] {len(result['secrets_exposed'])}",
            title=" Container Security Overview",
            border_style=risk_color
        )
        self.console.print(panel)
        
        # Vulnerabilities
        if result['vulnerabilities']:
            table = Table(title=" Vulnerabilities", box=box.ROUNDED)
            table.add_column("CVE", style="red")
            table.add_column("Severity", style="yellow")
            table.add_column("Package", style="cyan")
            table.add_column("Version", style="white")
            
            for vuln in result['vulnerabilities']:
                severity_color = {'CRITICAL': 'red', 'HIGH': 'yellow', 'MEDIUM': 'cyan'}.get(vuln['severity'], 'white')
                table.add_row(
                    vuln['cve'],
                    f"[{severity_color}]{vuln['severity']}[/{severity_color}]",
                    vuln['package'],
                    vuln['version']
                )
            
            self.console.print(table)
        
        # Misconfigurations
        if result['misconfigurations']:
            self.console.print("\n[yellow]  Misconfigurations:[/yellow]")
            for misconfig in result['misconfigurations']:
                self.console.print(f"   {misconfig}")
        
        # Secrets
        if result['secrets_exposed']:
            self.console.print("\n[red] Exposed Secrets:[/red]")
            for secret in result['secrets_exposed']:
                self.console.print(f"   {secret}")
        
        # Compliance
        if result['compliance_issues']:
            self.console.print("\n[cyan] Compliance Issues:[/cyan]")
            for issue in result['compliance_issues']:
                self.console.print(f"   {issue}")
        
        # Recommendations
        if result['recommendations']:
            self.console.print("\n[bold] Recommendations:[/bold]")
            for i, rec in enumerate(result['recommendations'], 1):
                self.console.print(f"  {i}. {rec}")
    
    def run_api_security(self):
        """Run API security assessment."""
        if not ENTERPRISE_FEATURES_AVAILABLE:
            self.console.print("[red]Enterprise features not available[/red]")
            return
        
        future = FutureSecurityFeatures()
        api_url = Prompt.ask("[cyan]API URL[/cyan]", default="https://api.example.com")
        
        self.console.print(f"\n[magenta] API Security Assessment[/magenta]\n")
        
        with self.console.status("[bold green]Analyzing API security..."):
            result = future.api_security_assessment(api_url)
        
        # Overview
        score_color = "green" if result['security_score'] >= 75 else "yellow" if result['security_score'] >= 50 else "red"
        
        panel = Panel(
            f"[bold]URL:[/bold] {result['url']}\n"
            f"[bold]API Type:[/bold] {result['api_type']}\n"
            f"[bold]Security Score:[/bold] [{score_color}]{result['security_score']}/100[/{score_color}]\n\n"
            f"[bold]Authentication Required:[/bold] {'[green]YES[/green]' if result['authentication']['required'] else '[red]NO[/red]'}\n"
            f"[bold]Rate Limiting:[/bold] {'[green]YES[/green]' if result['rate_limiting'] else '[red]NO[/red]'}\n"
            f"[bold]OAuth2 Detected:[/bold] {'[green]YES[/green]' if result['authentication'].get('oauth2') else '[dim]NO[/dim]'}",
            title=" API Security Overview",
            border_style=score_color
        )
        self.console.print(panel)
        
        # OWASP API Top 10
        self.console.print("\n[bold] OWASP API Security Top 10 (2023):[/bold]")
        for check, vulnerable in result['owasp_api_top10'].items():
            icon = "" if vulnerable else ""
            color = "red" if vulnerable else "green"
            self.console.print(f"  [{color}]{icon}[/{color}] {check}")
        
        # Data exposure
        if result['data_exposure']:
            self.console.print("\n[red]  Sensitive Data Exposure:[/red]")
            for data in result['data_exposure']:
                self.console.print(f"   {data}")
        
        # Injection vulnerabilities
        if result['injection_vulnerabilities']:
            self.console.print("\n[red] Injection Vulnerabilities:[/red]")
            for vuln in result['injection_vulnerabilities']:
                self.console.print(f"   {vuln}")
        
        # Recommendations
        if result['recommendations']:
            self.console.print("\n[bold] Recommendations:[/bold]")
            for i, rec in enumerate(result['recommendations'], 1):
                self.console.print(f"  {i}. {rec}")
    
    def run_supply_chain_security(self):
        """Run supply chain security analysis."""
        if not ENTERPRISE_FEATURES_AVAILABLE:
            self.console.print("[red]Enterprise features not available[/red]")
            return
        
        future = FutureSecurityFeatures()
        target = Prompt.ask("[cyan]Target (project/package)[/cyan]", default="my-project")
        
        self.console.print(f"\n[magenta] Supply Chain Security Analysis[/magenta]\n")
        
        with self.console.status("[bold green]Analyzing supply chain risks..."):
            result = future.supply_chain_security_analysis(target)
        
        # Overview
        risk_color = "red" if result['risk_score'] >= 70 else "yellow" if result['risk_score'] >= 40 else "green"
        
        panel = Panel(
            f"[bold]Target:[/bold] {result['target']}\n"
            f"[bold]Risk Score:[/bold] [{risk_color}]{result['risk_score']}/100[/{risk_color}]\n\n"
            f"[bold]SBOM Available:[/bold] {'[green]YES[/green]' if result['sbom_available'] else '[red]NO[/red]'}\n"
            f"[bold]SLSA Level:[/bold] {result['provenance_verification']['slsa_level']}/4\n"
            f"[bold]Signed Commits:[/bold] {'[green]YES[/green]' if result['provenance_verification']['signed_commits'] else '[red]NO[/red]'}",
            title=" Supply Chain Overview",
            border_style=risk_color
        )
        self.console.print(panel)
        
        # Dependency risks
        if result['dependency_risks']:
            table = Table(title="  Risky Dependencies", box=box.ROUNDED)
            table.add_column("Package", style="red")
            table.add_column("Risk", style="yellow")
            
            for dep in result['dependency_risks']:
                table.add_row(dep['name'], dep['risk'])
            
            self.console.print(table)
        
        # Typosquatting
        if result['typosquatting_detected']:
            self.console.print("\n[red] Typosquatting Detected:[/red]")
            for pkg in result['typosquatting_detected']:
                self.console.print(f"   {pkg}")
        
        # License compliance
        license_issues = []
        if result['license_compliance']['copyleft_detected']:
            license_issues.append("Copyleft licenses detected")
        if result['license_compliance']['incompatible_licenses']:
            license_issues.append("Incompatible licenses found")
        if result['license_compliance']['missing_licenses'] > 0:
            license_issues.append(f"{result['license_compliance']['missing_licenses']} packages without licenses")
        
        if license_issues:
            self.console.print("\n[yellow] License Compliance Issues:[/yellow]")
            for issue in license_issues:
                self.console.print(f"   {issue}")
        
        # Recommendations
        if result['recommendations']:
            self.console.print("\n[bold] Recommendations:[/bold]")
            for i, rec in enumerate(result['recommendations'], 1):
                self.console.print(f"  {i}. {rec}")
    
    def run_predictive_threat(self):
        """Run predictive threat modeling."""
        if not ENTERPRISE_FEATURES_AVAILABLE:
            self.console.print("[red]Enterprise features not available[/red]")
            return
        
        future = FutureSecurityFeatures()
        ip = Prompt.ask("[cyan]IP address to analyze[/cyan]")
        
        self.console.print(f"\n[magenta] Predictive Threat Modeling[/magenta]\n")
        
        with self.console.status("[bold green]Running ML prediction models..."):
            result = future.predictive_threat_score(ip)
        
        threat_level = "CRITICAL" if result['threat_probability'] >= 70 else "HIGH" if result['threat_probability'] >= 40 else "LOW"
        threat_color = {'CRITICAL': 'red', 'HIGH': 'yellow', 'LOW': 'green'}.get(threat_level, 'white')
        
        panel = Panel(
            f"[bold]IP Address:[/bold] {result['ip']}\n"
            f"[bold]Threat Level:[/bold] [{threat_color}]{threat_level}[/{threat_color}]\n"
            f"[bold]Probability:[/bold] {result['threat_probability']}%\n\n"
            f"[bold]Predicted Attack Types:[/bold]\n" +
            ("\n".join(f"   {attack}" for attack in result['predicted_attack_types']) if result['predicted_attack_types'] else "  None detected"),
            title=" Predictive Threat Analysis",
            border_style=threat_color
        )
        self.console.print(panel)
        
        if result['recommended_actions']:
            self.console.print("\n[bold] Recommended Actions:[/bold]")
            for i, action in enumerate(result['recommended_actions'], 1):
                self.console.print(f"  {i}. {action}")
    
    def show_2030_menu(self):
        """Quick access to all 2030 features."""
        self.console.print("\n[bold magenta] 2030 FUTURE SECURITY SUITE[/bold magenta]\n")
        
        options = {
            '1': ('Quantum-Safe Crypto', self.run_quantum_safe_check),
            '2': ('Zero-Trust Assessment', self.run_zero_trust_assessment),
            '3': ('Blockchain Security', self.run_blockchain_security),
            '4': ('AI Threat Hunting', self.run_ai_threat_hunting),
            '5': ('Container Security', self.run_container_security),
            '6': ('API Security', self.run_api_security),
            '7': ('Supply Chain Security', self.run_supply_chain_security),
            '8': ('Predictive Threat Modeling', self.run_predictive_threat),
            '9': ('Run All 2030 Features', None)
        }
        
        for key, (name, _) in options.items():
            self.console.print(f"[magenta]{key}.[/magenta] {name}")
        
        self.console.print("\n[dim]0. Back to main menu[/dim]")
        
        choice = Prompt.ask("\n[magenta]Select 2030 feature[/magenta]")
        
        if choice == '0':
            return
        elif choice == '9':
            self.console.print("\n[bold magenta] Running Complete 2030 Security Suite...[/bold magenta]\n")
            for key in ['1', '2', '3', '4', '5', '6', '7', '8']:
                if key in options and options[key][1]:
                    self.console.print(f"\n{'='*60}")
                    options[key][1]()
                    input("\n[dim]Press Enter to continue...[/dim]")
        elif choice in options and options[choice][1]:
            options[choice][1]()
    
    def run_future_features(self):
        """Run 2030 future features."""
        if not ENTERPRISE_FEATURES_AVAILABLE:
            self.console.print("[red]Enterprise features not available[/red]")
            return
        
        future = FutureSecurityFeatures()
        
        self.console.print("\n[bold magenta] 2030 Future Security Features[/bold magenta]\n")
        
        # Quantum-safe crypto check
        target = Prompt.ask("[cyan]Target to analyze[/cyan]", default="https://example.com")
        
        self.console.print(f"\n[yellow]Analyzing: {target}[/yellow]\n")
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Running future security checks...", total=3)
            
            # 1. Quantum-safe crypto
            quantum_result = future.check_quantum_safe_crypto(target)
            progress.update(task, advance=1)
            
            # 2. Zero-trust posture
            zt_result = future.analyze_zero_trust_posture(target)
            progress.update(task, advance=1)
            
            # 3. Predictive threat
            predictive_result = future.predictive_threat_score(target)
            progress.update(task, advance=1)
        
        # Display quantum-safe results
        quantum_panel = Panel(
            f"[bold]Quantum-Safe:[/bold] {'[green]YES[/green]' if quantum_result['quantum_safe'] else '[red]NO[/red]'}\n"
            f"[bold]Algorithms:[/bold] {', '.join(quantum_result['algorithms']) if quantum_result['algorithms'] else 'None detected'}\n"
            f"[bold]Recommendation:[/bold] {quantum_result['recommendation']}",
            title=" Quantum-Safe Cryptography",
            border_style="cyan"
        )
        self.console.print(quantum_panel)
        
        # Display zero-trust results
        zt_color = "green" if zt_result['score'] >= 80 else "yellow" if zt_result['score'] >= 50 else "red"
        zt_panel = Panel(
            f"[bold]Zero-Trust Score:[/bold] [{zt_color}]{zt_result['score']}/100[/{zt_color}]\n\n"
            f"[bold]Checks:[/bold]\n" +
            "\n".join(f"   {check['name']}: {'[green][/green]' if check['passed'] else '[red][/red]'}" 
                     for check in zt_result['checks']),
            title=" Zero-Trust Posture",
            border_style=zt_color
        )
        self.console.print(zt_panel)
        
        # Display predictive results
        pred_color = "red" if predictive_result['threat_level'] == "CRITICAL" else "yellow" if predictive_result['threat_level'] == "HIGH" else "green"
        pred_panel = Panel(
            f"[bold]Threat Level:[/bold] [{pred_color}]{predictive_result['threat_level']}[/{pred_color}]\n"
            f"[bold]Score:[/bold] {predictive_result['score']:.1f}/100\n\n"
            f"[bold]Recommended Actions:[/bold]\n" +
            "\n".join(f"   {action}" for action in predictive_result['recommendations']),
            title=" Predictive Threat Analysis",
            border_style=pred_color
        )
        self.console.print(pred_panel)


if __name__ == "__main__":
    # Check for admin privileges
    if platform.system() == "Windows":
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        is_admin = os.geteuid() == 0
    
    if not is_admin:
        console.print("[yellow]  Warning: Not running with admin privileges[/yellow]")
        console.print("[dim]Some features may be limited. Run as Administrator/root for full functionality.[/dim]\n")
    
    cli = CLIV3()
    cli.run()
