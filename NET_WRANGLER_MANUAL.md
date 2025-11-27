# NET-WRANGLER COMPREHENSIVE EDUCATIONAL MANUAL

```
 _   _ _____ _____    __        ______      _    _   _  ____ _     _____ ____  
| \ | | ____|_   _|   \ \      / /  _ \    / \  | \ | |/ ___| |   | ____|  _ \ 
|  \| |  _|   | |      \ \ /\ / /| |_) |  / _ \ |  \| | |  _| |   |  _| | |_) |
| |\  | |___  | |       \ V  V / |  _ <  / ___ \| |\  | |_| | |___| |___|  _ < 
|_| \_|_____| |_|        \_/\_/  |_| \_\/_/   \_\_| \_|\____|_____|_____|_| \_\
```

**Version 3.0 - The Complete Network Security and Learning Platform**

---

## ABOUT THIS MANUAL

This is not just a "how to use" guide. This manual is designed to be a **complete educational resource** that teaches you:

1. **WHAT** - What each technology/protocol actually is
2. **WHY** - Why it exists and why it matters for security
3. **HOW** - How it works at a technical level
4. **INTERPRET** - How to understand and act on the results
5. **SECURITY** - Real-world attack scenarios and defenses

By the end of this manual, you will understand networking and security concepts deeply, not just superficially.

---

## TABLE OF CONTENTS

### Part 1: Foundations
- [The OSI Model - Understanding Network Layers](#the-osi-model)
- [IP Addressing and Subnetting Deep Dive](#ip-addressing-and-subnetting)
- [TCP vs UDP - The Transport Layer](#tcp-vs-udp)

### Part 2: Discovery and Reconnaissance
- [Feature 1: ARP Scanning - Local Network Discovery](#feature-1-arp-scanning)
- [Feature 2: ICMP Ping Sweep - Remote Host Discovery](#feature-2-icmp-ping-sweep)
- [Feature 3-4: Port Scanning - Service Enumeration](#feature-3-4-port-scanning)

### Part 3: Information Gathering
- [Feature 5-6: DNS Analysis - The Internet Phonebook](#feature-5-6-dns-analysis)
- [Feature 7: WHOIS Lookup - Domain Intelligence](#feature-7-whois-lookup)
- [Feature 8: Traceroute - Network Path Mapping](#feature-8-traceroute)

### Part 4: Security Analysis
- [Feature 9: SSL/TLS Analysis - Encryption Assessment](#feature-9-ssltls-analysis)
- [Feature 10: HTTP Headers - Web Security Audit](#feature-10-http-header-analysis)
- [Feature 17: Packet Sniffing - Deep Traffic Analysis](#feature-17-packet-sniffing)

### Part 5: Advanced and 2030 Features
- [Enterprise Security Features](#enterprise-features)
- [2030 Future Security Suite](#2030-future-security-suite)

### Part 6: Reference
- [Complete Glossary of Terms](#glossary)
- [Common Ports Reference](#common-ports-reference)
- [Attack Types and Defenses](#attack-types-and-defenses)

---

# PART 1: FOUNDATIONS

## THE OSI MODEL

Before using any network tool, you must understand how networks are structured. The **OSI (Open Systems Interconnection) Model** divides networking into 7 layers:

```
+------------------------------------------------------------------+
| Layer 7: APPLICATION    | HTTP, DNS, FTP, SMTP                   |
|         What you see    | Web browsers, email clients            |
+------------------------------------------------------------------+
| Layer 6: PRESENTATION   | SSL/TLS, Encryption, Compression       |
|         Data formatting | HTTPS = HTTP + TLS                     |
+------------------------------------------------------------------+
| Layer 5: SESSION        | Establishing, managing connections     |
|         Connection mgmt | NetBIOS, RPC                           |
+------------------------------------------------------------------+
| Layer 4: TRANSPORT      | TCP, UDP                               |
|         Reliability     | Ports live here (80, 443, 22)         |
+------------------------------------------------------------------+
| Layer 3: NETWORK        | IP, ICMP, Routing                      |
|         Logical address | IP addresses (192.168.1.1)            |
+------------------------------------------------------------------+
| Layer 2: DATA LINK      | Ethernet, ARP, MAC addresses           |
|         Physical address| MAC (AA:BB:CC:DD:EE:FF)               |
+------------------------------------------------------------------+
| Layer 1: PHYSICAL       | Cables, Wi-Fi signals, voltage         |
|         The wire itself | Bits (1s and 0s)                      |
+------------------------------------------------------------------+
```

### Why This Matters for Security

Each layer can be attacked differently:
- **Layer 7 (Application):** SQL Injection, XSS, Command Injection
- **Layer 4 (Transport):** SYN Flood DDoS, Port Scanning
- **Layer 3 (Network):** IP Spoofing, ICMP Flood
- **Layer 2 (Data Link):** ARP Spoofing, MAC Flooding

NET-WRANGLER tools operate at different layers:

| Tool | OSI Layer | Protocol |
|------|-----------|----------|
| ARP Scan | Layer 2 | ARP |
| Ping Sweep | Layer 3 | ICMP |
| Port Scan | Layer 4 | TCP |
| DNS Lookup | Layer 7 | DNS |
| HTTP Headers | Layer 7 | HTTP |

---

## IP ADDRESSING AND SUBNETTING

### What is an IP Address?

An **IP Address** is like a postal address for computers. It uniquely identifies a device on a network.

**IPv4 Format:** `192.168.1.100`
- 4 numbers (octets) separated by dots
- Each octet ranges from 0 to 255
- Total: approximately 4.3 billion possible addresses

**IPv6 Format:** `2001:0db8:85a3:0000:0000:8a2e:0370:7334`
- 8 groups of 4 hexadecimal digits
- Total: 340 undecillion addresses (enough for every grain of sand on Earth)

### Private vs Public IP Addresses

**Private IPs** (used inside your home/office):
```
10.0.0.0    - 10.255.255.255    (Class A)
172.16.0.0  - 172.31.255.255    (Class B)
192.168.0.0 - 192.168.255.255   (Class C) <-- Most home routers use this
```

**Public IPs:** Everything else (assigned by ISPs, globally unique)

### CIDR Notation Explained

When you see `/24` or `/16`, this is **CIDR (Classless Inter-Domain Routing)** notation.

```
192.168.1.0/24
             |
             +-- The "/24" means the first 24 bits are the NETWORK portion
                 The remaining 8 bits are for HOSTS

/24 = 255.255.255.0 = 256 addresses (254 usable)
/16 = 255.255.0.0   = 65,536 addresses
/8  = 255.0.0.0     = 16,777,216 addresses
```

**Calculating Hosts:**
```
Hosts = 2^(32 - CIDR) - 2
/24 = 2^8 - 2 = 254 usable hosts
/22 = 2^10 - 2 = 1022 usable hosts
```

### Subnet Calculator (Feature 12)

NET-WRANGLER Subnet Calculator helps you:
- Calculate network and broadcast addresses
- Determine usable host range
- Identify if an IP is private or public

---

## TCP vs UDP

These are the two main **Transport Layer** protocols. Understanding them is crucial for port scanning.

### TCP (Transmission Control Protocol)

**Characteristics:**
- **Connection-oriented:** Must establish connection before sending data
- **Reliable:** Guarantees delivery (resends lost packets)
- **Ordered:** Data arrives in the correct sequence
- **Slower:** Due to overhead of reliability

**The TCP 3-Way Handshake:**
```
Client                          Server
   |                               |
   | -------- SYN --------------> |  "Hello, I want to connect"
   |                               |
   | <------- SYN-ACK ----------- |  "OK, I am listening"
   |                               |
   | -------- ACK --------------> |  "Great, let us talk"
   |                               |
   | ======== DATA =============> |  Actual communication
   |                               |
```

**Security Implication:** This handshake is why we can detect open ports. If a server responds with SYN-ACK, the port is OPEN. If it responds with RST (Reset), the port is CLOSED.

**Common TCP Services:**

| Port | Service | Description |
|------|---------|-------------|
| 20/21 | FTP | File Transfer (INSECURE - sends passwords in clear text) |
| 22 | SSH | Secure Shell (encrypted remote access) |
| 23 | Telnet | Remote access (INSECURE - unencrypted) |
| 25 | SMTP | Email sending |
| 80 | HTTP | Web (unencrypted) |
| 443 | HTTPS | Web (encrypted with TLS) |
| 3306 | MySQL | Database |
| 3389 | RDP | Remote Desktop (Windows) |

### UDP (User Datagram Protocol)

**Characteristics:**
- **Connectionless:** No handshake, just sends
- **Unreliable:** No guarantee of delivery
- **Fast:** No overhead, best for real-time applications

**Common UDP Services:**

| Port | Service | Description |
|------|---------|-------------|
| 53 | DNS | Domain Name System |
| 67/68 | DHCP | Automatic IP assignment |
| 123 | NTP | Time synchronization |
| 161 | SNMP | Network management |
| 500 | IKE | VPN key exchange |

**Security Implication:** UDP is often used for **DDoS amplification attacks** because servers respond with larger packets than the request.

---

# PART 2: DISCOVERY AND RECONNAISSANCE

## FEATURE 1: ARP SCANNING

### What is ARP?

**ARP (Address Resolution Protocol)** is the bridge between Layer 2 (MAC) and Layer 3 (IP).

When your computer wants to communicate with `192.168.1.5`:
1. It checks its ARP cache: "Do I already know the MAC for this IP?"
2. If not, it broadcasts: "Who has 192.168.1.5? Tell 192.168.1.100"
3. The device with that IP replies: "192.168.1.5 is at AA:BB:CC:DD:EE:FF"
4. Your computer caches this mapping and sends the packet

```
+------------------------------------------------------------------+
|                         ARP REQUEST                              |
|  Source MAC: AA:BB:CC:11:22:33 (Your computer)                   |
|  Dest MAC:   FF:FF:FF:FF:FF:FF (Broadcast - everyone)            |
|  Message:    "Who has 192.168.1.5?"                              |
+------------------------------------------------------------------+
                              |
                              v
+------------------------------------------------------------------+
|                         ARP REPLY                                |
|  Source MAC: DD:EE:FF:44:55:66 (Target device)                   |
|  Dest MAC:   AA:BB:CC:11:22:33 (Your computer)                   |
|  Message:    "192.168.1.5 is at DD:EE:FF:44:55:66"               |
+------------------------------------------------------------------+
```

### Why ARP Scanning Works

ARP is a Layer 2 protocol that **cannot be blocked by firewalls** (which operate at Layer 3+). Even devices configured to ignore pings MUST respond to ARP to function on the network.

This makes ARP scanning the **most reliable** method for local network discovery.

### Security Attack: ARP Spoofing

An attacker can send fake ARP replies:
```
Attacker: "192.168.1.1 (the router) is at MY MAC address"
```

Now all traffic meant for the router goes through the attacker first. This is called a **Man-in-the-Middle (MitM)** attack.

**Defense:** Enable Dynamic ARP Inspection (DAI) on managed switches.

### How to Use in NET-WRANGLER

```
Select option: 1
Enter network range: 192.168.1.0/24
```

### Interpreting Results

| IP Address | MAC Address | Hostname | Analysis |
|------------|-------------|----------|----------|
| 192.168.1.1 | 00:1A:2B:3C:4D:5E | router | Your gateway |
| 192.168.1.100 | AA:BB:CC:DD:EE:FF | DESKTOP-ABC | Windows PC (expected) |
| 192.168.1.150 | DC:A6:32:XX:XX:XX | Unknown | WARNING: Raspberry Pi MAC! Investigate! |

**MAC Vendor Lookup Tips:**
- `DC:A6:32` = Raspberry Pi (could be a hacking device)
- `00:0C:29` = VMware (virtual machine)
- `08:00:27` = VirtualBox (virtual machine)
- `B8:27:EB` = Raspberry Pi (older models)
- `E8:48:B8` or `60:01:94` = Espressif (IoT devices like smart bulbs)

---

## FEATURE 2: ICMP PING SWEEP

### What is ICMP?

**ICMP (Internet Control Message Protocol)** is the "error reporting" protocol of the internet. The most famous ICMP message is the **Echo Request/Reply** (ping).

```
+------------------------------------------------------------------+
|                    ICMP Echo Request (Ping)                      |
|  Type: 8                                                         |
|  Code: 0                                                         |
|  Message: "Are you there?"                                       |
+------------------------------------------------------------------+
                              |
                              v
+------------------------------------------------------------------+
|                    ICMP Echo Reply (Pong)                        |
|  Type: 0                                                         |
|  Code: 0                                                         |
|  Message: "Yes, I am here!"                                      |
+------------------------------------------------------------------+
```

### Other ICMP Message Types

| Type | Name | Purpose |
|------|------|---------|
| 0 | Echo Reply | Response to ping |
| 3 | Destination Unreachable | Host/port unreachable |
| 5 | Redirect | Better route available |
| 8 | Echo Request | Ping |
| 11 | Time Exceeded | TTL expired (used by traceroute) |

### Why Use Ping Sweep Instead of ARP?

| Scenario | Use ARP | Use Ping |
|----------|---------|----------|
| Same network (LAN) | Best choice | Works but slower |
| Remote network | Will not work | Only option |
| Firewall-protected hosts | Bypasses firewall | Often blocked |

### Interpreting Results

- **Response received:** Host is online
- **No response:** Host is offline OR configured to block ICMP
- **High latency (>100ms):** Possible network congestion or distant host

### Security Attack: Ping Flood (ICMP Flood)

An attacker sends thousands of ping requests to overwhelm a target. This is a type of **DoS (Denial of Service)** attack.

**Defense:** Rate-limit ICMP on firewalls.

---

## FEATURE 3-4: PORT SCANNING

### What is a Port?

Think of an IP address as a building street address. **Ports** are like apartment numbers inside that building.

```
IP Address: 192.168.1.100 (the building)
Port 22: SSH service (apartment 22)
Port 80: Web server (apartment 80)
Port 443: HTTPS (apartment 443)
```

There are **65,535 ports** (0-65535):
- **Well-known (0-1023):** Reserved for system services (HTTP, SSH, DNS)
- **Registered (1024-49151):** Application services
- **Dynamic (49152-65535):** Temporary client ports

### TCP Connect Scan (NET-WRANGLER Method)

```
Your Computer                    Target Server
     |                               |
     | ---- SYN (to port 80) -----> |
     |                               |
     | <--- SYN-ACK ---------------- |  PORT IS OPEN
     |                               |
     | ---- ACK ------------------> |  Connection established
     |                               |
     | ---- RST ------------------> |  Close connection
```

If the port is closed:
```
     | ---- SYN (to port 81) -----> |
     |                               |
     | <--- RST -------------------- |  PORT IS CLOSED
```

If a firewall is blocking:
```
     | ---- SYN (to port 82) -----> |
     |                               |
     |     (no response)            |  PORT IS FILTERED
```

### Port States Explained

| State | Meaning | Security Implication |
|-------|---------|---------------------|
| **OPEN** | Service is listening | Attack surface - investigate the service |
| **CLOSED** | Nothing listening | Safe, but reveals host is alive |
| **FILTERED** | Firewall blocking | Good security practice |

### Dangerous Open Ports

| Port | Service | Risk Level | Why It Is Risky |
|------|---------|------------|-----------------|
| 21 | FTP | HIGH | Passwords sent in clear text |
| 23 | Telnet | CRITICAL | Everything unencrypted, obsolete |
| 135/139/445 | SMB | CRITICAL | Target for ransomware (EternalBlue) |
| 1433 | MSSQL | HIGH | Database exposure |
| 3306 | MySQL | HIGH | Database exposure |
| 3389 | RDP | HIGH | Frequent brute-force target |
| 5900 | VNC | HIGH | Often weak authentication |

### Safe Open Ports

| Port | Service | Notes |
|------|---------|-------|
| 22 | SSH | Secure if using key authentication |
| 80 | HTTP | OK if redirects to HTTPS |
| 443 | HTTPS | Good - encrypted |

### How to Use in NET-WRANGLER

**Quick Scan (Common Ports):**
```
Select option: 3
Enter target: scanme.nmap.org
```

**Full Scan (All 65,535 Ports):**
```
Select option: 4
Enter target: 192.168.1.1
Start port: 1
End port: 65535
```

WARNING: Full scans take 5-30 minutes depending on network speed.

---

# PART 3: INFORMATION GATHERING

## FEATURE 5-6: DNS ANALYSIS

### What is DNS?

**DNS (Domain Name System)** translates human-readable domain names into IP addresses.

```
You type: www.google.com
DNS returns: 142.250.190.14
Your browser connects to: 142.250.190.14
```

Without DNS, you would have to memorize IP addresses for every website!

### DNS Record Types Deep Dive

| Record | Purpose | Example | Security Use |
|--------|---------|---------|--------------|
| **A** | IPv4 address | google.com -> 142.250.190.14 | Find server IP |
| **AAAA** | IPv6 address | google.com -> 2607:f8b0:: | Find IPv6 infrastructure |
| **MX** | Mail servers | google.com -> smtp.google.com | Find email infrastructure |
| **NS** | Name servers | google.com -> ns1.google.com | Who controls DNS |
| **TXT** | Text data | SPF, DKIM, domain verification | Security policies |
| **CNAME** | Alias | www.example.com -> example.com | Find true hostname |
| **SOA** | Zone info | Serial, refresh times | DNS configuration |

### Understanding TXT Records for Security

**SPF (Sender Policy Framework):**
```
v=spf1 include:_spf.google.com ~all
```
- Tells email servers: "Only these IPs can send email as @company.com"
- Prevents email spoofing/phishing

**DMARC (Domain-based Message Authentication):**
```
v=DMARC1; p=reject; rua=mailto:admin@company.com
```
- Tells receivers what to do with failed SPF/DKIM checks
- `p=reject` = delete fake emails

**DKIM (DomainKeys Identified Mail):**
- Public key in DNS, private key signs emails
- Proves email was not modified in transit

### Security Attack: DNS Spoofing/Poisoning

An attacker can inject fake DNS records:
```
Legitimate: bank.com -> 1.2.3.4 (real bank server)
Poisoned:   bank.com -> 6.6.6.6 (attacker fake site)
```

**Defense:** Use DNSSEC (DNS Security Extensions) which cryptographically signs DNS records.

### How to Use in NET-WRANGLER

```
Select option: 5
Enter domain: example.com
```

### Interpreting Results

```
A Records:
- 93.184.216.34     <-- Web server IP

MX Records:
- 10 mail.example.com   <-- Priority 10 mail server

TXT Records:
- "v=spf1 -all"     <-- SPF record (good!)
```

---

## FEATURE 7: WHOIS LOOKUP

### What is WHOIS?

WHOIS is a public database that stores **domain registration information**. When someone registers a domain, their contact information is recorded.

### WHOIS Information Explained

| Field | Meaning | Security Use |
|-------|---------|--------------|
| **Registrar** | Company that sold the domain | Identify registration platform |
| **Creation Date** | When domain was registered | New = suspicious |
| **Expiration Date** | When it expires | May indicate abandoned sites |
| **Name Servers** | DNS providers | Infrastructure intelligence |
| **Registrant** | Owner contact | Attribution (often hidden) |

### Identifying Suspicious Domains

**Red Flags:**
- Domain created in the last 30 days
- Uses privacy protection on a "business" site
- Registrar known for hosting scams
- Domain similar to legitimate brand (paypa1.com vs paypal.com)

### How to Use in NET-WRANGLER

```
Select option: 7
Enter domain: suspicious-site.com
```

### Example Analysis

```
Domain: definitely-not-paypal.com
Created: 2025-11-25 (yesterday!)
Registrar: ShadyRegistrar Inc.

WARNING VERDICT: Almost certainly a phishing site
```

---

## FEATURE 8: TRACEROUTE

### What is Traceroute?

Traceroute maps the **network path** between you and a destination by exploiting the **TTL (Time To Live)** field.

### How TTL Works

Every IP packet has a TTL field (default 64 or 128). Each router decrements TTL by 1. When TTL reaches 0, the router sends back an **ICMP Time Exceeded** message.

```
Packet with TTL=1:
You -> Router1 (TTL becomes 0) -> Router1 replies "Time Exceeded"
                                   You now know Router1 IP!

Packet with TTL=2:
You -> Router1 -> Router2 (TTL becomes 0) -> "Time Exceeded"
                                              You now know Router2 IP!

Packet with TTL=3:
You -> Router1 -> Router2 -> Router3 -> ... (continues until destination)
```

### Interpreting Traceroute

```
Hop  IP              RTT     Analysis
1    192.168.1.1     1ms     Your home router
2    10.0.0.1        5ms     ISP first router
3    72.14.215.85    20ms    ISP backbone
4    * * *           ---     Router blocking ICMP (normal)
5    142.250.190.14  25ms    Destination (Google)
```

**What `* * *` means:**
- Router is configured to not respond to ICMP
- Packet was dropped (firewall)
- Normal in many networks - do not panic

### Security Use Cases

1. **Identify ISP routing:** See which backbone providers are used
2. **Detect routing anomalies:** Traffic going through unexpected countries
3. **Troubleshoot latency:** Find which hop is causing delays

---

# PART 4: SECURITY ANALYSIS

## FEATURE 9: SSL/TLS ANALYSIS

### What is SSL/TLS?

**SSL (Secure Sockets Layer)** and its successor **TLS (Transport Layer Security)** encrypt communications between your browser and a website.

```
Without TLS (HTTP):
You ---- "Password: hunter2" --------------> Server
         ^ Anyone can read this!

With TLS (HTTPS):
You ---- "x#@$%^&*(!@#$%^" ----------------> Server
         ^ Encrypted, unreadable
```

### TLS Version History

| Version | Year | Status | Security |
|---------|------|--------|----------|
| SSL 2.0 | 1995 | Obsolete | Broken, do not use |
| SSL 3.0 | 1996 | Obsolete | Vulnerable (POODLE) |
| TLS 1.0 | 1999 | Deprecated | Weak |
| TLS 1.1 | 2006 | Deprecated | Weak |
| TLS 1.2 | 2008 | Acceptable | Secure if configured well |
| TLS 1.3 | 2018 | Best | Most secure, fastest |

### Certificate Components

```
+------------------------------------------------------------------+
|                    X.509 CERTIFICATE                             |
+------------------------------------------------------------------+
| Subject:     CN=www.example.com (who owns it)                    |
| Issuer:      CN=DigiCert (who verified it)                       |
| Valid From:  Jan 1, 2025                                         |
| Valid Until: Jan 1, 2026                                         |
| Public Key:  RSA 2048-bit (encryption strength)                  |
| Signature:   SHA256withRSA (hash algorithm)                      |
+------------------------------------------------------------------+
```

### What NET-WRANGLER Checks

1. **Protocol Version:** Is it TLS 1.2+?
2. **Certificate Validity:** Is it expired?
3. **Issuer Trust:** Is the CA (Certificate Authority) trusted?
4. **Key Strength:** Is the key at least 2048 bits?
5. **Cipher Suite:** Are strong algorithms used?

### Dangerous Findings

| Finding | Risk | Recommendation |
|---------|------|----------------|
| TLS 1.0 | HIGH | Upgrade to TLS 1.2+ |
| Expired certificate | HIGH | Renew immediately |
| Self-signed cert | MEDIUM | Get a proper CA cert |
| Weak cipher (RC4) | HIGH | Disable weak ciphers |

### How to Use in NET-WRANGLER

```
Select option: 9
Enter hostname: example.com
Port: 443
```

---

## FEATURE 10: HTTP HEADER ANALYSIS

### What are HTTP Headers?

When you visit a website, the server sends back **headers** with instructions for your browser. Security headers tell the browser how to protect you.

```
HTTP/1.1 200 OK
Content-Type: text/html
Strict-Transport-Security: max-age=31536000
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'
```

### Critical Security Headers

| Header | Purpose | Risk if Missing |
|--------|---------|-----------------|
| **Strict-Transport-Security (HSTS)** | Force HTTPS | Downgrade attacks possible |
| **X-Frame-Options** | Prevent framing | Clickjacking attacks |
| **X-Content-Type-Options** | Prevent MIME sniffing | Drive-by downloads |
| **Content-Security-Policy (CSP)** | Control resources | XSS attacks |
| **X-XSS-Protection** | Browser XSS filter | XSS attacks (legacy) |
| **Referrer-Policy** | Control referrer info | Information leakage |

### Understanding Each Header

**HSTS (Strict-Transport-Security):**
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```
- Tells browser: "Never connect to me over HTTP, only HTTPS"
- `max-age=31536000` = Remember for 1 year
- Prevents SSL stripping attacks

**X-Frame-Options:**
```
X-Frame-Options: DENY
```
- Prevents your site from being embedded in an `<iframe>`
- Stops **clickjacking** (invisible overlay tricks users into clicking)

**Content-Security-Policy (CSP):**
```
Content-Security-Policy: default-src 'self'; script-src 'self' cdn.example.com
```
- Whitelists where resources (scripts, images) can load from
- Prevents XSS by blocking inline scripts and untrusted sources
- The **most important** security header

### How to Use in NET-WRANGLER

```
Select option: 10
Enter URL: https://example.com
```

### Interpreting Results

```
Security Headers:
[OK] Strict-Transport-Security: max-age=31536000
[OK] X-Frame-Options: DENY
[MISSING] Content-Security-Policy    <-- BAD! Add CSP!
[MISSING] X-XSS-Protection           <-- OK, deprecated anyway
```

---

## FEATURE 17: PACKET SNIFFING

### What is Packet Sniffing?

A **packet sniffer** captures raw network traffic flowing through your network interface. It is like wiretapping a phone line.

### How It Works

1. Network card enters **promiscuous mode** (sees ALL packets, not just yours)
2. Packets are captured and decoded
3. You can see: Source, Destination, Protocol, Data

### What You Can See

**Unencrypted (HTTP):**
```
POST /login HTTP/1.1
Host: insecure-site.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=hunter2    <-- PASSWORD VISIBLE!
```

**Encrypted (HTTPS):**
```
.#$%^&*(!@#$%^&*()_+}{}|":?><    <-- Encrypted gibberish
```

This is why HTTPS is critical!

### Security Uses

1. **Detect clear-text passwords** being sent on your network
2. **Identify malicious traffic** (C2 beacons, data exfiltration)
3. **Troubleshoot network issues**
4. **Analyze malware behavior**

### Ethical and Legal Warning

WARNING: **ONLY sniff traffic on networks you own or have explicit permission to monitor.**

Sniffing others traffic without authorization is **illegal** in most jurisdictions.

### How to Use in NET-WRANGLER

```
Select option: 17
Enter interface: Ethernet
Number of packets: 100
```

---

# PART 5: ADVANCED AND 2030 FEATURES

## ENTERPRISE FEATURES

### Cloud Storage Audit (Feature 20)
Checks AWS S3, Azure Blob, and GCP buckets for misconfigurations (public access, missing encryption).

### Subdomain Enumeration (Feature 21)
Discovers subdomains using DNS brute-forcing, certificate transparency logs, and search engines.

### WAF Detection (Feature 22)
Identifies Web Application Firewalls (Cloudflare, AWS WAF, Akamai) protecting a target.

### Anomaly Detection (Feature 23)
Uses machine learning to detect unusual network traffic patterns.

### Compliance Check (Feature 24)
Validates configurations against PCI-DSS, HIPAA, SOC 2, and other frameworks.

---

## 2030 FUTURE SECURITY SUITE

### Feature 30: Quantum-Safe Cryptography Analysis

**The Threat:**
Quantum computers will break RSA and ECC encryption within the next decade. A sufficiently powerful quantum computer can factor large primes instantly using Shor algorithm.

**What This Tool Does:**
- Checks if servers support Post-Quantum Cryptography (PQC) algorithms
- Tests for Kyber, Dilithium, SPHINCS+ support
- Identifies hybrid TLS configurations

**NIST PQC Standards (2024):**

| Algorithm | Type | Status |
|-----------|------|--------|
| ML-KEM (Kyber) | Key Exchange | Standardized |
| ML-DSA (Dilithium) | Digital Signature | Standardized |
| SLH-DSA (SPHINCS+) | Digital Signature | Standardized |

### Feature 31: Zero-Trust Assessment

**The Principle:** "Never trust, always verify"

**What This Tool Checks:**
- Network segmentation (is everything flat or properly segmented?)
- MFA enforcement (is multi-factor authentication required?)
- Least privilege access (do users have only necessary permissions?)
- Micro-segmentation (are workloads isolated?)

### Feature 32: Blockchain Security Analysis

**What This Tool Checks:**
- Smart contract vulnerabilities (reentrancy, integer overflow)
- RPC endpoint security
- Wallet exposure
- DeFi protocol risks

### Feature 33: AI Threat Hunting

**What This Tool Does:**
- Uses ML to detect APT (Advanced Persistent Threat) patterns
- Identifies beaconing behavior (malware phoning home)
- Detects lateral movement (attackers moving between systems)
- Maps to MITRE ATT&CK framework

### Feature 34: Container Security

**What This Tool Checks:**
- Docker image vulnerabilities
- Kubernetes misconfigurations
- Secrets exposure in containers
- Network policy issues

### Feature 35: API Security Assessment

**Based on OWASP API Security Top 10:**
1. Broken Object Level Authorization
2. Broken Authentication
3. Broken Object Property Level Authorization
4. Unrestricted Resource Consumption
5. Broken Function Level Authorization
6. Unrestricted Access to Sensitive Business Flows
7. Server Side Request Forgery
8. Security Misconfiguration
9. Improper Inventory Management
10. Unsafe Consumption of APIs

### Feature 36: Supply Chain Security

**What This Tool Checks:**
- Dependency vulnerabilities
- Typosquatting detection (malicious packages with similar names)
- SBOM (Software Bill of Materials) generation
- Build provenance verification

### Feature 37: Predictive Threat Modeling

**What This Tool Does:**
- Analyzes attack surface
- Calculates threat probability scores
- Simulates attack paths
- Prioritizes risks
- Recommends mitigations

---

# PART 6: REFERENCE

## GLOSSARY

| Term | Definition |
|------|------------|
| **ARP** | Address Resolution Protocol - maps IP to MAC addresses |
| **Beacon** | Regular communication from malware to command and control server |
| **Botnet** | Network of compromised computers controlled by attacker |
| **CIDR** | Classless Inter-Domain Routing - IP notation like /24 |
| **C2/C&C** | Command and Control - attacker server |
| **DDoS** | Distributed Denial of Service attack |
| **DHCP** | Dynamic Host Configuration Protocol - assigns IPs automatically |
| **DNS** | Domain Name System - translates domains to IPs |
| **Firewall** | Security system controlling network traffic |
| **HSTS** | HTTP Strict Transport Security |
| **ICMP** | Internet Control Message Protocol (ping) |
| **MAC** | Media Access Control address - hardware identifier |
| **MitM** | Man-in-the-Middle attack |
| **NAT** | Network Address Translation |
| **OSI** | Open Systems Interconnection model |
| **PQC** | Post-Quantum Cryptography |
| **RST** | TCP Reset packet |
| **SYN** | TCP Synchronize packet |
| **TLS** | Transport Layer Security (encryption) |
| **TTL** | Time To Live |
| **UDP** | User Datagram Protocol |
| **VPN** | Virtual Private Network |
| **XSS** | Cross-Site Scripting |
| **Zero-Day** | Unknown vulnerability with no patch |

## COMMON PORTS REFERENCE

### Essential Ports to Know

| Port | Protocol | Service | Security Notes |
|------|----------|---------|----------------|
| 20-21 | TCP | FTP | INSECURE, use SFTP |
| 22 | TCP | SSH | Secure |
| 23 | TCP | Telnet | Never use |
| 25 | TCP | SMTP | Email sending |
| 53 | TCP/UDP | DNS | Domain resolution |
| 67-68 | UDP | DHCP | IP assignment |
| 80 | TCP | HTTP | Unencrypted web |
| 110 | TCP | POP3 | Email retrieval |
| 143 | TCP | IMAP | Email retrieval |
| 443 | TCP | HTTPS | Encrypted web |
| 445 | TCP | SMB | Ransomware target |
| 993 | TCP | IMAPS | Secure IMAP |
| 995 | TCP | POP3S | Secure POP3 |
| 1433 | TCP | MSSQL | Database |
| 1521 | TCP | Oracle | Database |
| 3306 | TCP | MySQL | Database |
| 3389 | TCP | RDP | Brute-force target |
| 5432 | TCP | PostgreSQL | Database |
| 5900 | TCP | VNC | Often weak auth |
| 6379 | TCP | Redis | Often no auth |
| 8080 | TCP | HTTP Proxy | Alternate web |
| 27017 | TCP | MongoDB | Often exposed |

## ATTACK TYPES AND DEFENSES

| Attack | Description | Defense |
|--------|-------------|---------|
| **ARP Spoofing** | Fake ARP replies to intercept traffic | Dynamic ARP Inspection |
| **DDoS** | Overwhelm with traffic | Rate limiting, CDN |
| **DNS Spoofing** | Fake DNS responses | DNSSEC |
| **MitM** | Intercept communications | Encryption (HTTPS/VPN) |
| **Phishing** | Fake websites/emails | User education, MFA |
| **Port Scanning** | Discover open services | Firewall, close unused ports |
| **SQL Injection** | Malicious database queries | Parameterized queries |
| **XSS** | Inject malicious scripts | CSP, input sanitization |
| **Brute Force** | Try many passwords | Account lockout, MFA |
| **Ransomware** | Encrypt files for ransom | Backups, patch management |

---

## QUICK COMMAND REFERENCE

```
+===============================================================+
|                    NET-WRANGLER COMMANDS                      |
+===============================================================+
|  1-19    | Run security tools (see menu)                     |
|  H       | Display this help manual                          |
|  D       | Define a term (glossary lookup)                   |
|  T       | Start interactive tutorial                        |
|  2030    | Access future security features                   |
|  0       | Exit                                              |
+---------------------------------------------------------------+
|  LAUNCHING                                                    |
|  python run.py          | Launcher menu                      |
|  python net_wrangler.py | Direct v2.0 launch                 |
+===============================================================+
```

---

## LEGAL AND ETHICAL NOTICE

**IMPORTANT: Always obtain proper authorization before scanning any network or system.**

Unauthorized network scanning may violate:
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- Similar laws in other jurisdictions

**Best Practices:**
1. Only scan networks you own or have written permission to test
2. Document all testing activities
3. Start with passive reconnaissance before active scanning
4. Report vulnerabilities responsibly
5. Never access systems without authorization

---

*NET-WRANGLER Educational Manual v3.0*
*Last Updated: November 2025*
*"Knowledge is the best security"*
