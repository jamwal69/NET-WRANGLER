
class EducationalFeatures:
    """Educational features for NET-WRANGLER."""
    
    GLOSSARY = {
        "arp": {
            "term": "ARP (Address Resolution Protocol)",
            "definition": "A protocol used to map an IP address (logical) to a MAC address (physical).",
            "analogy": "Like asking a room full of people 'Who has the name John Smith?' and waiting for John to raise his hand.",
            "security": "ARP Spoofing attacks can redirect traffic by faking these responses."
        },
        "icmp": {
            "term": "ICMP (Internet Control Message Protocol)",
            "definition": "A network layer protocol used for error reporting and diagnostics (like Ping).",
            "analogy": "Like a sonar ping used by submarines to detect objects.",
            "security": "Blocking ICMP can hide a server from basic scans, but doesn't make it invisible."
        },
        "tcp": {
            "term": "TCP (Transmission Control Protocol)",
            "definition": "A connection-oriented protocol that ensures reliable data delivery.",
            "analogy": "Like a certified mail delivery where you get a receipt for every package.",
            "security": "TCP scans (SYN scans) are the most common way to find open ports."
        },
        "udp": {
            "term": "UDP (User Datagram Protocol)",
            "definition": "A connectionless protocol that sends data without checking if it arrives.",
            "analogy": "Like sending a postcard via regular mail; you hope it arrives but don't get confirmation.",
            "security": "UDP services (DNS, SNMP) are often used for amplification DDoS attacks."
        },
        "port": {
            "term": "Network Port",
            "definition": "A virtual endpoint where network connections start and end (0-65535).",
            "analogy": "If an IP address is an apartment building, the port is the apartment number.",
            "security": "Open ports are potential entry points for hackers."
        },
        "dns": {
            "term": "DNS (Domain Name System)",
            "definition": "The system that translates domain names (google.com) to IP addresses.",
            "analogy": "The phonebook of the internet.",
            "security": "DNS poisoning can redirect users to fake websites."
        },
        "ssl": {
            "term": "SSL/TLS (Secure Sockets Layer)",
            "definition": "Protocols for establishing authenticated and encrypted links between computers.",
            "analogy": "Like putting your letter in a locked steel briefcase instead of a clear envelope.",
            "security": "Expired or weak certificates allow attackers to intercept data (Man-in-the-Middle)."
        },
        "mac": {
            "term": "MAC Address (Media Access Control)",
            "definition": "A unique identifier assigned to a network interface controller (NIC).",
            "analogy": "A permanent serial number stamped on your network card.",
            "security": "MAC filtering is a weak security measure because MAC addresses can be easily spoofed."
        },
        "ddos": {
            "term": "DDoS (Distributed Denial of Service)",
            "definition": "An attack where multiple compromised systems attack a target to cause a denial of service.",
            "analogy": "Like a traffic jam caused by thousands of fake cars blocking a highway.",
            "security": "Mitigation requires traffic analysis and filtering."
        },
        "xss": {
            "term": "XSS (Cross-Site Scripting)",
            "definition": "A vulnerability where attackers inject malicious scripts into trusted websites.",
            "analogy": "Like someone slipping a fake instruction note into a legitimate recipe book.",
            "security": "Prevented by proper input sanitization and Content Security Policy (CSP)."
        },
        "dhcp": {
            "term": "DHCP (Dynamic Host Configuration Protocol)",
            "definition": "A protocol that automatically assigns IP addresses to devices on a network.",
            "analogy": "Like a parking attendant assigning a spot number to every car that enters the lot.",
            "security": "Rogue DHCP servers can assign fake DNS settings to intercept traffic."
        },
        "nat": {
            "term": "NAT (Network Address Translation)",
            "definition": "A method to map multiple local private IP addresses to a single public IP address.",
            "analogy": "Like an office building where everyone has a unique extension, but calls to the outside world come from the main reception number.",
            "security": "NAT acts as a basic firewall by hiding internal IP addresses from the internet."
        },
        "vpn": {
            "term": "VPN (Virtual Private Network)",
            "definition": "A service that creates a secure, encrypted connection over a less secure network (like the internet).",
            "analogy": "Like driving your car through a private, opaque tunnel instead of on the open highway.",
            "security": "Protects data privacy and bypasses geo-restrictions."
        },
        "firewall": {
            "term": "Firewall",
            "definition": "A network security system that monitors and controls incoming and outgoing network traffic.",
            "analogy": "Like a security guard at a building entrance checking IDs against a guest list.",
            "security": "Essential for blocking unauthorized access and malicious traffic."
        },
        "phishing": {
            "term": "Phishing",
            "definition": "A social engineering attack used to steal user data, including login credentials and credit card numbers.",
            "analogy": "Like a fisherman using a fake lure to trick a fish into biting.",
            "security": "User education and email filtering are key defenses."
        },
        "malware": {
            "term": "Malware (Malicious Software)",
            "definition": "Any software intentionally designed to cause damage to a computer, server, client, or computer network.",
            "analogy": "Like a biological virus that infects a body and makes it sick.",
            "security": "Antivirus software and regular updates help prevent infection."
        },
        "ransomware": {
            "term": "Ransomware",
            "definition": "A type of malware that encrypts a victim's files and demands a ransom payment to decrypt them.",
            "analogy": "Like a thief putting a digital padlock on your safe and demanding money for the key.",
            "security": "Regular backups are the best defense against ransomware."
        },
        "mitm": {
            "term": "Man-in-the-Middle (MitM)",
            "definition": "An attack where the attacker secretly relays and possibly alters the communications between two parties.",
            "analogy": "Like a postman opening your letters, reading/changing them, and resealing them before delivery.",
            "security": "Encryption (HTTPS/VPN) prevents MitM attacks."
        },
        "sql_injection": {
            "term": "SQL Injection (SQLi)",
            "definition": "A code injection technique used to attack data-driven applications by inserting malicious SQL statements.",
            "analogy": "Like tricking a robot into giving you all the money by saying 'Give me $1 OR give me everything'.",
            "security": "Use prepared statements and parameterized queries to prevent SQLi."
        },
        "brute_force": {
            "term": "Brute Force Attack",
            "definition": "A trial-and-error method used to obtain information such as a user password or personal identification number.",
            "analogy": "Like trying every possible key on a keychain until one opens the door.",
            "security": "Strong passwords and account lockouts mitigate brute force attacks."
        },
        "encryption": {
            "term": "Encryption",
            "definition": "The process of encoding information so that only authorized parties can access it.",
            "analogy": "Like writing a message in a secret code that only the recipient can decode.",
            "security": "Fundamental for data privacy and security."
        },
        "botnet": {
            "term": "Botnet",
            "definition": "A network of private computers infected with malicious software and controlled as a group without the owners' knowledge.",
            "analogy": "Like a zombie army controlled by a master to attack a target.",
            "security": "Botnets are often used for DDoS attacks and spam."
        },
        "zero_day": {
            "term": "Zero-Day Vulnerability",
            "definition": "A software vulnerability that is unknown to the vendor and has no patch available.",
            "analogy": "Like a secret back door in a bank vault that only the thieves know about.",
            "security": "Zero-day attacks are highly dangerous because there is no immediate defense."
        },
        "hash": {
            "term": "Hash Function",
            "definition": "A function that converts an input (or 'message') into a fixed-size string of bytes.",
            "analogy": "Like a digital fingerprint; you can identify the person from the print, but you can't recreate the person from the print.",
            "security": "Used for password storage and verifying file integrity."
        }
    }

    TUTORIALS = {
        "1": {
            "title": "Network Discovery Basics",
            "steps": [
                "We will start by finding your local IP address.",
                "Next, we will identify your network range (e.g., 192.168.1.0/24).",
                "We will send ARP requests to every IP in that range.",
                "Finally, we will list every device that responded."
            ]
        },
        "3": {
            "title": "Port Scanning Explained",
            "steps": [
                "First, we choose a target (e.g., google.com).",
                "We select a list of common ports (22, 80, 443, etc.).",
                "For each port, we send a TCP SYN packet (Knock knock!).",
                "If we get a SYN-ACK back, the port is OPEN (Someone is home!).",
                "If we get a RST back, the port is CLOSED."
            ]
        },
        "5": {
            "title": "DNS Analysis Walkthrough",
            "steps": [
                "We start with a domain name (e.g., example.com).",
                "We query a DNS Resolver (like 8.8.8.8) for records.",
                "A Records show the IPv4 address (Where is the server?).",
                "MX Records show the Mail Servers (Where does email go?).",
                "TXT Records often contain security policies (SPF/DMARC)."
            ]
        },
        "9": {
            "title": "SSL/TLS Security Check",
            "steps": [
                "We connect to the target's HTTPS port (443).",
                "We ask the server to present its Digital Certificate.",
                "We check: Is it expired? Is the issuer trusted?",
                "We check the Encryption Protocol (TLS 1.2/1.3 is good).",
                "We check the Cipher Suite (Is the math strong enough?)."
            ]
        },
        "17": {
            "title": "Packet Sniffing 101",
            "steps": [
                "We put the network card into 'Promiscuous Mode'.",
                "This lets us see ALL traffic, not just traffic for us.",
                "We capture packets flying through the air (Wi-Fi) or wire.",
                "We decode the headers: Source IP, Destination IP, Protocol.",
                "We look at the Payload: Is it encrypted (gibberish) or clear text?"
            ]
        }
    }

    def get_glossary_term(self, term):
        """Get definition for a term."""
        term = term.lower().strip()
        return self.GLOSSARY.get(term)

    def get_all_terms(self):
        """Get list of all glossary terms."""
        return sorted([v["term"] for k, v in self.GLOSSARY.items()])

    def get_tutorial(self, feature_id):
        """Get tutorial for a feature."""
        return self.TUTORIALS.get(str(feature_id))
