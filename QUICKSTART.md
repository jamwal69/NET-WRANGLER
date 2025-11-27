# 🚀 NET-WRANGLER v3.0 - Quick Start Guide

## Installation

```powershell
# Install required packages
pip install -r requirements.txt

# Optional: For full ML features (recommended via conda on Windows)
conda install numpy scikit-learn
```

## First Launch

```powershell
# Run NET-WRANGLER v3.0
python net_wrangler_v3.py
```

## Configuration (Optional)

Configure API keys for threat intelligence:

```powershell
# In the CLI, type 'config' and follow prompts
# Or manually edit config.ini:

[API_KEYS]
abuseipdb_key = YOUR_ABUSEIPDB_KEY
shodan_key = YOUR_SHODAN_KEY
virustotal_key = YOUR_VIRUSTOTAL_KEY
```

## Key Features Quick Reference

### 🔍 Reconnaissance (Features 1-8)
```
1  - Network Discovery (ARP Scan)      | Find devices on local network
2  - Ping Sweep                        | Fast host discovery
3  - TCP Port Scan                     | Identify open ports and services
5  - DNS Lookup                        | Domain intelligence gathering
```

### 🔒 Security Analysis (Features 9-12)
```
9  - SSL/TLS Analysis                  | Certificate inspection
10 - HTTP Security Headers             | Web security audit
12 - WAF Detection                     | Detect Cloudflare, AWS WAF, etc.
```

### ☁️ Cloud & Modern Security (Features 13-15)
```
13 - Cloud Storage Auditor             | Scan S3/Azure/GCP buckets
14 - Subdomain Enumeration             | Certificate Transparency logs
15 - Threat Intelligence               | IP reputation checking
```

### 🤖 AI-Powered (Features 16-17)
```
16 - Traffic Anomaly Detection         | C2 beaconing detection
17 - 2030 Future Features              | Quantum-safe, zero-trust, predictive
```

## Example Usage

### Scan Your Network
```
1. Select option '1' (ARP Scan)
2. Press Enter to scan default network range
3. View discovered devices with threat scores
```

### Check for Exposed Cloud Buckets
```
1. Select option '13' (Cloud Storage Auditor)
2. Enter domain (e.g., example.com)
3. Wait for scan to complete
4. Review any exposed buckets found
```

### Enumerate Subdomains
```
1. Select option '14' (Subdomain Enumeration)
2. Enter domain (e.g., example.com)
3. View categorized subdomains (dev/staging/prod/api/admin)
```

### Detect WAF
```
1. Select option '12' (WAF Detection)
2. Enter URL (e.g., https://example.com)
3. View WAF type and confidence score
```

### AI Anomaly Detection
```
1. Select option '16' (Anomaly Detection)
2. Wait 60 seconds for baseline collection
3. View C2 beaconing patterns detected
```

### 2030 Future Features
```
1. Select option '17' (Future Features)
2. Enter target domain/IP
3. View:
   - Quantum-safe cryptography check
   - Zero-trust security score
   - Predictive threat analysis
```

## Getting Help

```
# In the CLI:
help 1      # Get help for feature #1
help cloud  # Get help for cloud features
help threat # Get help for threat intelligence
help waf    # Get help for WAF detection
```

## Testing

```powershell
# Run comprehensive test suite
python dynamic_testing.py

# Run specific v2.0 tests
python test_features.py

# Test help system
python test_help.py
```

## Troubleshooting

### Issue: numpy warnings on Windows
**Solution**: Install via conda for better Windows support
```powershell
conda install numpy scikit-learn
```

### Issue: "Not running with admin privileges"
**Solution**: Run PowerShell as Administrator for full features
```powershell
# Right-click PowerShell → Run as Administrator
```

### Issue: API features not working
**Solution**: Configure API keys via 'config' command

### Issue: Encoding errors
**Solution**: Ensure Python files are UTF-8 encoded
```powershell
# Add to top of .py files:
# -*- coding: utf-8 -*-
```

## Best Practices

### 🛡️ Security
- Always get permission before scanning external targets
- Use stealth mode for sensitive operations
- Rotate API keys regularly
- Review threat intelligence before taking action

### ⚡ Performance
- Use threading for large network scans
- Limit concurrent connections (default: 100)
- Adjust timeout values in config for slow networks

### 📊 Monitoring
- Enable logging for audit trails
- Export reports for documentation
- Use continuous monitoring features for real-time detection

## API Key Resources

### AbuseIPDB
1. Sign up at https://www.abuseipdb.com/
2. Generate API key
3. Free tier: 1,000 requests/day

### Shodan
1. Sign up at https://www.shodan.io/
2. Get API key from account page
3. Free tier: 100 requests/month

### VirusTotal
1. Sign up at https://www.virustotal.com/
2. Get API key
3. Free tier: 4 requests/minute

## Advanced Usage

### Custom Scanning
```python
from net_wrangler_v3 import NetWranglerV3

nw = NetWranglerV3()
results = nw.arp_scan("192.168.1.0/24")
for host in results:
    print(f"{host.ip} - {host.hostname}")
```

### Enterprise Features
```python
from enterprise_features import CloudStorageAuditor, WAFDetector

# Scan cloud storage
auditor = CloudStorageAuditor()
results = auditor.scan_domain("example.com")

# Detect WAF
detector = WAFDetector()
waf_info = detector.detect_waf("https://example.com")
```

## Command Reference

| Command | Description |
|---------|-------------|
| `1-25` | Select feature by number |
| `help <#>` | Show detailed help for feature |
| `config` | Configure API keys and settings |
| `exit` | Exit NET-WRANGLER |

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Ctrl+C` | Cancel current operation |
| `Enter` | Continue after results |
| `Ctrl+D` | Exit (Linux/Mac) |

## Pro Tips

1. **Start with ARP scan** to map your network before other scans
2. **Use threat intelligence** to prioritize investigation targets
3. **Enable stealth mode** when scanning sensitive targets
4. **Check WAF first** before attempting vulnerability scans
5. **Run anomaly detection** during normal operations to establish baseline
6. **Export results** for documentation and reporting
7. **Use help system** extensively - it contains valuable security insights

## Next Steps

After getting comfortable with basic features:
1. Configure all API keys for full functionality
2. Run comprehensive scans on test environments
3. Set up continuous monitoring
4. Integrate with your security workflow
5. Contribute improvements to the project

## Support

- **GitHub Issues**: Report bugs and feature requests
- **Documentation**: See IMPLEMENTATION_SUMMARY.md
- **Help System**: Use `help <feature>` in CLI
- **Testing**: Run `python dynamic_testing.py` for validation

---

**Happy Hacking! 🎉**

Remember: Use responsibly and ethically. Always obtain proper authorization.
