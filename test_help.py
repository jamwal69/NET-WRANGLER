#!/usr/bin/env python3
"""
Quick test of NET-WRANGLER v3.0 Help System
"""

import sys
sys.path.insert(0, '.')

from net_wrangler_v3 import HelpSystem, Console

console = Console()

print("\n" + "="*70)
print("NET-WRANGLER v3.0 - Help System Test")
print("="*70 + "\n")

# Test help for feature 1 (ARP Scan)
print("\n>>> Testing help for 'Network Discovery (ARP Scan)'...\n")
HelpSystem.show_help("1")

input("\nPress Enter to see Cloud Storage help...")

# Test help for Cloud feature
print("\n>>> Testing help for 'Cloud Storage Auditor'...\n")
HelpSystem.show_help("cloud")

input("\nPress Enter to see Threat Intelligence help...")

# Test help for Threat Intel
print("\n>>> Testing help for 'Threat Intelligence'...\n")
HelpSystem.show_help("threat")

print("\n" + "="*70)
print("Help System Test Complete!")
print("="*70)
