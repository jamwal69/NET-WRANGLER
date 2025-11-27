#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NET-WRANGLER - Run Script
Choose between v2.0 (stable) or v3.0 (enterprise)
"""

import sys
import os

def main():
    print("\n" + "="*60)
    print("NET-WRANGLER - Network Security Suite")
    print("="*60 + "\n")
    
    print("Select version to run:\n")
    print("1. NET-WRANGLER v2.0 (Stable - 19 features)")
    print("2. NET-WRANGLER v3.0 Enterprise (33 features)")
    print("3. Test Enterprise Features Only")
    print("0. Exit\n")
    
    choice = input("Choice: ").strip()
    
    if choice == "1":
        print("\nLaunching NET-WRANGLER v2.0...\n")
        os.system("python net_wrangler.py")
    elif choice == "2":
        print("\nLaunching NET-WRANGLER v3.0 Enterprise...\n")
        # Try to run v3.0
        try:
            os.system("python net_wrangler_v3.py")
        except Exception as e:
            print(f"Error: {e}")
            print("Falling back to v2.0...")
            os.system("python net_wrangler.py")
    elif choice == "3":
        print("\nTesting Enterprise Features...\n")
        try:
            from enterprise_features import (
                CloudStorageAuditor,
                SubdomainEnumerator,
                WAFDetector,
                AnomalyDetector,
                FutureSecurityFeatures
            )
            from rich.console import Console
            from rich.panel import Panel
            
            console = Console()
            
            console.print(Panel("[bold green]Enterprise Features Loaded Successfully![/bold green]", 
                               title="Status", border_style="green"))
            
            # Run quick test
            console.print("\n[bold cyan]Available 2030 Features:[/bold cyan]")
            console.print("  1. Quantum-Safe Crypto Analysis")
            console.print("  2. Zero-Trust Assessment")
            console.print("  3. Blockchain Security")
            console.print("  4. AI Threat Hunting")
            console.print("  5. Container Security")
            console.print("  6. API Security")
            console.print("  7. Supply Chain Analysis")
            console.print("  8. Predictive Threat Modeling")
            
            console.print("\n[yellow]Enter target domain to test:[/yellow]")
            target = input("Target: ").strip() or "example.com"
            
            # Run tests
            console.print(f"\n[bold]Testing features on: {target}[/bold]\n")
            
            future = FutureSecurityFeatures()
            
            # Quantum check
            console.print("[cyan]1. Quantum-Safe Crypto Check...[/cyan]")
            result = future.check_quantum_safe_crypto(target)
            console.print(f"   Quantum-Safe: {result['quantum_safe']}")
            
            # Zero-Trust
            console.print("[cyan]2. Zero-Trust Assessment...[/cyan]")
            result = future.analyze_zero_trust_posture(target)
            console.print(f"   Score: {result['zero_trust_score']}/100")
            
            # Blockchain
            console.print("[cyan]3. Blockchain Security...[/cyan]")
            result = future.blockchain_security_analysis(target)
            console.print(f"   Web3 Score: {result['web3_security_score']}/100")
            
            # Container
            console.print("[cyan]4. Container Security...[/cyan]")
            result = future.container_security_scan("nginx:latest")
            console.print(f"   Risk Score: {result['risk_score']}/100")
            
            # API
            console.print("[cyan]5. API Security...[/cyan]")
            result = future.api_security_assessment(f"https://{target}")
            console.print(f"   Security Score: {result['security_score']}/100")
            
            # Supply Chain
            console.print("[cyan]6. Supply Chain...[/cyan]")
            result = future.supply_chain_security_analysis(target)
            console.print(f"   Risk Score: {result['risk_score']}/100")
            
            # Predictive
            console.print("[cyan]7. Predictive Threat...[/cyan]")
            result = future.predictive_threat_score("8.8.8.8")
            console.print(f"   Threat Probability: {result['threat_probability']}%")
            
            console.print("\n[bold green]All 2030 features working![/bold green]\n")
            
        except Exception as e:
            print(f"Error testing enterprise features: {e}")
            import traceback
            traceback.print_exc()
    elif choice == "0":
        print("\nGoodbye!\n")
        sys.exit(0)
    else:
        print("\nInvalid choice. Please try again.\n")
        main()

if __name__ == "__main__":
    main()
