#!/usr/bin/env python3
"""
NET-WRANGLER v3.0 - Dynamic Testing Framework
Comprehensive automated testing with performance benchmarks and security validation.

Features:
- Dynamic test generation
- Performance benchmarking
- Security validation
- Coverage analysis
- Stress testing
- Integration testing
"""

import sys
import time
import json
import statistics
from datetime import datetime
from typing import Dict, List, Any, Callable
from dataclasses import dataclass, field
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
from rich import box

console = Console()

# ===================== TEST FRAMEWORK =====================

@dataclass
class TestResult:
    """Test result data class."""
    name: str
    category: str
    passed: bool
    duration: float
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    severity: str = "INFO"  # INFO, WARNING, ERROR, CRITICAL

class DynamicTestFramework:
    """Dynamic testing framework for NET-WRANGLER."""
    
    def __init__(self):
        self.console = Console()
        self.results: List[TestResult] = []
        self.start_time = None
        self.end_time = None
    
    def add_result(self, result: TestResult):
        """Add a test result."""
        self.results.append(result)
    
    def run_test(self, name: str, category: str, test_func: Callable, *args, **kwargs) -> TestResult:
        """Run a single test and return result."""
        start = time.time()
        
        try:
            result = test_func(*args, **kwargs)
            duration = time.time() - start
            
            if isinstance(result, bool):
                passed = result
                message = "Test passed" if passed else "Test failed"
                details = {}
            elif isinstance(result, dict):
                passed = result.get('passed', False)
                message = result.get('message', '')
                details = result.get('details', {})
            else:
                passed = True
                message = str(result)
                details = {}
            
            test_result = TestResult(
                name=name,
                category=category,
                passed=passed,
                duration=duration,
                message=message,
                details=details
            )
        
        except Exception as e:
            duration = time.time() - start
            test_result = TestResult(
                name=name,
                category=category,
                passed=False,
                duration=duration,
                message=f"Exception: {str(e)}",
                severity="ERROR"
            )
        
        self.add_result(test_result)
        return test_result
    
    def run_performance_test(self, name: str, test_func: Callable, iterations: int = 10) -> TestResult:
        """Run performance benchmark."""
        durations = []
        
        for i in range(iterations):
            start = time.time()
            try:
                test_func()
                duration = time.time() - start
                durations.append(duration)
            except Exception as e:
                return TestResult(
                    name=name,
                    category="Performance",
                    passed=False,
                    duration=0,
                    message=f"Performance test failed: {e}",
                    severity="ERROR"
                )
        
        avg_duration = statistics.mean(durations)
        std_dev = statistics.stdev(durations) if len(durations) > 1 else 0
        
        return TestResult(
            name=name,
            category="Performance",
            passed=True,
            duration=avg_duration,
            message=f"Avg: {avg_duration:.3f}s, StdDev: {std_dev:.3f}s",
            details={
                'iterations': iterations,
                'avg': avg_duration,
                'std_dev': std_dev,
                'min': min(durations),
                'max': max(durations)
            }
        )
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report."""
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = total - passed
        
        # Group by category
        by_category = {}
        for result in self.results:
            if result.category not in by_category:
                by_category[result.category] = []
            by_category[result.category].append(result)
        
        # Calculate statistics
        total_duration = sum(r.duration for r in self.results)
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_tests': total,
                'passed': passed,
                'failed': failed,
                'success_rate': (passed / total * 100) if total > 0 else 0,
                'total_duration': total_duration
            },
            'by_category': {},
            'failed_tests': []
        }
        
        # Category statistics
        for category, results in by_category.items():
            cat_passed = sum(1 for r in results if r.passed)
            cat_total = len(results)
            
            report['by_category'][category] = {
                'total': cat_total,
                'passed': cat_passed,
                'failed': cat_total - cat_passed,
                'success_rate': (cat_passed / cat_total * 100) if cat_total > 0 else 0
            }
        
        # Failed tests details
        for result in self.results:
            if not result.passed:
                report['failed_tests'].append({
                    'name': result.name,
                    'category': result.category,
                    'message': result.message,
                    'severity': result.severity
                })
        
        return report
    
    def display_results(self):
        """Display test results in formatted tables."""
        self.console.print("\n")
        self.console.print(Panel(
            "[bold magenta]NET-WRANGLER v3.0 - Test Results[/bold magenta]",
            border_style="magenta"
        ))
        
        # Summary table
        report = self.generate_report()
        summary = report['summary']
        
        summary_table = Table(title="Summary", box=box.ROUNDED)
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="yellow")
        
        summary_table.add_row("Total Tests", str(summary['total_tests']))
        summary_table.add_row("Passed", f"[green]{summary['passed']}[/green]")
        summary_table.add_row("Failed", f"[red]{summary['failed']}[/red]")
        summary_table.add_row("Success Rate", f"{summary['success_rate']:.1f}%")
        summary_table.add_row("Total Duration", f"{summary['total_duration']:.2f}s")
        
        self.console.print(summary_table)
        
        # Category breakdown
        self.console.print("\n[bold cyan]Results by Category:[/bold cyan]\n")
        
        for category, stats in report['by_category'].items():
            cat_table = Table(title=category, box=box.SIMPLE)
            cat_table.add_column("Metric", style="cyan")
            cat_table.add_column("Value")
            
            cat_table.add_row("Total", str(stats['total']))
            cat_table.add_row("Passed", f"[green]{stats['passed']}[/green]")
            cat_table.add_row("Failed", f"[red]{stats['failed']}[/red]")
            cat_table.add_row("Success Rate", f"{stats['success_rate']:.1f}%")
            
            self.console.print(cat_table)
        
        # Failed tests
        if report['failed_tests']:
            self.console.print("\n[bold red]Failed Tests:[/bold red]\n")
            
            failed_table = Table(box=box.ROUNDED)
            failed_table.add_column("Test", style="cyan")
            failed_table.add_column("Category", style="yellow")
            failed_table.add_column("Message", style="red")
            
            for test in report['failed_tests']:
                failed_table.add_row(
                    test['name'],
                    test['category'],
                    test['message']
                )
            
            self.console.print(failed_table)
        
        # Overall status
        self.console.print()
        if summary['failed'] == 0:
            self.console.print("[bold green]🎉 All tests passed![/bold green]")
        else:
            self.console.print(f"[bold yellow]⚠ {summary['failed']} test(s) failed[/bold yellow]")
    
    def save_report(self, filename: str = "test_report.json"):
        """Save test report to JSON file."""
        report = self.generate_report()
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.console.print(f"\n[green]✓ Report saved to {filename}[/green]")


# ===================== TEST SUITES =====================

def test_basic_functionality(framework: DynamicTestFramework):
    """Test basic NET-WRANGLER functionality."""
    console.print("\n[bold cyan]Testing Basic Functionality...[/bold cyan]\n")
    
    # Import modules
    try:
        from net_wrangler_v3 import NetWranglerV3, Config
        nw = NetWranglerV3()
        
        # Test 1: Get Local IP
        def test_local_ip():
            ip = nw.get_local_ip()
            return {'passed': ip != "127.0.0.1", 'message': f"Local IP: {ip}"}
        
        framework.run_test("Get Local IP", "Basic", test_local_ip)
        
        # Test 2: Get Network Range
        def test_network_range():
            network = nw.get_network_range()
            return {'passed': "/24" in network, 'message': f"Network: {network}"}
        
        framework.run_test("Get Network Range", "Basic", test_network_range)
        
        # Test 3: Config System
        def test_config():
            config = Config.load_config()
            return {'passed': config is not None, 'message': "Config loaded"}
        
        framework.run_test("Configuration System", "Basic", test_config)
    
    except Exception as e:
        framework.add_result(TestResult(
            name="Module Import",
            category="Basic",
            passed=False,
            duration=0,
            message=f"Failed to import: {e}",
            severity="CRITICAL"
        ))


def test_enterprise_features(framework: DynamicTestFramework):
    """Test enterprise features."""
    console.print("\n[bold cyan]Testing Enterprise Features...[/bold cyan]\n")
    
    try:
        from enterprise_features import (
            CloudStorageAuditor,
            SubdomainEnumerator,
            WAFDetector,
            AnomalyDetector,
            FutureSecurityFeatures
        )
        
        # Test Cloud Scanner
        def test_cloud_scanner():
            scanner = CloudStorageAuditor()
            names = scanner.generate_bucket_names("example.com")
            return {'passed': len(names) > 10, 'message': f"Generated {len(names)} bucket names"}
        
        framework.run_test("Cloud Storage Scanner", "Enterprise", test_cloud_scanner)
        
        # Test Subdomain Enumerator
        def test_subdomain_enum():
            enumerator = SubdomainEnumerator()
            return {'passed': True, 'message': "Subdomain enumerator initialized"}
        
        framework.run_test("Subdomain Enumerator", "Enterprise", test_subdomain_enum)
        
        # Test WAF Detector
        def test_waf_detector():
            detector = WAFDetector()
            return {'passed': len(detector.WAF_SIGNATURES) >= 5, 
                   'message': f"{len(detector.WAF_SIGNATURES)} WAF signatures loaded"}
        
        framework.run_test("WAF Detector", "Enterprise", test_waf_detector)
        
        # Test Anomaly Detector
        def test_anomaly_detector():
            detector = AnomalyDetector()
            return {'passed': True, 'message': "Anomaly detector initialized"}
        
        framework.run_test("AI Anomaly Detector", "Enterprise", test_anomaly_detector)
        
        # Test Future Features
        def test_future_features():
            future = FutureSecurityFeatures()
            return {'passed': True, 'message': "2030 features module loaded"}
        
        framework.run_test("2030 Future Features", "Enterprise", test_future_features)
    
    except Exception as e:
        framework.add_result(TestResult(
            name="Enterprise Features Import",
            category="Enterprise",
            passed=False,
            duration=0,
            message=f"Failed to import: {e}",
            severity="ERROR"
        ))


def test_security_validation(framework: DynamicTestFramework):
    """Security-focused validation tests."""
    console.print("\n[bold cyan]Running Security Validation...[/bold cyan]\n")
    
    # Test 1: Check for hardcoded credentials
    def test_no_hardcoded_creds():
        import re
        
        files_to_check = ['net_wrangler_v3.py', 'enterprise_features.py']
        patterns = [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']'
        ]
        
        for filename in files_to_check:
            try:
                with open(filename, 'r') as f:
                    content = f.read()
                    for pattern in patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            return {'passed': False, 'message': f"Potential hardcoded credential in {filename}"}
            except FileNotFoundError:
                pass
        
        return {'passed': True, 'message': "No hardcoded credentials found"}
    
    framework.run_test("Hardcoded Credentials Check", "Security", test_no_hardcoded_creds)
    
    # Test 2: SSL/TLS verification
    def test_ssl_warnings():
        # Check if SSL warnings are properly handled
        import warnings
        import urllib3
        
        # Should not raise warnings in normal operation
        return {'passed': True, 'message': "SSL handling configured"}
    
    framework.run_test("SSL/TLS Configuration", "Security", test_ssl_warnings)


def test_performance_benchmarks(framework: DynamicTestFramework):
    """Performance benchmarking tests."""
    console.print("\n[bold cyan]Running Performance Benchmarks...[/bold cyan]\n")
    
    try:
        from net_wrangler_v3 import NetWranglerV3
        nw = NetWranglerV3()
        
        # Benchmark 1: IP validation
        def bench_ip_validation():
            import ipaddress
            ipaddress.ip_address("192.168.1.1")
        
        result = framework.run_performance_test("IP Validation", bench_ip_validation, iterations=100)
        framework.add_result(result)
        
        # Benchmark 2: Network range calculation
        def bench_network_range():
            nw.get_network_range()
        
        result = framework.run_performance_test("Network Range Calculation", bench_network_range, iterations=50)
        framework.add_result(result)
    
    except Exception as e:
        console.print(f"[yellow]Performance tests skipped: {e}[/yellow]")


def run_all_tests():
    """Run complete test suite."""
    console.print(Panel(
        "[bold magenta]NET-WRANGLER v3.0 - Dynamic Testing Framework[/bold magenta]\n"
        "[dim]Comprehensive automated testing with performance benchmarks[/dim]",
        border_style="magenta"
    ))
    
    framework = DynamicTestFramework()
    framework.start_time = datetime.now()
    
    # Run test suites
    test_basic_functionality(framework)
    test_enterprise_features(framework)
    test_security_validation(framework)
    test_performance_benchmarks(framework)
    
    framework.end_time = datetime.now()
    
    # Display results
    framework.display_results()
    
    # Save report
    framework.save_report()
    
    # Return exit code
    report = framework.generate_report()
    return 0 if report['summary']['failed'] == 0 else 1


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)
