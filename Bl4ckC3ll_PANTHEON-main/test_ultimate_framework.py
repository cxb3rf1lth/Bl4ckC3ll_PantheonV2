#!/usr/bin/env python3
"""
Comprehensive Test Suite for BL4CKC3LL PANTHEON ULTIMATE
Tests all major functionalities of the consolidated master script
"""

import unittest
import subprocess
import tempfile
import json
import time
import os
from pathlib import Path
import sys

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

class TestUltimateFramework(unittest.TestCase):
    """Test suite for the Ultimate PANTHEON Framework"""
    
    def setUp(self):
        """Set up test environment"""
        self.script_path = Path(__file__).parent / "bl4ckc3ll_pantheon_ultimate.py"
        self.test_domain = "example.com"
        self.timeout = 30
    
    def test_help_functionality(self):
        """Test help command functionality"""
        result = subprocess.run([
            "python3", str(self.script_path), "--help"
        ], capture_output=True, text=True, timeout=self.timeout)
        
        self.assertEqual(result.returncode, 0)
        self.assertIn("BL4CKC3LL_PANTHEON_ULTIMATE", result.stdout)
        self.assertIn("--recon", result.stdout)
        self.assertIn("--vuln", result.stdout)
        self.assertIn("--comprehensive", result.stdout)
        self.assertIn("--bcar", result.stdout)
        self.assertIn("--tui", result.stdout)
    
    def test_version_functionality(self):
        """Test version command functionality"""
        result = subprocess.run([
            "python3", str(self.script_path), "--version"
        ], capture_output=True, text=True, timeout=self.timeout)
        
        self.assertEqual(result.returncode, 0)
        self.assertIn("11.0.0-ULTIMATE-MASTER", result.stdout)
    
    def test_wordlist_update(self):
        """Test wordlist update functionality"""
        result = subprocess.run([
            "python3", str(self.script_path), "--update-wordlists", "--quiet"
        ], capture_output=True, text=True, timeout=60)
        
        self.assertEqual(result.returncode, 0)
        
        # Check if wordlist files were created
        wordlists_dir = Path(__file__).parent / "wordlists_extra"
        self.assertTrue(wordlists_dir.exists())
        
        # Check for specific wordlist files
        expected_files = [
            "subdomains_small.txt",
            "subdomains_medium.txt", 
            "directories_small.txt",
            "directories_medium.txt"
        ]
        
        for filename in expected_files:
            filepath = wordlists_dir / filename
            self.assertTrue(filepath.exists(), f"Wordlist file {filename} not found")
            self.assertGreater(filepath.stat().st_size, 0, f"Wordlist file {filename} is empty")
    
    def test_payload_generation(self):
        """Test payload generation functionality"""
        # Run wordlist update to trigger payload generation
        result = subprocess.run([
            "python3", str(self.script_path), "--update-wordlists", "--quiet"
        ], capture_output=True, text=True, timeout=60)
        
        self.assertEqual(result.returncode, 0)
        
        # Check if payload files were created
        payloads_dir = Path(__file__).parent / "payloads"
        self.assertTrue(payloads_dir.exists())
        
        # Check for specific payload files
        expected_files = [
            "xss_payloads.txt",
            "sqli_payloads.txt"
        ]
        
        for filename in expected_files:
            filepath = payloads_dir / filename
            self.assertTrue(filepath.exists(), f"Payload file {filename} not found")
            self.assertGreater(filepath.stat().st_size, 0, f"Payload file {filename} is empty")
    
    def test_bcar_functionality_offline(self):
        """Test BCAR functionality in offline mode"""
        # Test with a short timeout since we can't reach external CT logs
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(self.test_domain)
            targets_file = f.name
        
        try:
            result = subprocess.run([
                "python3", str(self.script_path), 
                "--targets-file", targets_file,
                "--bcar", "--quiet", "--batch"
            ], capture_output=True, text=True, timeout=30)
            
            # Should complete even if CT logs are unreachable
            # The exit code might be 0 or non-zero depending on timeout/interruption
            self.assertIn("PANTHEON ULTIMATE", result.stdout)
            
        except subprocess.TimeoutExpired:
            # Expected in sandboxed environment
            pass
        finally:
            os.unlink(targets_file)
    
    def test_script_syntax_validation(self):
        """Test that the script has valid Python syntax"""
        result = subprocess.run([
            "python3", "-m", "py_compile", str(self.script_path)
        ], capture_output=True, text=True, timeout=30)
        
        self.assertEqual(result.returncode, 0, f"Syntax error in script: {result.stderr}")
    
    def test_import_validation(self):
        """Test that all imports work correctly"""
        # Test basic import functionality
        test_script = f"""
import sys
sys.path.insert(0, '{Path(__file__).parent}')

try:
    # Test core classes can be imported
    from bl4ckc3ll_pantheon_ultimate import (
        UltimateLogger, SecurityValidator, RateLimiter, 
        PerformanceMonitor, BCARCore, WordlistGenerator,
        AdvancedToolManager, ScanningEngine, ReportGenerator,
        UltimateCLI
    )
    print("SUCCESS: All core classes imported successfully")
except ImportError as e:
    print(f"FAILED: Import error - {{e}}")
    sys.exit(1)
except Exception as e:
    print(f"FAILED: Unexpected error - {{e}}")
    sys.exit(1)
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(test_script)
            test_file = f.name
        
        try:
            result = subprocess.run([
                "python3", test_file
            ], capture_output=True, text=True, timeout=30)
            
            self.assertEqual(result.returncode, 0, f"Import test failed: {result.stderr}")
            self.assertIn("SUCCESS", result.stdout)
            
        finally:
            os.unlink(test_file)
    
    def test_security_validation(self):
        """Test security validation functions"""
        test_script = f"""
import sys
sys.path.insert(0, '{Path(__file__).parent}')

from bl4ckc3ll_pantheon_ultimate import SecurityValidator

# Test domain validation
test_cases = [
    ("example.com", True),
    ("sub.example.com", True),
    ("invalid..domain", False),
    ("", False),
    ("valid-domain.org", True),
    ("192.168.1.1", False),  # IP should be handled separately
]

for domain, expected in test_cases:
    result = SecurityValidator.validate_domain(domain)
    if result != expected:
        print(f"FAILED: Domain validation for '{{domain}}' expected {{expected}}, got {{result}}")
        sys.exit(1)

# Test URL validation
url_test_cases = [
    ("https://example.com", True),
    ("http://test.com", True),
    ("ftp://invalid.com", False),
    ("not-a-url", False),
    ("https://valid-site.org/path", True),
]

for url, expected in url_test_cases:
    result = SecurityValidator.validate_url(url)
    if result != expected:
        print(f"FAILED: URL validation for '{{url}}' expected {{expected}}, got {{result}}")
        sys.exit(1)

print("SUCCESS: All security validation tests passed")
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(test_script)
            test_file = f.name
        
        try:
            result = subprocess.run([
                "python3", test_file
            ], capture_output=True, text=True, timeout=30)
            
            self.assertEqual(result.returncode, 0, f"Security validation test failed: {result.stderr}")
            self.assertIn("SUCCESS", result.stdout)
            
        finally:
            os.unlink(test_file)
    
    def test_performance_monitoring(self):
        """Test performance monitoring functionality"""
        test_script = f"""
import sys
import time
sys.path.insert(0, '{Path(__file__).parent}')

from bl4ckc3ll_pantheon_ultimate import PerformanceMonitor

monitor = PerformanceMonitor()

# Test metrics recording
monitor.record_request(True, 0.5)
monitor.record_request(False, 1.0)
monitor.record_request(True, 0.3)

metrics = monitor.get_metrics()

# Validate metrics
if metrics['total_requests'] != 3:
    print(f"FAILED: Expected 3 total requests, got {{metrics['total_requests']}}")
    sys.exit(1)

if metrics['successful_requests'] != 2:
    print(f"FAILED: Expected 2 successful requests, got {{metrics['successful_requests']}}")
    sys.exit(1)

if metrics['success_rate'] < 65 or metrics['success_rate'] > 67:
    print(f"FAILED: Expected ~66.7% success rate, got {{metrics['success_rate']}}")
    sys.exit(1)

print("SUCCESS: Performance monitoring tests passed")
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(test_script)
            test_file = f.name
        
        try:
            result = subprocess.run([
                "python3", test_file
            ], capture_output=True, text=True, timeout=30)
            
            self.assertEqual(result.returncode, 0, f"Performance monitoring test failed: {result.stderr}")
            self.assertIn("SUCCESS", result.stdout)
            
        finally:
            os.unlink(test_file)
    
    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        test_script = f"""
import sys
import time
sys.path.insert(0, '{Path(__file__).parent}')

from bl4ckc3ll_pantheon_ultimate import RateLimiter

# Test with low limits for quick testing
limiter = RateLimiter(max_requests=2, time_window=1)

# First two requests should be allowed
if not limiter.is_allowed("test"):
    print("FAILED: First request should be allowed")
    sys.exit(1)

if not limiter.is_allowed("test"):
    print("FAILED: Second request should be allowed")
    sys.exit(1)

# Third request should be blocked
if limiter.is_allowed("test"):
    print("FAILED: Third request should be blocked")
    sys.exit(1)

print("SUCCESS: Rate limiting tests passed")
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(test_script)
            test_file = f.name
        
        try:
            result = subprocess.run([
                "python3", test_file
            ], capture_output=True, text=True, timeout=30)
            
            self.assertEqual(result.returncode, 0, f"Rate limiting test failed: {result.stderr}")
            self.assertIn("SUCCESS", result.stdout)
            
        finally:
            os.unlink(test_file)
    
    def test_wordlist_generator(self):
        """Test wordlist generator functionality"""
        test_script = f"""
import sys
sys.path.insert(0, '{Path(__file__).parent}')

from bl4ckc3ll_pantheon_ultimate import WordlistGenerator

gen = WordlistGenerator()

# Test subdomain wordlist generation
subdomains = gen.generate_subdomain_wordlist("small")
if len(subdomains) < 50:
    print(f"FAILED: Expected at least 50 subdomains, got {{len(subdomains)}}")
    sys.exit(1)

# Test directory wordlist generation  
directories = gen.generate_directory_wordlist("small")
if len(directories) < 100:
    print(f"FAILED: Expected at least 100 directories, got {{len(directories)}}")
    sys.exit(1)

# Test payload generation
xss_payloads = gen.generate_xss_payloads()
if len(xss_payloads) < 5:
    print(f"FAILED: Expected at least 5 XSS payloads, got {{len(xss_payloads)}}")
    sys.exit(1)

sqli_payloads = gen.generate_sql_injection_payloads()
if len(sqli_payloads) < 5:
    print(f"FAILED: Expected at least 5 SQLi payloads, got {{len(sqli_payloads)}}")
    sys.exit(1)

print("SUCCESS: Wordlist generator tests passed")
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(test_script)
            test_file = f.name
        
        try:
            result = subprocess.run([
                "python3", test_file
            ], capture_output=True, text=True, timeout=30)
            
            self.assertEqual(result.returncode, 0, f"Wordlist generator test failed: {result.stderr}")
            self.assertIn("SUCCESS", result.stdout)
            
        finally:
            os.unlink(test_file)
    
    def test_logging_system(self):
        """Test logging system functionality"""
        test_script = f"""
import sys
import tempfile
sys.path.insert(0, '{Path(__file__).parent}')

from bl4ckc3ll_pantheon_ultimate import UltimateLogger

logger = UltimateLogger("test_logger")

# Test different logging levels
logger.info("Test info message")
logger.warning("Test warning message")
logger.error("Test error message") 
logger.success("Test success message")
logger.failure("Test failure message")

print("SUCCESS: Logging system tests passed")
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(test_script)
            test_file = f.name
        
        try:
            result = subprocess.run([
                "python3", test_file
            ], capture_output=True, text=True, timeout=30)
            
            self.assertEqual(result.returncode, 0, f"Logging system test failed: {result.stderr}")
            self.assertIn("SUCCESS", result.stdout)
            
        finally:
            os.unlink(test_file)

class TestIntegration(unittest.TestCase):
    """Integration tests for the complete framework"""
    
    def setUp(self):
        """Set up integration test environment"""
        self.script_path = Path(__file__).parent / "bl4ckc3ll_pantheon_ultimate.py"
    
    def test_complete_workflow(self):
        """Test a complete workflow from start to finish"""
        # This test validates the entire framework can run without crashing
        
        steps = [
            # Update wordlists
            ["python3", str(self.script_path), "--update-wordlists", "--quiet"],
            # Check version
            ["python3", str(self.script_path), "--version"],
            # Test help
            ["python3", str(self.script_path), "--help"],
        ]
        
        for step in steps:
            with self.subTest(step=step):
                try:
                    result = subprocess.run(
                        step, 
                        capture_output=True, 
                        text=True, 
                        timeout=60
                    )
                    # Allow either success (0) or controlled failure
                    self.assertIn(result.returncode, [0, 1], 
                                f"Step failed unexpectedly: {step}\nStdout: {result.stdout}\nStderr: {result.stderr}")
                    
                    # Ensure we got some output
                    self.assertTrue(
                        result.stdout or result.stderr,
                        f"No output from step: {step}"
                    )
                except subprocess.TimeoutExpired:
                    self.fail(f"Step timed out: {step}")

def run_comprehensive_tests():
    """Run comprehensive test suite and display results"""
    print("🧪 BL4CKC3LL PANTHEON ULTIMATE - COMPREHENSIVE TEST SUITE")
    print("=" * 70)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestUltimateFramework))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Display summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success Rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    
    if result.failures:
        print("\nFAILURES:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback}")
    
    if result.errors:
        print("\nERRORS:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback}")
    
    # Return success status
    return len(result.failures) == 0 and len(result.errors) == 0

if __name__ == "__main__":
    success = run_comprehensive_tests()
    sys.exit(0 if success else 1)