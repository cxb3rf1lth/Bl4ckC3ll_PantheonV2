#!/usr/bin/env python3
"""
Enhanced Comprehensive Test Suite for Bl4ckC3ll_PANTHEON
Tests all new features and improvements including CLI, wordlists, and scanning
"""

import unittest
import subprocess
import json
import time
import tempfile
import os
from pathlib import Path
import sys

# Add the main directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

class TestEnhancedCLI(unittest.TestCase):
    """Test enhanced CLI functionality"""
    
    def setUp(self):
        self.script_path = Path(__file__).parent / "bl4ckc3ll_p4nth30n.py"
        self.test_targets = ["test.example.com", "127.0.0.1"]
        
    def test_cli_help(self):
        """Test CLI help functionality"""
        result = subprocess.run([
            "python3", str(self.script_path), "--help"
        ], capture_output=True, text=True, timeout=30)
        
        self.assertEqual(result.returncode, 0)
        self.assertIn("Bl4ckC3ll_PANTHEON", result.stdout)
        self.assertIn("--recon", result.stdout)
        self.assertIn("--vuln", result.stdout)
        self.assertIn("--output", result.stdout)
    
    def test_tool_check(self):
        """Test tool availability check"""
        result = subprocess.run([
            "python3", str(self.script_path), "--check-tools"
        ], capture_output=True, text=True, timeout=60)
        
        self.assertEqual(result.returncode, 0)
        self.assertIn("Security tools available:", result.stderr)
    
    def test_wordlist_update(self):
        """Test wordlist update functionality"""
        result = subprocess.run([
            "python3", str(self.script_path), "--update-wordlists"
        ], capture_output=True, text=True, timeout=60)
        
        self.assertEqual(result.returncode, 0)

class TestEnhancedWordlists(unittest.TestCase):
    """Test enhanced wordlist generation"""
    
    def setUp(self):
        self.wordlists_dir = Path(__file__).parent / "wordlists_extra"
        self.payloads_dir = Path(__file__).parent / "payloads"
    
    def test_wordlists_exist(self):
        """Test that enhanced wordlists were created"""
        expected_wordlists = [
            "technology_php.txt",
            "technology_python.txt",
            "technology_nodejs.txt",
            "cloud_aws.txt",
            "cloud_azure.txt",
            "api_endpoints.txt",
            "security_admin_panels.txt",
            "security_login_pages.txt"
        ]
        
        for wordlist in expected_wordlists:
            wordlist_path = self.wordlists_dir / wordlist
            self.assertTrue(wordlist_path.exists(), f"Wordlist {wordlist} should exist")
            
            # Check that wordlist has content
            with open(wordlist_path, 'r') as f:
                content = f.read().strip()
                self.assertTrue(len(content) > 0, f"Wordlist {wordlist} should not be empty")
    
    def test_payloads_exist(self):
        """Test that enhanced payloads were created"""
        expected_payloads = [
            "xss_payloads.txt",
            "sqli_payloads.txt",
            "command_injection_payloads.txt",
            "lfi_payloads.txt",
            "comprehensive_payloads.json"
        ]
        
        for payload_file in expected_payloads:
            payload_path = self.payloads_dir / payload_file
            self.assertTrue(payload_path.exists(), f"Payload file {payload_file} should exist")
            
            # Check that payload file has content
            with open(payload_path, 'r') as f:
                content = f.read().strip()
                self.assertTrue(len(content) > 0, f"Payload file {payload_file} should not be empty")
    
    def test_comprehensive_payloads_structure(self):
        """Test comprehensive payloads JSON structure"""
        comprehensive_file = self.payloads_dir / "comprehensive_payloads.json"
        self.assertTrue(comprehensive_file.exists())
        
        with open(comprehensive_file, 'r') as f:
            payloads_data = json.load(f)
        
        expected_keys = ['xss', 'sqli', 'command_injection', 'lfi', 'technology_wordlists']
        for key in expected_keys:
            self.assertIn(key, payloads_data, f"Key {key} should exist in comprehensive payloads")
            self.assertTrue(len(payloads_data[key]) > 0, f"Section {key} should not be empty")

class TestEnhancedScanning(unittest.TestCase):
    """Test enhanced scanning capabilities"""
    
    def setUp(self):
        self.scanning_module = Path(__file__).parent / "enhanced_scanning.py"
    
    def test_scanning_module_import(self):
        """Test that enhanced scanning module can be imported"""
        try:
            import enhanced_scanning
            self.assertTrue(hasattr(enhanced_scanning, 'AdaptiveScanManager'))
            self.assertTrue(hasattr(enhanced_scanning, 'run_enhanced_scanning'))
        except ImportError as e:
            self.fail(f"Failed to import enhanced scanning module: {e}")
    
    def test_adaptive_scan_manager_init(self):
        """Test AdaptiveScanManager initialization"""
        try:
            import enhanced_scanning
            config = {'scan_depth': 3, 'max_threads': 10, 'rate_limit': 5}
            manager = enhanced_scanning.AdaptiveScanManager(config)
            
            self.assertEqual(manager.scan_depth, 3)
            self.assertEqual(manager.max_threads, 10)
            self.assertEqual(manager.rate_limit, 5)
            self.assertTrue(hasattr(manager, 'wordlists'))
            self.assertTrue(hasattr(manager, 'payloads'))
        except Exception as e:
            self.fail(f"Failed to initialize AdaptiveScanManager: {e}")

class TestOutputFormats(unittest.TestCase):
    """Test different output formats"""
    
    def setUp(self):
        self.script_path = Path(__file__).parent / "bl4ckc3ll_p4nth30n.py"
        self.temp_dir = Path(tempfile.mkdtemp())
    
    def tearDown(self):
        # Clean up temporary files
        import shutil
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
    
    def test_json_output_format(self):
        """Test JSON output format"""
        output_file = self.temp_dir / "test_output.json"
        
        # Create a simple test targets file
        targets_file = self.temp_dir / "targets.txt"
        with open(targets_file, 'w') as f:
            f.write("test.example.com\n")
        
        result = subprocess.run([
            "python3", str(self.script_path),
            "-t", str(targets_file),
            "--batch", "--recon",
            "--output", "json",
            "--outfile", str(output_file),
            "--quiet"
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0 and output_file.exists():
            # Check if output is valid JSON
            try:
                with open(output_file, 'r') as f:
                    json.load(f)
            except json.JSONDecodeError:
                self.fail("Output is not valid JSON")

class TestIntegration(unittest.TestCase):
    """Test integration between components"""
    
    def test_bcar_integration(self):
        """Test BCAR integration"""
        try:
            import bl4ckc3ll_p4nth30n as main_script
            self.assertTrue(hasattr(main_script, 'BCAR_AVAILABLE'))
        except ImportError as e:
            self.fail(f"Failed to import main script: {e}")
    
    def test_enhanced_wordlist_integration(self):
        """Test enhanced wordlist integration with main script"""
        try:
            import enhanced_wordlists
            # Test that we can generate wordlists
            generator = enhanced_wordlists.EnhancedWordlistGenerator()
            tech_wordlists = generator.generate_technology_specific_wordlists()
            self.assertTrue(len(tech_wordlists) > 0)
            self.assertIn('php', tech_wordlists)
        except Exception as e:
            self.fail(f"Enhanced wordlist integration failed: {e}")

class TestPerformance(unittest.TestCase):
    """Test performance aspects"""
    
    def test_startup_time(self):
        """Test that script starts up in reasonable time"""
        start_time = time.time()
        
        result = subprocess.run([
            "python3", str(Path(__file__).parent / "bl4ckc3ll_p4nth30n.py"),
            "--help"
        ], capture_output=True, text=True, timeout=30)
        
        end_time = time.time()
        startup_time = end_time - start_time
        
        self.assertEqual(result.returncode, 0)
        self.assertLess(startup_time, 10, "Startup time should be less than 10 seconds")
    
    def test_wordlist_generation_performance(self):
        """Test wordlist generation performance"""
        start_time = time.time()
        
        result = subprocess.run([
            "python3", str(Path(__file__).parent / "enhanced_wordlists.py")
        ], capture_output=True, text=True, timeout=60)
        
        end_time = time.time()
        generation_time = end_time - start_time
        
        self.assertEqual(result.returncode, 0)
        self.assertLess(generation_time, 30, "Wordlist generation should complete in less than 30 seconds")

class TestErrorHandling(unittest.TestCase):
    """Test error handling and edge cases"""
    
    def setUp(self):
        self.script_path = Path(__file__).parent / "bl4ckc3ll_p4nth30n.py"
    
    def test_invalid_target(self):
        """Test handling of invalid targets"""
        result = subprocess.run([
            "python3", str(self.script_path),
            "-t", "invalid..domain..name",
            "--batch", "--recon", "--quiet"
        ], capture_output=True, text=True, timeout=30)
        
        # Should handle gracefully (return code 1 is acceptable for invalid input)
        self.assertIn(result.returncode, [0, 1])
    
    def test_nonexistent_targets_file(self):
        """Test handling of non-existent targets file"""
        result = subprocess.run([
            "python3", str(self.script_path),
            "-t", "/nonexistent/file.txt",
            "--batch", "--recon", "--quiet"
        ], capture_output=True, text=True, timeout=30)
        
        # Should handle gracefully (return code 1 is acceptable for file not found)
        self.assertIn(result.returncode, [0, 1])
    
    def test_conflicting_options(self):
        """Test handling of conflicting CLI options"""
        result = subprocess.run([
            "python3", str(self.script_path),
            "--interactive", "--batch",
            "-t", "test.example.com"
        ], capture_output=True, text=True, timeout=30)
        
        # Should handle gracefully
        self.assertIn(result.returncode, [0, 1, 2])

def run_comprehensive_tests():
    """Run all test suites"""
    print("🧪 Starting Enhanced Comprehensive Test Suite for Bl4ckC3ll_PANTHEON")
    print("=" * 70)
    
    # Test suites to run
    test_suites = [
        TestEnhancedCLI,
        TestEnhancedWordlists,
        TestEnhancedScanning,
        TestOutputFormats,
        TestIntegration,
        TestPerformance,
        TestErrorHandling
    ]
    
    all_results = []
    total_tests = 0
    total_failures = 0
    total_errors = 0
    
    for test_suite_class in test_suites:
        print(f"\n🔍 Running {test_suite_class.__name__}...")
        
        # Create test suite
        suite = unittest.TestLoader().loadTestsFromTestCase(test_suite_class)
        
        # Run tests
        runner = unittest.TextTestRunner(verbosity=1, stream=open(os.devnull, 'w'))
        result = runner.run(suite)
        
        # Collect results
        suite_tests = result.testsRun
        suite_failures = len(result.failures)
        suite_errors = len(result.errors)
        suite_success = suite_tests - suite_failures - suite_errors
        
        total_tests += suite_tests
        total_failures += suite_failures
        total_errors += suite_errors
        
        # Print results
        if suite_failures == 0 and suite_errors == 0:
            print(f"✅ {test_suite_class.__name__}: {suite_success}/{suite_tests} tests passed")
        else:
            print(f"❌ {test_suite_class.__name__}: {suite_success}/{suite_tests} tests passed, {suite_failures} failures, {suite_errors} errors")
            
            # Print failure details
            for failure in result.failures:
                print(f"   FAIL: {failure[0]}")
                print(f"   {failure[1].split('AssertionError:')[-1].strip()}")
            
            for error in result.errors:
                print(f"   ERROR: {error[0]}")
                print(f"   {error[1].split('Exception:')[-1].strip()}")
        
        all_results.append({
            'suite': test_suite_class.__name__,
            'tests': suite_tests,
            'success': suite_success,
            'failures': suite_failures,
            'errors': suite_errors
        })
    
    # Print summary
    print("\n" + "=" * 70)
    print("📊 ENHANCED TEST SUMMARY")
    print("=" * 70)
    
    success_rate = ((total_tests - total_failures - total_errors) / total_tests * 100) if total_tests > 0 else 0
    
    print(f"Total Tests Run: {total_tests}")
    print(f"Successful: {total_tests - total_failures - total_errors}")
    print(f"Failures: {total_failures}")
    print(f"Errors: {total_errors}")
    print(f"Success Rate: {success_rate:.1f}%")
    
    if total_failures == 0 and total_errors == 0:
        print("\n🎉 All tests passed! Enhanced Bl4ckC3ll_PANTHEON is ready for production.")
        return True
    else:
        print(f"\n⚠️ {total_failures + total_errors} test(s) failed. Please review and fix issues.")
        return False

if __name__ == "__main__":
    success = run_comprehensive_tests()
    sys.exit(0 if success else 1)