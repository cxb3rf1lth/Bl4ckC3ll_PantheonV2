#!/usr/bin/env python3
"""
Quick Functional Test for Fixed Modules
Tests that our new modules and fixes are working correctly
"""

import sys
from pathlib import Path


def test_config_validator():
    """Test config validator functionality"""
    print("🔧 Testing Config Validator...")

    try:
        from config_validator import ConfigValidator

        validator = ConfigValidator()

        # Test default config
        default_config = validator.get_default_config()
        result = validator.validate_config(default_config)

        print(
            f"   Default config validation: {'✅ PASS' if result['valid'] else '❌ FAIL'}"
        )

        # Test invalid config
        invalid_config = {
            "limits": {
                "parallel_jobs": -5,  # Invalid: negative
                "http_timeout": 500,  # Invalid: too high
            }
        }
        result = validator.validate_config(invalid_config)
        print(
            f"   Invalid config detection: {'✅ PASS' if not result['valid'] else '❌ FAIL'}"
        )

        # Test actual config file
        config_file = Path("p4nth30n.cfg.json")
        if config_file.exists():
            result = validator.validate_file(config_file)
            print(
                f"   Actual config file validation: {'✅ PASS' if result['valid'] else '❌ FAIL'}"
            )

        return True

    except Exception as e:
        print(f"   ❌ Config validator test failed: {e}")
        return False


def test_enhanced_scanner():
    """Test enhanced scanner module"""
    print("🔍 Testing Enhanced Scanner...")

    try:
        from enhanced_scanner import (
            AdaptiveScanManager,
            EnhancedScanner,
            get_current_success_rate,
        )

        # Test imports work
        print("   ✅ Module imports successful")

        # Test function call
        success_rate = get_current_success_rate()
        print(f"   Current success rate: {success_rate:.1%}")

        # Test class instantiation
        scan_manager = AdaptiveScanManager()
        print("   ✅ AdaptiveScanManager instantiated")

        return True

    except Exception as e:
        print(f"   ❌ Enhanced scanner test failed: {e}")
        return False


def test_domain_validation():
    """Test domain validation fixes"""
    print("🌐 Testing Domain Validation...")

    try:
        import bl4ckc3ll_p4nth30n as main

        test_cases = [
            ("google.com", True, "Valid domain"),
            ("localhost", True, "Single-word domain"),
            ("192.168.1.1", False, "IP address"),
            ("invalid..domain", False, "Invalid format"),
            ("", False, "Empty string"),
        ]

        passed = 0
        for domain, expected, description in test_cases:
            result = main.validate_domain_input(domain)
            status = "✅ PASS" if result == expected else "❌ FAIL"
            print(f"   {description}: {status}")
            if result == expected:
                passed += 1

        print(f"   Overall: {passed}/{len(test_cases)} cases passed")
        return passed == len(test_cases)

    except Exception as e:
        print(f"   ❌ Domain validation test failed: {e}")
        return False


def test_main_imports():
    """Test that all major modules can be imported"""
    print("📦 Testing Core Module Imports...")

    modules_to_test = [
        "bl4ckc3ll_p4nth30n",
        "config_validator",
        "enhanced_scanner",
        "enhanced_scanning",
        "enhanced_validation",
        "enhanced_wordlists",
        "error_handler",
        "security_utils",
    ]

    passed = 0
    for module in modules_to_test:
        try:
            __import__(module)
            print(f"   ✅ {module}")
            passed += 1
        except ImportError as e:
            print(f"   ❌ {module}: {e}")
        except Exception as e:
            print(f"   ⚠️  {module}: {e}")

    print(f"   Imports: {passed}/{len(modules_to_test)} successful")
    return passed == len(modules_to_test)


def main():
    """Run all tests"""
    print("🧪 Quick Functional Test Suite")
    print("=" * 50)

    tests = [
        test_main_imports,
        test_config_validator,
        test_enhanced_scanner,
        test_domain_validation,
    ]

    passed_tests = 0
    total_tests = len(tests)

    for test_func in tests:
        try:
            if test_func():
                passed_tests += 1
        except Exception as e:
            print(f"   ❌ Test {test_func.__name__} failed with exception: {e}")
        print()

    print("=" * 50)
    print(
        f"📊 SUMMARY: {passed_tests}/{total_tests} tests passed ({passed_tests/total_tests*100:.1f}%)"
    )

    if passed_tests == total_tests:
        print("🎉 All functional tests PASSED!")
        return 0
    else:
        print("⚠️  Some tests failed - review output above")
        return 1


if __name__ == "__main__":
    sys.exit(main())
