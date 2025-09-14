#!/usr/bin/env python3
"""
Enhanced Automation Integration Test Suite
Tests the new ESLint integration, bug bounty commands, and automated testing chain
"""

import os
import sys
import pytest
import json
import subprocess
import tempfile
from pathlib import Path


def test_eslint_integration():
    """Test ESLint integration and configuration"""
    print("Testing ESLint integration...")

    # Check package.json exists
    package_json = Path("package.json")
    assert package_json.exists(), "package.json not found"

    with open(package_json, "r") as f:
        pkg_data = json.load(f)

    # Check required scripts
    scripts = pkg_data.get("scripts", {})
    required_scripts = ["lint", "lint:check", "lint:security"]

    for script in required_scripts:
        assert script in scripts, f"Missing npm script: {script}"

    # Check ESLint configuration files
    eslint_configs = [".eslintrc.json", ".eslintrc-security.json"]
    for config in eslint_configs:
        assert Path(config).exists(), f"Missing ESLint config: {config}"

    print("✓ ESLint integration configuration validated")
    return True


def test_bug_bounty_script():
    """Test bug bounty commands script"""
    print("Testing bug bounty commands script...")

    script_path = Path("bug_bounty_commands.sh")
    assert script_path.exists(), "bug_bounty_commands.sh not found"

    # Check script is executable
    assert os.access(script_path, os.X_OK), "bug_bounty_commands.sh is not executable"

    # Test script syntax
    result = subprocess.run(["bash", "-n", str(script_path)], capture_output=True, text=True, timeout=300)

    assert result.returncode == 0, f"Script syntax error: {result.stderr}"

    # Check for required functions
    with open(script_path, "r") as f:
        content = f.read()

    required_functions = ["subdomain_enum", "port_scan", "http_probe", "vuln_scan", "generate_report"]

    for func in required_functions:
        assert func in content, f"Missing function: {func}"

    print("✓ Bug bounty script validated")
    return True


def test_enhanced_application_features():
    """Test enhanced application features"""
    print("Testing enhanced application features...")

    try:
        # Import main application
        sys.path.insert(0, str(Path(__file__).parent))
        import bl4ckc3ll_p4nth30n as main

        # Check for new functions
        required_functions = [
            "run_eslint_security_check",
            "run_bug_bounty_automation",
            "run_automated_testing_chain",
            "enhanced_subdomain_enum",
            "enhanced_port_scanning",
            "enhanced_tech_detection",
            "enhanced_web_crawling",
        ]

        for func_name in required_functions:
            assert hasattr(main, func_name), f"✗ Missing function: {func_name}"

        print("✓ Test passed")
        return True

    except Exception as e:
        pytest.fail(f"Test failed: {e}")


def test_github_workflow_integration():
    """Test GitHub Actions workflow integration"""
    print("Testing GitHub Actions workflow integration...")

    workflow_path = Path(".github/workflows/security_scan.yml")
    assert workflow_path.exists(), "✗ GitHub workflow file not found"

    try:
        with open(workflow_path, "r") as f:
            workflow_content = f.read()

        # Check for enhanced features
        required_elements = [
            "eslint-security",
            "Install ESLint dependencies",
            "Run ESLint security check",
            "Enhanced Testing Chain",
            "Bug Bounty Automation",
            "bug-bounty",
            "automated-chain",
        ]

        for element in required_elements:
            assert element in workflow_content, f"✗ Missing workflow element: {element}"

        print("✓ Test passed")
        return True

    except Exception as e:
        pytest.fail(f"Test failed: {e}")


def test_automation_chain_integration():
    """Test that all automation components integrate properly"""
    print("Testing automation chain integration...")

    try:
        # Check configuration consistency
        config_path = Path("p4nth30n.cfg.json")
        if config_path.exists():
            with open(config_path, "r") as f:
                config = json.load(f)

            # Verify enhanced configuration sections
            enhanced_sections = ["eslint", "bug_bounty", "automation_chain"]
            for section in enhanced_sections:
                if section not in config:
                    # This is not a failure, just a note
                    print(f"ℹ Configuration section '{section}' not found (optional)")

        # Test file dependencies
        critical_files = [
            "package.json",
            ".eslintrc.json",
            "bug_bounty_commands.sh",
            ".github/workflows/security_scan.yml",
        ]

        for file_path in critical_files:
            assert Path(file_path).exists(), f"✗ Critical file missing: {file_path}"

        print("✓ Test passed")
        return True

    except Exception as e:
        pytest.fail(f"Test failed: {e}")


def test_security_and_compliance():
    """Test security features and compliance"""
    print("Testing security and compliance...")

    try:
        # Check ESLint security configuration
        eslint_security_config = Path(".eslintrc-security.json")
        if eslint_security_config.exists():
            with open(eslint_security_config, "r") as f:
                config = json.load(f)

            # Verify security plugin is configured
            plugins = config.get("plugins", [])
            assert "security" in plugins, "✗ ESLint security plugin not configured"

            # Check for security rules
            rules = config.get("rules", {})
            security_rules = [rule for rule in rules.keys() if rule.startswith("security/")]
            assert len(security_rules) >= 5, "✗ Insufficient security rules configured"

        # Check bug bounty script security
        bug_bounty_script = Path("bug_bounty_commands.sh")
        if bug_bounty_script.exists():
            with open(bug_bounty_script, "r") as f:
                content = f.read()

            # Check for security practices
            if "set -euo pipefail" not in content:
                print("⚠ Bug bounty script missing bash safety options")

            if "timeout" not in content:
                print("⚠ Bug bounty script missing timeout controls")

        print("✓ Test passed")
        return True

    except Exception as e:
        pytest.fail(f"Test failed: {e}")


def main():
    """Run all automation integration tests"""
    print("🔧 Bl4ckC3ll_PANTHEON Automation Integration Test Suite")
    print("=" * 60)

    tests = [
        ("ESLint Integration", test_eslint_integration),
        ("Bug Bounty Script", test_bug_bounty_script),
        ("Enhanced Application Features", test_enhanced_application_features),
        ("GitHub Workflow Integration", test_github_workflow_integration),
        ("Automation Chain Integration", test_automation_chain_integration),
        ("Security and Compliance", test_security_and_compliance),
    ]

    results = {}

    for test_name, test_func in tests:
        print(f"\n🔍 {test_name}")
        print("-" * 40)
        try:
            result = test_func()
            results[test_name] = result
            status = "✅ PASSED" if result else "❌ FAILED"
            print(f"{status}")
        except Exception as e:
            print(f"❌ FAILED - Exception: {e}")
            results[test_name] = False

    # Summary
    print(f"\n📊 Test Results Summary")
    print("=" * 60)

    passed = sum(1 for result in results.values() if result)
    total = len(results)

    for test_name, result in results.items():
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{test_name}: {status}")

    print(f"\n📈 Overall: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All automation integration tests PASSED!")
        return 0
    else:
        print("⚠️ Some tests failed - review implementation")
        return 1


if __name__ == "__main__":
    sys.exit(main())
