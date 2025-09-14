#!/usr/bin/env python3
"""Test script to validate Bl4ckC3ll_PANTHEON installation"""

import sys
import subprocess
import shutil
from pathlib import Path

def test_python_deps():
    """Test Python dependencies"""
    try:
        import psutil
        import distro
        print("✓ Python dependencies available")
        return True
    except ImportError as e:
        print(f"✗ Python dependency missing: {e}")
        return False

def test_go_tools():
    """Test Go tools availability"""
    tools = ['subfinder', 'httpx', 'naabu', 'nuclei', 'katana', 'gau']
    available = []
    
    for tool in tools:
        if shutil.which(tool):
            available.append(tool)
    
    print(f"✓ {len(available)}/{len(tools)} Go tools available: {', '.join(available)}")
    return len(available) > 0

def test_main_script():
    """Test main script syntax"""
    try:
        result = subprocess.run([sys.executable, '-m', 'py_compile', 'bl4ckc3ll_p4nth30n.py'], 
                               capture_output=True, text=True)
        if result.returncode == 0:
            print("✓ Main script syntax is valid")
            return True
        else:
            print(f"✗ Main script syntax error: {result.stderr}")
            return False
    except Exception as e:
        print(f"✗ Error testing main script: {e}")
        return False

def test_nuclei_templates():
    """Test nuclei templates availability"""
    templates_dir = Path("nuclei-templates")
    if templates_dir.exists():
        template_count = len(list(templates_dir.rglob("*.yaml")))
        print(f"✓ {template_count} nuclei templates found")
        return True
    else:
        print("✗ No nuclei templates directory found")
        return False

def test_wordlists():
    """Test wordlists availability"""
    wordlists_dir = Path("wordlists_extra")
    if wordlists_dir.exists():
        wordlist_count = len(list(wordlists_dir.glob("*.txt")))
        print(f"✓ {wordlist_count} wordlists available")
        return True
    else:
        print("✗ No wordlists directory found")
        return False

if __name__ == "__main__":
    print("Testing Bl4ckC3ll_PANTHEON installation...\n")
    
    tests = [
        test_python_deps,
        test_go_tools, 
        test_main_script,
        test_nuclei_templates,
        test_wordlists
    ]
    
    passed = 0
    for test in tests:
        if test():
            passed += 1
        print()
    
    print(f"Tests passed: {passed}/{len(tests)}")
    
    if passed == len(tests):
        print("🎉 Installation appears to be successful!")
        sys.exit(0)
    elif passed >= 3:
        print("⚠️  Installation mostly successful with some optional components missing.")
        sys.exit(0)
    else:
        print("⚠️  Some critical tests failed. Check the output above.")
        sys.exit(1)