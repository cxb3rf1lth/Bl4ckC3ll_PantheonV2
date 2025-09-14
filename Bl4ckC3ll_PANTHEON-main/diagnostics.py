#!/usr/bin/env python3
"""
Bl4ckC3ll_PANTHEON Diagnostics Script
Provides detailed system and installation diagnostics
"""

import sys
import os
import shutil
import subprocess
import platform
from pathlib import Path

def print_header(title):
    print(f"\n{'='*50}")
    print(f"  {title}")
    print(f"{'='*50}")

def print_section(title):
    print(f"\n{'-'*30}")
    print(f"  {title}")
    print(f"{'-'*30}")

def check_status(condition, message):
    status = "✓" if condition else "✗"
    color = "\033[92m" if condition else "\033[91m"
    reset = "\033[0m"
    print(f"{color}{status}{reset} {message}")
    return condition

def run_command(cmd, capture=True):
    """Run command and return result"""
    try:
        if capture:
            # SECURITY FIX: Use argument list instead of shell=True
            import shlex
            cmd_args = shlex.split(cmd) if isinstance(cmd, str) else cmd
            result = subprocess.run(cmd_args, shell=False, capture_output=True, text=True, timeout=10)
            return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
        else:
            import shlex
            cmd_args = shlex.split(cmd) if isinstance(cmd, str) else cmd
            result = subprocess.run(cmd_args, shell=False, timeout=10)
            return result.returncode == 0, "", ""
    except Exception as e:
        return False, "", str(e)

def main():
    print_header("Bl4ckC3ll_PANTHEON Diagnostics")
    
    # System information
    print_section("System Information")
    print(f"Operating System: {platform.system()} {platform.release()}")
    print(f"Architecture: {platform.machine()}")
    print(f"Python Version: {sys.version}")
    print(f"Current Directory: {Path.cwd()}")
    
    # Python environment
    print_section("Python Environment")
    
    # Python version check
    py_version = sys.version_info
    check_status(
        py_version.major >= 3 and py_version.minor >= 9,
        f"Python 3.9+ requirement (found {py_version.major}.{py_version.minor})"
    )
    
    # Pip availability
    pip_available, pip_version, _ = run_command("python3 -m pip --version")
    check_status(pip_available, f"pip available ({pip_version.split()[1] if pip_available else 'Not found'})")
    
    # Python packages
    print_section("Python Dependencies")
    
    packages = {
        'psutil': 'System monitoring',
        'distro': 'OS detection',
        'requests': 'HTTP requests (optional)'
    }
    
    for package, description in packages.items():
        try:
            __import__(package)
            check_status(True, f"{package} - {description}")
        except ImportError:
            check_status(False, f"{package} - {description}")
    
    # Go environment
    print_section("Go Environment")
    
    go_available, go_version, _ = run_command("go version")
    check_status(go_available, f"Go compiler ({go_version if go_available else 'Not found'})")
    
    if go_available:
        gopath = os.environ.get('GOPATH', 'Not set')
        gobin = os.environ.get('GOBIN', 'Not set')
        print(f"  GOPATH: {gopath}")
        print(f"  GOBIN: {gobin}")
        
        # Check Go bin in PATH
        go_bin_path = Path.home() / "go" / "bin"
        path_env = os.environ.get("PATH", "")
        check_status(
            str(go_bin_path) in path_env,
            f"Go bin directory in PATH ({go_bin_path})"
        )
    
    # Security tools
    print_section("Security Tools")
    
    tools = {
        'subfinder': 'Subdomain discovery',
        'httpx': 'HTTP probing',
        'naabu': 'Port scanning',
        'nuclei': 'Vulnerability scanning',
        'katana': 'Web crawling',
        'gau': 'URL gathering',
        'amass': 'Asset discovery (optional)'
    }
    
    available_tools = 0
    for tool, description in tools.items():
        available = shutil.which(tool) is not None
        if available:
            # Get version if possible
            version_available, version_output, _ = run_command(f"{tool} -version 2>/dev/null || {tool} --version 2>/dev/null || echo 'version unknown'")
            version_info = version_output.split('\n')[0] if version_available else 'version unknown'
            check_status(True, f"{tool} - {description} ({version_info})")
            available_tools += 1
        else:
            check_status(False, f"{tool} - {description}")
    
    print(f"\nTotal tools available: {available_tools}/{len(tools)}")
    
    # Essential system tools
    print_section("Essential System Tools")
    
    essential = ['git', 'wget', 'unzip', 'curl']
    for tool in essential:
        available = shutil.which(tool) is not None
        check_status(available, f"{tool}")
    
    # File system checks
    print_section("File System")
    
    script_dir = Path(__file__).parent
    
    # Required files
    required_files = [
        'bl4ckc3ll_p4nth30n.py',
        'requirements.txt',
        'install.sh',
        'quickstart.sh',
        'p4nth30n.cfg.json',
        'targets.txt'
    ]
    
    for file in required_files:
        file_path = script_dir / file
        exists = file_path.exists()
        if exists:
            size = file_path.stat().st_size
            check_status(True, f"{file} ({size} bytes)")
        else:
            check_status(False, f"{file}")
    
    # Directory structure
    directories = [
        'runs', 'logs', 'external_lists', 'lists_merged',
        'payloads', 'exploits', 'plugins', 'backups'
    ]
    
    for directory in directories:
        dir_path = script_dir / directory
        exists = dir_path.exists() and dir_path.is_dir()
        check_status(exists, f"Directory: {directory}")
    
    # Write permissions
    try:
        test_file = script_dir / '.write_test'
        test_file.touch()
        test_file.unlink()
        check_status(True, "Write permissions in script directory")
    except Exception:
        check_status(False, "Write permissions in script directory")
    
    # Configuration validation
    print_section("Configuration")
    
    config_file = script_dir / 'p4nth30n.cfg.json'
    if config_file.exists():
        try:
            import json
            with open(config_file) as f:
                config = json.load(f)
            check_status(True, "Configuration file is valid JSON")
            
            # Check key sections
            required_sections = ['repos', 'limits', 'nuclei', 'report']
            for section in required_sections:
                has_section = section in config
                check_status(has_section, f"Configuration section: {section}")
                
        except json.JSONDecodeError:
            check_status(False, "Configuration file is invalid JSON")
        except Exception as e:
            check_status(False, f"Configuration file error: {e}")
    else:
        check_status(False, "Configuration file missing")
    
    # Network connectivity
    print_section("Network Connectivity")
    
    # Test basic connectivity
    connectivity_ok, _, _ = run_command("ping -c 1 google.com > /dev/null 2>&1")
    check_status(connectivity_ok, "Internet connectivity")
    
    if connectivity_ok:
        # Test GitHub access
        github_ok, _, _ = run_command("curl -s --max-time 5 https://api.github.com/zen > /dev/null")
        check_status(github_ok, "GitHub API access")
        
        # Test Go proxy
        goproxy_ok, _, _ = run_command("curl -s --max-time 5 https://proxy.golang.org > /dev/null")
        check_status(goproxy_ok, "Go module proxy access")
    
    # Summary
    print_section("Summary")
    
    if available_tools >= 4:
        print("🎉 Installation looks good! Most tools are available.")
    elif available_tools >= 2:
        print("⚠️  Partial installation. Some tools are missing but core functionality should work.")
    else:
        print("❌ Installation issues detected. Run install.sh to fix.")
    
    print(f"\nFor installation help, run: ./install.sh")
    print(f"For quick start, run: ./quickstart.sh")
    print(f"To start the application: python3 bl4ckc3ll_p4nth30n.py")

if __name__ == "__main__":
    main()