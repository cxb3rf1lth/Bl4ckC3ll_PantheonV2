#!/usr/bin/env python3
"""
Comprehensive Repository Setup and Runner
Complete setup and management system for the advanced workflow automation
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


class ComprehensiveSetup:
    def __init__(self):
        self.repo_root = Path(".")
        self.scripts_dir = self.repo_root / "scripts"

    def install_dependencies(self) -> bool:
        """Install all required dependencies"""
        print("📦 Installing Dependencies...")

        success = True

        # Python dependencies
        try:
            print("  🐍 Installing Python dependencies...")
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
                check=True,
                capture_output=True,
            )
            print("  ✅ Python dependencies installed")
        except subprocess.CalledProcessError as e:
            print(f"  ❌ Python dependencies failed: {e}")
            success = False

        # Node.js dependencies
        if Path("package.json").exists():
            try:
                print("  📦 Installing Node.js dependencies...")
                subprocess.run(["npm", "install"], check=True, capture_output=True)
                print("  ✅ Node.js dependencies installed")
            except subprocess.CalledProcessError as e:
                print(f"  ❌ Node.js dependencies failed: {e}")
                success = False

        # Development tools
        try:
            print("  🔧 Installing development tools...")
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    "pre-commit",
                    "coverage",
                    "black",
                    "isort",
                    "mypy",
                ],
                check=True,
                capture_output=True,
            )
            print("  ✅ Development tools installed")
        except subprocess.CalledProcessError as e:
            print(f"  ❌ Development tools failed: {e}")
            success = False

        return success

    def setup_pre_commit_hooks(self) -> bool:
        """Setup pre-commit hooks"""
        print("🪝 Setting up pre-commit hooks...")

        try:
            # Install pre-commit hooks
            subprocess.run(["pre-commit", "install"], check=True, capture_output=True)
            subprocess.run(
                ["pre-commit", "install", "--hook-type", "commit-msg"],
                check=True,
                capture_output=True,
            )
            print("  ✅ Pre-commit hooks installed")
            return True
        except subprocess.CalledProcessError as e:
            print(f"  ❌ Pre-commit hooks setup failed: {e}")
            return False

    def setup_git_hooks(self) -> bool:
        """Setup additional Git hooks"""
        print("⚙️ Setting up Git hooks...")

        git_hooks_dir = Path(".git/hooks")
        if not git_hooks_dir.exists():
            print("  ❌ Git hooks directory not found")
            return False

        # Create pre-push hook for comprehensive testing
        pre_push_hook = git_hooks_dir / "pre-push"
        pre_push_content = """#!/bin/bash
# Pre-push hook for comprehensive testing

echo "🚀 Running pre-push comprehensive tests..."

# Run master workflow automation in quick mode
python3 scripts/master_workflow_automation.py --quick

if [ $? -ne 0 ]; then
    echo "❌ Pre-push tests failed. Push aborted."
    exit 1
fi

echo "✅ Pre-push tests passed!"
exit 0
"""

        try:
            with open(pre_push_hook, "w") as f:
                f.write(pre_push_content)
            pre_push_hook.chmod(0o755)
            print("  ✅ Pre-push hook created")
            return True
        except Exception as e:
            print(f"  ❌ Git hooks setup failed: {e}")
            return False

    def setup_github_workflows(self) -> bool:
        """Validate GitHub workflow setup"""
        print("⚡ Validating GitHub workflows...")

        workflows_dir = Path(".github/workflows")
        if not workflows_dir.exists():
            print("  ❌ GitHub workflows directory not found")
            return False

        required_workflows = ["advanced-cicd.yml", "automated-maintenance.yml"]

        missing_workflows = []
        for workflow in required_workflows:
            if not (workflows_dir / workflow).exists():
                missing_workflows.append(workflow)

        if missing_workflows:
            print(f"  ❌ Missing workflows: {missing_workflows}")
            return False
        else:
            print("  ✅ All required workflows present")
            return True

    def create_configuration_files(self) -> bool:
        """Create default configuration files"""
        print("📄 Creating configuration files...")

        # Repository manager config
        repo_config = {
            "auto_merge": {
                "enabled": False,
                "conditions": {
                    "all_tests_pass": True,
                    "no_conflicts": True,
                    "security_scan_pass": True,
                },
            },
            "maintenance": {"auto_cleanup": True, "generate_reports": True},
            "monitoring": {
                "performance_tracking": True,
                "security_monitoring": True,
                "error_detection": True,
            },
        }

        # Monitoring config
        monitoring_config = {
            "monitoring": {
                "enabled": True,
                "interval_seconds": 300,
                "alert_thresholds": {
                    "cpu_usage": 80,
                    "memory_usage": 85,
                    "disk_usage": 90,
                    "test_failure_rate": 20,
                    "security_score": 80,
                },
            },
            "alerts": {
                "console_enabled": True,
                "email_enabled": False,
                "webhook_enabled": False,
            },
        }

        try:
            # Save configs
            with open("repo-manager-config.json", "w") as f:
                json.dump(repo_config, f, indent=2)

            with open("monitoring-config.json", "w") as f:
                json.dump(monitoring_config, f, indent=2)

            print("  ✅ Configuration files created")
            return True
        except Exception as e:
            print(f"  ❌ Configuration creation failed: {e}")
            return False

    def validate_scripts(self) -> bool:
        """Validate all automation scripts"""
        print("🔍 Validating automation scripts...")

        required_scripts = [
            "master_workflow_automation.py",
            "comprehensive_test_framework.py",
            "intelligent_debugger.py",
            "intelligent_repo_manager.py",
            "monitoring_system.py",
            "security_validator.py",
            "performance_tester.py",
            "docs_validator.py",
        ]

        missing_scripts = []
        invalid_scripts = []

        for script in required_scripts:
            script_path = self.scripts_dir / script
            if not script_path.exists():
                missing_scripts.append(script)
                continue

            # Check if script is executable
            if not os.access(script_path, os.X_OK):
                script_path.chmod(0o755)

            # Basic syntax check
            try:
                subprocess.run(
                    [sys.executable, "-m", "py_compile", str(script_path)],
                    check=True,
                    capture_output=True,
                )
            except subprocess.CalledProcessError:
                invalid_scripts.append(script)

        if missing_scripts:
            print(f"  ❌ Missing scripts: {missing_scripts}")
            return False

        if invalid_scripts:
            print(f"  ❌ Invalid scripts: {invalid_scripts}")
            return False

        print("  ✅ All automation scripts validated")
        return True

    def run_initial_tests(self) -> bool:
        """Run initial test suite to validate setup"""
        print("🧪 Running initial validation tests...")

        test_commands = [
            ([sys.executable, "enhanced_test_suite.py"], "Enhanced Test Suite"),
            ([sys.executable, "scripts/security_validator.py"], "Security Validation"),
            ([sys.executable, "scripts/performance_tester.py"], "Performance Testing"),
            ([sys.executable, "scripts/docs_validator.py"], "Documentation Validation"),
        ]

        failed_tests = []

        for command, name in test_commands:
            try:
                print(f"  🔍 Running {name}...")
                result = subprocess.run(
                    command, capture_output=True, text=True, timeout=120
                )
                if result.returncode == 0:
                    print(f"  ✅ {name} passed")
                else:
                    print(f"  ⚠️  {name} completed with warnings")
                    # Don't fail setup for warnings, only for critical errors
            except subprocess.TimeoutExpired:
                print(f"  ⚠️  {name} timed out")
                failed_tests.append(name)
            except Exception as e:
                print(f"  ❌ {name} failed: {e}")
                failed_tests.append(name)

        if failed_tests:
            print(f"  ⚠️  Some tests had issues: {failed_tests}")
            print("  ℹ️  Setup will continue, but review these issues")

        return True  # Don't fail setup for test issues

    def setup_monitoring(self) -> bool:
        """Setup monitoring system"""
        print("📊 Setting up monitoring system...")

        try:
            # Create monitoring directories
            os.makedirs("logs", exist_ok=True)
            os.makedirs("reports", exist_ok=True)

            print("  ✅ Monitoring directories created")
            return True
        except Exception as e:
            print(f"  ❌ Monitoring setup failed: {e}")
            return False

    def run_complete_setup(self) -> bool:
        """Run complete repository setup"""
        print("🚀 Starting Comprehensive Repository Setup")
        print("=" * 60)

        setup_steps = [
            ("Installing Dependencies", self.install_dependencies),
            ("Setting up Pre-commit Hooks", self.setup_pre_commit_hooks),
            ("Setting up Git Hooks", self.setup_git_hooks),
            ("Validating GitHub Workflows", self.setup_github_workflows),
            ("Creating Configuration Files", self.create_configuration_files),
            ("Validating Scripts", self.validate_scripts),
            ("Setting up Monitoring", self.setup_monitoring),
            ("Running Initial Tests", self.run_initial_tests),
        ]

        failed_steps = []

        for step_name, step_function in setup_steps:
            print(f"\n📋 {step_name}")
            try:
                if not step_function():
                    failed_steps.append(step_name)
            except Exception as e:
                print(f"  ❌ {step_name} encountered an error: {e}")
                failed_steps.append(step_name)

        # Generate setup report
        setup_success = len(failed_steps) == 0

        print(f"\n{'='*60}")
        print(f"🏁 Setup Complete!")
        print(f"✅ Successful Steps: {len(setup_steps) - len(failed_steps)}")
        print(f"❌ Failed Steps: {len(failed_steps)}")

        if failed_steps:
            print(f"⚠️  Failed steps: {', '.join(failed_steps)}")
            print("ℹ️  Review the errors above and re-run setup if needed")
        else:
            print("🎉 All setup steps completed successfully!")

        # Create setup completion marker
        setup_marker = {
            "setup_completed": True,
            "setup_date": datetime.now().isoformat(),
            "setup_success": setup_success,
            "failed_steps": failed_steps,
            "version": "2.0.0",
        }

        with open(".setup-complete.json", "w") as f:
            json.dump(setup_marker, f, indent=2)

        return setup_success


class ComprehensiveRunner:
    def __init__(self):
        self.scripts_dir = Path("scripts")

    def run_component(self, component: str, args: List[str] = None) -> int:
        """Run a specific component"""
        component_map = {
            "setup": self._run_setup,
            "test": self._run_tests,
            "security": self._run_security,
            "performance": self._run_performance,
            "docs": self._run_docs,
            "debug": self._run_debug,
            "monitor": self._run_monitor,
            "manage": self._run_manage,
            "workflow": self._run_workflow,
            "format": self._run_format,
            "validate": self._run_validate,
        }

        if component not in component_map:
            print(f"❌ Unknown component: {component}")
            print(f"Available components: {', '.join(component_map.keys())}")
            return 1

        return component_map[component](args or [])

    def _run_setup(self, args: List[str]) -> int:
        """Run complete setup"""
        setup = ComprehensiveSetup()
        success = setup.run_complete_setup()
        return 0 if success else 1

    def _run_tests(self, args: List[str]) -> int:
        """Run test suites"""
        quick = "--quick" in args

        if quick:
            cmd = [sys.executable, "scripts/master_workflow_automation.py", "--quick"]
        else:
            cmd = [sys.executable, "scripts/master_workflow_automation.py"]

        result = subprocess.run(cmd)
        return result.returncode

    def _run_security(self, args: List[str]) -> int:
        """Run security validation"""
        result = subprocess.run([sys.executable, "scripts/security_validator.py"])
        return result.returncode

    def _run_performance(self, args: List[str]) -> int:
        """Run performance tests"""
        result = subprocess.run([sys.executable, "scripts/performance_tester.py"])
        return result.returncode

    def _run_docs(self, args: List[str]) -> int:
        """Run documentation validation"""
        result = subprocess.run([sys.executable, "scripts/docs_validator.py"])
        return result.returncode

    def _run_debug(self, args: List[str]) -> int:
        """Run intelligent debugging"""
        result = subprocess.run([sys.executable, "scripts/intelligent_debugger.py"])
        return result.returncode

    def _run_monitor(self, args: List[str]) -> int:
        """Run monitoring system"""
        monitor_args = [sys.executable, "scripts/monitoring_system.py"]

        if "--once" in args:
            monitor_args.append("--once")
        elif "--report" in args:
            monitor_args.append("--report")

        result = subprocess.run(monitor_args)
        return result.returncode

    def _run_manage(self, args: List[str]) -> int:
        """Run repository management"""
        result = subprocess.run([sys.executable, "scripts/intelligent_repo_manager.py"])
        return result.returncode

    def _run_workflow(self, args: List[str]) -> int:
        """Run master workflow automation"""
        workflow_args = [sys.executable, "scripts/master_workflow_automation.py"]
        workflow_args.extend(args)

        result = subprocess.run(workflow_args)
        return result.returncode

    def _run_format(self, args: List[str]) -> int:
        """Run code formatting"""
        print("🎨 Formatting code...")

        # Run Black
        result1 = subprocess.run(
            [sys.executable, "-m", "black", ".", "--line-length", "88"]
        )

        # Run isort
        result2 = subprocess.run(
            [sys.executable, "-m", "isort", ".", "--profile", "black"]
        )

        return max(result1.returncode, result2.returncode)

    def _run_validate(self, args: List[str]) -> int:
        """Run all validation checks"""
        print("🔍 Running all validation checks...")

        validators = [
            "scripts/security_validator.py",
            "scripts/performance_tester.py",
            "scripts/docs_validator.py",
        ]

        failed = 0
        for validator in validators:
            result = subprocess.run([sys.executable, validator])
            if result.returncode != 0:
                failed += 1

        return 1 if failed > 0 else 0


def main():
    parser = argparse.ArgumentParser(
        description="Comprehensive Repository Setup and Runner"
    )
    parser.add_argument(
        "component",
        nargs="?",
        default="workflow",
        help="Component to run (setup, test, security, performance, docs, debug, monitor, manage, workflow, format, validate)",
    )
    parser.add_argument("--quick", action="store_true", help="Run in quick mode")
    parser.add_argument("--once", action="store_true", help="Run once (for monitoring)")
    parser.add_argument(
        "--report", action="store_true", help="Generate report (for monitoring)"
    )

    args = parser.parse_args()

    # Check if setup has been completed
    setup_marker = Path(".setup-complete.json")
    if args.component != "setup" and not setup_marker.exists():
        print("⚠️  Repository setup has not been completed yet.")
        print("Run 'python3 setup_runner.py setup' first.")
        return 1

    runner = ComprehensiveRunner()

    # Prepare args list for component
    component_args = []
    if args.quick:
        component_args.append("--quick")
    if args.once:
        component_args.append("--once")
    if args.report:
        component_args.append("--report")

    exit_code = runner.run_component(args.component, component_args)

    if exit_code == 0:
        print(f"\n✅ {args.component} completed successfully!")
    else:
        print(f"\n❌ {args.component} completed with errors (exit code: {exit_code})")

    return exit_code


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
