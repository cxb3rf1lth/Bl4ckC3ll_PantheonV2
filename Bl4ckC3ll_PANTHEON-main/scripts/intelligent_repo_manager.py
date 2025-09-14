#!/usr/bin/env python3
"""
Intelligent Repository Manager
Automatically manages repository operations, optimizations, and maintenance
"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List

import requests


class IntelligentRepoManager:
    def __init__(self):
        self.repo_path = Path(".")
        self.config_file = self.repo_path / "repo-manager-config.json"
        self.state_file = self.repo_path / "repo-manager-state.json"

        # Load configuration
        self.config = self._load_config()
        self.state = self._load_state()

    def _load_config(self) -> Dict[str, Any]:
        """Load repository manager configuration"""
        default_config = {
            "auto_merge": {
                "enabled": False,
                "conditions": {
                    "all_tests_pass": True,
                    "no_conflicts": True,
                    "approved_by_maintainer": False,
                    "security_scan_pass": True,
                },
            },
            "maintenance": {
                "auto_cleanup": True,
                "archive_old_branches": True,
                "update_dependencies": True,
                "generate_reports": True,
            },
            "monitoring": {
                "performance_tracking": True,
                "security_monitoring": True,
                "dependency_alerts": True,
                "error_detection": True,
            },
            "optimization": {
                "compress_assets": True,
                "optimize_images": False,
                "minify_code": False,
                "cache_dependencies": True,
            },
        }

        if self.config_file.exists():
            try:
                with open(self.config_file, "r") as f:
                    user_config = json.load(f)
                # Merge with defaults
                for key, value in user_config.items():
                    if isinstance(value, dict) and key in default_config:
                        default_config[key].update(value)
                    else:
                        default_config[key] = value
            except Exception as e:
                print(f"Warning: Could not load config: {e}")

        return default_config

    def _load_state(self) -> Dict[str, Any]:
        """Load repository manager state"""
        default_state = {
            "last_maintenance": None,
            "last_optimization": None,
            "last_security_scan": None,
            "performance_baseline": {},
            "error_history": [],
            "dependency_updates": [],
        }

        if self.state_file.exists():
            try:
                with open(self.state_file, "r") as f:
                    return json.load(f)
            except Exception as e:
                print(f"Warning: Could not load state: {e}")

        return default_state

    def _save_state(self):
        """Save current state"""
        try:
            with open(self.state_file, "w") as f:
                json.dump(self.state, f, indent=2, default=str)
        except Exception as e:
            print(f"Warning: Could not save state: {e}")

    def check_repository_health(self) -> Dict[str, Any]:
        """Check overall repository health"""
        print("🏥 Checking repository health...")

        health_report = {
            "timestamp": datetime.now().isoformat(),
            "overall_status": "healthy",
            "issues": [],
            "metrics": {},
        }

        # Check Git repository status
        try:
            result = subprocess.run(
                ["git", "status", "--porcelain"], capture_output=True, text=True
            )
            if result.stdout.strip():
                health_report["issues"].append("Uncommitted changes detected")
        except Exception as e:
            health_report["issues"].append(f"Git status check failed: {e}")

        # Check for required files
        required_files = ["README.md", "requirements.txt", "package.json"]
        for file in required_files:
            if not Path(file).exists():
                health_report["issues"].append(f"Missing required file: {file}")

        # Check Python environment
        try:
            result = subprocess.run(
                [sys.executable, "--version"], capture_output=True, text=True
            )
            health_report["metrics"]["python_version"] = result.stdout.strip()
        except Exception as e:
            health_report["issues"].append(f"Python check failed: {e}")

        # Check Node.js environment
        try:
            result = subprocess.run(
                ["node", "--version"], capture_output=True, text=True
            )
            health_report["metrics"]["node_version"] = result.stdout.strip()
        except Exception as e:
            health_report["issues"].append(f"Node.js check failed: {e}")

        # Run security validation
        try:
            result = subprocess.run(
                [sys.executable, "scripts/security_validator.py"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            health_report["metrics"]["security_issues"] = result.returncode
        except Exception as e:
            health_report["issues"].append(f"Security validation failed: {e}")

        # Run performance tests
        try:
            result = subprocess.run(
                [sys.executable, "scripts/performance_tester.py"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            health_report["metrics"]["performance_status"] = result.returncode
        except Exception as e:
            health_report["issues"].append(f"Performance test failed: {e}")

        # Determine overall status
        if len(health_report["issues"]) == 0:
            health_report["overall_status"] = "healthy"
        elif len(health_report["issues"]) <= 2:
            health_report["overall_status"] = "warning"
        else:
            health_report["overall_status"] = "critical"

        return health_report

    def automated_maintenance(self) -> Dict[str, Any]:
        """Perform automated repository maintenance"""
        print("🔧 Running automated maintenance...")

        maintenance_report = {
            "timestamp": datetime.now().isoformat(),
            "tasks_completed": [],
            "tasks_failed": [],
            "cleanup_summary": {},
        }

        if self.config["maintenance"]["auto_cleanup"]:
            print("  🧹 Running cleanup tasks...")

            # Clean Python cache
            try:
                subprocess.run(
                    [
                        "find",
                        ".",
                        "-name",
                        "__pycache__",
                        "-type",
                        "d",
                        "-exec",
                        "rm",
                        "-rf",
                        "{}",
                        "+",
                    ],
                    check=False,
                )
                subprocess.run(["find", ".", "-name", "*.pyc", "-delete"], check=False)
                maintenance_report["tasks_completed"].append("Python cache cleanup")
            except Exception as e:
                maintenance_report["tasks_failed"].append(f"Python cache cleanup: {e}")

            # Clean Node.js cache
            try:
                if Path("node_modules").exists():
                    result = subprocess.run(
                        ["npm", "cache", "clean", "--force"],
                        capture_output=True,
                        text=True,
                    )
                    maintenance_report["tasks_completed"].append(
                        "Node.js cache cleanup"
                    )
            except Exception as e:
                maintenance_report["tasks_failed"].append(f"Node.js cache cleanup: {e}")

            # Remove temporary files
            try:
                temp_patterns = ["*.tmp", "*.temp", "*.log", "*~", "*.bak"]
                for pattern in temp_patterns:
                    subprocess.run(
                        ["find", ".", "-name", pattern, "-type", "f", "-delete"],
                        check=False,
                    )
                maintenance_report["tasks_completed"].append("Temporary file cleanup")
            except Exception as e:
                maintenance_report["tasks_failed"].append(
                    f"Temporary file cleanup: {e}"
                )

        if self.config["maintenance"]["generate_reports"]:
            print("  📊 Generating maintenance reports...")

            try:
                # Run comprehensive test framework
                result = subprocess.run(
                    [sys.executable, "scripts/comprehensive_test_framework.py"],
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
                if result.returncode == 0:
                    maintenance_report["tasks_completed"].append(
                        "Comprehensive test report generation"
                    )
                else:
                    maintenance_report["tasks_failed"].append(
                        "Comprehensive test report generation"
                    )
            except Exception as e:
                maintenance_report["tasks_failed"].append(
                    f"Test report generation: {e}"
                )

            try:
                # Run intelligent debugging
                result = subprocess.run(
                    [sys.executable, "scripts/intelligent_debugger.py"],
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
                if result.returncode == 0:
                    maintenance_report["tasks_completed"].append(
                        "Intelligent debugging report"
                    )
                else:
                    maintenance_report["tasks_failed"].append(
                        "Intelligent debugging report"
                    )
            except Exception as e:
                maintenance_report["tasks_failed"].append(
                    f"Debugging report generation: {e}"
                )

        # Update state
        self.state["last_maintenance"] = datetime.now().isoformat()
        self._save_state()

        return maintenance_report

    def optimize_repository(self) -> Dict[str, Any]:
        """Optimize repository for performance and storage"""
        print("⚡ Optimizing repository...")

        optimization_report = {
            "timestamp": datetime.now().isoformat(),
            "optimizations_applied": [],
            "space_saved": 0,
            "performance_improvements": {},
        }

        if self.config["optimization"]["compress_assets"]:
            print("  📦 Compressing assets...")

            # Git garbage collection
            try:
                result = subprocess.run(
                    ["git", "gc", "--aggressive"], capture_output=True, text=True
                )
                optimization_report["optimizations_applied"].append(
                    "Git garbage collection"
                )
            except Exception as e:
                print(f"Git gc failed: {e}")

        if self.config["optimization"]["cache_dependencies"]:
            print("  💾 Optimizing dependency cache...")

            # Python dependencies
            try:
                subprocess.run(
                    [sys.executable, "-m", "pip", "cache", "purge"], check=False
                )
                optimization_report["optimizations_applied"].append(
                    "Python dependency cache optimization"
                )
            except Exception as e:
                print(f"Python cache optimization failed: {e}")

        # Update state
        self.state["last_optimization"] = datetime.now().isoformat()
        self._save_state()

        return optimization_report

    def monitor_and_alert(self) -> Dict[str, Any]:
        """Monitor repository and send alerts if needed"""
        print("📊 Monitoring repository status...")

        monitoring_report = {
            "timestamp": datetime.now().isoformat(),
            "alerts": [],
            "metrics": {},
            "recommendations": [],
        }

        if self.config["monitoring"]["performance_tracking"]:
            # Check performance metrics
            try:
                result = subprocess.run(
                    [sys.executable, "scripts/performance_tester.py"],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if result.returncode != 0:
                    monitoring_report["alerts"].append("Performance tests failing")
                else:
                    monitoring_report["metrics"]["performance"] = "passing"
            except Exception as e:
                monitoring_report["alerts"].append(
                    f"Performance monitoring failed: {e}"
                )

        if self.config["monitoring"]["security_monitoring"]:
            # Check security status
            try:
                result = subprocess.run(
                    [sys.executable, "scripts/security_validator.py"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if result.returncode != 0:
                    monitoring_report["alerts"].append(
                        "Security validation issues found"
                    )
                else:
                    monitoring_report["metrics"]["security"] = "passing"
            except Exception as e:
                monitoring_report["alerts"].append(f"Security monitoring failed: {e}")

        if self.config["monitoring"]["error_detection"]:
            # Check for recent errors
            try:
                result = subprocess.run(
                    [sys.executable, "scripts/intelligent_debugger.py"],
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
                if result.returncode != 0:
                    monitoring_report["alerts"].append("Error detection found issues")
                else:
                    monitoring_report["metrics"]["error_detection"] = "passing"
            except Exception as e:
                monitoring_report["alerts"].append(f"Error detection failed: {e}")

        # Generate recommendations
        if len(monitoring_report["alerts"]) > 0:
            monitoring_report["recommendations"].append(
                "Address reported alerts immediately"
            )

        if len(monitoring_report["alerts"]) == 0:
            monitoring_report["recommendations"].append(
                "Repository is healthy - continue regular monitoring"
            )

        return monitoring_report

    def auto_merge_eligible_prs(self) -> Dict[str, Any]:
        """Automatically merge eligible pull requests"""
        print("🔀 Checking for auto-merge eligible PRs...")

        merge_report = {
            "timestamp": datetime.now().isoformat(),
            "prs_checked": 0,
            "prs_merged": 0,
            "merge_failures": [],
        }

        if not self.config["auto_merge"]["enabled"]:
            merge_report["status"] = "Auto-merge disabled"
            return merge_report

        # Note: This would require GitHub API integration
        # For now, just report that the feature is configured
        merge_report["status"] = "Auto-merge configured but requires GitHub API setup"

        return merge_report

    def run_full_management_cycle(self) -> int:
        """Run complete repository management cycle"""
        print("🤖 Starting Intelligent Repository Management Cycle")
        print("=" * 60)

        cycle_start = time.time()

        try:
            # Phase 1: Health Check
            health_report = self.check_repository_health()

            # Phase 2: Maintenance
            maintenance_report = self.automated_maintenance()

            # Phase 3: Optimization
            optimization_report = self.optimize_repository()

            # Phase 4: Monitoring
            monitoring_report = self.monitor_and_alert()

            # Phase 5: Auto-merge (if enabled)
            merge_report = self.auto_merge_eligible_prs()

            # Generate comprehensive report
            full_report = {
                "cycle_duration": time.time() - cycle_start,
                "timestamp": datetime.now().isoformat(),
                "health": health_report,
                "maintenance": maintenance_report,
                "optimization": optimization_report,
                "monitoring": monitoring_report,
                "auto_merge": merge_report,
            }

            # Save reports
            with open("repo-management-report.json", "w") as f:
                json.dump(full_report, f, indent=2, default=str)

            # Generate summary
            print(f"\n✅ Repository management cycle completed!")
            print(f"⏱️  Duration: {full_report['cycle_duration']:.2f} seconds")
            print(f"🏥 Health Status: {health_report['overall_status']}")
            print(
                f"🔧 Maintenance Tasks: {len(maintenance_report['tasks_completed'])} completed"
            )
            print(
                f"⚡ Optimizations: {len(optimization_report['optimizations_applied'])} applied"
            )
            print(f"📊 Alerts: {len(monitoring_report['alerts'])} active")
            print(f"📁 Report saved: repo-management-report.json")

            # Determine exit code
            if health_report["overall_status"] == "critical":
                return 1
            elif len(monitoring_report["alerts"]) > 3:
                return 1
            else:
                return 0

        except Exception as e:
            print(f"❌ Repository management cycle failed: {e}")
            return 1


if __name__ == "__main__":
    manager = IntelligentRepoManager()
    exit_code = manager.run_full_management_cycle()
    sys.exit(exit_code)
