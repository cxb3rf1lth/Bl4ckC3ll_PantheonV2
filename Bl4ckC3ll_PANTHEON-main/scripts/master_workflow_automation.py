#!/usr/bin/env python3
"""
Master Workflow Automation System
Orchestrates all workflow components for 100% automated repository management
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


class MasterWorkflowAutomation:
    def __init__(self):
        self.start_time = time.time()
        self.results = {}
        self.total_success = True

    def run_component(
        self, name: str, command: List[str], timeout: int = 300
    ) -> Dict[str, Any]:
        """Run a workflow component and capture results"""
        print(f"\n🔧 Running {name}...")
        print("-" * 50)

        component_start = time.time()

        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=timeout, cwd="."
            )

            duration = time.time() - component_start

            component_result = {
                "name": name,
                "success": result.returncode == 0,
                "duration": duration,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "timestamp": datetime.now().isoformat(),
            }

            if component_result["success"]:
                print(f"✅ {name} completed successfully in {duration:.2f}s")
            else:
                print(f"❌ {name} failed with exit code {result.returncode}")
                if result.stderr:
                    print(f"Error: {result.stderr[:500]}")
                self.total_success = False

            return component_result

        except subprocess.TimeoutExpired:
            print(f"⏰ {name} timed out after {timeout}s")
            self.total_success = False
            return {
                "name": name,
                "success": False,
                "duration": timeout,
                "returncode": -1,
                "error": "Timeout",
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as e:
            print(f"💥 {name} encountered an error: {e}")
            self.total_success = False
            return {
                "name": name,
                "success": False,
                "duration": time.time() - component_start,
                "returncode": -1,
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            }

    def run_security_validation(self) -> Dict[str, Any]:
        """Run comprehensive security validation"""
        return self.run_component(
            "Security Validation",
            [sys.executable, "scripts/security_validator.py"],
            timeout=120,
        )

    def run_performance_testing(self) -> Dict[str, Any]:
        """Run performance benchmarks"""
        return self.run_component(
            "Performance Testing",
            [sys.executable, "scripts/performance_tester.py"],
            timeout=180,
        )

    def run_documentation_validation(self) -> Dict[str, Any]:
        """Run documentation validation"""
        return self.run_component(
            "Documentation Validation",
            [sys.executable, "scripts/docs_validator.py"],
            timeout=60,
        )

    def run_comprehensive_testing(self) -> Dict[str, Any]:
        """Run comprehensive test framework"""
        return self.run_component(
            "Comprehensive Test Framework",
            [sys.executable, "scripts/comprehensive_test_framework.py"],
            timeout=600,
        )

    def run_intelligent_debugging(self) -> Dict[str, Any]:
        """Run intelligent debugging system"""
        return self.run_component(
            "Intelligent Debugging",
            [sys.executable, "scripts/intelligent_debugger.py"],
            timeout=600,
        )

    def run_repository_management(self) -> Dict[str, Any]:
        """Run repository management"""
        return self.run_component(
            "Repository Management",
            [sys.executable, "scripts/intelligent_repo_manager.py"],
            timeout=300,
        )

    def run_existing_test_suites(self) -> List[Dict[str, Any]]:
        """Run existing test suites"""
        test_suites = [
            ("Enhanced Test Suite", [sys.executable, "enhanced_test_suite.py"]),
            ("Final Integration Test", [sys.executable, "final_integration_test.py"]),
            (
                "Test Automation Integration",
                [sys.executable, "test_automation_integration.py"],
            ),
        ]

        results = []
        for name, command in test_suites:
            result = self.run_component(name, command, timeout=180)
            results.append(result)

        return results

    def run_code_quality_checks(self) -> List[Dict[str, Any]]:
        """Run code quality and linting checks"""
        quality_checks = []

        # Python code quality
        if Path("requirements.txt").exists():
            # Black formatting check
            quality_checks.append(
                self.run_component(
                    "Black Code Formatting Check",
                    [sys.executable, "-m", "black", "--check", "--diff", "."],
                    timeout=60,
                )
            )

            # isort import sorting check
            quality_checks.append(
                self.run_component(
                    "isort Import Sorting Check",
                    [sys.executable, "-m", "isort", "--check-only", "--diff", "."],
                    timeout=60,
                )
            )

        # Node.js code quality
        if Path("package.json").exists():
            quality_checks.append(
                self.run_component(
                    "ESLint JavaScript Linting",
                    ["npm", "run", "lint:check"],
                    timeout=120,
                )
            )

        return quality_checks

    def generate_comprehensive_report(self) -> str:
        """Generate comprehensive workflow report"""
        total_duration = time.time() - self.start_time

        # Count successes and failures
        all_results = []
        for key, value in self.results.items():
            if isinstance(value, list):
                all_results.extend(value)
            else:
                all_results.append(value)

        successful_components = sum(1 for r in all_results if r.get("success", False))
        total_components = len(all_results)
        success_rate = (
            (successful_components / total_components * 100)
            if total_components > 0
            else 0
        )

        report = f"""# 🚀 Master Workflow Automation Report

## 📊 Executive Summary

- **Execution Time**: {total_duration:.2f} seconds
- **Components Executed**: {total_components}
- **Successful Components**: {successful_components}
- **Success Rate**: {success_rate:.1f}%
- **Overall Status**: {'✅ PASSED' if self.total_success else '❌ FAILED'}
- **Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

## 🔍 Component Results

"""

        # Add detailed results for each category
        for category, results in self.results.items():
            report += f"### {category.replace('_', ' ').title()}\n\n"

            if isinstance(results, list):
                for result in results:
                    status = "✅" if result.get("success", False) else "❌"
                    report += (
                        f"- {status} **{result['name']}** ({result['duration']:.2f}s)\n"
                    )
                    if not result.get("success", False) and "error" in result:
                        report += f"  - Error: {result['error']}\n"
            else:
                status = "✅" if results.get("success", False) else "❌"
                report += (
                    f"- {status} **{results['name']}** ({results['duration']:.2f}s)\n"
                )
                if not results.get("success", False) and "error" in results:
                    report += f"  - Error: {results['error']}\n"

            report += "\n"

        # Add recommendations
        report += "## 🎯 Recommendations\n\n"

        if self.total_success:
            report += """- ✅ All workflow components completed successfully
- 📊 Repository is in excellent health
- 🔄 Continue regular automated maintenance
- 📈 Consider expanding test coverage further
"""
        else:
            report += """- ⚠️ Some workflow components failed - review and fix issues
- 🔧 Address failed components before next deployment
- 📋 Check component logs for detailed error information
- 🔄 Re-run workflow after fixes are applied
"""

        # Add next steps
        report += "\n## 📋 Next Steps\n\n"
        report += """1. Review any failed components and address issues
2. Update documentation if needed
3. Consider scheduling regular automated runs
4. Monitor performance metrics and trends
5. Implement any suggested improvements

## 📁 Generated Artifacts

The following reports and artifacts were generated:
- `master-workflow-report.md` - This comprehensive report
- `master-workflow-results.json` - Detailed results in JSON format
- Individual component reports in respective directories

---
*Generated by Master Workflow Automation System*
"""

        return report

    def run_complete_workflow(self, quick_mode: bool = False) -> int:
        """Run the complete workflow automation system"""
        print("🚀 Starting Master Workflow Automation System")
        print("=" * 60)
        print(f"Mode: {'Quick' if quick_mode else 'Comprehensive'}")
        print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print()

        # Phase 1: Security and Performance Validation
        print("🔒 Phase 1: Security and Performance Validation")
        self.results["security_validation"] = self.run_security_validation()
        self.results["performance_testing"] = self.run_performance_testing()

        # Phase 2: Code Quality Checks
        print("\n📏 Phase 2: Code Quality Checks")
        self.results["code_quality_checks"] = self.run_code_quality_checks()

        # Phase 3: Documentation Validation
        print("\n📚 Phase 3: Documentation Validation")
        self.results["documentation_validation"] = self.run_documentation_validation()

        # Phase 4: Existing Test Suites
        print("\n🧪 Phase 4: Existing Test Suites")
        self.results["existing_test_suites"] = self.run_existing_test_suites()

        if not quick_mode:
            # Phase 5: Comprehensive Testing (only in full mode)
            print("\n🔬 Phase 5: Comprehensive Testing")
            self.results["comprehensive_testing"] = self.run_comprehensive_testing()

            # Phase 6: Intelligent Debugging (only in full mode)
            print("\n🐛 Phase 6: Intelligent Debugging")
            self.results["intelligent_debugging"] = self.run_intelligent_debugging()

        # Phase 7: Repository Management
        print("\n🏠 Phase 7: Repository Management")
        self.results["repository_management"] = self.run_repository_management()

        # Generate reports
        print("\n📊 Generating Reports...")
        comprehensive_report = self.generate_comprehensive_report()

        # Save reports
        with open("master-workflow-report.md", "w") as f:
            f.write(comprehensive_report)

        with open("master-workflow-results.json", "w") as f:
            json.dump(self.results, f, indent=2, default=str)

        # Final summary
        total_duration = time.time() - self.start_time
        print(f"\n{'='*60}")
        print(f"🏁 Master Workflow Automation Complete!")
        print(f"⏱️  Total Duration: {total_duration:.2f} seconds")
        print(
            f"📊 Overall Status: {'✅ SUCCESS' if self.total_success else '❌ FAILURE'}"
        )
        print(f"📁 Reports Generated:")
        print(f"   - master-workflow-report.md")
        print(f"   - master-workflow-results.json")

        if not self.total_success:
            print(
                f"\n⚠️  Some components failed. Check the detailed report for information."
            )

        return 0 if self.total_success else 1


def main():
    parser = argparse.ArgumentParser(description="Master Workflow Automation System")
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run in quick mode (skip comprehensive testing and debugging)",
    )
    parser.add_argument("--component", type=str, help="Run specific component only")

    args = parser.parse_args()

    automation = MasterWorkflowAutomation()

    if args.component:
        # Run specific component
        component_map = {
            "security": automation.run_security_validation,
            "performance": automation.run_performance_testing,
            "docs": automation.run_documentation_validation,
            "testing": automation.run_comprehensive_testing,
            "debugging": automation.run_intelligent_debugging,
            "management": automation.run_repository_management,
        }

        if args.component in component_map:
            result = component_map[args.component]()
            print(f"\nComponent result: {result}")
            sys.exit(0 if result.get("success", False) else 1)
        else:
            print(f"Unknown component: {args.component}")
            print(f"Available components: {', '.join(component_map.keys())}")
            sys.exit(1)
    else:
        # Run complete workflow
        exit_code = automation.run_complete_workflow(quick_mode=args.quick)
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
