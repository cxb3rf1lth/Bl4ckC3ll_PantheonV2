#!/usr/bin/env python3
"""
Intelligent Debugging and Error Detection System
Automatically detects, analyzes, and suggests fixes for errors in the codebase
"""

import ast
import json
import logging
import os
import re
import subprocess
import sys
import time
import traceback
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ErrorPattern:
    """Represents a detected error pattern"""

    pattern_type: str
    severity: str
    message: str
    file_path: str
    line_number: int
    suggested_fix: str
    confidence: float


class IntelligentDebugger:
    def __init__(self):
        self.error_patterns = []
        self.fix_suggestions = []
        self.analysis_results = {}

        # Common error patterns and their fixes
        self.known_patterns = {
            "syntax_errors": [
                {
                    "pattern": r"SyntaxError: invalid syntax",
                    "fix": "Check for missing colons, parentheses, or quotes",
                    "confidence": 0.9,
                },
                {
                    "pattern": r"IndentationError",
                    "fix": "Fix indentation - use consistent spaces or tabs",
                    "confidence": 0.95,
                },
            ],
            "import_errors": [
                {
                    "pattern": r"ModuleNotFoundError: No module named",
                    "fix": "Install missing module with pip or check import path",
                    "confidence": 0.9,
                },
                {
                    "pattern": r"ImportError: cannot import name",
                    "fix": "Check if the imported name exists in the module",
                    "confidence": 0.85,
                },
            ],
            "runtime_errors": [
                {
                    "pattern": r"NameError: name .* is not defined",
                    "fix": "Define the variable or check for typos",
                    "confidence": 0.9,
                },
                {
                    "pattern": r"AttributeError: .* has no attribute",
                    "fix": "Check if the attribute exists or if object is None",
                    "confidence": 0.85,
                },
                {
                    "pattern": r"KeyError:",
                    "fix": "Check if key exists in dictionary or use .get() method",
                    "confidence": 0.8,
                },
            ],
        }

    def analyze_file_for_errors(self, file_path: Path) -> List[ErrorPattern]:
        """Analyze a single file for potential errors"""
        errors = []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Parse AST to detect syntax issues
            try:
                tree = ast.parse(content)
                errors.extend(self._analyze_ast_patterns(tree, file_path, content))
            except SyntaxError as e:
                errors.append(
                    ErrorPattern(
                        pattern_type="syntax_error",
                        severity="high",
                        message=f"Syntax error: {e.msg}",
                        file_path=str(file_path),
                        line_number=e.lineno or 0,
                        suggested_fix="Fix syntax error according to Python grammar rules",
                        confidence=0.95,
                    )
                )
            except Exception as e:
                errors.append(
                    ErrorPattern(
                        pattern_type="parse_error",
                        severity="medium",
                        message=f"Parse error: {str(e)}",
                        file_path=str(file_path),
                        line_number=0,
                        suggested_fix="Check file encoding and syntax",
                        confidence=0.7,
                    )
                )

            # Analyze content patterns
            errors.extend(self._analyze_content_patterns(content, file_path))

        except Exception as e:
            errors.append(
                ErrorPattern(
                    pattern_type="file_error",
                    severity="medium",
                    message=f"Could not analyze file: {str(e)}",
                    file_path=str(file_path),
                    line_number=0,
                    suggested_fix="Check file permissions and encoding",
                    confidence=0.5,
                )
            )

        return errors

    def _analyze_ast_patterns(
        self, tree: ast.AST, file_path: Path, content: str
    ) -> List[ErrorPattern]:
        """Analyze AST for common error patterns"""
        errors = []
        lines = content.split("\n")

        for node in ast.walk(tree):
            # Check for potential issues

            # Bare except clauses
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                errors.append(
                    ErrorPattern(
                        pattern_type="code_quality",
                        severity="medium",
                        message="Bare except clause detected",
                        file_path=str(file_path),
                        line_number=node.lineno,
                        suggested_fix="Specify exception type: except SpecificException:",
                        confidence=0.9,
                    )
                )

            # Unused variables (simplified detection)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                var_name = node.id
                if var_name.startswith("_") and len(var_name) > 1:
                    # This is likely intentionally unused
                    continue

                # Check if variable is used later (simplified check)
                used = False
                for other_node in ast.walk(tree):
                    if (
                        isinstance(other_node, ast.Name)
                        and other_node.id == var_name
                        and isinstance(other_node.ctx, ast.Load)
                        and other_node.lineno > node.lineno
                    ):
                        used = True
                        break

                if not used:
                    errors.append(
                        ErrorPattern(
                            pattern_type="unused_variable",
                            severity="low",
                            message=f"Variable '{var_name}' appears to be unused",
                            file_path=str(file_path),
                            line_number=node.lineno,
                            suggested_fix=f"Remove unused variable or prefix with underscore: _{var_name}",
                            confidence=0.7,
                        )
                    )

            # Dangerous function calls
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    if func_name in ["eval", "exec"]:
                        errors.append(
                            ErrorPattern(
                                pattern_type="security_risk",
                                severity="high",
                                message=f"Dangerous function '{func_name}' detected",
                                file_path=str(file_path),
                                line_number=node.lineno,
                                suggested_fix=f"Replace {func_name} with safer alternatives",
                                confidence=0.95,
                            )
                        )

            # Complex conditions (too many boolean operators)
            if isinstance(node, ast.BoolOp):
                if len(node.values) > 3:
                    errors.append(
                        ErrorPattern(
                            pattern_type="complexity",
                            severity="medium",
                            message="Complex boolean expression detected",
                            file_path=str(file_path),
                            line_number=node.lineno,
                            suggested_fix="Break down complex condition into multiple variables",
                            confidence=0.8,
                        )
                    )

        return errors

    def _analyze_content_patterns(
        self, content: str, file_path: Path
    ) -> List[ErrorPattern]:
        """Analyze file content for error patterns"""
        errors = []
        lines = content.split("\n")

        for i, line in enumerate(lines, 1):
            # Check for common issues

            # Long lines
            if len(line) > 120:
                errors.append(
                    ErrorPattern(
                        pattern_type="style",
                        severity="low",
                        message=f"Line too long ({len(line)} characters)",
                        file_path=str(file_path),
                        line_number=i,
                        suggested_fix="Break long line into multiple lines",
                        confidence=0.8,
                    )
                )

            # Hardcoded credentials patterns
            credential_patterns = [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'api_key\s*=\s*["\'][^"\']+["\']',
                r'secret\s*=\s*["\'][^"\']+["\']',
                r'token\s*=\s*["\'][^"\']+["\']',
            ]

            for pattern in credential_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    errors.append(
                        ErrorPattern(
                            pattern_type="security_risk",
                            severity="critical",
                            message="Potential hardcoded credential detected",
                            file_path=str(file_path),
                            line_number=i,
                            suggested_fix="Move credentials to environment variables or config files",
                            confidence=0.9,
                        )
                    )

            # TODO/FIXME comments
            if re.search(r"(TODO|FIXME|XXX|HACK):", line, re.IGNORECASE):
                errors.append(
                    ErrorPattern(
                        pattern_type="maintenance",
                        severity="low",
                        message="TODO/FIXME comment found",
                        file_path=str(file_path),
                        line_number=i,
                        suggested_fix="Address the TODO item or create an issue",
                        confidence=0.7,
                    )
                )

        return errors

    def run_automated_tests_with_debugging(self) -> Dict[str, Any]:
        """Run tests and capture debugging information"""
        print("🐛 Running automated tests with debugging...")

        test_results = {}

        # Run existing test suites with debugging
        test_commands = [
            ["python3", "enhanced_test_suite.py"],
            ["python3", "final_integration_test.py"],
            ["python3", "test_automation_integration.py"],
        ]

        for cmd in test_commands:
            test_name = cmd[1].replace(".py", "")
            print(f"  🧪 Running {test_name}...")

            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=300, cwd="."
                )

                test_results[test_name] = {
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "success": result.returncode == 0,
                }

                # Analyze errors in output
                if result.returncode != 0:
                    errors = self._analyze_test_output(result.stderr, test_name)
                    test_results[test_name]["detected_errors"] = errors

            except subprocess.TimeoutExpired:
                test_results[test_name] = {
                    "returncode": -1,
                    "error": "Test timed out",
                    "success": False,
                }
            except Exception as e:
                test_results[test_name] = {
                    "returncode": -1,
                    "error": str(e),
                    "success": False,
                }

        return test_results

    def _analyze_test_output(self, stderr: str, test_name: str) -> List[Dict[str, Any]]:
        """Analyze test output for error patterns"""
        errors = []

        for category, patterns in self.known_patterns.items():
            for pattern_info in patterns:
                pattern = pattern_info["pattern"]
                matches = re.finditer(pattern, stderr, re.MULTILINE)

                for match in matches:
                    errors.append(
                        {
                            "category": category,
                            "pattern": pattern,
                            "match": match.group(),
                            "fix": pattern_info["fix"],
                            "confidence": pattern_info["confidence"],
                            "test_source": test_name,
                        }
                    )

        return errors

    def generate_automated_fixes(self, errors: List[ErrorPattern]) -> List[str]:
        """Generate automated fixes for detected errors"""
        fixes = []

        # Group errors by file
        errors_by_file = defaultdict(list)
        for error in errors:
            errors_by_file[error.file_path].append(error)

        for file_path, file_errors in errors_by_file.items():
            fix_script = f"# Automated fixes for {file_path}\n\n"

            # Sort errors by line number (descending to avoid line number shifts)
            file_errors.sort(key=lambda x: x.line_number, reverse=True)

            for error in file_errors:
                if error.confidence >= 0.8 and error.severity in ["high", "critical"]:
                    fix_script += (
                        f"# Fix for line {error.line_number}: {error.message}\n"
                    )
                    fix_script += f"# Suggested fix: {error.suggested_fix}\n"

                    # Generate specific fix code based on error type
                    if (
                        error.pattern_type == "security_risk"
                        and "credential" in error.message
                    ):
                        fix_script += f"# TODO: Move hardcoded credential to environment variable\n"
                    elif (
                        error.pattern_type == "code_quality"
                        and "bare except" in error.message
                    ):
                        fix_script += f"# TODO: Replace 'except:' with 'except Exception:' on line {error.line_number}\n"

                    fix_script += "\n"

            fixes.append(fix_script)

        return fixes

    def recursive_improvement_cycle(self) -> Dict[str, Any]:
        """Run recursive improvement cycles"""
        print("🔄 Running recursive improvement cycles...")

        cycles = []
        max_cycles = 3

        for cycle in range(max_cycles):
            print(f"  📊 Cycle {cycle + 1}/{max_cycles}")

            cycle_start = time.time()

            # Analyze all Python files
            all_errors = []
            python_files = list(Path(".").glob("**/*.py"))

            for file_path in python_files:
                if any(
                    exclude in str(file_path)
                    for exclude in [".git", "__pycache__", ".pytest_cache"]
                ):
                    continue

                file_errors = self.analyze_file_for_errors(file_path)
                all_errors.extend(file_errors)

            # Run tests
            test_results = self.run_automated_tests_with_debugging()

            # Generate fixes
            fixes = self.generate_automated_fixes(all_errors)

            cycle_data = {
                "cycle": cycle + 1,
                "duration": time.time() - cycle_start,
                "errors_found": len(all_errors),
                "critical_errors": len(
                    [e for e in all_errors if e.severity == "critical"]
                ),
                "high_errors": len([e for e in all_errors if e.severity == "high"]),
                "test_results": test_results,
                "fixes_generated": len(fixes),
                "errors_by_type": {},
            }

            # Group errors by type
            for error in all_errors:
                error_type = error.pattern_type
                if error_type not in cycle_data["errors_by_type"]:
                    cycle_data["errors_by_type"][error_type] = 0
                cycle_data["errors_by_type"][error_type] += 1

            cycles.append(cycle_data)

            print(
                f"    ✅ Found {len(all_errors)} errors ({cycle_data['critical_errors']} critical)"
            )

            # Break if no critical errors found
            if cycle_data["critical_errors"] == 0 and cycle_data["high_errors"] == 0:
                print("    🎉 No critical or high severity errors found!")
                break

        return {
            "cycles": cycles,
            "total_cycles": len(cycles),
            "final_status": (
                "success" if cycles[-1]["critical_errors"] == 0 else "needs_attention"
            ),
        }

    def generate_debugging_report(self, improvement_data: Dict[str, Any]) -> str:
        """Generate comprehensive debugging and improvement report"""
        report = "# 🐛 Intelligent Debugging and Error Detection Report\n\n"
        report += f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"

        # Executive Summary
        final_cycle = improvement_data["cycles"][-1]
        report += "## 📊 Executive Summary\n\n"
        report += (
            f"- **Total Improvement Cycles**: {improvement_data['total_cycles']}\n"
        )
        report += f"- **Final Status**: {improvement_data['final_status'].replace('_', ' ').title()}\n"
        report += f"- **Critical Errors**: {final_cycle['critical_errors']}\n"
        report += f"- **High Priority Errors**: {final_cycle['high_errors']}\n"
        report += f"- **Total Errors Found**: {final_cycle['errors_found']}\n\n"

        # Cycle Analysis
        report += "## 🔄 Improvement Cycle Analysis\n\n"

        for cycle_data in improvement_data["cycles"]:
            status_emoji = "✅" if cycle_data["critical_errors"] == 0 else "⚠️"
            report += f"### {status_emoji} Cycle {cycle_data['cycle']}\n\n"
            report += f"- **Duration**: {cycle_data['duration']:.2f} seconds\n"
            report += f"- **Errors Found**: {cycle_data['errors_found']}\n"
            report += f"  - Critical: {cycle_data['critical_errors']}\n"
            report += f"  - High: {cycle_data['high_errors']}\n"
            report += f"- **Fixes Generated**: {cycle_data['fixes_generated']}\n"

            # Error breakdown
            if cycle_data["errors_by_type"]:
                report += "- **Error Types**:\n"
                for error_type, count in cycle_data["errors_by_type"].items():
                    report += f"  - {error_type.replace('_', ' ').title()}: {count}\n"

            # Test results
            test_results = cycle_data["test_results"]
            successful_tests = sum(
                1 for result in test_results.values() if result.get("success", False)
            )
            total_tests = len(test_results)

            report += f"- **Test Results**: {successful_tests}/{total_tests} passed\n"

            if successful_tests < total_tests:
                report += "- **Failed Tests**:\n"
                for test_name, result in test_results.items():
                    if not result.get("success", False):
                        report += (
                            f"  - `{test_name}`: {result.get('error', 'Failed')}\n"
                        )

            report += "\n"

        # Recommendations
        report += "## 🎯 Recommendations\n\n"

        if final_cycle["critical_errors"] > 0:
            report += "### ⚠️ Critical Issues Requiring Immediate Attention\n\n"
            report += "1. Address all critical security risks immediately\n"
            report += "2. Fix syntax errors preventing code execution\n"
            report += (
                "3. Remove hardcoded credentials and use environment variables\n\n"
            )

        if final_cycle["high_errors"] > 0:
            report += "### 🔧 High Priority Improvements\n\n"
            report += "1. Fix code quality issues affecting maintainability\n"
            report += "2. Address potential runtime errors\n"
            report += "3. Improve error handling patterns\n\n"

        report += "### 📈 Continuous Improvement\n\n"
        report += "1. Implement pre-commit hooks to catch issues early\n"
        report += "2. Set up automated code quality checks in CI/CD\n"
        report += "3. Regular security audits and dependency updates\n"
        report += "4. Code review processes for all changes\n\n"

        return report

    def run_full_debugging_system(self) -> int:
        """Run the complete intelligent debugging system"""
        print("🤖 Starting Intelligent Debugging and Error Detection System")
        print("=" * 65)

        try:
            # Run recursive improvement cycles
            improvement_data = self.recursive_improvement_cycle()

            # Generate comprehensive report
            debugging_report = self.generate_debugging_report(improvement_data)

            # Save reports
            with open("debugging-report.md", "w") as f:
                f.write(debugging_report)

            with open("improvement-cycles.json", "w") as f:
                json.dump(improvement_data, f, indent=2, default=str)

            # Summary
            final_status = improvement_data["final_status"]
            final_cycle = improvement_data["cycles"][-1]

            print(f"\n✅ Debugging system execution completed!")
            print(f"📊 Final Status: {final_status.replace('_', ' ').title()}")
            print(f"🔍 Total Errors Found: {final_cycle['errors_found']}")
            print(f"⚠️  Critical Errors: {final_cycle['critical_errors']}")
            print(f"📁 Reports generated:")
            print(f"  - debugging-report.md")
            print(f"  - improvement-cycles.json")

            return 0 if final_cycle["critical_errors"] == 0 else 1

        except Exception as e:
            print(f"❌ Debugging system encountered an error: {e}")
            traceback.print_exc()
            return 1


if __name__ == "__main__":
    debugger = IntelligentDebugger()
    exit_code = debugger.run_full_debugging_system()
    sys.exit(exit_code)
