#!/usr/bin/env python3
"""
Security Configuration Validator
Validates security configurations and detects potential vulnerabilities
"""

import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

import yaml


class SecurityValidator:
    def __init__(self):
        self.issues = []
        self.critical_patterns = [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']',
            r'token\s*=\s*["\'][^"\']+["\']',
            r"-----BEGIN.*PRIVATE KEY-----",
        ]

    def validate_python_files(self, file_path: Path) -> List[str]:
        """Validate Python files for security issues"""
        issues = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Check for hardcoded secrets
            for pattern in self.critical_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    issues.append(
                        f"CRITICAL: Potential hardcoded secret in {file_path}"
                    )

            # Check for dangerous imports
            dangerous_imports = ["eval", "exec", "input", "__import__"]
            for imp in dangerous_imports:
                if f"({imp}" in content or f" {imp}(" in content:
                    issues.append(
                        f"WARNING: Potentially dangerous function '{imp}' used in {file_path}"
                    )

            # Check for SQL injection patterns
            sql_patterns = [
                r"cursor\.execute\([^)]*%[^)]*\)",
                r"\.format\([^)]*\).*execute",
            ]
            for pattern in sql_patterns:
                if re.search(pattern, content):
                    issues.append(
                        f"WARNING: Potential SQL injection vulnerability in {file_path}"
                    )

        except Exception as e:
            issues.append(f"ERROR: Could not validate {file_path}: {e}")

        return issues

    def validate_json_files(self, file_path: Path) -> List[str]:
        """Validate JSON configuration files"""
        issues = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                config = json.load(f)

            # Check for sensitive data in configs
            if self._contains_sensitive_data(config):
                issues.append(f"WARNING: Potential sensitive data in {file_path}")

            # Validate security-specific configs
            if "security" in str(config).lower():
                if not self._validate_security_config(config):
                    issues.append(
                        f"WARNING: Insecure security configuration in {file_path}"
                    )

        except json.JSONDecodeError as e:
            issues.append(f"ERROR: Invalid JSON in {file_path}: {e}")
        except Exception as e:
            issues.append(f"ERROR: Could not validate {file_path}: {e}")

        return issues

    def validate_yaml_files(self, file_path: Path) -> List[str]:
        """Validate YAML configuration files"""
        issues = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)

            if config and self._contains_sensitive_data(config):
                issues.append(f"WARNING: Potential sensitive data in {file_path}")

        except yaml.YAMLError as e:
            issues.append(f"ERROR: Invalid YAML in {file_path}: {e}")
        except Exception as e:
            issues.append(f"ERROR: Could not validate {file_path}: {e}")

        return issues

    def _contains_sensitive_data(self, data: Any) -> bool:
        """Check if data structure contains sensitive information"""
        if isinstance(data, dict):
            for key, value in data.items():
                if any(
                    term in str(key).lower()
                    for term in ["password", "secret", "key", "token"]
                ):
                    if isinstance(value, str) and len(value) > 10:
                        return True
                if self._contains_sensitive_data(value):
                    return True
        elif isinstance(data, list):
            for item in data:
                if self._contains_sensitive_data(item):
                    return True
        return False

    def _validate_security_config(self, config: Dict) -> bool:
        """Validate security-specific configuration"""
        # Check for weak security settings
        if isinstance(config, dict):
            for key, value in config.items():
                if "ssl" in key.lower() or "tls" in key.lower():
                    if value is False:
                        return False
                if "verify" in key.lower():
                    if value is False:
                        return False
        return True

    def validate_all(self) -> int:
        """Validate all relevant files"""
        print("🔍 Running Security Configuration Validation...")

        # Get all files to validate
        python_files = list(Path(".").glob("**/*.py"))
        json_files = list(Path(".").glob("**/*.json"))
        yaml_files = list(Path(".").glob("**/*.yaml")) + list(
            Path(".").glob("**/*.yml")
        )

        total_issues = 0

        # Validate Python files
        for file_path in python_files:
            if ".git" in str(file_path) or "__pycache__" in str(file_path):
                continue
            issues = self.validate_python_files(file_path)
            self.issues.extend(issues)
            total_issues += len(issues)

        # Validate JSON files
        for file_path in json_files:
            if ".git" in str(file_path):
                continue
            issues = self.validate_json_files(file_path)
            self.issues.extend(issues)
            total_issues += len(issues)

        # Validate YAML files
        for file_path in yaml_files:
            if ".git" in str(file_path):
                continue
            issues = self.validate_yaml_files(file_path)
            self.issues.extend(issues)
            total_issues += len(issues)

        # Report results
        if total_issues == 0:
            print("✅ Security validation passed - no issues found!")
        else:
            print(f"⚠️  Found {total_issues} security issues:")
            for issue in self.issues:
                print(f"  - {issue}")

        # Save report
        with open("security-validation-report.json", "w") as f:
            json.dump(
                {
                    "total_issues": total_issues,
                    "issues": self.issues,
                    "files_checked": {
                        "python": len(python_files),
                        "json": len(json_files),
                        "yaml": len(yaml_files),
                    },
                },
                f,
                indent=2,
            )

        return total_issues


if __name__ == "__main__":
    validator = SecurityValidator()
    issues = validator.validate_all()
    sys.exit(1 if issues > 0 else 0)
