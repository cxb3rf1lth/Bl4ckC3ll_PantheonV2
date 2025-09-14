#!/usr/bin/env python3
"""
Configuration Validator for Bl4ckC3ll_PANTHEON
Validates configuration files and settings for security and correctness
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class ConfigValidator:
    """Validates configuration files and settings"""

    def __init__(self):
        self.validation_rules = {
            "limits": {
                "parallel_jobs": {"type": int, "min": 1, "max": 100},
                "http_timeout": {"type": int, "min": 1, "max": 300},
                "max_results": {"type": int, "min": 1, "max": 100000, "optional": True},
                "rate_limit": {
                    "type": float,
                    "min": 0.1,
                    "max": 10.0,
                    "optional": True,
                },
                "rps": {"type": int, "min": 1, "max": 10000, "optional": True},
                "max_concurrent_scans": {
                    "type": int,
                    "min": 1,
                    "max": 50,
                    "optional": True,
                },
                "retry_attempts": {"type": int, "min": 1, "max": 10, "optional": True},
                "max_retries": {"type": int, "min": 1, "max": 10, "optional": True},
                "backoff_delay": {
                    "type": (int, float),
                    "min": 0.1,
                    "max": 60,
                    "optional": True,
                },
                "scan_depth": {"type": int, "min": 1, "max": 10, "optional": True},
            },
            "nuclei": {
                "severity": {
                    "type": (list, str),
                    "allowed_values": ["critical", "high", "medium", "low", "info"],
                },
                "update_interval": {
                    "type": int,
                    "min": 1,
                    "max": 168,
                    "optional": True,
                },
                "custom_templates": {"type": bool, "optional": True},
                "enabled": {"type": bool, "optional": True},
                "rps": {"type": int, "min": 1, "max": 10000, "optional": True},
                "conc": {"type": int, "min": 1, "max": 500, "optional": True},
                "timeout": {"type": int, "min": 1, "max": 300, "optional": True},
                "retries": {"type": int, "min": 0, "max": 10, "optional": True},
                "all_templates": {"type": bool, "optional": True},
            },
            "report": {
                "format": {
                    "type": list,
                    "allowed_values": ["html", "json", "csv", "xml"],
                    "optional": True,
                },
                "formats": {
                    "type": list,
                    "allowed_values": ["html", "json", "csv", "xml"],
                    "optional": True,
                },
                "include_screenshots": {"type": bool, "optional": True},
                "detailed_analysis": {"type": bool, "optional": True},
            },
            "repos": {
                "seclists": {"type": str, "pattern": r"^https?://.*", "optional": True},
                "payloads": {"type": str, "pattern": r"^https?://.*", "optional": True},
                "wordlists": {
                    "type": str,
                    "pattern": r"^https?://.*",
                    "optional": True,
                },
                "SecLists": {"type": str, "pattern": r"^https?://.*", "optional": True},
                "PayloadsAllTheThings": {
                    "type": str,
                    "pattern": r"^https?://.*",
                    "optional": True,
                },
                "Wordlists": {
                    "type": str,
                    "pattern": r"^https?://.*",
                    "optional": True,
                },
                "NucleiTemplates": {
                    "type": str,
                    "pattern": r"^https?://.*",
                    "optional": True,
                },
                "Exploits": {"type": str, "pattern": r"^https?://.*", "optional": True},
            },
            # Additional sections that may exist in the config
            "bcar": {"_allow_any": True},
            "payload_injection": {"_allow_any": True},
            "performance": {"_allow_any": True},
            "resource_management": {"_allow_any": True},
            "fuzzing": {"_allow_any": True},
            "validation": {"_allow_any": True},
            "scanning": {"_allow_any": True},
            "fallback": {"_allow_any": True},
            "plugins": {"_allow_any": True},
            "reliability": {"_allow_any": True},
            "notifications": {"_allow_any": True},
            "security": {"_allow_any": True},
            "output": {"_allow_any": True},
        }

    def validate_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate configuration against rules

        Args:
            config: Configuration dictionary to validate

        Returns:
            Dict with validation results
        """
        result = {"valid": True, "errors": [], "warnings": [], "sections_validated": 0}

        try:
            # Validate each section
            for section_name, section_rules in self.validation_rules.items():
                if section_name in config:
                    section_result = self._validate_section(
                        config[section_name], section_rules, section_name
                    )
                    result["errors"].extend(section_result["errors"])
                    result["warnings"].extend(section_result["warnings"])
                    result["sections_validated"] += 1
                else:
                    result["warnings"].append(
                        f"Optional section '{section_name}' not found in config"
                    )

            # Check for unknown sections
            known_sections = set(self.validation_rules.keys())
            config_sections = set(config.keys())
            unknown_sections = config_sections - known_sections

            for unknown in unknown_sections:
                result["warnings"].append(f"Unknown configuration section: '{unknown}'")

            # Set overall validity
            result["valid"] = len(result["errors"]) == 0

        except Exception as e:
            result["valid"] = False
            result["errors"].append(f"Configuration validation failed: {str(e)}")

        return result

    def _validate_section(
        self, section_data: Dict[str, Any], rules: Dict[str, Any], section_name: str
    ) -> Dict[str, Any]:
        """Validate a configuration section against its rules"""
        result = {"errors": [], "warnings": []}

        # Special case: if _allow_any is True, skip detailed validation
        if rules.get("_allow_any", False):
            return result

        for key, rule in rules.items():
            if key == "_allow_any":
                continue

            if key in section_data:
                value = section_data[key]
                validation_result = self._validate_value(
                    value, rule, f"{section_name}.{key}"
                )
                result["errors"].extend(validation_result["errors"])
                result["warnings"].extend(validation_result["warnings"])
            else:
                if not rule.get("optional", False):
                    result["warnings"].append(
                        f"Optional setting '{section_name}.{key}' not found"
                    )

        # Check for unknown keys in section (only if not _allow_any)
        if not rules.get("_allow_any", False):
            known_keys = set(key for key in rules.keys() if key != "_allow_any")
            section_keys = set(section_data.keys())
            unknown_keys = section_keys - known_keys

            for unknown in unknown_keys:
                result["warnings"].append(
                    f"Unknown setting in {section_name}: '{unknown}'"
                )

        return result

    def _validate_value(
        self, value: Any, rule: Dict[str, Any], field_path: str
    ) -> Dict[str, Any]:
        """Validate a single value against its rule"""
        result = {"errors": [], "warnings": []}

        # Type validation (handle tuple types for multiple allowed types)
        expected_type = rule.get("type")
        if expected_type:
            if isinstance(expected_type, tuple):
                # Multiple types allowed
                if not any(isinstance(value, t) for t in expected_type):
                    type_names = [t.__name__ for t in expected_type]
                    result["errors"].append(
                        f"{field_path}: Expected {' or '.join(type_names)}, got {type(value).__name__}"
                    )
                    return result
            else:
                # Single type expected
                if not isinstance(value, expected_type):
                    result["errors"].append(
                        f"{field_path}: Expected {expected_type.__name__}, got {type(value).__name__}"
                    )
                    return result

        # Range validation for numbers
        if isinstance(value, (int, float)):
            if "min" in rule and value < rule["min"]:
                result["errors"].append(
                    f"{field_path}: Value {value} is below minimum {rule['min']}"
                )
            if "max" in rule and value > rule["max"]:
                result["errors"].append(
                    f"{field_path}: Value {value} is above maximum {rule['max']}"
                )

        # Pattern validation for strings
        if isinstance(value, str) and "pattern" in rule:
            pattern = rule["pattern"]
            if not re.match(pattern, value):
                result["errors"].append(
                    f"{field_path}: Value '{value}' does not match pattern '{pattern}'"
                )

        # Allowed values validation for lists and strings
        if "allowed_values" in rule:
            allowed = rule["allowed_values"]
            if isinstance(value, list):
                for item in value:
                    if item not in allowed:
                        result["errors"].append(
                            f"{field_path}: Invalid list item '{item}'. Allowed: {allowed}"
                        )
            elif isinstance(value, str):
                # Handle comma-separated string (like nuclei severity)
                if "," in value:
                    items = [item.strip() for item in value.split(",")]
                    for item in items:
                        if item not in allowed:
                            result["errors"].append(
                                f"{field_path}: Invalid severity '{item}'. Allowed: {allowed}"
                            )
                else:
                    if value not in allowed:
                        result["errors"].append(
                            f"{field_path}: Invalid value '{value}'. Allowed: {allowed}"
                        )
            elif value not in allowed:
                result["errors"].append(
                    f"{field_path}: Invalid value '{value}'. Allowed: {allowed}"
                )

        return result

    def validate_file(self, config_path: Path) -> Dict[str, Any]:
        """
        Validate a configuration file

        Args:
            config_path: Path to the configuration file

        Returns:
            Dict with validation results
        """
        result = {
            "valid": False,
            "errors": [],
            "warnings": [],
            "file_path": str(config_path),
        }

        try:
            if not config_path.exists():
                result["errors"].append(f"Configuration file not found: {config_path}")
                return result

            # Load JSON configuration
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)

            # Validate the loaded configuration
            validation_result = self.validate_config(config)
            result.update(validation_result)

        except json.JSONDecodeError as e:
            result["errors"].append(f"Invalid JSON in configuration file: {str(e)}")
        except Exception as e:
            result["errors"].append(f"Error reading configuration file: {str(e)}")

        return result

    def get_default_config(self) -> Dict[str, Any]:
        """Get a default valid configuration"""
        return {
            "limits": {
                "parallel_jobs": 10,
                "http_timeout": 30,
                "max_results": 1000,
                "rate_limit": 1.0,
            },
            "nuclei": {
                "severity": ["critical", "high", "medium"],
                "update_interval": 24,
                "custom_templates": True,
            },
            "report": {
                "format": ["html", "json"],
                "include_screenshots": True,
                "detailed_analysis": True,
            },
            "repos": {
                "seclists": "https://github.com/danielmiessler/SecLists.git",
                "payloads": "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
                "wordlists": "https://github.com/assetnote/commonspeak2-wordlists.git",
            },
        }

    def generate_config_template(self, output_path: Optional[Path] = None) -> str:
        """Generate a configuration template with comments"""
        template = """// Bl4ckC3ll_PANTHEON Configuration Template
// This file contains all available configuration options with examples
{
    // System limits and performance settings
    "limits": {
        "parallel_jobs": 10,        // Number of parallel jobs (1-100)
        "http_timeout": 30,         // HTTP request timeout in seconds (1-300)
        "max_results": 1000,        // Maximum results per scan (1-100000)
        "rate_limit": 1.0           // Rate limit for requests per second (0.1-10.0)
    },
    
    // Nuclei vulnerability scanner settings
    "nuclei": {
        "severity": ["critical", "high", "medium"],  // Severity levels to scan
        "update_interval": 24,      // Template update interval in hours (1-168)
        "custom_templates": true    // Use custom templates
    },
    
    // Report generation settings
    "report": {
        "format": ["html", "json"], // Output formats: html, json, csv, xml
        "include_screenshots": true, // Include screenshots in reports
        "detailed_analysis": true   // Include detailed vulnerability analysis
    },
    
    // External repository URLs
    "repos": {
        "seclists": "https://github.com/danielmiessler/SecLists.git",
        "payloads": "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
        "wordlists": "https://github.com/assetnote/commonspeak2-wordlists.git"
    }
}
"""

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(template)

        return template


def validate_config_file(file_path: str) -> bool:
    """
    Convenience function to validate a configuration file

    Args:
        file_path: Path to the configuration file

    Returns:
        True if valid, False otherwise
    """
    validator = ConfigValidator()
    result = validator.validate_file(Path(file_path))

    if result["valid"]:
        print(f"✅ Configuration file '{file_path}' is valid")
        if result["warnings"]:
            print("⚠️  Warnings:")
            for warning in result["warnings"]:
                print(f"   - {warning}")
        return True
    else:
        print(f"❌ Configuration file '{file_path}' is invalid")
        print("Errors:")
        for error in result["errors"]:
            print(f"   - {error}")
        if result["warnings"]:
            print("Warnings:")
            for warning in result["warnings"]:
                print(f"   - {warning}")
        return False


if __name__ == "__main__":
    # Example usage and testing
    print("Config Validator Test")
    print("=" * 50)

    validator = ConfigValidator()

    # Test with default config
    default_config = validator.get_default_config()
    result = validator.validate_config(default_config)
    print(f"Default config validation: {'✅ PASS' if result['valid'] else '❌ FAIL'}")

    # Test with invalid config
    invalid_config = {
        "limits": {
            "parallel_jobs": -1,  # Invalid: below minimum
            "http_timeout": 999,  # Invalid: above maximum
        }
    }
    result = validator.validate_config(invalid_config)
    print(
        f"Invalid config detection: {'✅ PASS' if not result['valid'] else '❌ FAIL'}"
    )

    # Test config file validation if p4nth30n.cfg.json exists
    config_file = Path("p4nth30n.cfg.json")
    if config_file.exists():
        print(f"\nValidating existing config file: {config_file}")
        validate_config_file(str(config_file))
