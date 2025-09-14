#!/usr/bin/env python3
"""
Enhanced configuration management for Bl4ckC3ll_PANTHEON
"""

import json
import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional, Union
from dataclasses import dataclass

@dataclass
class ScanConfig:
    """Scan configuration dataclass"""
    max_threads: int = 50
    timeout: int = 300
    rate_limit: int = 100
    retry_attempts: int = 3
    output_format: str = "json"

@dataclass
class SecurityConfig:
    """Security configuration dataclass"""
    strict_mode: bool = True
    command_validation: bool = True
    rate_limiting: bool = True
    audit_logging: bool = True
    max_scan_duration: int = 3600

class ConfigManager:
    """Enhanced configuration manager with validation and security"""
    
    DEFAULT_CONFIG = {
        "version": "2.0.0",
        "security": {
            "strict_mode": True,
            "command_validation": True,
            "rate_limiting": True,
            "audit_logging": True,
            "max_scan_duration": 3600,
            "allowed_output_dirs": ["runs", "logs", "output", "reports"]
        },
        "scanning": {
            "max_threads": 50,
            "timeout": 300,
            "rate_limit": 100,
            "retry_attempts": 3,
            "output_format": "json"
        },
        "limits": {
            "parallel_jobs": 20,
            "http_timeout": 15,
            "rps": 500,
            "max_concurrent_scans": 8
        },
        "nuclei": {
            "enabled": True,
            "severity": "low,medium,high,critical",
            "rps": 800,
            "concurrency": 150,
            "timeout": 30
        },
        "recon": {
            "subdomain_tools": ["subfinder", "amass", "assetfinder"],
            "port_scan_top_ports": 1000,
            "http_probe_threads": 100,
            "crawl_depth": 3
        },
        "reporting": {
            "formats": ["html", "json", "csv"],
            "auto_open_html": True,
            "include_screenshots": False,
            "severity_filter": "medium"
        },
        "api": {
            "enable_api_discovery": True,
            "test_endpoints": True,
            "include_swagger": True,
            "max_api_requests": 1000
        },
        "cloud": {
            "aws_enabled": False,
            "azure_enabled": False,
            "gcp_enabled": False,
            "check_misconfigurations": True
        },
        "containers": {
            "scan_images": False,
            "check_k8s_manifests": False,
            "vulnerability_db_update": True
        }
    }
    
    def __init__(self, config_file: str = "p4nth30n.cfg.json"):
        self.config_file = Path(config_file)
        self.config = self.DEFAULT_CONFIG.copy()
        self.load_config()
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file with fallback to defaults"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    if self.config_file.suffix.lower() == '.yaml' or self.config_file.suffix.lower() == '.yml':
                        loaded_config = yaml.safe_load(f)
                    else:
                        loaded_config = json.load(f)
                
                # Merge with defaults
                self.config = self._merge_configs(self.DEFAULT_CONFIG, loaded_config)
                
            except (json.JSONDecodeError, yaml.YAMLError) as e:
                print(f"Error loading config file {self.config_file}: {e}")
                print("Using default configuration")
                
        return self.config
    
    def save_config(self):
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                if self.config_file.suffix.lower() == '.yaml' or self.config_file.suffix.lower() == '.yml':
                    yaml.dump(self.config, f, default_flow_style=False, indent=2)
                else:
                    json.dump(self.config, f, indent=2)
                    
        except Exception as e:
            print(f"Error saving config file: {e}")
    
    def _merge_configs(self, default: Dict, loaded: Dict) -> Dict:
        """Recursively merge configuration dictionaries"""
        merged = default.copy()
        
        for key, value in loaded.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                merged[key] = self._merge_configs(merged[key], value)
            else:
                merged[key] = value
                
        return merged
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
                
        return value
    
    def set(self, key: str, value: Any):
        """Set configuration value using dot notation"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
            
        config[keys[-1]] = value
    
    def get_scan_config(self) -> ScanConfig:
        """Get scan configuration as dataclass"""
        scan_cfg = self.get('scanning', {})
        return ScanConfig(
            max_threads=scan_cfg.get('max_threads', 50),
            timeout=scan_cfg.get('timeout', 300),
            rate_limit=scan_cfg.get('rate_limit', 100),
            retry_attempts=scan_cfg.get('retry_attempts', 3),
            output_format=scan_cfg.get('output_format', 'json')
        )
    
    def get_security_config(self) -> SecurityConfig:
        """Get security configuration as dataclass"""
        sec_cfg = self.get('security', {})
        return SecurityConfig(
            strict_mode=sec_cfg.get('strict_mode', True),
            command_validation=sec_cfg.get('command_validation', True),
            rate_limiting=sec_cfg.get('rate_limiting', True),
            audit_logging=sec_cfg.get('audit_logging', True),
            max_scan_duration=sec_cfg.get('max_scan_duration', 3600)
        )
    
    def validate_config(self) -> bool:
        """Validate configuration values"""
        try:
            # Validate numeric ranges
            limits = self.get('limits', {})
            if limits.get('parallel_jobs', 0) > 100:
                print("Warning: parallel_jobs > 100 may cause performance issues")
            
            if limits.get('max_concurrent_scans', 0) > 20:
                print("Warning: max_concurrent_scans > 20 may overload system")
            
            # Validate nuclei configuration
            nuclei_cfg = self.get('nuclei', {})
            valid_severities = ['info', 'low', 'medium', 'high', 'critical']
            severities = nuclei_cfg.get('severity', '').split(',')
            
            for severity in severities:
                if severity.strip() not in valid_severities:
                    print(f"Warning: Invalid nuclei severity: {severity}")
            
            # Validate paths
            security_cfg = self.get('security', {})
            allowed_dirs = security_cfg.get('allowed_output_dirs', [])
            for dir_path in allowed_dirs:
                if '..' in dir_path or dir_path.startswith('/'):
                    print(f"Warning: Potentially unsafe output directory: {dir_path}")
            
            return True
            
        except Exception as e:
            print(f"Configuration validation error: {e}")
            return False
    
    def update_from_env(self):
        """Update configuration from environment variables"""
        env_mappings = {
            'PANTHEON_MAX_THREADS': 'scanning.max_threads',
            'PANTHEON_TIMEOUT': 'scanning.timeout',
            'PANTHEON_STRICT_MODE': 'security.strict_mode',
            'PANTHEON_NUCLEI_RPS': 'nuclei.rps',
            'PANTHEON_PARALLEL_JOBS': 'limits.parallel_jobs'
        }
        
        for env_var, config_key in env_mappings.items():
            if env_var in os.environ:
                value = os.environ[env_var]
                
                # Convert to appropriate type
                if value.lower() in ['true', 'false']:
                    value = value.lower() == 'true'
                elif value.isdigit():
                    value = int(value)
                
                self.set(config_key, value)

# Global configuration manager instance
config_manager = ConfigManager()

__all__ = ['ConfigManager', 'ScanConfig', 'SecurityConfig', 'config_manager']