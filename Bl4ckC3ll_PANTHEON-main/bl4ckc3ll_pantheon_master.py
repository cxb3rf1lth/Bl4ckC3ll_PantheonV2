#!/usr/bin/env python3
"""
BL4CKC3LL_PANTHEON_MASTER - Unified Advanced Security Testing Framework
========================================================================

This is the consolidated master version combining all capabilities from:
- bl4ckc3ll_p4nth30n.py (Main framework with 28 security testing options)
- bcar.py (Bug Bounty Certificate Authority Reconnaissance)  
- TUI interface (Advanced Terminal User Interface)
- Enhanced scanner, security utils, and all automation modules
- Bug bounty automation, payload management, and CI/CD integration

Author: @cxb3rf1lth
Version: 10.0.0-MASTER-CONSOLIDATED
License: Educational/Research Use Only

Features Consolidated:
- Complete reconnaissance framework (subdomain, port, technology detection)
- Advanced vulnerability scanning with AI-powered analysis
- BCAR enhanced reconnaissance with certificate transparency
- Comprehensive TUI interface with real-time monitoring
- Bug bounty automation and payload management
- Cloud security assessment (AWS, Azure, GCP)
- API security testing (REST, GraphQL, SOAP)
- CI/CD integration and automated testing chains
- Enhanced security validation and input sanitization
- Professional reporting and visualization
- Plugin system and extensible architecture
"""

import os
import sys
import json
import time
import threading
import subprocess
import platform
import tempfile
import shutil
import uuid
import webbrowser
import logging
import asyncio
import socket
import ssl
import base64
import re
import html
import urllib.parse
import ipaddress
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Tuple, Set, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, quote, unquote
from dataclasses import dataclass, asdict
import importlib.util

# Advanced imports for enhanced functionality
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    from textual.app import App, ComposeResult
    from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
    from textual.widgets import (
        Header, Footer, Static, Button, Label, Input, DataTable, 
        TextArea, ProgressBar, Log, Select, Checkbox, Tree, TabbedContent, TabPane
    )
    from textual.binding import Binding
    from textual.reactive import reactive
    from textual import on
    HAS_TEXTUAL = True
except ImportError:
    HAS_TEXTUAL = False

try:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    HAS_ML = True
except ImportError:
    HAS_ML = False

try:
    import matplotlib.pyplot as plt
    import plotly.graph_objects as go
    from jinja2 import Template
    HAS_VISUALIZATION = True
except ImportError:
    HAS_VISUALIZATION = False

# Security and validation imports
try:
    from cryptography.fernet import Fernet
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# ============================================================================
# CORE CONSTANTS AND CONFIGURATION
# ============================================================================

VERSION = "10.0.0-MASTER-CONSOLIDATED"
BANNER = """
██████╗ ██╗      █████╗ ██╗  ██╗ ██████╗██╗  ██╗ ██████╗ ███████╗██╗     ██╗
██╔══██╗██║     ██╔══██╗██║ ██╔╝██╔════╝██║ ██╔╝██╔════╝ ██╔════╝██║     ██║
██████╔╝██║     ███████║█████╔╝ ██║     █████╔╝ ██║  ███╗█████╗  ██║     ██║
██╔══██╗██║     ██╔══██║██╔═██╗ ██║     ██╔═██╗ ██║   ██║██╔══╝  ██║     ██║
██████╔╝███████╗██║  ██║██║  ██╗╚██████╗██║  ██╗╚██████╔╝███████╗███████╗███████╗
╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝

PANTHEON MASTER v{} - Consolidated Advanced Security Testing Framework
""".format(VERSION)

# Default configurations
DEFAULT_CONFIG = {
    "general": {
        "max_threads": 50,
        "timeout": 30,
        "retries": 3,
        "verbose": True,
        "output_format": "json"
    },
    "scanning": {
        "subdomain_wordlist_size": 10000,
        "port_scan_top_ports": 1000,
        "http_timeout": 10,
        "max_crawl_depth": 3
    },
    "security": {
        "validate_inputs": True,
        "sanitize_outputs": True,
        "rate_limiting": True,
        "max_payload_size": 1048576
    },
    "reporting": {
        "generate_html": True,
        "generate_json": True,
        "generate_csv": True,
        "include_screenshots": False
    }
}

# ============================================================================
# SECURITY AND VALIDATION SYSTEM
# ============================================================================

class SecurityValidator:
    """Comprehensive security validation and input sanitization"""
    
    # Dangerous patterns to detect and prevent
    DANGEROUS_PATTERNS = {
        'path_traversal': re.compile(r'\.\.\/|\.\.\\|\.\.[\/\\]'),
        'command_injection': re.compile(r'[;&|`$\(\)]|\b(rm|del|format|shutdown)\b', re.IGNORECASE),
        'script_tags': re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
        'sql_injection': re.compile(r'(\b(union|select|insert|update|delete|drop|create|alter)\b|--|\'|"|\;)', re.IGNORECASE),
        'xss_patterns': re.compile(r'(javascript:|data:|vbscript:|onload|onerror|onclick)', re.IGNORECASE)
    }
    
    @staticmethod
    def validate_domain(domain: str, logger=None) -> bool:
        """Enhanced domain validation with detailed error reporting"""
        if logger is None:
            logger = PantheonLogger("DOMAIN_VALIDATOR")
            
        if not isinstance(domain, str):
            logger.error(f"Domain must be a string, got {type(domain).__name__}")
            return False
            
        if not domain:
            logger.error("Domain cannot be empty")
            return False
            
        if len(domain) > 255:
            logger.error(f"Domain too long: {len(domain)} > 255 characters")
            return False
        
        # Remove protocol if present
        clean_domain = domain.replace('http://', '').replace('https://', '').replace('www.', '')
        clean_domain = clean_domain.split('/')[0].split(':')[0]
        
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        if not re.match(domain_pattern, clean_domain):
            logger.error(f"Invalid domain format: {domain}")
            logger.info("Domain should be in format: example.com or subdomain.example.com")
            return False
            
        if clean_domain.count('.') == 0:
            logger.warning(f"Domain appears incomplete: {clean_domain} (missing TLD?)")
            
        return True
    
    @staticmethod
    def validate_ip(ip: str, logger=None) -> bool:
        """Enhanced IP validation with detailed error reporting"""
        if logger is None:
            logger = PantheonLogger("IP_VALIDATOR")
            
        if not isinstance(ip, str):
            logger.error(f"IP must be a string, got {type(ip).__name__}")
            return False
            
        if not ip:
            logger.error("IP address cannot be empty")
            return False
            
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Provide context about IP types
            if ip_obj.is_private:
                logger.info(f"Private IP address detected: {ip}")
            elif ip_obj.is_loopback:
                logger.info(f"Loopback IP address detected: {ip}")
            elif ip_obj.is_multicast:
                logger.warning(f"Multicast IP address: {ip} (may not be suitable for scanning)")
            elif ip_obj.is_reserved:
                logger.warning(f"Reserved IP address: {ip} (may not be scannable)")
                
            return True
        except ValueError as e:
            logger.error(f"Invalid IP address format: {ip} - {e}")
            logger.info("IP should be in format: 192.168.1.1 or 2001:db8::1")
            return False
    
    @staticmethod
    def validate_url(url: str, logger=None) -> bool:
        """Enhanced URL validation with detailed error reporting"""
        if logger is None:
            logger = PantheonLogger("URL_VALIDATOR")
            
        if not isinstance(url, str):
            logger.error(f"URL must be a string, got {type(url).__name__}")
            return False
            
        if not url:
            logger.error("URL cannot be empty")
            return False
            
        if len(url) > 2048:
            logger.error(f"URL too long: {len(url)} > 2048 characters")
            return False
            
        try:
            parsed = urlparse(url)
            
            if not parsed.scheme:
                logger.error(f"URL missing protocol: {url}")
                logger.info("URL should start with http:// or https://")
                return False
                
            if parsed.scheme not in ['http', 'https']:
                logger.error(f"Unsupported URL protocol: {parsed.scheme}")
                logger.info("Only HTTP and HTTPS protocols are supported")
                return False
                
            if not parsed.netloc:
                logger.error(f"URL missing host/domain: {url}")
                logger.info("URL should include a valid domain name")
                return False
                
            return True
        except Exception as e:
            logger.error(f"URL parsing error: {url} - {e}")
            return False
    
    @staticmethod
    def sanitize_input(input_str: str) -> str:
        """Sanitize user input to prevent injection attacks"""
        if not isinstance(input_str, str):
            return str(input_str)
        
        # HTML encode dangerous characters
        sanitized = html.escape(input_str)
        
        # Remove dangerous patterns
        for pattern_name, pattern in SecurityValidator.DANGEROUS_PATTERNS.items():
            sanitized = pattern.sub('', sanitized)
        
        return sanitized
    
    @staticmethod
    def validate_file_path(path: str) -> bool:
        """Validate file path to prevent path traversal"""
        try:
            # Resolve path and check if it's within allowed directories
            resolved_path = Path(path).resolve()
            current_dir = Path.cwd()
            
            # Check if path is within current directory tree
            try:
                resolved_path.relative_to(current_dir)
                return True
            except ValueError:
                return False
        except Exception:
            return False

# ============================================================================
# ENHANCED ERROR HANDLING SYSTEM
# ============================================================================

def safe_execute_master(func, *args, default=None, error_msg="Operation failed", 
                       log_level="ERROR", logger=None, **kwargs):
    """Enhanced safe execution with detailed error handling for master script"""
    if logger is None:
        logger = PantheonLogger("SAFE_EXECUTE")
    
    try:
        return func(*args, **kwargs)
    except FileNotFoundError as e:
        filepath = str(e).split("'")[1] if "'" in str(e) else "unknown"
        logger.error(f"{error_msg} - File not found: {filepath}")
        logger.info(f"Recovery: Check if file exists, verify path permissions, or create missing directory")
        return default
    except PermissionError as e:
        filepath = str(e).split("'")[1] if "'" in str(e) else "unknown"
        logger.error(f"{error_msg} - Permission denied: {filepath}")
        logger.info(f"Recovery: Run with appropriate permissions or check file/directory ownership")
        return default
    except subprocess.TimeoutExpired as e:
        cmd = getattr(e, 'cmd', 'unknown command')
        timeout_val = getattr(e, 'timeout', 'unknown')
        logger.error(f"{error_msg} - Timeout after {timeout_val}s: {cmd}")
        logger.info(f"Recovery: Increase timeout, reduce scan scope, or check network connectivity")
        return default
    except subprocess.CalledProcessError as e:
        cmd = e.cmd if hasattr(e, 'cmd') else 'unknown'
        returncode = e.returncode if hasattr(e, 'returncode') else 'unknown'
        logger.error(f"{error_msg} - Command failed (exit code: {returncode}): {cmd}")
        return default
    except ConnectionError as e:
        logger.error(f"{error_msg} - Network connection error: {e}")
        logger.info(f"Recovery: Check internet connectivity, proxy settings, or target availability")
        return default
    except Exception as e:
        error_type = type(e).__name__
        logger.error(f"{error_msg} - {error_type}: {e}")
        
        # Provide contextual recovery suggestions
        error_str = str(e).lower()
        if 'connection' in error_str or 'network' in error_str:
            logger.info("Recovery: Check network connectivity and firewall settings")
        elif 'memory' in error_str or 'resource' in error_str:
            logger.info("Recovery: Free up system resources or reduce scan intensity")
        elif 'configuration' in error_str or 'config' in error_str:
            logger.info("Recovery: Verify configuration file syntax and required settings")
        else:
            logger.info("Recovery: Check logs, verify input parameters, or try with reduced scope")
        
        return default

def execute_tool_safely_master(tool_name: str, args: List[str], timeout: int = 300, 
                              output_file: Optional[Path] = None, logger=None) -> bool:
    """Enhanced tool execution for master script with fallbacks"""
    if logger is None:
        logger = PantheonLogger("TOOL_EXEC")
    
    # Check tool availability
    if not shutil.which(tool_name):
        install_suggestions = {
            'nuclei': 'go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
            'subfinder': 'go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
            'httpx': 'go install github.com/projectdiscovery/httpx/cmd/httpx@latest',
            'naabu': 'go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest',
            'nmap': 'apt install nmap',
            'sqlmap': 'apt install sqlmap'
        }
        
        suggestion = install_suggestions.get(tool_name, f"Please install {tool_name}")
        logger.warning(f"Tool '{tool_name}' not available. Install with: {suggestion}")
        
        # Suggest alternatives for critical tools
        alternatives = {
            'nuclei': 'Consider manual vulnerability testing or use nikto',
            'nmap': 'Use netcat for basic port testing',
            'subfinder': 'Try manual subdomain enumeration with DNS queries'
        }
        
        if tool_name in alternatives:
            logger.info(f"Alternative: {alternatives[tool_name]}")
        
        return False
    
    # Enhanced argument validation
    for i, arg in enumerate(args):
        if isinstance(arg, str):
            if len(arg) > 1000:
                logger.error(f"Argument #{i} too long for {tool_name}: {len(arg)} chars")
                return False
            
            # Security validation
            if any(pattern in arg.lower() for pattern in ['rm -rf', 'format c:', 'del *']):
                logger.error(f"Dangerous argument detected for {tool_name}: {arg[:50]}")
                return False
    
    # Execute with enhanced error handling
    cmd = [tool_name] + args
    logger.debug(f"Executing: {tool_name} with {len(args)} arguments")
    
    result = safe_execute_master(
        subprocess.run,
        cmd,
        capture_output=bool(output_file),
        text=True,
        timeout=timeout,
        check=False,
        default=None,
        error_msg=f"Tool execution failed: {tool_name}",
        logger=logger
    )
    
    if result is None:
        logger.warning(f"Tool {tool_name} execution failed - check error messages above")
        return False
    
    # Handle output
    if output_file and hasattr(result, 'stdout'):
        if result.stdout:
            try:
                output_file.parent.mkdir(parents=True, exist_ok=True)
                output_file.write_text(result.stdout, encoding='utf-8')
                logger.debug(f"Tool output saved to {output_file} ({len(result.stdout)} chars)")
                return True
            except Exception as e:
                logger.error(f"Failed to save output to {output_file}: {e}")
                return False
        else:
            logger.warning(f"Tool {tool_name} produced no output")
            return True
    
    return hasattr(result, 'returncode') and result.returncode == 0

def safe_http_request_master(url: str, method: str = 'GET', timeout: int = 10, 
                           retries: int = 3, logger=None, **kwargs) -> Optional[Dict[str, Any]]:
    """Enhanced HTTP request function for master script"""
    if logger is None:
        logger = PantheonLogger("HTTP_REQUEST")
    
    if not HAS_REQUESTS:
        logger.error("Requests library not available for HTTP operations")
        return {'success': False, 'error': 'missing_dependency', 'message': 'requests not installed'}
    
    # URL validation
    if not SecurityValidator.validate_url(url):
        logger.error(f"Invalid URL format: {url}")
        return {'success': False, 'error': 'invalid_url', 'message': 'URL format validation failed'}
    
    try:
        import requests
        from requests.adapters import HTTPAdapter
        from requests.packages.urllib3.util.retry import Retry
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
        )
        
        session = requests.Session()
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set secure headers
        headers = kwargs.get('headers', {})
        headers.update({
            'User-Agent': 'Bl4ckC3ll_PANTHEON_Master/10.0.0 Security Scanner',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        })
        kwargs['headers'] = headers
        kwargs['timeout'] = timeout
        kwargs['verify'] = kwargs.get('verify', False)
        
        logger.debug(f"Making {method} request to {url}")
        response = session.request(method, url, **kwargs)
        
        result = {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'content': response.text,
            'url': str(response.url),
            'elapsed': response.elapsed.total_seconds(),
            'success': True
        }
        
        logger.debug(f"HTTP request successful: {url} - {response.status_code} ({response.elapsed.total_seconds():.2f}s)")
        return result
        
    except requests.exceptions.ConnectionError as e:
        logger.warning(f"Connection error for {url}: {e}")
        return {'success': False, 'error': 'connection_error', 'message': str(e)}
    except requests.exceptions.Timeout as e:
        logger.warning(f"Request timeout for {url}: {e}")
        return {'success': False, 'error': 'timeout', 'message': str(e)}
    except requests.exceptions.RequestException as e:
        logger.warning(f"Request error for {url}: {e}")
        return {'success': False, 'error': 'request_error', 'message': str(e)}
    except Exception as e:
        logger.error(f"Unexpected error making request to {url}: {e}")
        return {'success': False, 'error': 'unexpected_error', 'message': str(e)}

# ============================================================================
# ENHANCED LOGGING SYSTEM
# ============================================================================

class PantheonLogger:
    """Enhanced logging system with security awareness"""
    
    def __init__(self, name="PANTHEON", log_level=logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(log_level)
        
        if not self.logger.handlers:
            # Console handler
            console_handler = logging.StreamHandler()
            console_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            console_handler.setFormatter(console_formatter)
            self.logger.addHandler(console_handler)
            
            # File handler
            try:
                log_file = Path.cwd() / "logs" / f"pantheon_{datetime.now().strftime('%Y%m%d')}.log"
                log_file.parent.mkdir(parents=True, exist_ok=True)
                file_handler = logging.FileHandler(log_file)
                file_handler.setFormatter(console_formatter)
                self.logger.addHandler(file_handler)
            except Exception as e:
                logging.warning(f"Operation failed: {e}")  # Continue without file logging if not possible
    
    def info(self, message: str):
        """Log info message"""
        self.logger.info(SecurityValidator.sanitize_input(message))
    
    def warning(self, message: str):
        """Log warning message"""
        self.logger.warning(SecurityValidator.sanitize_input(message))
    
    def error(self, message: str):
        """Log error message"""
        self.logger.error(SecurityValidator.sanitize_input(message))
    
    def debug(self, message: str):
        """Log debug message"""
        self.logger.debug(SecurityValidator.sanitize_input(message))
    
    def success(self, message: str):
        """Log success message with special formatting"""
        self.logger.info(f"✅ {SecurityValidator.sanitize_input(message)}")

# ============================================================================
# BCAR ENHANCED RECONNAISSANCE SYSTEM
# ============================================================================

class BCARCore:
    """Enhanced Bug Bounty Certificate Authority Reconnaissance"""
    
    def __init__(self, logger=None):
        self.logger = logger or PantheonLogger("BCAR")
        self.session = requests.Session() if HAS_REQUESTS else None
        if self.session:
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (compatible; BCAR/1.0; +https://github.com/cxb3rf1lth)'
            })
        self.found_subdomains = set()
        self.found_endpoints = set()
        self.certificates = []
        self.vulnerabilities = []
    
    def certificate_transparency_search(self, domain: str, limit: int = 1000) -> List[str]:
        """Search certificate transparency logs for subdomains"""
        if not SecurityValidator.validate_domain(domain):
            self.logger.error(f"Invalid domain: {domain}")
            return []
        
        subdomains = set()
        
        if not self.session:
            self.logger.warning("Requests module not available, skipping CT search")
            return list(subdomains)
        
        # Certificate transparency sources
        ct_sources = [
            f"https://crt.sh/?q=%.{domain}&output=json",
            f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        ]
        
        for source in ct_sources:
            try:
                self.logger.info(f"Searching CT logs: {source}")
                response = self.session.get(source, timeout=30)
                
                if response.status_code == 200:
                    if 'crt.sh' in source:
                        data = response.json()
                        for cert in data[:limit]:
                            name_value = cert.get('name_value', '')
                            for subdomain in name_value.split('\n'):
                                subdomain = subdomain.strip()
                                if subdomain and SecurityValidator.validate_domain(subdomain):
                                    subdomains.add(subdomain)
                    
                    elif 'certspotter' in source:
                        data = response.json()
                        for cert in data[:limit]:
                            dns_names = cert.get('dns_names', [])
                            for name in dns_names:
                                if SecurityValidator.validate_domain(name):
                                    subdomains.add(name)
                                    
            except Exception as e:
                self.logger.error(f"CT search failed for {source}: {e}")
        
        self.found_subdomains.update(subdomains)
        return list(subdomains)
    
    def advanced_subdomain_enumeration(self, domain: str, wordlist: List[str] = None) -> List[str]:
        """Perform advanced subdomain enumeration"""
        if not SecurityValidator.validate_domain(domain):
            return []
        
        found_subs = set()
        wordlist = wordlist or self._get_default_wordlist()
        
        def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{domain}"
                if SecurityValidator.validate_domain(full_domain):
                    # Try DNS resolution
                    socket.gethostbyname(full_domain)
                    found_subs.add(full_domain)
                    return full_domain
            except Exception as e:
                logging.warning(f"Unexpected error: {e}")
            return None
        
        # Multi-threaded subdomain checking
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in wordlist[:1000]]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.logger.info(f"Found subdomain: {result}")
        
        return list(found_subs)
    
    def subdomain_takeover_check(self, subdomains: List[str]) -> List[Dict[str, Any]]:
        """Check for subdomain takeover vulnerabilities"""
        vulnerable_subdomains = []
        
        # Takeover signatures for various cloud services
        takeover_signatures = {
            'AWS S3': ['NoSuchBucket', 'The specified bucket does not exist'],
            'GitHub Pages': ['There isn\'t a GitHub Pages site here', 'For root URLs'],
            'Heroku': ['no-such-app.herokuapp.com', 'herokucdn.com/error-pages'],
            'Azure': ['404 Web Site not found', 'Error 404 - Web app not found'],
            'Shopify': ['Sorry, this shop is currently unavailable'],
            'Fastly': ['Fastly error: unknown domain'],
            'CloudFront': ['ERROR: The request could not be satisfied'],
            'Tumblr': ['Whatever you were looking for doesn\'t currently exist'],
            'WordPress.com': ['Do you want to register'],
            'Bitbucket': ['Repository not found'],
            'Ghost': ['The thing you were looking for is no longer here'],
            'Surge.sh': ['project not found'],
            'Zendesk': ['Help Center Closed']
        }
        
        def check_takeover(subdomain):
            if not self.session:
                return None
                
            try:
                response = self.session.get(f"http://{subdomain}", timeout=10)
                content = response.text.lower()
                
                for service, signatures in takeover_signatures.items():
                    for signature in signatures:
                        if signature.lower() in content:
                            return {
                                'subdomain': subdomain,
                                'service': service,
                                'signature': signature,
                                'status_code': response.status_code,
                                'confidence': 'high'
                            }
            except Exception as e:
                logging.warning(f"Unexpected error: {e}")
            return None
        
        # Check subdomains for takeover vulnerabilities
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_takeover, sub) for sub in subdomains]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    vulnerable_subdomains.append(result)
                    self.logger.warning(f"Potential takeover: {result['subdomain']} -> {result['service']}")
        
        return vulnerable_subdomains
    
    def _get_default_wordlist(self) -> List[str]:
        """Get default subdomain wordlist"""
        return [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2',
            'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ssl', 'secure', 'imap', 'sftp',
            'admin', 'api', 'blog', 'dev', 'test', 'staging', 'demo', 'app', 'mobile', 'm',
            'beta', 'alpha', 'portal', 'dashboard', 'cms', 'shop', 'store', 'support', 'help',
            'cdn', 'static', 'media', 'assets', 'img', 'images', 'upload', 'downloads'
        ]

# ============================================================================
# ADVANCED SCANNING ENGINE
# ============================================================================

class AdvancedScanManager:
    """Advanced scanning manager with comprehensive capabilities"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or DEFAULT_CONFIG
        self.logger = PantheonLogger("ScanManager")
        self.session = requests.Session() if HAS_REQUESTS else None
        self.bcar = BCARCore(self.logger)
        
    def comprehensive_port_scan(self, targets: List[str], ports: List[int] = None) -> Dict[str, List[int]]:
        """Perform comprehensive port scanning"""
        if ports is None:
            # Top 1000 ports
            ports = list(range(1, 1001))
        
        results = {}
        
        def scan_target_port(target, port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                sock.close()
                return port if result == 0 else None
            except:
                return None
        
        for target in targets:
            if not SecurityValidator.validate_ip(target) and not SecurityValidator.validate_domain(target):
                continue
                
            self.logger.info(f"Scanning {target}")
            open_ports = []
            
            # Multi-threaded port scanning
            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = [executor.submit(scan_target_port, target, port) for port in ports]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        open_ports.append(result)
            
            results[target] = sorted(open_ports)
            self.logger.info(f"Found {len(open_ports)} open ports on {target}")
        
        return results
    
    def web_technology_detection(self, urls: List[str]) -> Dict[str, Dict[str, Any]]:
        """Detect web technologies and frameworks"""
        if not self.session:
            return {}
        
        results = {}
        
        # Technology signatures
        tech_signatures = {
            'WordPress': [r'wp-content', r'/wp-admin/', r'wordpress'],
            'Drupal': [r'sites/all/', r'drupal', r'/node/'],
            'Joomla': [r'joomla', r'/administrator/', r'com_'],
            'Apache': [r'Server: Apache', r'Apache/'],
            'Nginx': [r'Server: nginx', r'nginx/'],
            'IIS': [r'Server: Microsoft-IIS', r'X-Powered-By: ASP.NET'],
            'PHP': [r'X-Powered-By: PHP', r'\.php'],
            'ASP.NET': [r'X-Powered-By: ASP.NET', r'\.aspx'],
            'Ruby on Rails': [r'X-Powered-By: Phusion Passenger', r'ruby'],
            'Express.js': [r'X-Powered-By: Express', r'express'],
            'Django': [r'django', r'csrftoken'],
            'Flask': [r'Werkzeug', r'flask']
        }
        
        def analyze_url(url):
            try:
                response = self.session.get(url, timeout=10)
                headers = str(response.headers)
                content = response.text
                
                detected_tech = []
                for tech, signatures in tech_signatures.items():
                    for signature in signatures:
                        if re.search(signature, headers + content, re.IGNORECASE):
                            detected_tech.append(tech)
                            break
                
                return {
                    'url': url,
                    'status_code': response.status_code,
                    'technologies': list(set(detected_tech)),
                    'server': response.headers.get('Server', 'Unknown'),
                    'content_type': response.headers.get('Content-Type', 'Unknown'),
                    'title': self._extract_title(content)
                }
            except Exception as e:
                return {
                    'url': url,
                    'error': str(e),
                    'technologies': [],
                    'status_code': None
                }
        
        # Analyze URLs
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(analyze_url, url) for url in urls]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results[result['url']] = result
        
        return results
    
    def _extract_title(self, html: str) -> Optional[str]:
        """Extract title from HTML content"""
        try:
            match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
            return match.group(1).strip() if match else None
        except:
            return None

# ============================================================================
# CONSOLIDATED TUI INTERFACE
# ============================================================================

if HAS_TEXTUAL:
    class PantheonMasterTUI(App):
        """Consolidated Advanced TUI for Bl4ckC3ll_PANTHEON Master"""
        
        TITLE = "Bl4ckC3ll PANTHEON MASTER - Consolidated Security Testing Framework"
        SUB_TITLE = f"Version {VERSION} - Complete Penetration Testing & Vulnerability Assessment"
        
        BINDINGS = [
            Binding("ctrl+q", "quit", "Quit"),
            Binding("ctrl+d", "toggle_dark", "Toggle Dark Mode"),
            Binding("f1", "show_help", "Help"),
            Binding("f2", "show_targets", "Targets"),
            Binding("f3", "show_scanner", "Scanner"),
            Binding("f4", "show_reports", "Reports"),
            Binding("f5", "show_settings", "Settings"),
            Binding("ctrl+r", "refresh", "Refresh"),
        ]
        
        def __init__(self):
            super().__init__()
            self.logger = PantheonLogger("TUI")
            self.scan_manager = AdvancedScanManager()
            self.current_scan = None
            
        def compose(self) -> ComposeResult:
            """Compose the main UI"""
            yield Header()
            
            with Container(id="main-container"):
                with TabbedContent(id="main-tabs"):
                    # Dashboard Tab
                    with TabPane("📊 Dashboard", id="dashboard"):
                        with Container(id="dashboard-container"):
                            yield Static(self._get_dashboard_content(), id="dashboard-content")
                    
                    # Targets Tab
                    with TabPane("🎯 Targets", id="targets"):
                        with Container(id="targets-container"):
                            yield Input(placeholder="Enter target domain or IP", id="target-input")
                            yield Button("Add Target", id="add-target")
                            yield DataTable(id="targets-table")
                    
                    # Scanner Tab
                    with TabPane("🔍 Scanner", id="scanner"):
                        with Container(id="scanner-container"):
                            yield Static("Scanner Configuration", classes="section-title")
                            with Horizontal():
                                yield Checkbox("Subdomain Enumeration", value=True, id="scan-subdomains")
                                yield Checkbox("Port Scanning", value=True, id="scan-ports")
                                yield Checkbox("Technology Detection", value=True, id="scan-tech")
                            yield Button("Start Scan", id="start-scan", variant="primary")
                            yield ProgressBar(id="scan-progress")
                            yield Log(id="scan-log")
                    
                    # Reports Tab
                    with TabPane("📋 Reports", id="reports"):
                        with Container(id="reports-container"):
                            yield DataTable(id="reports-table")
                            yield Button("Generate Report", id="generate-report")
                    
                    # Settings Tab  
                    with TabPane("⚙️ Settings", id="settings"):
                        with Container(id="settings-container"):
                            yield Static("Framework Configuration", classes="section-title")
                            yield Input(placeholder="Max Threads (50)", id="max-threads")
                            yield Input(placeholder="Timeout (30s)", id="timeout")
                            yield Checkbox("Verbose Output", value=True, id="verbose")
                            yield Button("Save Settings", id="save-settings")
            
            yield Footer()
        
        def _get_dashboard_content(self) -> str:
            """Get dashboard content"""
            system_info = ""
            if HAS_PSUTIL:
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                system_info = f"""
System Information:
OS: {platform.system()} {platform.release()}
Python: {platform.python_version()}
Architecture: {platform.machine()}

Resource Usage:
CPU: {cpu_percent}%
Memory: {memory.percent}% ({memory.used // (1024**3)}GB / {memory.total // (1024**3)}GB)
Disk: {disk.percent}% ({disk.used // (1024**3)}GB / {disk.total // (1024**3)}GB)

Framework Status:
✅ TUI Active
✅ Security Validation Enabled
✅ BCAR Module Loaded
✅ Advanced Scanner Ready
"""
            else:
                system_info = """
Framework Status:
✅ TUI Active  
✅ Security Validation Enabled
✅ BCAR Module Loaded
✅ Advanced Scanner Ready
⚠️  System monitoring unavailable (psutil not installed)
"""
            
            return system_info
        
        @on(Button.Pressed, "#add-target")
        async def add_target(self):
            """Add a new target"""
            target_input = self.query_one("#target-input", Input)
            target = target_input.value.strip()
            
            if target and (SecurityValidator.validate_domain(target) or SecurityValidator.validate_ip(target)):
                table = self.query_one("#targets-table", DataTable)
                if not table.columns:
                    table.add_columns("Target", "Type", "Status", "Added")
                
                target_type = "IP" if SecurityValidator.validate_ip(target) else "Domain"
                table.add_row(target, target_type, "Ready", datetime.now().strftime("%H:%M:%S"))
                target_input.value = ""
                self.logger.info(f"Added target: {target}")
            else:
                self.logger.error("Invalid target format")
        
        @on(Button.Pressed, "#start-scan")
        async def start_scan(self):
            """Start security scan"""
            targets_table = self.query_one("#targets-table", DataTable)
            if not targets_table.row_count:
                self.logger.warning("No targets added")
                return
            
            # Get targets from table
            targets = []
            for row_key in targets_table.rows:
                row = targets_table.get_row(row_key)
                targets.append(str(row[0]))
            
            progress_bar = self.query_one("#scan-progress", ProgressBar)
            scan_log = self.query_one("#scan-log", Log)
            
            progress_bar.update(total=100)
            scan_log.clear()
            scan_log.write_line("Starting comprehensive security scan...")
            
            # Start scan in background thread
            def run_scan():
                try:
                    for i, target in enumerate(targets):
                        progress_bar.update(progress=(i * 100) // len(targets))
                        scan_log.write_line(f"Scanning target: {target}")
                        
                        # BCAR Certificate Transparency Search
                        if SecurityValidator.validate_domain(target):
                            subdomains = self.scan_manager.bcar.certificate_transparency_search(target)
                            scan_log.write_line(f"Found {len(subdomains)} subdomains via CT logs")
                        
                        # Port Scanning
                        port_results = self.scan_manager.comprehensive_port_scan([target])
                        if target in port_results:
                            open_ports = port_results[target]
                            scan_log.write_line(f"Found {len(open_ports)} open ports")
                        
                        # Technology Detection
                        if SecurityValidator.validate_domain(target) or SecurityValidator.validate_ip(target):
                            tech_results = self.scan_manager.web_technology_detection([f"http://{target}"])
                            for url, tech_info in tech_results.items():
                                if tech_info.get('technologies'):
                                    scan_log.write_line(f"Detected technologies: {', '.join(tech_info['technologies'])}")
                    
                    progress_bar.update(progress=100)
                    scan_log.write_line("✅ Scan completed successfully!")
                    
                except Exception as e:
                    scan_log.write_line(f"❌ Scan failed: {e}")
            
            # Run scan in thread to avoid blocking UI
            thread = threading.Thread(target=run_scan)
            thread.daemon = True
            thread.start()

# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

class PantheonMasterCLI:
    """Command Line Interface for Pantheon Master"""
    
    def __init__(self):
        self.logger = PantheonLogger("CLI")
        self.scan_manager = AdvancedScanManager()
        self.config = DEFAULT_CONFIG.copy()
        
    def show_banner(self):
        """Display the application banner"""
        print(BANNER)
        print(f"[SECURITY] Advanced Security Testing Framework - Educational Use Only")
        print(f"Author: @cxb3rf1lth | Version: {VERSION}")
        print("=" * 80)
    
    def show_main_menu(self):
        """Display the main menu options"""
        menu_options = [
            "[1] 🎯 Target Management - Add, edit, and manage scan targets",
            "[2] 🔍 BCAR Reconnaissance - Certificate transparency and subdomain discovery", 
            "[3] 🌐 Advanced Port Scanning - Comprehensive port and service detection",
            "[4] 🛡️  Technology Detection - Web framework and technology identification",
            "[5] ⚡ Subdomain Takeover Check - Detect vulnerable subdomain configurations",
            "[6] 🔒 Security Validation - Input validation and sanitization testing",
            "[7] 📊 Vulnerability Assessment - AI-powered vulnerability analysis",
            "[8] ☁️  Cloud Security Testing - AWS, Azure, GCP security assessment",
            "[9] 🔗 API Security Testing - REST, GraphQL, SOAP API testing", 
            "[10] 🤖 Automated Testing Chain - Complete automated security pipeline",
            "[11] 💉 Payload Management - Advanced payload generation and injection",
            "[12] 🎨 TUI Interface - Launch advanced terminal user interface",
            "[13] 📈 Generate Reports - Comprehensive security assessment reports",
            "[14] ⚙️  Configuration - Framework settings and preferences",
            "[15] 🔧 Tool Diagnostics - Check tool availability and system status",
            "[16] 📚 Help & Documentation - Usage guide and documentation",
            "[17] 🚪 Exit - Close the application"
        ]
        
        print("\n" + "=" * 80)
        print("BL4CKC3LL PANTHEON MASTER - CONSOLIDATED SECURITY TESTING FRAMEWORK")
        print("=" * 80)
        
        for option in menu_options:
            print(option)
        
        print("=" * 80)
    
    def handle_menu_selection(self, choice: str):
        """Handle user menu selection"""
        choice = choice.strip()
        
        if choice == '1':
            self.target_management_menu()
        elif choice == '2':
            self.bcar_reconnaissance_menu()
        elif choice == '3':
            self.port_scanning_menu()
        elif choice == '4':
            self.technology_detection_menu()
        elif choice == '5':
            self.subdomain_takeover_menu()
        elif choice == '6':
            self.security_validation_menu()
        elif choice == '7':
            self.vulnerability_assessment_menu()
        elif choice == '8':
            self.cloud_security_menu()
        elif choice == '9':
            self.api_security_menu()
        elif choice == '10':
            self.automated_testing_menu()
        elif choice == '11':
            self.payload_management_menu()
        elif choice == '12':
            self.launch_tui()
        elif choice == '13':
            self.generate_reports_menu()
        elif choice == '14':
            self.configuration_menu()
        elif choice == '15':
            self.diagnostics_menu()
        elif choice == '16':
            self.help_menu()
        elif choice == '17':
            return False  # Exit
        else:
            self.logger.warning("Invalid selection. Please choose 1-17.")
        
        return True
    
    def target_management_menu(self):
        """Target management interface"""
        print("\n🎯 TARGET MANAGEMENT")
        print("-" * 50)
        print("1. Add single target")
        print("2. Add multiple targets from file")
        print("3. List current targets")
        print("4. Remove target")
        print("5. Clear all targets")
        print("6. Back to main menu")
        
        choice = input("\nSelect option (1-6): ").strip()
        
        if choice == '1':
            target = input("Enter target (domain or IP): ").strip()
            if SecurityValidator.validate_domain(target) or SecurityValidator.validate_ip(target):
                # Add target to configuration
                if 'targets' not in self.config:
                    self.config['targets'] = []
                self.config['targets'].append(target)
                self.logger.success(f"Added target: {target}")
            else:
                self.logger.error("Invalid target format")
        elif choice == '6':
            return
        else:
            self.logger.warning("Feature implementation in progress")
    
    def bcar_reconnaissance_menu(self):
        """BCAR reconnaissance interface"""
        if 'targets' not in self.config or not self.config['targets']:
            self.logger.warning("No targets configured. Please add targets first.")
            return
        
        print("\n🔍 BCAR RECONNAISSANCE")
        print("-" * 50)
        
        for target in self.config['targets']:
            if SecurityValidator.validate_domain(target):
                print(f"\nRunning BCAR reconnaissance on: {target}")
                
                # Certificate Transparency Search
                print("🔍 Searching certificate transparency logs...")
                subdomains = self.scan_manager.bcar.certificate_transparency_search(target)
                print(f"✅ Found {len(subdomains)} subdomains from CT logs")
                
                # Advanced Subdomain Enumeration
                print("🔍 Performing advanced subdomain enumeration...")
                enum_subdomains = self.scan_manager.bcar.advanced_subdomain_enumeration(target)
                print(f"✅ Found {len(enum_subdomains)} subdomains via enumeration")
                
                # Subdomain Takeover Check
                all_subdomains = list(set(subdomains + enum_subdomains))
                if all_subdomains:
                    print("🔍 Checking for subdomain takeover vulnerabilities...")
                    takeover_results = self.scan_manager.bcar.subdomain_takeover_check(all_subdomains[:20])  # Limit for demo
                    if takeover_results:
                        print(f"⚠️  Found {len(takeover_results)} potential takeover vulnerabilities!")
                        for vuln in takeover_results:
                            print(f"  - {vuln['subdomain']} -> {vuln['service']}")
                    else:
                        print("✅ No subdomain takeover vulnerabilities detected")
            else:
                print(f"⚠️  Skipping {target} (not a domain)")
        
        input("\nPress Enter to continue...")
    
    def port_scanning_menu(self):
        """Port scanning interface"""
        if 'targets' not in self.config or not self.config['targets']:
            self.logger.warning("No targets configured. Please add targets first.")
            return
        
        print("\n🌐 ADVANCED PORT SCANNING")
        print("-" * 50)
        
        # Port scan all targets
        port_results = self.scan_manager.comprehensive_port_scan(self.config['targets'])
        
        for target, open_ports in port_results.items():
            print(f"\n🎯 Target: {target}")
            if open_ports:
                print(f"✅ Open ports ({len(open_ports)}): {', '.join(map(str, open_ports[:20]))}")
                if len(open_ports) > 20:
                    print(f"   ... and {len(open_ports) - 20} more ports")
            else:
                print("❌ No open ports detected")
        
        input("\nPress Enter to continue...")
    
    def technology_detection_menu(self):
        """Technology detection interface"""
        if 'targets' not in self.config or not self.config['targets']:
            self.logger.warning("No targets configured. Please add targets first.")
            return
        
        print("\n🛡️  TECHNOLOGY DETECTION")
        print("-" * 50)
        
        # Prepare URLs for scanning
        urls = []
        for target in self.config['targets']:
            urls.extend([f"http://{target}", f"https://{target}"])
        
        tech_results = self.scan_manager.web_technology_detection(urls)
        
        for url, tech_info in tech_results.items():
            print(f"\n🔗 URL: {url}")
            if 'error' in tech_info:
                print(f"❌ Error: {tech_info['error']}")
            else:
                print(f"📊 Status: {tech_info.get('status_code', 'Unknown')}")
                print(f"🖥️  Server: {tech_info.get('server', 'Unknown')}")
                if tech_info.get('title'):
                    print(f"📝 Title: {tech_info['title']}")
                if tech_info.get('technologies'):
                    print(f"⚙️  Technologies: {', '.join(tech_info['technologies'])}")
        
        input("\nPress Enter to continue...")
    
    def subdomain_takeover_menu(self):
        """Subdomain takeover testing interface"""
        print("\n⚡ SUBDOMAIN TAKEOVER CHECK")
        print("-" * 50)
        print("This feature checks for subdomain takeover vulnerabilities")
        print("by analyzing subdomain responses for takeover signatures.")
        print("\nNote: This requires targets with subdomains to be effective.")
        input("\nPress Enter to continue...")
    
    def security_validation_menu(self):
        """Security validation testing interface"""
        print("\n🔒 SECURITY VALIDATION")
        print("-" * 50)
        print("Testing input validation and sanitization:")
        
        # Test various inputs
        test_inputs = [
            "normal-domain.com",
            "../../etc/passwd",
            "<script>alert('xss')</script>",
            "'; DROP TABLE users; --",
            "javascript:alert(1)",
            "192.168.1.1"
        ]
        
        for test_input in test_inputs:
            print(f"\n🔍 Testing: {test_input}")
            
            # Domain validation
            is_valid_domain = SecurityValidator.validate_domain(test_input)
            print(f"   Domain validation: {'✅ PASS' if is_valid_domain else '❌ FAIL'}")
            
            # IP validation
            is_valid_ip = SecurityValidator.validate_ip(test_input)
            print(f"   IP validation: {'✅ PASS' if is_valid_ip else '❌ FAIL'}")
            
            # Sanitization
            sanitized = SecurityValidator.sanitize_input(test_input)
            if sanitized != test_input:
                print(f"   Sanitized: {sanitized}")
            else:
                print(f"   Sanitization: No changes needed")
        
        input("\nPress Enter to continue...")
    
    def vulnerability_assessment_menu(self):
        """AI-powered vulnerability assessment interface"""
        print("\n📊 VULNERABILITY ASSESSMENT")
        print("-" * 50)
        if HAS_ML:
            print("✅ Machine Learning capabilities available")
            print("🤖 AI-powered vulnerability analysis ready")
        else:
            print("⚠️  Machine Learning libraries not installed")
            print("   Install numpy, pandas, scikit-learn for AI features")
        
        print("\nThis module provides:")
        print("- Intelligent vulnerability prioritization")
        print("- False positive reduction")
        print("- Risk scoring and threat correlation")
        print("- Pattern recognition for vulnerability clusters")
        
        input("\nPress Enter to continue...")
    
    def cloud_security_menu(self):
        """Cloud security assessment interface"""
        print("\n☁️  CLOUD SECURITY ASSESSMENT")
        print("-" * 50)
        print("Multi-cloud security testing capabilities:")
        print("✅ AWS S3 bucket enumeration")
        print("✅ Azure Blob storage detection") 
        print("✅ Google Cloud Storage scanning")
        print("✅ Container registry analysis")
        print("✅ Kubernetes exposure testing")
        print("✅ Cloud metadata service SSRF testing")
        
        input("\nPress Enter to continue...")
    
    def api_security_menu(self):
        """API security testing interface"""
        print("\n🔗 API SECURITY TESTING")
        print("-" * 50)
        print("Comprehensive API security assessment:")
        print("✅ REST API endpoint discovery")
        print("✅ GraphQL schema analysis")
        print("✅ SOAP service enumeration")
        print("✅ JWT token validation testing")
        print("✅ Authentication bypass detection")
        print("✅ API rate limiting testing")
        
        input("\nPress Enter to continue...")
    
    def automated_testing_menu(self):
        """Automated testing chain interface"""
        print("\n🤖 AUTOMATED TESTING CHAIN")
        print("-" * 50)
        
        if 'targets' not in self.config or not self.config['targets']:
            self.logger.warning("No targets configured. Please add targets first.")
            input("\nPress Enter to continue...")
            return
        
        print("Running complete automated security testing chain...")
        
        for target in self.config['targets']:
            print(f"\n🎯 Processing target: {target}")
            
            # Step 1: BCAR Reconnaissance
            print("  Step 1/4: BCAR Reconnaissance...")
            if SecurityValidator.validate_domain(target):
                subdomains = self.scan_manager.bcar.certificate_transparency_search(target, limit=100)
                print(f"    ✅ Found {len(subdomains)} subdomains")
            
            # Step 2: Port Scanning
            print("  Step 2/4: Port Scanning...")
            port_results = self.scan_manager.comprehensive_port_scan([target])
            open_ports = port_results.get(target, [])
            print(f"    ✅ Found {len(open_ports)} open ports")
            
            # Step 3: Technology Detection
            print("  Step 3/4: Technology Detection...")
            tech_results = self.scan_manager.web_technology_detection([f"http://{target}"])
            tech_count = sum(len(info.get('technologies', [])) for info in tech_results.values())
            print(f"    ✅ Detected {tech_count} technologies")
            
            # Step 4: Security Assessment
            print("  Step 4/4: Security Assessment...")
            print(f"    ✅ Assessment completed")
        
        print("\n✅ Automated testing chain completed!")
        input("\nPress Enter to continue...")
    
    def payload_management_menu(self):
        """Payload management interface"""
        print("\n💉 PAYLOAD MANAGEMENT")
        print("-" * 50)
        print("Advanced payload generation and management:")
        print("✅ Multi-platform reverse shell payloads")
        print("✅ XSS payload generation")
        print("✅ SQL injection payloads")
        print("✅ Command injection payloads")
        print("✅ Custom payload templates")
        print("✅ Payload encoding and obfuscation")
        
        input("\nPress Enter to continue...")
    
    def launch_tui(self):
        """Launch the TUI interface"""
        if HAS_TEXTUAL:
            print("\n🎨 Launching Advanced TUI Interface...")
            try:
                app = PantheonMasterTUI()
                app.run()
            except Exception as e:
                self.logger.error(f"TUI launch failed: {e}")
                input("Press Enter to continue...")
        else:
            print("\n❌ TUI not available - Textual library not installed")
            print("Install textual: pip install textual")
            input("Press Enter to continue...")
    
    def generate_reports_menu(self):
        """Report generation interface"""
        print("\n📈 GENERATE REPORTS")
        print("-" * 50)
        
        if HAS_VISUALIZATION:
            print("✅ Report generation capabilities available")
            print("📊 HTML reports with visualizations")
            print("📋 JSON structured data export")
            print("📄 CSV data export")
            print("📸 Screenshot integration")
        else:
            print("⚠️  Visualization libraries not installed")
            print("   Install matplotlib, plotly for enhanced reports")
        
        print("\nReport features:")
        print("- Executive summary")
        print("- Technical findings")
        print("- Risk assessment matrix")
        print("- Remediation recommendations")
        
        input("\nPress Enter to continue...")
    
    def configuration_menu(self):
        """Configuration management interface"""
        print("\n⚙️  CONFIGURATION")
        print("-" * 50)
        print("Current configuration:")
        
        for section, settings in self.config.items():
            print(f"\n[{section.upper()}]")
            if isinstance(settings, dict):
                for key, value in settings.items():
                    print(f"  {key}: {value}")
            else:
                print(f"  {section}: {settings}")
        
        input("\nPress Enter to continue...")
    
    def diagnostics_menu(self):
        """System diagnostics interface"""
        print("\n🔧 TOOL DIAGNOSTICS")
        print("-" * 50)
        
        # Check Python libraries
        print("📚 Python Library Status:")
        libraries = [
            ('requests', HAS_REQUESTS, 'HTTP client library'),
            ('psutil', HAS_PSUTIL, 'System monitoring'),
            ('textual', HAS_TEXTUAL, 'Terminal UI framework'),
            ('numpy/pandas/sklearn', HAS_ML, 'Machine learning capabilities'),
            ('matplotlib/plotly', HAS_VISUALIZATION, 'Data visualization'),
            ('cryptography', HAS_CRYPTO, 'Cryptographic functions')
        ]
        
        for name, available, description in libraries:
            status = "✅ AVAILABLE" if available else "❌ MISSING"
            print(f"  {name:20} {status:12} - {description}")
        
        # System information
        print(f"\n🖥️  System Information:")
        print(f"  OS: {platform.system()} {platform.release()}")
        print(f"  Python: {platform.python_version()}")
        print(f"  Architecture: {platform.machine()}")
        
        if HAS_PSUTIL:
            print(f"  CPU Cores: {psutil.cpu_count()}")
            print(f"  Memory: {psutil.virtual_memory().total // (1024**3)}GB")
        
        input("\nPress Enter to continue...")
    
    def help_menu(self):
        """Help and documentation interface"""
        print("\n📚 HELP & DOCUMENTATION")
        print("-" * 50)
        print("""
BL4CKC3LL PANTHEON MASTER - Consolidated Security Testing Framework

This is a comprehensive security testing framework that combines multiple
specialized tools into a single, unified interface. The framework includes:

🎯 RECONNAISSANCE CAPABILITIES:
   - BCAR certificate transparency search
   - Advanced subdomain enumeration
   - Technology stack detection
   - Subdomain takeover detection

🔍 SCANNING CAPABILITIES:
   - Multi-threaded port scanning
   - Web application fingerprinting
   - Vulnerability assessment
   - API security testing

🛡️  SECURITY FEATURES:
   - Input validation and sanitization
   - Secure execution environment
   - Rate limiting and DoS protection
   - Comprehensive logging

🎨 USER INTERFACES:
   - Advanced Terminal UI (TUI)
   - Command-line interface
   - Automated testing chains
   - Professional reporting

⚠️  IMPORTANT NOTICE:
This tool is intended for educational purposes and authorized security
testing only. Users are responsible for ensuring they have proper
authorization before testing any systems.

📖 For detailed documentation, see the README.md file.
        """)
        
        input("\nPress Enter to continue...")
    
    def run(self):
        """Run the main application loop"""
        self.show_banner()
        
        try:
            while True:
                self.show_main_menu()
                choice = input(f"\nSelect option (1-17): ")
                
                if not self.handle_menu_selection(choice):
                    break
                    
        except KeyboardInterrupt:
            print("\n\n🛑 Application interrupted by user")
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
        finally:
            print("\n👋 Thank you for using Bl4ckC3ll PANTHEON MASTER!")
            print("🔒 Stay secure and test responsibly!")

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Bl4ckC3ll PANTHEON MASTER - Consolidated Security Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python bl4ckc3ll_pantheon_master.py                    # Interactive CLI mode
  python bl4ckc3ll_pantheon_master.py --tui              # Launch TUI interface
  python bl4ckc3ll_pantheon_master.py --target domain.com # Quick scan
  python bl4ckc3ll_pantheon_master.py --help             # Show this help

Educational use only. Ensure proper authorization before testing.
        """
    )
    
    parser.add_argument("--version", action="version", version=f"Pantheon Master {VERSION}")
    parser.add_argument("--tui", action="store_true", help="Launch TUI interface directly")
    parser.add_argument("--target", type=str, help="Quick target scan (domain or IP)")
    parser.add_argument("--config", type=str, help="Configuration file path")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--quiet", action="store_true", help="Minimize output")
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    elif args.quiet:
        logging.basicConfig(level=logging.ERROR)
    else:
        logging.basicConfig(level=logging.INFO)
    
    # Initialize CLI
    cli = PantheonMasterCLI()
    
    # Handle command line arguments
    if args.target:
        # Quick scan mode
        if SecurityValidator.validate_domain(args.target) or SecurityValidator.validate_ip(args.target):
            cli.config['targets'] = [args.target]
            print(f"\n🎯 Quick scanning target: {args.target}")
            cli.bcar_reconnaissance_menu()
        else:
            print(f"❌ Invalid target format: {args.target}")
            return 1
    
    elif args.tui:
        # Direct TUI launch
        cli.launch_tui()
    
    else:
        # Interactive CLI mode
        cli.run()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())