#!/usr/bin/env python3
"""
Enhanced Security Controls for Bl4ckC3ll_PANTHEON
Implements stricter command argument sanitization and allow-listing
"""

import re
import shlex
import subprocess
import logging
from typing import List, Dict, Any, Optional, Set
from pathlib import Path

logger = logging.getLogger(__name__)

class SecurityManager:
    """Enhanced security manager with strict controls"""
    
    # Allow-listed commands for security
    ALLOWED_COMMANDS = {
        # Reconnaissance tools
        'subfinder', 'amass', 'naabu', 'httpx', 'katana', 'gau',
        'waybackurls', 'gospider', 'paramspider', 'assetfinder',
        'findomain', 'dnsrecon', 'fierce',
        
        # Vulnerability scanners
        'nuclei', 'nikto', 'sqlmap', 'commix', 'xsstrike',
        'dalfox', 'arjun', 'wappalyzer',
        
        # Web fuzzers and crawlers
        'ffuf', 'gobuster', 'feroxbuster', 'dirb', 'dirsearch',
        
        # Network tools
        'nmap', 'masscan', 'rustscan',
        
        # SSL/TLS tools
        'sslscan', 'sslyze', 'testssl.sh',
        
        # System tools
        'curl', 'wget', 'dig', 'host', 'nslookup', 'whois',
        'grep', 'awk', 'sed', 'sort', 'uniq', 'head', 'tail',
        'cat', 'cut', 'tr', 'wc'
    }
    
    # Dangerous characters that should be escaped or blocked
    DANGEROUS_CHARS = set([';', '|', '&', '$', '`', '(', ')', '{', '}', '[', ']', '<', '>', '"', "'"])
    
    # URL/Domain validation regex
    DOMAIN_REGEX = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    
    IP_REGEX = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    
    def __init__(self, strict_mode: bool = True):
        self.strict_mode = strict_mode
        self.command_history = []
        
    def validate_command(self, command: str) -> bool:
        """Validate if command is allowed"""
        base_command = command.split()[0] if command.split() else ""
        
        # Remove path and get just the command name
        base_command = Path(base_command).name
        
        if base_command not in self.ALLOWED_COMMANDS:
            logger.warning(f"Command not in allow-list: {base_command}")
            return False
            
        return True
    
    def sanitize_arguments(self, args: List[str]) -> List[str]:
        """Sanitize command arguments to prevent injection"""
        sanitized_args = []
        
        for arg in args:
            # Skip empty arguments
            if not arg:
                continue
                
            # Check for dangerous characters
            if any(char in arg for char in self.DANGEROUS_CHARS):
                if self.strict_mode:
                    logger.error(f"Dangerous character detected in argument: {arg}")
                    continue
                else:
                    # Escape dangerous characters
                    arg = shlex.quote(arg)
            
            # Validate URLs/domains if they look like targets
            if self._looks_like_target(arg):
                if not self.validate_target(arg):
                    logger.warning(f"Invalid target format: {arg}")
                    continue
            
            sanitized_args.append(arg)
            
        return sanitized_args
    
    def _looks_like_target(self, arg: str) -> bool:
        """Check if argument looks like a target (domain/IP)"""
        # Simple heuristic: contains dots and looks like domain/IP
        return ('.' in arg and 
                not arg.startswith('-') and 
                not '/' in arg and
                not '=' in arg)
    
    def validate_target(self, target: str) -> bool:
        """Validate target format (domain or IP)"""
        target = target.strip()
        
        # Check for valid domain
        if self.DOMAIN_REGEX.match(target):
            return True
            
        # Check for valid IP
        if self.IP_REGEX.match(target):
            return True
            
        # Check for CIDR notation
        if '/' in target:
            parts = target.split('/')
            if len(parts) == 2:
                ip, prefix = parts
                if self.IP_REGEX.match(ip) and prefix.isdigit() and 0 <= int(prefix) <= 32:
                    return True
        
        return False
    
    def execute_command_safely(self, command: List[str], timeout: int = 300, 
                             capture_output: bool = True) -> subprocess.CompletedProcess:
        """Execute command with enhanced security controls"""
        
        if not command:
            raise ValueError("Empty command")
        
        # Validate base command
        if not self.validate_command(command[0]):
            raise SecurityError(f"Command not allowed: {command[0]}")
        
        # Sanitize arguments
        sanitized_command = [command[0]] + self.sanitize_arguments(command[1:])
        
        # Log command execution
        logger.info(f"Executing command: {' '.join(sanitized_command)}")
        self.command_history.append({
            'command': sanitized_command,
            'timestamp': time.time()
        })
        
        try:
            result = subprocess.run(
                sanitized_command,
                capture_output=capture_output,
                text=True,
                timeout=timeout,
                check=False
            )
            return result
            
        except subprocess.TimeoutExpired as e:
            logger.error(f"Command timeout: {sanitized_command}")
            raise
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            raise


class CommandValidator:
    """Validates and sanitizes command line arguments"""
    
    def __init__(self):
        self.security_manager = SecurityManager()
    
    def validate_scan_parameters(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and sanitize scan parameters"""
        validated_params = {}
        
        for key, value in params.items():
            if key == 'targets':
                validated_params[key] = self._validate_targets(value)
            elif key == 'ports':
                validated_params[key] = self._validate_ports(value)
            elif key == 'threads':
                validated_params[key] = self._validate_threads(value)
            elif key == 'timeout':
                validated_params[key] = self._validate_timeout(value)
            elif key == 'output_file':
                validated_params[key] = self._validate_output_path(value)
            else:
                # Generic validation for other parameters
                validated_params[key] = self._validate_generic(value)
        
        return validated_params
    
    def _validate_targets(self, targets) -> List[str]:
        """Validate target list"""
        if isinstance(targets, str):
            targets = [targets]
        
        validated_targets = []
        for target in targets:
            if self.security_manager.validate_target(target):
                validated_targets.append(target)
            else:
                logger.warning(f"Invalid target skipped: {target}")
        
        return validated_targets
    
    def _validate_ports(self, ports) -> str:
        """Validate port specification"""
        if isinstance(ports, int):
            if 1 <= ports <= 65535:
                return str(ports)
            else:
                raise ValueError(f"Invalid port number: {ports}")
        
        if isinstance(ports, str):
            # Handle port ranges and lists
            if ports in ['top-ports', 'all']:
                return ports
            
            # Validate individual ports and ranges
            port_pattern = re.compile(r'^[\d,\-]+$')
            if port_pattern.match(ports):
                return ports
            
        raise ValueError(f"Invalid port specification: {ports}")
    
    def _validate_threads(self, threads) -> int:
        """Validate thread count"""
        if isinstance(threads, str):
            threads = int(threads)
        
        if not isinstance(threads, int) or threads < 1 or threads > 1000:
            raise ValueError(f"Invalid thread count: {threads}")
        
        return threads
    
    def _validate_timeout(self, timeout) -> int:
        """Validate timeout value"""
        if isinstance(timeout, str):
            timeout = int(timeout)
        
        if not isinstance(timeout, int) or timeout < 1 or timeout > 3600:
            raise ValueError(f"Invalid timeout: {timeout}")
        
        return timeout
    
    def _validate_output_path(self, path) -> str:
        """Validate output file path"""
        path = str(path)
        
        # Prevent directory traversal
        if '..' in path or path.startswith('/'):
            raise ValueError(f"Invalid output path: {path}")
        
        # Ensure path is within allowed directories
        allowed_dirs = ['runs', 'logs', 'output', 'reports']
        path_parts = Path(path).parts
        
        if path_parts and path_parts[0] not in allowed_dirs:
            raise ValueError(f"Output path must be in allowed directories: {allowed_dirs}")
        
        return path
    
    def _validate_generic(self, value) -> Any:
        """Generic validation for other parameters"""
        if isinstance(value, str):
            # Check for dangerous characters
            if any(char in value for char in SecurityManager.DANGEROUS_CHARS):
                return shlex.quote(value)
        
        return value


class SecurityError(Exception):
    """Custom security exception"""
    pass


# Rate limiting for security
import time
from collections import defaultdict, deque
from threading import Lock

class RateLimiter:
    """Thread-safe rate limiter for security"""
    
    def __init__(self, max_requests: int = 60, time_window: int = 60):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = defaultdict(deque)
        self.lock = Lock()
    
    def is_allowed(self, identifier: str) -> bool:
        """Check if request is allowed for given identifier"""
        with self.lock:
            now = time.time()
            request_times = self.requests[identifier]
            
            # Remove old requests outside time window
            while request_times and request_times[0] < now - self.time_window:
                request_times.popleft()
            
            # Check if under limit
            if len(request_times) < self.max_requests:
                request_times.append(now)
                return True
            
            return False
    
    def wait_time(self, identifier: str) -> float:
        """Get wait time until next request is allowed"""
        with self.lock:
            request_times = self.requests[identifier]
            if not request_times:
                return 0.0
            
            oldest_request = request_times[0]
            wait_time = max(0, (oldest_request + self.time_window) - time.time())
            return wait_time


# Global security manager instance
security_manager = SecurityManager()
command_validator = CommandValidator()
rate_limiter = RateLimiter()

__all__ = ['SecurityManager', 'CommandValidator', 'SecurityError', 'RateLimiter', 
           'security_manager', 'command_validator', 'rate_limiter']