#!/usr/bin/env python3
"""
Enhanced logging functionality for Bl4ckC3ll_PANTHEON
"""

import logging
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
import sys

class PantheonLogger:
    """Enhanced logger with structured logging and security event tracking"""
    
    def __init__(self, name: str = "pantheon", log_dir: str = "logs"):
        self.name = name
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Setup main logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Setup file handler
        log_file = self.log_dir / f"{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        
        # Setup console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        
        # Setup formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        # Security events log
        self.security_log = self.log_dir / f"security_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
    def log(self, message: str, level: str = "INFO", **kwargs):
        """Log message with enhanced context"""
        context = {
            'timestamp': time.time(),
            'level': level,
            'message': message,
            **kwargs
        }
        
        if level.upper() == "DEBUG":
            self.logger.debug(message)
        elif level.upper() == "INFO":
            self.logger.info(message)
        elif level.upper() == "WARNING":
            self.logger.warning(message)
        elif level.upper() == "ERROR":
            self.logger.error(message)
        elif level.upper() == "CRITICAL":
            self.logger.critical(message)
    
    def log_security_event(self, event_type: str, details: Dict[str, Any]):
        """Log security-related events"""
        security_event = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'details': details
        }
        
        with open(self.security_log, 'a') as f:
            f.write(json.dumps(security_event) + '\n')
        
        self.logger.warning(f"Security event: {event_type} - {details}")
    
    def log_command_execution(self, command: list, result_code: int, output: str = ""):
        """Log command execution for audit trail"""
        self.log_security_event('command_execution', {
            'command': command,
            'result_code': result_code,
            'output_length': len(output),
            'success': result_code == 0
        })
    
    def log_scan_start(self, scan_type: str, targets: list, parameters: dict):
        """Log scan initiation"""
        self.log("Starting scan", "INFO", 
                scan_type=scan_type, 
                target_count=len(targets),
                parameters=parameters)
    
    def log_scan_complete(self, scan_type: str, duration: float, results_count: int):
        """Log scan completion"""
        self.log("Scan completed", "INFO",
                scan_type=scan_type,
                duration=duration,
                results_count=results_count)

# Global logger instance
pantheon_logger = PantheonLogger()

__all__ = ['PantheonLogger', 'pantheon_logger']