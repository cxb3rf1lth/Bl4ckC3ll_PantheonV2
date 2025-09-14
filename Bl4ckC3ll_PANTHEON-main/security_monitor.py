#!/usr/bin/env python3
"""
Security Monitoring for Bl4ckC3ll_PANTHEON
Real-time security event monitoring and alerting
"""

import logging
import time
import re
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class SecurityMonitor(FileSystemEventHandler):
    """Monitor for security events"""
    
    def __init__(self):
        self.security_logger = logging.getLogger('security')
        self.suspicious_patterns = [
            r'failed login',
            r'unauthorized access',
            r'injection attempt',
            r'path traversal',
            r'rate limit exceeded'
        ]
    
    def on_modified(self, event):
        if event.is_directory:
            return
        
        if event.src_path.endswith('.log'):
            self.check_log_file(event.src_path)
    
    def check_log_file(self, log_path):
        """Check log file for suspicious activity"""
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                # Read only new lines (simplified approach)
                lines = f.readlines()[-10:]  # Last 10 lines
                
                for line in lines:
                    for pattern in self.suspicious_patterns:
                        if re.search(pattern, line, re.IGNORECASE):
                            self.security_logger.warning(f"Suspicious activity detected: {line.strip()}")
                            
        except Exception as e:
            self.security_logger.error(f"Error checking log file {log_path}: {e}")

def start_monitoring():
    """Start security monitoring"""
    monitor = SecurityMonitor()
    observer = Observer()
    observer.schedule(monitor, 'logs', recursive=True)
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    
    observer.join()

if __name__ == "__main__":
    start_monitoring()
