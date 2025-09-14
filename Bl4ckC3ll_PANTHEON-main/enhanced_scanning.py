#!/usr/bin/env python3
"""
Enhanced Scanning Module for Bl4ckC3ll_PANTHEON
Provides adaptive scanning capabilities with success rate tracking and optimization
"""

import os
import time
import json
import threading
import statistics
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass, field
import logging

# Enhanced modules integration
try:
    from enhanced_tool_manager import enhanced_which
    ENHANCED_TOOL_MANAGER_AVAILABLE = True
except ImportError:
    ENHANCED_TOOL_MANAGER_AVAILABLE = False
    def enhanced_which(tool):
        return None

# Import main components - using try/except for graceful fallback
try:
    from bl4ckc3ll_p4nth30n import (
        safe_run_command, which, atomic_write, read_lines,
        PantheonLogger, validate_domain_input, validate_ip_input,
        rate_limiter
    )
except ImportError:
    # Fallback implementations for testing
    import subprocess
    import shutil
    
    def safe_run_command(cmd, timeout=60):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.returncode, result.stdout, result.stderr
        except Exception as e:
            return 1, "", str(e)
    
    def which(tool):
        return shutil.which(tool)
    
    def atomic_write(path, data):
        with open(path, 'w') as f:
            f.write(data)
        return True
    
    def read_lines(path):
        try:
            with open(path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except:
            return []
    
    class PantheonLogger:
        def __init__(self, name):
            self.name = name
        def log(self, msg, level="INFO"):
            print(f"[{level}] {self.name}: {msg}")
    
    def validate_domain_input(domain):
        return bool(domain and '.' in domain)
    
    def validate_ip_input(ip):
        try:
            import ipaddress
            ipaddress.ip_address(ip)
            return True
        except:
            return False
    
    class MockRateLimiter:
        def is_allowed(self, key):
            return True
        def wait_time(self, key):
            return 0
    
    rate_limiter = MockRateLimiter()

@dataclass
class ScanResult:
    """Represents a scan operation result with performance metrics"""
    target: str
    tool: str
    start_time: float
    end_time: float
    success: bool
    output_size: int = 0
    error_message: Optional[str] = None
    findings_count: int = 0
    
    @property
    def duration(self) -> float:
        return self.end_time - self.start_time
    
    @property
    def success_score(self) -> float:
        """Calculate success score based on multiple factors"""
        if not self.success:
            return 0.0
        
        score = 1.0
        
        # Bonus for findings
        if self.findings_count > 0:
            score += min(0.2, self.findings_count * 0.01)
        
        # Penalty for very slow scans
        if self.duration > 300:  # 5 minutes
            score -= 0.1
        
        # Bonus for reasonable output size
        if 100 < self.output_size < 1000000:  # 100B to 1MB
            score += 0.05
        
        return min(1.0, score)

@dataclass
class PerformanceMetrics:
    """Track performance metrics for adaptive scanning"""
    success_rate: float = 0.0
    average_duration: float = 0.0
    throughput: float = 0.0  # targets per minute
    error_rate: float = 0.0
    last_updated: datetime = field(default_factory=datetime.now)
    
    def update(self, results: List[ScanResult]):
        """Update metrics based on recent results"""
        if not results:
            return
        
        total = len(results)
        successful = sum(1 for r in results if r.success)
        
        self.success_rate = successful / total
        self.error_rate = 1.0 - self.success_rate
        self.average_duration = statistics.mean(r.duration for r in results)
        
        # Calculate throughput (targets per minute)
        if self.average_duration > 0:
            self.throughput = 60.0 / self.average_duration
        
        self.last_updated = datetime.now()

class AdaptiveScanManager:
    """
    Manages adaptive scanning with success rate optimization
    Automatically adjusts parameters based on performance
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None, target_success_rate: float = 0.96):
        # Initialize from config if provided
        if config:
            self.scan_depth = config.get('scan_depth', 3)
            self.max_threads = config.get('max_threads', 10)
            self.rate_limit = config.get('rate_limit', 5)
        else:
            self.scan_depth = 3
            self.max_threads = 10
            self.rate_limit = 5
            
        self.target_success_rate = target_success_rate
        self.logger = PantheonLogger("AdaptiveScanManager")
        self.results_history: deque = deque(maxlen=1000)  # Keep last 1000 results
        self.metrics_by_tool: Dict[str, PerformanceMetrics] = {}
        self.adaptive_settings: Dict[str, Dict] = self._initialize_adaptive_settings()
        self.lock = threading.Lock()
        
        # Initialize wordlists and payloads attributes expected by tests
        self.wordlists = []
        self.payloads = []
        
    def _initialize_adaptive_settings(self) -> Dict[str, Dict]:
        """Initialize adaptive settings for different tools"""
        return {
            'nuclei': {
                'initial_rps': 500,
                'max_rps': 1000,
                'min_rps': 50,
                'concurrency': 150,
                'timeout': 30
            },
            'subfinder': {
                'timeout': 60,
                'max_retries': 3,
                'rate_limit': 10
            },
            'httpx': {
                'threads': 50,
                'timeout': 15,
                'max_retries': 2,
                'rate_limit': 100
            },
            'naabu': {
                'rate': 1000,
                'timeout': 10,
                'retries': 2
            }
        }
    
    def record_result(self, result: ScanResult):
        """Record a scan result and update metrics"""
        with self.lock:
            self.results_history.append(result)
            
            # Update tool-specific metrics
            tool = result.tool
            if tool not in self.metrics_by_tool:
                self.metrics_by_tool[tool] = PerformanceMetrics()
            
            # Get recent results for this tool (last 50)
            recent_results = [r for r in list(self.results_history)[-50:] if r.tool == tool]
            if recent_results:
                self.metrics_by_tool[tool].update(recent_results)
            
            # Auto-adjust settings if performance is poor
            self._auto_adjust_settings(tool)
    
    def _auto_adjust_settings(self, tool: str):
        """Automatically adjust tool settings based on performance"""
        metrics = self.metrics_by_tool.get(tool)
        if not metrics:
            return
        
        settings = self.adaptive_settings.get(tool, {})
        
        # Adjust based on success rate
        if metrics.success_rate < self.target_success_rate:
            self.logger.log(f"Low success rate for {tool}: {metrics.success_rate:.1%}")
            
            if tool == 'nuclei':
                # Reduce rate and concurrency for better stability
                current_rps = settings.get('initial_rps', 500)
                settings['initial_rps'] = max(settings['min_rps'], int(current_rps * 0.8))
                settings['concurrency'] = max(50, int(settings['concurrency'] * 0.8))
                settings['timeout'] = min(60, settings['timeout'] + 5)
                
            elif tool == 'httpx':
                # Reduce threading and increase timeout
                settings['threads'] = max(10, int(settings['threads'] * 0.7))
                settings['timeout'] = min(30, settings['timeout'] + 5)
                settings['max_retries'] = min(5, settings['max_retries'] + 1)
        
        elif metrics.success_rate > self.target_success_rate + 0.02:
            # Performance is good, we can be more aggressive
            if tool == 'nuclei':
                current_rps = settings.get('initial_rps', 500)
                settings['initial_rps'] = min(settings['max_rps'], int(current_rps * 1.1))
                settings['concurrency'] = min(200, int(settings['concurrency'] * 1.1))
            
            elif tool == 'httpx':
                settings['threads'] = min(100, int(settings['threads'] * 1.2))
    
    def get_optimized_settings(self, tool: str) -> Dict[str, Any]:
        """Get optimized settings for a specific tool"""
        return self.adaptive_settings.get(tool, {}).copy()
    
    def get_current_success_rate(self) -> float:
        """Get current overall success rate"""
        if not self.results_history:
            return 0.0
        
        recent_results = list(self.results_history)[-100:]  # Last 100 results
        if not recent_results:
            return 0.0
        
        successful = sum(1 for r in recent_results if r.success)
        return successful / len(recent_results)
    
    def get_tool_performance(self, tool: str) -> Optional[PerformanceMetrics]:
        """Get performance metrics for a specific tool"""
        return self.metrics_by_tool.get(tool)
    
    def should_skip_tool(self, tool: str) -> bool:
        """Determine if a tool should be skipped due to poor performance"""
        metrics = self.metrics_by_tool.get(tool)
        if not metrics:
            return False
        
        # Skip if success rate is extremely low and we have enough data
        recent_results = [r for r in list(self.results_history)[-20:] if r.tool == tool]
        if len(recent_results) >= 10 and metrics.success_rate < 0.1:
            self.logger.log(f"Skipping {tool} due to low success rate: {metrics.success_rate:.1%}")
            return True
        
        return False
    
    def export_metrics(self, file_path: str):
        """Export performance metrics to JSON file"""
        metrics_data = {
            'overall_success_rate': self.get_current_success_rate(),
            'target_success_rate': self.target_success_rate,
            'total_scans': len(self.results_history),
            'tools': {}
        }
        
        for tool, metrics in self.metrics_by_tool.items():
            metrics_data['tools'][tool] = {
                'success_rate': metrics.success_rate,
                'average_duration': metrics.average_duration,
                'throughput': metrics.throughput,
                'error_rate': metrics.error_rate,
                'last_updated': metrics.last_updated.isoformat(),
                'optimized_settings': self.adaptive_settings.get(tool, {})
            }
        
        atomic_write(file_path, json.dumps(metrics_data, indent=2))

class EnhancedScanner:
    """Enhanced scanner with improved reliability and success tracking"""
    
    def __init__(self, scan_manager: AdaptiveScanManager):
        self.scan_manager = scan_manager
        self.logger = PantheonLogger("EnhancedScanner")
        
    def enhanced_nuclei_scan(self, targets: List[str], output_dir: Path) -> Tuple[bool, int]:
        """Enhanced nuclei scan with adaptive settings and fallback"""
        # Check tool availability using enhanced tool manager
        tool_available = False
        if ENHANCED_TOOL_MANAGER_AVAILABLE:
            nuclei_path = enhanced_which('nuclei')
            tool_available = nuclei_path is not None and not nuclei_path.startswith('virtual:')
        else:
            tool_available = which('nuclei')
        
        # Try nuclei first if available, otherwise use fallback
        if tool_available:
            return self._nuclei_scan_with_tool(targets, output_dir)
        else:
            # Use fallback scanner
            self.logger.log("Nuclei not available, using fallback scanner", "INFO")
            return self._fallback_scan(targets, output_dir)
    
    def _nuclei_scan_with_tool(self, targets: List[str], output_dir: Path) -> Tuple[bool, int]:
        """Original nuclei scan with external tool"""
        if self.scan_manager.should_skip_tool('nuclei'):
            return False, 0
        
        settings = self.scan_manager.get_optimized_settings('nuclei')
        findings_count = 0
        success_count = 0
        
        for target in targets:
            if not (validate_domain_input(target) or validate_ip_input(target)):
                continue
            
            start_time = time.time()
            
            try:
                # Rate limiting
                if not rate_limiter.is_allowed(f"nuclei_{target}"):
                    wait_time = rate_limiter.wait_time(f"nuclei_{target}")
                    if wait_time > 0:
                        time.sleep(min(wait_time, 5))
                
                output_file = output_dir / f"nuclei_{target.replace(':', '_')}.json"
                
                cmd = [
                    'nuclei',
                    '-target', target,
                    '-json',
                    '-o', str(output_file),
                    '-rate-limit', str(settings.get('initial_rps', 500)),
                    '-concurrency', str(settings.get('concurrency', 150)),
                    '-timeout', str(settings.get('timeout', 30))
                ]
                
                result_code, stdout, stderr = safe_run_command(cmd, timeout=300)
                end_time = time.time()
                
                # Count findings
                target_findings = 0
                if output_file.exists():
                    try:
                        with open(output_file, 'r') as f:
                            content = f.read().strip()
                            if content:
                                target_findings = len([line for line in content.split('\n') if line.strip()])
                        findings_count += target_findings
                    except Exception as e:
                        self.logger.log(f"Error reading nuclei output: {e}", "WARNING")
                
                # Record result
                scan_result = ScanResult(
                    target=target,
                    tool='nuclei',
                    start_time=start_time,
                    end_time=end_time,
                    success=(result_code == 0),
                    output_size=len(stdout) if stdout else 0,
                    error_message=stderr if result_code != 0 else None,
                    findings_count=target_findings
                )
                
                self.scan_manager.record_result(scan_result)
                
                if result_code == 0:
                    success_count += 1
                
            except Exception as e:
                end_time = time.time()
                self.logger.log(f"Nuclei scan failed for {target}: {e}", "ERROR")
                
                # Record failure
                scan_result = ScanResult(
                    target=target,
                    tool='nuclei',
                    start_time=start_time,
                    end_time=end_time,
                    success=False,
                    error_message=str(e)
                )
                self.scan_manager.record_result(scan_result)
        
        success_rate = success_count / len(targets) if targets else 0
        self.logger.log(f"Nuclei scan completed: {success_count}/{len(targets)} targets successful ({success_rate:.1%})")
        
        return success_rate >= 0.8, findings_count
    
    def _fallback_scan(self, targets: List[str], output_dir: Path) -> Tuple[bool, int]:
        """Fallback scan using built-in capabilities"""
        try:
            # Import fallback scanner
            from fallback_scanner import run_fallback_scan
            
            # Run fallback scan
            success, findings_count = run_fallback_scan(targets, output_dir)
            
            # Record results for each target
            for target in targets:
                scan_result = ScanResult(
                    target=target,
                    tool='fallback_scanner',
                    start_time=time.time(),
                    end_time=time.time(),
                    success=success,
                    findings_count=findings_count // len(targets) if targets else 0  # Approximate
                )
                self.scan_manager.record_result(scan_result)
            
            self.logger.log(f"Fallback scan completed: {findings_count} findings from {len(targets)} targets")
            return success, findings_count
            
        except ImportError:
            self.logger.log("Fallback scanner not available", "ERROR")
            return False, 0
        except Exception as e:
            self.logger.log(f"Fallback scan failed: {e}", "ERROR")
            return False, 0
    
    def enhanced_subdomain_enum(self, domain: str, output_dir: Path) -> Tuple[bool, List[str]]:
        """Enhanced subdomain enumeration with multiple tools and fallbacks"""
        if not validate_domain_input(domain):
            return False, []
        
        all_subdomains = set()
        tools_used = []
        success_count = 0
        
        # Try subfinder first
        if which('subfinder') and not self.scan_manager.should_skip_tool('subfinder'):
            start_time = time.time()
            try:
                output_file = output_dir / f"subfinder_{domain}.txt"
                cmd = ['subfinder', '-domain', domain, '-o', str(output_file), '-silent']
                
                result_code, stdout, stderr = safe_run_command(cmd, timeout=120)
                end_time = time.time()
                
                subdomains = []
                if output_file.exists():
                    subdomains = read_lines(str(output_file))
                    all_subdomains.update(subdomains)
                
                scan_result = ScanResult(
                    target=domain,
                    tool='subfinder',
                    start_time=start_time,
                    end_time=end_time,
                    success=(result_code == 0),
                    findings_count=len(subdomains)
                )
                self.scan_manager.record_result(scan_result)
                
                if result_code == 0:
                    success_count += 1
                    tools_used.append('subfinder')
                
            except Exception as e:
                end_time = time.time()
                scan_result = ScanResult(
                    target=domain,
                    tool='subfinder',
                    start_time=start_time,
                    end_time=end_time,
                    success=False,
                    error_message=str(e)
                )
                self.scan_manager.record_result(scan_result)
        
        # Try certificate transparency as fallback
        if len(all_subdomains) < 5:  # If we didn't get many results
            try:
                ct_subdomains = self._certificate_transparency_search(domain)
                all_subdomains.update(ct_subdomains)
                if ct_subdomains:
                    tools_used.append('certificate_transparency')
                    success_count += 1
            except Exception as e:
                self.logger.log(f"CT search failed: {e}", "WARNING")
        
        # Write combined results
        if all_subdomains:
            combined_file = output_dir / f"subdomains_{domain}.txt"
            atomic_write(str(combined_file), '\n'.join(sorted(all_subdomains)))
        
        success_rate = success_count / max(1, len(tools_used)) if tools_used else 0
        self.logger.log(f"Subdomain enumeration for {domain}: {len(all_subdomains)} found using {tools_used}")
        
        return success_rate >= 0.5, list(all_subdomains)
    
    def _certificate_transparency_search(self, domain: str) -> List[str]:
        """Search certificate transparency logs for subdomains"""
        import requests
        
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                subdomains = set()
                
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for name in name_value.split('\n'):
                        name = name.strip()
                        if name and '.' in name and name.endswith(domain):
                            subdomains.add(name)
                
                return list(subdomains)
        
        except Exception as e:
            self.logger.log(f"Certificate transparency search failed: {e}", "WARNING")
        
        return []

# Global instance for easy import
adaptive_scan_manager = AdaptiveScanManager()
enhanced_scanner = EnhancedScanner(adaptive_scan_manager)

def get_current_success_rate() -> float:
    """Get current overall success rate"""
    return adaptive_scan_manager.get_current_success_rate()

def get_performance_report() -> Dict[str, Any]:
    """Get comprehensive performance report"""
    return {
        'overall_success_rate': adaptive_scan_manager.get_current_success_rate(),
        'target_success_rate': adaptive_scan_manager.target_success_rate,
        'total_scans': len(adaptive_scan_manager.results_history),
        'tools_performance': {
            tool: {
                'success_rate': metrics.success_rate,
                'average_duration': metrics.average_duration,
                'throughput': metrics.throughput
            }
            for tool, metrics in adaptive_scan_manager.metrics_by_tool.items()
        }
    }

def run_enhanced_scanning(targets: List[str], config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Run enhanced scanning with adaptive management
    
    Args:
        targets: List of targets to scan
        config: Optional configuration dictionary
        
    Returns:
        Dictionary with scan results and performance metrics
    """
    from pathlib import Path
    import tempfile
    
    # Use temporary directory for output if not specified
    output_dir = Path(tempfile.mkdtemp(prefix="enhanced_scan_"))
    
    # Initialize scanner with config
    if config:
        scan_manager = AdaptiveScanManager(config)
    else:
        scan_manager = adaptive_scan_manager
    
    scanner = EnhancedScanner(scan_manager)
    
    results = {
        'targets_processed': len(targets),
        'successful_scans': 0,
        'failed_scans': 0,
        'findings': [],
        'performance_metrics': {},
        'output_directory': str(output_dir)
    }
    
    try:
        # Run nuclei scan if targets provided
        if targets:
            success, findings_count = scanner.enhanced_nuclei_scan(targets, output_dir)
            if success:
                results['successful_scans'] += 1
                results['findings'].append({
                    'tool': 'nuclei',
                    'findings_count': findings_count,
                    'success': True
                })
            else:
                results['failed_scans'] += 1
        
        # Get performance metrics
        results['performance_metrics'] = get_performance_report()
        
        return results
        
    except Exception as e:
        results['error'] = str(e)
        results['failed_scans'] = len(targets)
        return results

if __name__ == "__main__":
    # Quick test
    print("Enhanced Scanning Module - Test")
    print(f"Current success rate: {get_current_success_rate():.1%}")
    print("Available functions:")
    print("- AdaptiveScanManager: Adaptive scanning with performance optimization")
    print("- EnhancedScanner: Enhanced scanning with reliability improvements")
    print("- get_current_success_rate(): Get current success rate")
    print("- get_performance_report(): Get performance metrics")