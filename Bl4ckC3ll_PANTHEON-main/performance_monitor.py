#!/usr/bin/env python3
"""
Performance Monitoring and Auto-Optimization System for Bl4ckC3ll_PANTHEON
Real-time monitoring with intelligent parameter tuning to achieve 96% success rate
"""

import os
import json
import time
import psutil
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from collections import deque, defaultdict
import statistics
import logging

@dataclass
class PerformanceSnapshot:
    """Snapshot of system performance at a point in time"""
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    disk_usage_percent: float
    network_io: Dict[str, int]
    active_processes: int
    success_rate: float
    throughput: float  # operations per minute
    error_count: int
    response_time_avg: float

@dataclass
class OptimizationRule:
    """Rule for automatic optimization"""
    condition: str  # Python expression to evaluate
    action: str    # Action to take
    parameter: str # Parameter to adjust
    adjustment: float # How much to adjust
    description: str
    priority: int = 1

class PerformanceMonitor:
    """Real-time performance monitoring with automatic optimization"""
    
    def __init__(self, target_success_rate: float = 0.96):
        self.target_success_rate = target_success_rate
        self.is_monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.performance_history: deque = deque(maxlen=1000)
        self.optimization_rules = self._initialize_optimization_rules()
        self.current_settings: Dict[str, Any] = self._load_current_settings()
        self.lock = threading.Lock()
        
        # Performance metrics
        self.total_operations = 0
        self.successful_operations = 0
        self.error_count = 0
        self.response_times: deque = deque(maxlen=100)
        
        # Auto-tuning parameters
        self.auto_tuning_enabled = True
        self.last_optimization_time = datetime.now()
        self.optimization_cooldown = timedelta(minutes=5)  # Prevent too frequent changes
        
    def _initialize_optimization_rules(self) -> List[OptimizationRule]:
        """Initialize optimization rules for automatic tuning"""
        return [
            OptimizationRule(
                condition="success_rate < 0.9 and cpu_percent > 80",
                action="decrease",
                parameter="concurrency",
                adjustment=0.8,
                description="Reduce concurrency when high CPU usage impacts success rate",
                priority=1
            ),
            OptimizationRule(
                condition="success_rate < 0.85",
                action="increase",
                parameter="timeout",
                adjustment=1.5,
                description="Increase timeouts when success rate is low",
                priority=2
            ),
            OptimizationRule(
                condition="success_rate < 0.8 and error_count > 10",
                action="decrease",
                parameter="rate_limit",
                adjustment=0.7,
                description="Reduce rate limiting when many errors occur",
                priority=1
            ),
            OptimizationRule(
                condition="success_rate > 0.95 and cpu_percent < 50",
                action="increase",
                parameter="concurrency",
                adjustment=1.2,
                description="Increase concurrency when performance is good",
                priority=3
            ),
            OptimizationRule(
                condition="memory_percent > 90",
                action="decrease",
                parameter="parallel_jobs",
                adjustment=0.5,
                description="Reduce parallel jobs when memory is high",
                priority=1
            ),
            OptimizationRule(
                condition="response_time_avg > 30 and success_rate < 0.9",
                action="decrease",
                parameter="batch_size",
                adjustment=0.6,
                description="Reduce batch size when response times are high",
                priority=2
            )
        ]
    
    def _load_current_settings(self) -> Dict[str, Any]:
        """Load current system settings"""
        try:
            config_file = Path("p4nth30n.cfg.json")
            if config_file.exists():
                with open(config_file, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        
        # Default settings
        return {
            "limits": {
                "parallel_jobs": 20,
                "http_timeout": 15,
                "rps": 500,
                "max_concurrent_scans": 8
            },
            "nuclei": {
                "rps": 800,
                "conc": 150
            }
        }
    
    def start_monitoring(self, interval: float = 5.0):
        """Start performance monitoring"""
        if self.is_monitoring:
            return
        
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            args=(interval,),
            daemon=True
        )
        self.monitor_thread.start()
        print(f"🔍 Performance monitoring started (target success rate: {self.target_success_rate:.1%})")
    
    def stop_monitoring(self):
        """Stop performance monitoring"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        print("🛑 Performance monitoring stopped")
    
    def _monitoring_loop(self, interval: float):
        """Main monitoring loop"""
        while self.is_monitoring:
            try:
                snapshot = self._capture_performance_snapshot()
                
                with self.lock:
                    self.performance_history.append(snapshot)
                
                # Check for optimization opportunities
                if self.auto_tuning_enabled:
                    self._check_optimization_triggers(snapshot)
                
                # Log performance if significantly changed
                self._log_performance_changes(snapshot)
                
                time.sleep(interval)
                
            except Exception as e:
                print(f"⚠️ Monitoring error: {e}")
                time.sleep(interval)
    
    def _capture_performance_snapshot(self) -> PerformanceSnapshot:
        """Capture current system performance"""
        # System metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Network I/O
        network = psutil.net_io_counters()
        network_io = {
            'bytes_sent': network.bytes_sent,
            'bytes_recv': network.bytes_recv
        }
        
        # Process count
        active_processes = len(psutil.pids())
        
        # Application metrics
        success_rate = self.get_current_success_rate()
        throughput = self.get_current_throughput()
        error_count = self.error_count
        
        # Response times
        avg_response_time = 0.0
        if self.response_times:
            avg_response_time = statistics.mean(self.response_times)
        
        return PerformanceSnapshot(
            timestamp=datetime.now(),
            cpu_percent=cpu_percent,
            memory_percent=memory.percent,
            disk_usage_percent=disk.percent,
            network_io=network_io,
            active_processes=active_processes,
            success_rate=success_rate,
            throughput=throughput,
            error_count=error_count,
            response_time_avg=avg_response_time
        )
    
    def _check_optimization_triggers(self, snapshot: PerformanceSnapshot):
        """Check if any optimization rules should be triggered"""
        # Cooldown check
        if datetime.now() - self.last_optimization_time < self.optimization_cooldown:
            return
        
        # Prepare evaluation context
        context = {
            'success_rate': snapshot.success_rate,
            'cpu_percent': snapshot.cpu_percent,
            'memory_percent': snapshot.memory_percent,
            'error_count': snapshot.error_count,
            'response_time_avg': snapshot.response_time_avg,
            'throughput': snapshot.throughput
        }
        
        # Sort rules by priority
        sorted_rules = sorted(self.optimization_rules, key=lambda r: r.priority)
        
        for rule in sorted_rules:
            try:
                if eval(rule.condition, {}, context):
                    self._apply_optimization(rule, snapshot)
                    self.last_optimization_time = datetime.now()
                    break  # Apply only one rule at a time
            except Exception as e:
                print(f"⚠️ Error evaluating optimization rule: {e}")
    
    def _apply_optimization(self, rule: OptimizationRule, snapshot: PerformanceSnapshot):
        """Apply an optimization rule"""
        try:
            current_value = self._get_parameter_value(rule.parameter)
            if current_value is None:
                return
            
            if rule.action == "increase":
                new_value = current_value * rule.adjustment
            elif rule.action == "decrease":
                new_value = current_value * rule.adjustment
            else:
                return
            
            # Apply reasonable bounds
            new_value = self._apply_parameter_bounds(rule.parameter, new_value)
            
            # Update the parameter
            success = self._set_parameter_value(rule.parameter, new_value)
            
            if success:
                print(f"🎯 Auto-optimization: {rule.description}")
                print(f"   📊 {rule.parameter}: {current_value} -> {new_value}")
                print(f"   📈 Success rate: {snapshot.success_rate:.1%} (target: {self.target_success_rate:.1%})")
                
                # Log the optimization
                self._log_optimization(rule, current_value, new_value, snapshot)
        
        except Exception as e:
            print(f"⚠️ Failed to apply optimization: {e}")
    
    def _get_parameter_value(self, parameter: str) -> Optional[float]:
        """Get current value of a parameter"""
        try:
            if parameter == "concurrency":
                return self.current_settings.get("nuclei", {}).get("conc", 150)
            elif parameter == "timeout":
                return self.current_settings.get("limits", {}).get("http_timeout", 15)
            elif parameter == "rate_limit":
                return self.current_settings.get("nuclei", {}).get("rps", 800)
            elif parameter == "parallel_jobs":
                return self.current_settings.get("limits", {}).get("parallel_jobs", 20)
            elif parameter == "batch_size":
                return self.current_settings.get("limits", {}).get("max_concurrent_scans", 8)
        except Exception:
            pass
        return None
    
    def _set_parameter_value(self, parameter: str, value: float) -> bool:
        """Set a parameter value"""
        try:
            value = int(value)  # Convert to int for most parameters
            
            if parameter == "concurrency":
                self.current_settings.setdefault("nuclei", {})["conc"] = value
            elif parameter == "timeout":
                self.current_settings.setdefault("limits", {})["http_timeout"] = value
            elif parameter == "rate_limit":
                self.current_settings.setdefault("nuclei", {})["rps"] = value
            elif parameter == "parallel_jobs":
                self.current_settings.setdefault("limits", {})["parallel_jobs"] = value
            elif parameter == "batch_size":
                self.current_settings.setdefault("limits", {})["max_concurrent_scans"] = value
            else:
                return False
            
            # Save to config file
            self._save_settings()
            return True
        
        except Exception as e:
            print(f"⚠️ Failed to set parameter {parameter}: {e}")
            return False
    
    def _apply_parameter_bounds(self, parameter: str, value: float) -> float:
        """Apply reasonable bounds to parameter values"""
        bounds = {
            "concurrency": (10, 300),
            "timeout": (5, 120),
            "rate_limit": (50, 2000),
            "parallel_jobs": (1, 50),
            "batch_size": (1, 20)
        }
        
        if parameter in bounds:
            min_val, max_val = bounds[parameter]
            return max(min_val, min(max_val, value))
        
        return value
    
    def _save_settings(self):
        """Save current settings to config file"""
        try:
            config_file = Path("p4nth30n.cfg.json")
            with open(config_file, 'w') as f:
                json.dump(self.current_settings, f, indent=2)
        except Exception as e:
            print(f"⚠️ Failed to save settings: {e}")
    
    def _log_optimization(self, rule: OptimizationRule, old_value: float, new_value: float, snapshot: PerformanceSnapshot):
        """Log optimization actions"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'rule': rule.description,
            'parameter': rule.parameter,
            'old_value': old_value,
            'new_value': new_value,
            'trigger_condition': rule.condition,
            'system_state': {
                'success_rate': snapshot.success_rate,
                'cpu_percent': snapshot.cpu_percent,
                'memory_percent': snapshot.memory_percent,
                'error_count': snapshot.error_count
            }
        }
        
        # Append to optimization log
        log_file = Path("logs/optimizations.jsonl")
        log_file.parent.mkdir(exist_ok=True)
        
        try:
            with open(log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            print(f"⚠️ Failed to log optimization: {e}")
    
    def _log_performance_changes(self, snapshot: PerformanceSnapshot):
        """Log significant performance changes"""
        if len(self.performance_history) < 2:
            return
        
        previous = self.performance_history[-2]
        
        # Check for significant changes
        success_change = abs(snapshot.success_rate - previous.success_rate)
        cpu_change = abs(snapshot.cpu_percent - previous.cpu_percent)
        
        if success_change > 0.05 or cpu_change > 20:
            print(f"📊 Performance change detected:")
            print(f"   Success rate: {previous.success_rate:.1%} -> {snapshot.success_rate:.1%}")
            print(f"   CPU usage: {previous.cpu_percent:.1f}% -> {snapshot.cpu_percent:.1f}%")
    
    def record_operation(self, success: bool, response_time: float = 0.0):
        """Record the result of an operation"""
        with self.lock:
            self.total_operations += 1
            if success:
                self.successful_operations += 1
            else:
                self.error_count += 1
            
            if response_time > 0:
                self.response_times.append(response_time)
    
    def get_current_success_rate(self) -> float:
        """Get current success rate"""
        if self.total_operations == 0:
            return 1.0  # No operations yet
        return self.successful_operations / self.total_operations
    
    def get_current_throughput(self) -> float:
        """Get current throughput (operations per minute)"""
        if len(self.performance_history) < 2:
            return 0.0
        
        recent_snapshots = list(self.performance_history)[-10:]  # Last 10 snapshots
        if len(recent_snapshots) < 2:
            return 0.0
        
        time_span = (recent_snapshots[-1].timestamp - recent_snapshots[0].timestamp).total_seconds()
        if time_span == 0:
            return 0.0
        
        # Approximate throughput based on total operations
        return (self.total_operations / time_span) * 60  # per minute
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Get comprehensive performance report"""
        current_snapshot = self.performance_history[-1] if self.performance_history else None
        
        report = {
            'current_success_rate': self.get_current_success_rate(),
            'target_success_rate': self.target_success_rate,
            'success_rate_gap': self.target_success_rate - self.get_current_success_rate(),
            'total_operations': self.total_operations,
            'error_count': self.error_count,
            'throughput': self.get_current_throughput(),
            'auto_tuning_enabled': self.auto_tuning_enabled,
            'monitoring_active': self.is_monitoring
        }
        
        if current_snapshot:
            report.update({
                'cpu_percent': current_snapshot.cpu_percent,
                'memory_percent': current_snapshot.memory_percent,
                'disk_usage_percent': current_snapshot.disk_usage_percent,
                'avg_response_time': current_snapshot.response_time_avg
            })
        
        # Performance trend
        if len(self.performance_history) >= 10:
            recent_success_rates = [s.success_rate for s in list(self.performance_history)[-10:]]
            report['success_rate_trend'] = statistics.mean(recent_success_rates)
        
        # Recommendations
        recommendations = []
        current_success_rate = self.get_current_success_rate()
        
        if current_success_rate < self.target_success_rate:
            gap = self.target_success_rate - current_success_rate
            if gap > 0.1:
                recommendations.append("Critical: Success rate significantly below target")
            elif gap > 0.05:
                recommendations.append("Warning: Success rate below target")
            else:
                recommendations.append("Minor: Success rate slightly below target")
        
        if current_snapshot:
            if current_snapshot.cpu_percent > 90:
                recommendations.append("High CPU usage detected - consider reducing concurrency")
            if current_snapshot.memory_percent > 90:
                recommendations.append("High memory usage detected - reduce parallel operations")
        
        report['recommendations'] = recommendations
        
        return report
    
    def export_performance_data(self, file_path: str):
        """Export performance data for analysis"""
        export_data = {
            'timestamp': datetime.now().isoformat(),
            'monitoring_period': {
                'start': self.performance_history[0].timestamp.isoformat() if self.performance_history else None,
                'end': self.performance_history[-1].timestamp.isoformat() if self.performance_history else None,
                'duration_minutes': len(self.performance_history) * 5 / 60  # Assuming 5-second intervals
            },
            'summary': self.get_performance_report(),
            'performance_snapshots': [
                {
                    'timestamp': s.timestamp.isoformat(),
                    'cpu_percent': s.cpu_percent,
                    'memory_percent': s.memory_percent,
                    'success_rate': s.success_rate,
                    'throughput': s.throughput,
                    'error_count': s.error_count,
                    'response_time_avg': s.response_time_avg
                }
                for s in self.performance_history
            ]
        }
        
        with open(file_path, 'w') as f:
            json.dump(export_data, f, indent=2)

# Global performance monitor instance
performance_monitor = PerformanceMonitor()

def start_performance_monitoring(target_success_rate: float = 0.96):
    """Start performance monitoring with specified target"""
    performance_monitor.target_success_rate = target_success_rate
    performance_monitor.start_monitoring()

def stop_performance_monitoring():
    """Stop performance monitoring"""
    performance_monitor.stop_monitoring()

def record_operation_result(success: bool, response_time: float = 0.0):
    """Record an operation result for performance tracking"""
    performance_monitor.record_operation(success, response_time)

def get_current_performance_metrics() -> Dict[str, Any]:
    """Get current performance metrics"""
    return performance_monitor.get_performance_report()

def is_success_rate_target_met() -> bool:
    """Check if success rate target is being met"""
    current_rate = performance_monitor.get_current_success_rate()
    return current_rate >= performance_monitor.target_success_rate

if __name__ == "__main__":
    # Test the performance monitor
    print("Performance Monitor - Test")
    
    start_performance_monitoring(0.96)
    
    # Simulate some operations
    for i in range(50):
        success = i % 5 != 0  # 80% success rate
        response_time = 2.0 + (i % 10) * 0.5
        record_operation_result(success, response_time)
        time.sleep(0.1)
    
    time.sleep(5)  # Let monitor collect data
    
    report = get_current_performance_metrics()
    print(f"Current success rate: {report['current_success_rate']:.1%}")
    print(f"Target success rate: {report['target_success_rate']:.1%}")
    print(f"Target met: {is_success_rate_target_met()}")
    
    stop_performance_monitoring()