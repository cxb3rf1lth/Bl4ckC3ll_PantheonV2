"""
System Monitoring Widget for Bl4ckC3ll_PANTHEON TUI
Real-time system resource monitoring
"""

from textual.widgets import Static, ProgressBar, Label
from textual.containers import Vertical
import time
import threading


class SystemMonitor(Static):
    """System resource monitoring widget"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.monitor_active = True
        self.monitor_thread = None
        
    def compose(self):
        yield Label("System Monitor", classes="widget-title")
        
        with Vertical():
            yield Label("CPU: 0%", id="cpu-display")
            yield ProgressBar(total=100, id="cpu-progress")
            
            yield Label("Memory: 0%", id="memory-display")
            yield ProgressBar(total=100, id="memory-progress")
            
            yield Label("Network: 0 KB/s", id="network-display")
            
    def start_monitoring(self):
        """Start system resource monitoring"""
        self.monitor_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
    def stop_monitoring(self):
        """Stop system resource monitoring"""
        self.monitor_active = False
        
    def _monitor_loop(self):
        """Background monitoring loop"""
        while self.monitor_active:
            try:
                # Try to get system stats
                import psutil
                
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                
                # Update displays
                self.query_one("#cpu-display").update(f"CPU: {cpu_percent:.1f}%")
                self.query_one("#cpu-progress").progress = cpu_percent
                
                self.query_one("#memory-display").update(f"Memory: {memory.percent:.1f}%")
                self.query_one("#memory-progress").progress = memory.percent
                
            except ImportError:
                # Fallback without psutil
                time.sleep(1)
            except Exception:
                time.sleep(1)
                
    def on_mount(self):
        """Initialize monitoring on mount"""
        self.start_monitoring()
        
    def on_unmount(self):
        """Stop monitoring on unmount"""
        self.stop_monitoring()