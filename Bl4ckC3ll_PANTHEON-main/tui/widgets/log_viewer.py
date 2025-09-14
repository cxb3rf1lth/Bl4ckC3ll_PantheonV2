"""
Log Viewer Widget for Bl4ckC3ll_PANTHEON TUI
Real-time log display and filtering
"""

from textual.widgets import Static, Log, Label, Input, Select
from textual.containers import Vertical, Horizontal
from textual import on
from datetime import datetime
import threading
import queue


class LogViewer(Static):
    """Advanced log viewing widget with filtering and search"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.log_queue = queue.Queue()
        self.filter_level = "ALL"
        
    def compose(self):
        yield Label("System Logs", classes="widget-title")
        
        with Vertical():
            with Horizontal():
                yield Select([
                    ("All Levels", "ALL"),
                    ("Error", "ERROR"),
                    ("Warning", "WARNING"), 
                    ("Info", "INFO"),
                    ("Debug", "DEBUG")
                ], value="ALL", id="log-level-filter")
                
                yield Input(placeholder="Search logs...", id="log-search")
                
            yield Log(id="log-display")
            
    def add_log_entry(self, message: str, level: str = "INFO"):
        """Add a new log entry"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {level}: {message}"
        
        # Add to queue for processing
        self.log_queue.put((level, formatted_message))
        
        # Update display if level matches filter
        if self.filter_level == "ALL" or level == self.filter_level:
            log_display = self.query_one("#log-display", Log)
            log_display.write_line(formatted_message)
            
    @on(Select.Changed, "#log-level-filter")
    def filter_logs(self, event):
        """Filter logs by level"""
        self.filter_level = event.value
        # Refresh log display with new filter
        self.refresh_log_display()
        
    @on(Input.Changed, "#log-search")
    def search_logs(self, event):
        """Search logs by text"""
        search_term = event.value.lower()
        # Implement log searching
        pass
        
    def refresh_log_display(self):
        """Refresh the log display with current filters"""
        log_display = self.query_one("#log-display", Log)
        log_display.clear()
        
        # Re-add filtered messages
        # This would iterate through stored log messages
        pass
        
    def clear_logs(self):
        """Clear all log entries"""
        log_display = self.query_one("#log-display", Log)
        log_display.clear()
        
        # Clear queue
        while not self.log_queue.empty():
            self.log_queue.get()