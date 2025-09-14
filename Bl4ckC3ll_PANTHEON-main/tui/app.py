"""
Main TUI Application for Bl4ckC3ll_PANTHEON
Advanced Terminal User Interface with real-time monitoring and professional layout
"""

from textual.app import App
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import (
    Header, Footer, Static, Button, Input, Log, 
    DataTable, ProgressBar, Tree, TabbedContent, TabPane
)
from textual.binding import Binding
from textual import on
import asyncio
import time
from datetime import datetime
import threading
import logging

# Import screens locally to avoid circular import issues
import sys
import os
from pathlib import Path

# Add parent directory to path for relative imports
sys.path.append(str(Path(__file__).parent.parent))

# Setup logging
logging.basicConfig(level=logging.INFO)


class PantheonTUI(App):
    """Advanced TUI for Bl4ckC3ll_PANTHEON Security Testing Framework"""
    
    CSS_PATH = "styles.css"
    TITLE = "Bl4ckC3ll PANTHEON - Advanced Security Testing Framework"
    SUB_TITLE = "Professional Penetration Testing & Vulnerability Assessment"
    
    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit"),
        Binding("ctrl+d", "toggle_dark", "Toggle Dark Mode"),
        Binding("f1", "show_help", "Help"),
        Binding("f2", "targets", "Targets"),
        Binding("f3", "scan", "Scan"),
        Binding("f4", "reports", "Reports"),
        Binding("f5", "settings", "Settings"),
        Binding("ctrl+r", "refresh", "Refresh"),
        Binding("ctrl+s", "save_config", "Save Config"),
    ]
    
    def __init__(self):
        super().__init__()
        self.scan_runner = None
        self.system_monitor = None
        
    def compose(self):
        """Create the main layout"""
        yield Header()
        
        # Use a simple container structure instead of TabbedContent for now
        with Container(id="main-container"):
            # Tab buttons
            with Horizontal(id="tab-buttons"):
                yield Button("Dashboard", id="tab-dashboard", classes="tab-btn active")
                yield Button("Targets", id="tab-targets", classes="tab-btn")
                yield Button("Scanner", id="tab-scanner", classes="tab-btn")
                yield Button("Reports", id="tab-reports", classes="tab-btn")
                yield Button("Settings", id="tab-settings", classes="tab-btn")
            
            # Content areas - only one visible at a time
            with Container(id="content-area"):
                with Container(id="dashboard-content", classes="tab-content active"):
                    from .screens.main_dashboard import MainDashboard
                    yield MainDashboard()
                
                with Container(id="targets-content", classes="tab-content hidden"):
                    from .screens.targets import TargetsScreen
                    yield TargetsScreen()
                
                with Container(id="scanner-content", classes="tab-content hidden"):
                    from .screens.scan_runner import ScanRunner
                    yield ScanRunner()
                
                with Container(id="reports-content", classes="tab-content hidden"):
                    from .screens.reports import ReportsScreen
                    yield ReportsScreen()
                
                with Container(id="settings-content", classes="tab-content hidden"):
                    from .screens.settings import SettingsScreen
                    yield SettingsScreen()
                
        yield Footer()
    
    @on(Button.Pressed, ".tab-btn")
    def switch_tab(self, event: Button.Pressed):
        """Handle tab button clicks"""
        tab_id = event.button.id
        
        # Remove active class from all tab buttons and content
        for btn in self.query(".tab-btn"):
            btn.remove_class("active")
        for content in self.query(".tab-content"):
            content.remove_class("active")
            content.add_class("hidden")
        
        # Activate clicked tab
        event.button.add_class("active")
        
        # Show corresponding content
        content_map = {
            "tab-dashboard": "dashboard-content",
            "tab-targets": "targets-content", 
            "tab-scanner": "scanner-content",
            "tab-reports": "reports-content",
            "tab-settings": "settings-content"
        }
        
        content_id = content_map.get(tab_id)
        if content_id:
            content = self.query_one(f"#{content_id}")
            content.remove_class("hidden")
            content.add_class("active")
        
    def on_mount(self):
        """Initialize the application"""
        self.title = self.TITLE
        self.sub_title = self.SUB_TITLE
        
        # Start system monitoring
        self.start_system_monitor()
        
    def start_system_monitor(self):
        """Start background system monitoring"""
        def monitor_loop():
            while True:
                # Update system stats, scan progress, etc.
                time.sleep(1)
                
        self.system_monitor = threading.Thread(target=monitor_loop, daemon=True)
        self.system_monitor.start()
        
    def action_quit(self):
        """Quit the application"""
        self.exit()
        
    def action_toggle_dark(self):
        """Toggle dark mode"""
        self.dark = not self.dark
        
    def action_show_help(self):
        """Show help screen"""
        self.push_screen("help")
        
    def action_targets(self):
        """Switch to targets tab"""
        self.query_one("#tab-targets").press()
        
    def action_scan(self):
        """Switch to scanner tab"""
        self.query_one("#tab-scanner").press()
        
    def action_reports(self):
        """Switch to reports tab"""
        self.query_one("#tab-reports").press()
        
    def action_settings(self):
        """Switch to settings tab"""
        self.query_one("#tab-settings").press()
        
    def action_refresh(self):
        """Refresh current view"""
        # Refresh the active tab content
        pass
        
    def action_save_config(self):
        """Save current configuration"""
        # Save settings to config file
        pass


if __name__ == "__main__":
    app = PantheonTUI()
    app.run()