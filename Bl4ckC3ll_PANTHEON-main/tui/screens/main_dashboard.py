"""
Main Dashboard Screen for Bl4ckC3ll_PANTHEON TUI
Real-time system monitoring and status overview
"""

from textual.containers import Container, Horizontal, Vertical, Grid
from textual.widgets import Static, Button, Label, ProgressBar, DataTable
from textual.widget import Widget
from textual.reactive import reactive
from textual import on
import platform
import time
from datetime import datetime
import os
import sys
from pathlib import Path

# Try to import psutil, fallback gracefully
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# Import backend integration
try:
    from ..backend_integration import scan_manager, config_manager, target_manager, report_manager
    HAS_BACKEND = True
except ImportError:
    HAS_BACKEND = False


class SystemInfoWidget(Static):
    """System information display widget"""
    
    def compose(self):
        yield Label("System Information", classes="widget-title")
        yield Label(f"OS: {platform.system()} {platform.release()}", classes="info-item")
        yield Label(f"Python: {platform.python_version()}", classes="info-item")
        yield Label(f"Architecture: {platform.machine()}", classes="info-item")
        yield Label(f"Hostname: {platform.node()}", classes="info-item")


class ResourceMonitor(Static):
    """Real-time system resource monitoring"""
    
    cpu_usage = reactive(0.0)
    memory_usage = reactive(0.0) 
    disk_usage = reactive(0.0)
    
    def compose(self):
        yield Label("Resource Monitor", classes="widget-title")
        
        with Vertical():
            yield Label("CPU Usage:", classes="metric-label")
            yield ProgressBar(total=100, show_percentage=True, id="cpu-bar")
            
            yield Label("Memory Usage:", classes="metric-label")  
            yield ProgressBar(total=100, show_percentage=True, id="memory-bar")
            
            yield Label("Disk Usage:", classes="metric-label")
            yield ProgressBar(total=100, show_percentage=True, id="disk-bar")
            
    def on_mount(self):
        """Start resource monitoring"""
        self.set_interval(1.0, self.update_resources)
        
    def update_resources(self):
        """Update resource usage metrics"""
        if not HAS_PSUTIL:
            return
            
        try:
            # Get system metrics
            self.cpu_usage = psutil.cpu_percent(interval=None)
            memory = psutil.virtual_memory()
            self.memory_usage = memory.percent
            disk = psutil.disk_usage('/')
            self.disk_usage = (disk.used / disk.total) * 100
            
            # Update progress bars
            cpu_bar = self.query_one("#cpu-bar", ProgressBar)
            memory_bar = self.query_one("#memory-bar", ProgressBar) 
            disk_bar = self.query_one("#disk-bar", ProgressBar)
            
            cpu_bar.progress = self.cpu_usage
            memory_bar.progress = self.memory_usage
            disk_bar.progress = self.disk_usage
            
        except Exception as e:
            # Fallback for systems without psutil or other errors
            pass


class StatusOverview(Static):
    """Current status and recent activity overview"""
    
    def compose(self):
        yield Label("Status Overview", classes="widget-title")
        
        with Vertical():
            yield Label("Framework Status: READY", classes="status-ready")
            yield Label("Last Scan: None", classes="info-item")
            yield Label("Active Targets: 0", classes="info-item") 
            yield Label("Available Tools: Checking...", classes="info-item")
            yield Label("Reports Generated: 0", classes="info-item")
            yield Label("Plugins Loaded: 0", classes="info-item")
            
    def on_mount(self):
        """Initialize status display"""
        self.set_interval(5.0, self.update_status)
        
    def update_status(self):
        """Update status information"""
        # This would connect to the main application state
        pass


class QuickActionsPanel(Static):
    """Quick action buttons for common operations"""
    
    def compose(self):
        yield Label("Quick Actions", classes="widget-title")
        
        with Vertical(classes="quick-actions"):
            yield Button("Start Full Scan", variant="primary", id="btn-full-scan")
            yield Button("Quick Reconnaissance", variant="default", id="btn-quick-recon") 
            yield Button("Vulnerability Scan", variant="warning", id="btn-vuln-scan")
            yield Button("Generate Report", variant="success", id="btn-report")
            yield Button("View Last Results", variant="default", id="btn-view-results")
            yield Button("Open Settings", variant="default", id="btn-settings")
            
    @on(Button.Pressed, "#btn-full-scan")
    def start_full_scan(self):
        """Start a full security scan"""
        if HAS_BACKEND and scan_manager:
            success = scan_manager.start_full_scan()
            if success:
                self.app.action_scan()
            else:
                # Show error message
                pass
        else:
            self.app.action_scan()
        
    @on(Button.Pressed, "#btn-quick-recon")  
    def quick_recon(self):
        """Start quick reconnaissance"""
        if HAS_BACKEND and scan_manager:
            success = scan_manager.start_recon_scan()
            if success:
                self.app.action_scan()
        else:
            self.app.action_scan()
        
    @on(Button.Pressed, "#btn-vuln-scan")
    def vuln_scan(self):
        """Start vulnerability scan"""
        if HAS_BACKEND and scan_manager:
            success = scan_manager.start_vuln_scan()
            if success:
                self.app.action_scan()
        else:
            self.app.action_scan()
        
    @on(Button.Pressed, "#btn-report")
    def generate_report(self):
        """Generate security report"""
        self.app.action_reports()
        
    @on(Button.Pressed, "#btn-view-results")
    def view_results(self):
        """View last scan results"""
        self.app.action_reports()
        
    @on(Button.Pressed, "#btn-settings")
    def open_settings(self):
        """Open settings"""
        self.app.action_settings()


class RecentActivity(Static):
    """Display recent scan activity and logs"""
    
    def compose(self):
        yield Label("Recent Activity", classes="widget-title")
        
        # Create a simple table for recent activities
        table = DataTable()
        table.add_columns("Time", "Action", "Status")
        
        # Add some sample data
        table.add_rows([
            (datetime.now().strftime("%H:%M:%S"), "System Startup", "Complete"),
            (datetime.now().strftime("%H:%M:%S"), "Dependencies Check", "Warning"),
            (datetime.now().strftime("%H:%M:%S"), "Configuration Load", "Success"),
        ])
        
        yield table


class MainDashboard(Container):
    """Main dashboard layout with multiple information panels"""
    
    def compose(self):
        with Grid(id="dashboard-grid"):
            yield SystemInfoWidget(classes="dashboard-panel")
            yield ResourceMonitor(classes="dashboard-panel")
            yield StatusOverview(classes="dashboard-panel")  
            yield QuickActionsPanel(classes="dashboard-panel")
            yield RecentActivity(classes="dashboard-panel span-col-2")
            
    def on_mount(self):
        """Initialize dashboard"""
        pass