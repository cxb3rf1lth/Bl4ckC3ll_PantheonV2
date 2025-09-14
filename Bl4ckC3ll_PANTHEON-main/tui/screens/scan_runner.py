"""
Scan Runner Screen for Bl4ckC3ll_PANTHEON TUI
Interactive scanning interface with real-time progress
"""

from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Static, Button, Label, ProgressBar, Log, Select, Input
from textual.widget import Widget
from textual import on
import asyncio
import threading
import time
from datetime import datetime

# Import backend integration
try:
    from ..backend_integration import scan_manager, target_manager
    HAS_BACKEND = True
except ImportError:
    HAS_BACKEND = False


class ScanConfigPanel(Static):
    """Scan configuration and options panel"""
    
    def compose(self):
        yield Label("Scan Configuration", classes="widget-title")
        
        with Vertical():
            yield Label("Scan Type:", classes="form-label")
            yield Select([
                ("Quick Scan", "quick"),
                ("Full Pipeline", "full"), 
                ("Reconnaissance Only", "recon"),
                ("Vulnerability Scan Only", "vuln"),
                ("API Security Test", "api"),
                ("Cloud Security Assessment", "cloud"),
                ("BCAR Enhanced Recon", "bcar"),
                ("Subdomain Takeover", "takeover"),
                ("Advanced Fuzzing", "fuzz"),
                ("Payload Injection", "payload")
            ], id="scan-type")
            
            yield Label("Target Input:", classes="form-label")
            yield Input(placeholder="Enter target domain or IP", id="target-input")
            
            yield Label("Advanced Options:", classes="form-label")
            yield Select([
                ("Default Settings", "default"),
                ("Aggressive Mode", "aggressive"),
                ("Stealth Mode", "stealth"),
                ("Custom Configuration", "custom")
            ], id="scan-options")


class ScanControlPanel(Static):
    """Scan control buttons and actions"""
    
    def compose(self):
        yield Label("Scan Controls", classes="widget-title")
        
        with Vertical():
            with Horizontal():
                yield Button("Start Scan", variant="primary", id="btn-start-scan")
                yield Button("Stop Scan", variant="error", id="btn-stop-scan", disabled=True)
                
            with Horizontal():
                yield Button("Pause Scan", variant="warning", id="btn-pause-scan", disabled=True)
                yield Button("Resume Scan", variant="success", id="btn-resume-scan", disabled=True)
                
            yield Button("View Live Logs", variant="default", id="btn-view-logs")
            yield Button("Export Results", variant="default", id="btn-export-results")
            
    @on(Button.Pressed, "#btn-start-scan")
    def start_scan(self):
        """Start the security scan"""
        # Get scan configuration
        scan_type_select = self.parent.query_one("#scan-type", Select)
        target_input = self.parent.query_one("#target-input", Input)
        
        scan_type = scan_type_select.value if scan_type_select else "full"
        target = target_input.value.strip() if target_input else ""
        
        # Enable/disable buttons
        self.query_one("#btn-start-scan").disabled = True
        self.query_one("#btn-stop-scan").disabled = False
        self.query_one("#btn-pause-scan").disabled = False
        
        # Start scan using backend if available
        if HAS_BACKEND and scan_manager:
            # Set up progress callback
            scan_progress = self.parent.query_one("#scan-progress")
            scan_manager.set_progress_callback(scan_progress.update_from_backend)
            
            # Start appropriate scan type
            if scan_type == "recon":
                success = scan_manager.start_recon_scan([target] if target else None)
            elif scan_type == "vuln":  
                success = scan_manager.start_vuln_scan([target] if target else None)
            else:
                success = scan_manager.start_full_scan([target] if target else None)
                
            if not success:
                # Re-enable start button if scan failed to start
                self.query_one("#btn-start-scan").disabled = False
                self.query_one("#btn-stop-scan").disabled = True
                self.query_one("#btn-pause-scan").disabled = True
        else:
            # Start simulated scan
            scan_runner = self.parent.query_one("#scan-progress")
            scan_runner.start_scan()
        
    @on(Button.Pressed, "#btn-stop-scan")
    def stop_scan(self):
        """Stop the current scan"""
        self.query_one("#btn-start-scan").disabled = False
        self.query_one("#btn-stop-scan").disabled = True
        self.query_one("#btn-pause-scan").disabled = True
        self.query_one("#btn-resume-scan").disabled = True
        
        # Stop scan using backend if available
        if HAS_BACKEND and scan_manager:
            scan_manager.stop_scan()
        else:
            # Stop simulated scan
            scan_runner = self.parent.query_one("#scan-progress")
            scan_runner.stop_scan()


class ScanProgressPanel(Static):
    """Real-time scan progress display"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.scan_active = False
        self.current_phase = "Idle"
        self.progress_thread = None
        
    def compose(self):
        yield Label("Scan Progress", classes="widget-title")
        
        with Vertical():
            yield Label("Status: Idle", id="scan-status", classes="status-idle")
            yield Label("Phase: Not Started", id="current-phase")
            yield Label("Targets: 0", id="target-count")
            yield Label("Elapsed Time: 00:00:00", id="elapsed-time")
            
            yield Label("Overall Progress:", classes="form-label")
            yield ProgressBar(total=100, show_percentage=True, id="overall-progress")
            
            yield Label("Current Phase Progress:", classes="form-label") 
            yield ProgressBar(total=100, show_percentage=True, id="phase-progress")
            
            yield Label("Phase Details:", classes="form-label")
            yield Static("Waiting to start...", id="phase-details")
            
    def start_scan(self):
        """Start scan progress monitoring"""
        self.scan_active = True
        self.query_one("#scan-status").update("Status: Running")
        self.query_one("#scan-status").classes = "status-running"
        
        # Start progress monitoring thread
        self.progress_thread = threading.Thread(target=self._progress_monitor, daemon=True)
        self.progress_thread.start()
        
    def stop_scan(self):
        """Stop scan progress monitoring"""
        self.scan_active = False
        self.query_one("#scan-status").update("Status: Stopped")
        self.query_one("#scan-status").classes = "status-stopped"
        
    def update_from_backend(self, progress, phase, status):
        """Update progress from backend scan manager"""
        self.query_one("#scan-status").update(f"Status: {status}")
        self.query_one("#current-phase").update(f"Phase: {phase}")
        self.query_one("#phase-details").update(f"Executing: {phase}")
        self.query_one("#overall-progress").progress = progress
        
        # Update status classes for styling
        status_widget = self.query_one("#scan-status")
        if status == "Running":
            status_widget.classes = "status-running"
        elif status in ["Complete", "Completed"]:
            status_widget.classes = "status-complete"
        elif status in ["Error", "Failed"]:
            status_widget.classes = "status-error"
        elif status in ["Stopped"]:
            status_widget.classes = "status-stopped"
        else:
            status_widget.classes = "status-idle"
            
    def _progress_monitor(self):
        """Monitor scan progress in background"""
        phases = [
            "Initializing scan environment",
            "Loading target configuration", 
            "Starting reconnaissance phase",
            "Subdomain enumeration",
            "Port scanning", 
            "HTTP service discovery",
            "Vulnerability scanning",
            "Generating report",
            "Scan complete"
        ]
        
        phase_idx = 0
        progress = 0
        
        while self.scan_active and phase_idx < len(phases):
            # Update current phase
            self.current_phase = phases[phase_idx]
            self.query_one("#current-phase").update(f"Phase: {self.current_phase}")
            self.query_one("#phase-details").update(f"Executing: {self.current_phase}")
            
            # Simulate phase progress
            for i in range(101):
                if not self.scan_active:
                    break
                    
                # Update progress bars
                overall_progress = (phase_idx * 100 + i) // len(phases)
                self.query_one("#overall-progress").progress = overall_progress
                self.query_one("#phase-progress").progress = i
                
                time.sleep(0.1)
                
            phase_idx += 1
            
        if self.scan_active:
            self.query_one("#scan-status").update("Status: Complete")
            self.query_one("#scan-status").classes = "status-complete"
            self.scan_active = False


class LiveLogsPanel(Static):
    """Live log display during scanning"""
    
    def compose(self):
        yield Label("Live Scan Logs", classes="widget-title")
        
        log_widget = Log(id="scan-logs")
        log_widget.write_line("Bl4ckC3ll PANTHEON - Advanced Security Testing Framework")
        log_widget.write_line("Ready to start security assessment...")
        log_widget.write_line("")
        
        yield log_widget
        
    def add_log_entry(self, message, level="INFO"):
        """Add a new log entry"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_widget = self.query_one("#scan-logs")
        log_widget.write_line(f"[{timestamp}] {level}: {message}")


class ScanRunner(Container):
    """Main scan runner interface"""
    
    def compose(self):
        with Horizontal():
            with Vertical(classes="left-panel"):
                yield ScanConfigPanel()
                yield ScanControlPanel()
                
            with Vertical(classes="right-panel"):
                yield ScanProgressPanel(id="scan-progress")
                
        yield LiveLogsPanel()
        
    def on_mount(self):
        """Initialize scan runner"""
        pass