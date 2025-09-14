"""
Scan Progress Widget for Bl4ckC3ll_PANTHEON TUI
Real-time scanning progress display
"""

from textual.widgets import Static, ProgressBar, Label
from textual.containers import Vertical
from textual.reactive import reactive


class ScanProgress(Static):
    """Real-time scan progress widget"""
    
    progress = reactive(0)
    phase = reactive("Idle")
    status = reactive("Not Started")
    
    def compose(self):
        yield Label("Scan Progress", classes="widget-title")
        
        with Vertical():
            yield Label(self.status, id="scan-status")
            yield Label(self.phase, id="scan-phase")
            yield ProgressBar(total=100, show_percentage=True, id="progress-bar")
            
    def watch_progress(self, progress: int):
        """Update progress bar when progress changes"""
        progress_bar = self.query_one("#progress-bar", ProgressBar)
        progress_bar.progress = progress
        
    def watch_phase(self, phase: str):
        """Update phase display when phase changes"""
        phase_label = self.query_one("#scan-phase", Label)
        phase_label.update(f"Phase: {phase}")
        
    def watch_status(self, status: str):
        """Update status display when status changes"""
        status_label = self.query_one("#scan-status", Label)
        status_label.update(f"Status: {status}")
        
    def start_scan(self):
        """Start scan progress tracking"""
        self.status = "Running"
        self.phase = "Initializing"
        self.progress = 0
        
    def stop_scan(self):
        """Stop scan progress tracking"""
        self.status = "Stopped"
        self.phase = "Idle"
        
    def complete_scan(self):
        """Mark scan as completed"""
        self.status = "Complete"
        self.phase = "Finished"
        self.progress = 100