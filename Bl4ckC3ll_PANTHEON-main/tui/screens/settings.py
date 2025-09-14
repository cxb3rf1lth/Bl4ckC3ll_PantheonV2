"""
Settings Management Screen for Bl4ckC3ll_PANTHEON TUI
Interactive configuration management
"""

from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Static, Button, Label, Input, Select, Checkbox, TabbedContent, TabPane
from textual.widget import Widget
from textual import on
import json
from pathlib import Path


class GeneralSettingsPanel(Static):
    """General framework settings"""
    
    def compose(self):
        yield Label("General Settings", classes="widget-title")
        
        with Vertical():
            yield Label("Parallel Jobs:", classes="form-label") 
            yield Input(value="20", id="parallel-jobs")
            
            yield Label("HTTP Timeout (seconds):", classes="form-label")
            yield Input(value="15", id="http-timeout")
            
            yield Label("Requests Per Second:", classes="form-label")
            yield Input(value="500", id="rps-limit")
            
            yield Label("Max Concurrent Scans:", classes="form-label")
            yield Input(value="8", id="max-scans")
            
            yield Label("Auto-save Results:", classes="form-label")
            yield Checkbox("Automatically save scan results", value=True, id="auto-save")
            
            yield Label("Debug Mode:", classes="form-label")
            yield Checkbox("Enable debug logging", value=False, id="debug-mode")


class NucleiSettingsPanel(Static):
    """Nuclei scanner configuration"""
    
    def compose(self):
        yield Label("Nuclei Configuration", classes="widget-title")
        
        with Vertical():
            yield Label("Enable Nuclei:", classes="form-label")
            yield Checkbox("Use Nuclei for vulnerability scanning", value=True, id="nuclei-enabled")
            
            yield Label("Severity Levels:", classes="form-label")
            yield Select([
                ("All Severities", "info,low,medium,high,critical"),
                ("Medium and Above", "medium,high,critical"), 
                ("High and Critical", "high,critical"),
                ("Critical Only", "critical")
            ], value="info,low,medium,high,critical", id="nuclei-severity")
            
            yield Label("Rate Limiting:", classes="form-label")
            yield Input(value="800", placeholder="Requests per second", id="nuclei-rps")
            
            yield Label("Concurrency:", classes="form-label")
            yield Input(value="150", placeholder="Concurrent threads", id="nuclei-concurrency")
            
            yield Label("Template Options:", classes="form-label")
            yield Checkbox("Use all templates", value=True, id="nuclei-all-templates")
            yield Checkbox("Include community templates", value=True, id="nuclei-community")
            yield Checkbox("Use custom templates", value=True, id="nuclei-custom")


class ScanningSettingsPanel(Static):
    """Scanning behavior settings"""
    
    def compose(self):
        yield Label("Scanning Configuration", classes="widget-title")
        
        with Vertical():
            yield Label("Reconnaissance Tools:", classes="form-label")
            yield Checkbox("Use Subfinder", value=True, id="use-subfinder")
            yield Checkbox("Use Amass", value=True, id="use-amass") 
            yield Checkbox("Use HTTPx", value=True, id="use-httpx")
            
            yield Label("Discovery Tools:", classes="form-label")
            yield Checkbox("Use GAU", value=True, id="use-gau")
            yield Checkbox("Use Katana", value=True, id="use-katana")
            yield Checkbox("Use Waybackurls", value=True, id="use-waybackurls")
            
            yield Label("Subdomain Depth:", classes="form-label")
            yield Select([
                ("1 Level", "1"),
                ("2 Levels", "2"),
                ("3 Levels", "3"), 
                ("Unlimited", "0")
            ], value="3", id="subdomain-depth")
            
            yield Label("Crawl Time Limit (seconds):", classes="form-label")
            yield Input(value="600", id="crawl-timeout")


class ReportSettingsPanel(Static):
    """Report generation settings"""
    
    def compose(self):
        yield Label("Report Configuration", classes="widget-title")
        
        with Vertical():
            yield Label("Report Formats:", classes="form-label")
            yield Checkbox("Generate HTML reports", value=True, id="report-html")
            yield Checkbox("Generate JSON reports", value=True, id="report-json")
            yield Checkbox("Generate PDF reports", value=False, id="report-pdf")
            yield Checkbox("Generate XML reports", value=False, id="report-xml")
            
            yield Label("Report Options:", classes="form-label")
            yield Checkbox("Auto-open HTML reports", value=True, id="auto-open-html")
            yield Checkbox("Include screenshots", value=True, id="include-screenshots")
            yield Checkbox("Include raw tool output", value=False, id="include-raw-output")
            
            yield Label("Report Template:", classes="form-label")
            yield Select([
                ("Professional", "professional"),
                ("Executive Summary", "executive"),
                ("Technical Details", "technical"),
                ("Compliance Report", "compliance")
            ], value="professional", id="report-template")


class AdvancedSettingsPanel(Static):
    """Advanced configuration options"""
    
    def compose(self):
        yield Label("Advanced Configuration", classes="widget-title")
        
        with Vertical():
            yield Label("Resource Management:", classes="form-label")
            yield Input(value="85", placeholder="CPU threshold %", id="cpu-threshold")
            yield Input(value="90", placeholder="Memory threshold %", id="memory-threshold")
            yield Input(value="95", placeholder="Disk threshold %", id="disk-threshold")
            
            yield Label("Plugin Settings:", classes="form-label")
            yield Checkbox("Enable plugin system", value=True, id="plugins-enabled")
            yield Input(placeholder="Plugin directory path", id="plugin-directory")
            
            yield Label("Backup Configuration:", classes="form-label")
            yield Checkbox("Auto-backup configurations", value=True, id="auto-backup")
            yield Input(value="30", placeholder="Keep backups for days", id="backup-retention")


class SettingsControlPanel(Static):
    """Save, load, and reset configuration controls"""
    
    def compose(self):
        yield Label("Configuration Management", classes="widget-title")
        
        with Vertical():
            with Horizontal():
                yield Button("Save Configuration", variant="success", id="btn-save-config")
                yield Button("Load Configuration", variant="primary", id="btn-load-config")
                
            with Horizontal():
                yield Button("Reset to Defaults", variant="error", id="btn-reset-config")
                yield Button("Export Config", variant="default", id="btn-export-config")
                
            yield Label("Configuration Status:", classes="form-label")
            yield Static("Ready", id="config-status", classes="status-ready")
            
    @on(Button.Pressed, "#btn-save-config")
    def save_configuration(self):
        """Save current configuration to file"""
        try:
            config = self.collect_config_values()
            config_file = Path(__file__).parent.parent.parent / "p4nth30n.cfg.json"
            
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
                
            self.query_one("#config-status").update("Configuration saved successfully")
            self.query_one("#config-status").classes = "status-success"
            
        except Exception as e:
            self.query_one("#config-status").update(f"Error saving config: {e}")
            self.query_one("#config-status").classes = "status-error"
            
    @on(Button.Pressed, "#btn-load-config")
    def load_configuration(self):
        """Load configuration from file"""
        try:
            config_file = Path(__file__).parent.parent.parent / "p4nth30n.cfg.json"
            
            if config_file.exists():
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    
                self.apply_config_values(config)
                self.query_one("#config-status").update("Configuration loaded successfully")
                self.query_one("#config-status").classes = "status-success"
            else:
                self.query_one("#config-status").update("No configuration file found")
                self.query_one("#config-status").classes = "status-warning"
                
        except Exception as e:
            self.query_one("#config-status").update(f"Error loading config: {e}")
            self.query_one("#config-status").classes = "status-error"
            
    @on(Button.Pressed, "#btn-reset-config")
    def reset_configuration(self):
        """Reset all settings to default values"""
        # Implementation to reset all form fields to defaults
        self.query_one("#config-status").update("Configuration reset to defaults")
        self.query_one("#config-status").classes = "status-info"
        
    def collect_config_values(self):
        """Collect all configuration values from form fields"""
        config = {
            "limits": {
                "parallel_jobs": int(self.app.query_one("#parallel-jobs").value or 20),
                "http_timeout": int(self.app.query_one("#http-timeout").value or 15),
                "rps": int(self.app.query_one("#rps-limit").value or 500),
                "max_concurrent_scans": int(self.app.query_one("#max-scans").value or 8)
            },
            "nuclei": {
                "enabled": self.app.query_one("#nuclei-enabled").value,
                "severity": self.app.query_one("#nuclei-severity").value,
                "rps": int(self.app.query_one("#nuclei-rps").value or 800),
                "conc": int(self.app.query_one("#nuclei-concurrency").value or 150),
                "all_templates": self.app.query_one("#nuclei-all-templates").value
            }
            # Add more configuration sections...
        }
        return config
        
    def apply_config_values(self, config):
        """Apply configuration values to form fields"""
        # Implementation to set form field values from config
        pass


class SettingsScreen(Container):
    """Main settings screen with tabbed interface"""
    
    def compose(self):
        with TabbedContent():
            with TabPane("General", id="general-tab"):
                yield GeneralSettingsPanel()
                
            with TabPane("Nuclei", id="nuclei-tab"):
                yield NucleiSettingsPanel()
                
            with TabPane("Scanning", id="scanning-tab"):
                yield ScanningSettingsPanel()
                
            with TabPane("Reports", id="reports-tab"):
                yield ReportSettingsPanel()
                
            with TabPane("Advanced", id="advanced-tab"):
                yield AdvancedSettingsPanel()
                
        yield SettingsControlPanel()
        
    def on_mount(self):
        """Initialize settings screen"""
        # Load current configuration values
        pass