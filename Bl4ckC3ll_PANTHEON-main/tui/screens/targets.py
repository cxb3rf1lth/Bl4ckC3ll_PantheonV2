"""
Targets Management Screen for Bl4ckC3ll_PANTHEON TUI
Interactive target management with validation
"""

from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Static, Button, Label, Input, DataTable, TextArea
from textual.widget import Widget
from textual import on
from pathlib import Path
import re
import logging


class TargetInputPanel(Static):
    """Target input and validation panel"""
    
    def compose(self):
        yield Label("Target Management", classes="widget-title")
        
        with Vertical():
            yield Label("Add Single Target:", classes="form-label")
            with Horizontal():
                yield Input(placeholder="domain.com or 192.168.1.1", id="single-target")
                yield Button("Add", variant="primary", id="btn-add-target")
                
            yield Label("Bulk Import:", classes="form-label")
            yield TextArea(placeholder="Enter multiple targets, one per line", id="bulk-targets")
            with Horizontal():
                yield Button("Import Targets", variant="success", id="btn-import-targets")
                yield Button("Load from File", variant="default", id="btn-load-file")
                
            yield Label("Target Validation:", classes="form-label")
            yield Static("", id="validation-status")
            
    @on(Button.Pressed, "#btn-add-target")
    def add_single_target(self):
        """Add a single target"""
        target_input = self.query_one("#single-target", Input)
        target = target_input.value.strip()
        
        if self.validate_target(target):
            # Query from the screen root instead of parent
            try:
                target_list = self.screen.query_one("#target-list", DataTable)
                target_list.add_row(target, "Valid", "Active", "Not Scanned")
                target_input.value = ""
                self.query_one("#validation-status").update(f"Added target: {target}")
            except Exception as e:
                self.query_one("#validation-status").update(f"Error adding target: {str(e)}")
        else:
            self.query_one("#validation-status").update(f"Invalid target: {target}")
            
    @on(Button.Pressed, "#btn-import-targets")
    def import_bulk_targets(self):
        """Import multiple targets from text area"""
        bulk_input = self.query_one("#bulk-targets", TextArea)
        targets = [line.strip() for line in bulk_input.text.split('\n') if line.strip()]
        
        valid_count = 0
        invalid_count = 0
        
        try:
            target_list = self.screen.query_one("#target-list", DataTable)
            
            for target in targets:
                if self.validate_target(target):
                    target_list.add_row(target, "Valid", "Active", "Not Scanned")
                    valid_count += 1
                else:
                    invalid_count += 1
                    
            bulk_input.text = ""
            self.query_one("#validation-status").update(
                f"Imported {valid_count} valid targets, {invalid_count} invalid"
            )
        except Exception as e:
            self.query_one("#validation-status").update(f"Error importing targets: {str(e)}")
        
    def validate_target(self, target):
        """Validate target format (domain or IP)"""
        # Basic domain regex
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        )
        
        # Basic IP regex  
        ip_pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )
        
        return bool(domain_pattern.match(target)) or bool(ip_pattern.match(target))


class TargetListPanel(Static):
    """Display and manage current targets"""
    
    def compose(self):
        yield Label("Current Targets", classes="widget-title")
        
        # Create targets table
        table = DataTable(id="target-list")
        table.add_columns("Target", "Status", "State", "Last Scan")
        
        # Load existing targets if any
        self.load_existing_targets(table)
        
        yield table
        
        with Horizontal():
            yield Button("Remove Selected", variant="error", id="btn-remove-target")
            yield Button("Clear All", variant="error", id="btn-clear-all")
            yield Button("Export List", variant="default", id="btn-export-list") 
            yield Button("Refresh Status", variant="default", id="btn-refresh-status")
            
    def load_existing_targets(self, table):
        """Load targets from targets.txt file"""
        try:
            targets_file = Path(__file__).parent.parent.parent / "targets.txt"
            if targets_file.exists():
                content = targets_file.read_text().strip()
                if content:
                    for target in content.split('\n'):
                        target = target.strip()
                        if target:
                            table.add_row(target, "Valid", "Active", "Not Scanned")
        except Exception as e:
            logging.warning(f"Failed to load existing targets: {e}")
            
    @on(Button.Pressed, "#btn-remove-target")
    def remove_selected_target(self):
        """Remove selected target from list"""
        table = self.query_one("#target-list", DataTable)
        if table.cursor_row is not None:
            table.remove_row(table.cursor_row)
            
    @on(Button.Pressed, "#btn-clear-all")
    def clear_all_targets(self):
        """Clear all targets from list"""
        table = self.query_one("#target-list", DataTable)
        table.clear()
        
    @on(Button.Pressed, "#btn-export-list") 
    def export_target_list(self):
        """Export targets to file"""
        table = self.query_one("#target-list", DataTable)
        targets = []
        for row_key in table.rows:
            row = table.get_row(row_key)
            targets.append(row[0])  # First column is target
            
        try:
            targets_file = Path(__file__).parent.parent.parent / "targets.txt"
            targets_file.write_text('\n'.join(targets))
            # Show confirmation somehow - could add a status message
            logging.info(f"Exported {len(targets)} targets to {targets_file}")
        except Exception as e:
            logging.warning(f"Failed to export targets: {e}")
            
    @on(Button.Pressed, "#btn-refresh-status")
    def refresh_target_status(self):
        """Refresh target validation status"""
        # Re-validate all targets and update status
        table = self.query_one("#target-list", DataTable)
        # Implementation could be added to re-validate targets
        pass


class TargetStatsPanel(Static):
    """Display target statistics and information"""
    
    def compose(self):
        yield Label("Target Statistics", classes="widget-title")
        
        with Vertical():
            yield Label("Total Targets: 0", id="total-targets")
            yield Label("Valid Targets: 0", id="valid-targets")
            yield Label("Invalid Targets: 0", id="invalid-targets")
            yield Label("Scanned Targets: 0", id="scanned-targets")
            yield Label("Active Scans: 0", id="active-scans")
            
            yield Label("Target Types:", classes="form-label")
            yield Label("  Domains: 0", id="domain-count")
            yield Label("  IP Addresses: 0", id="ip-count")
            yield Label("  IP Ranges: 0", id="range-count")
            
    def update_stats(self):
        """Update statistics display"""
        # This would calculate stats from the target list
        pass


class TargetsScreen(Container):
    """Main targets management screen"""
    
    def compose(self):
        with Horizontal():
            with Vertical(classes="left-panel"):
                yield TargetInputPanel()
                yield TargetStatsPanel()
                
            yield TargetListPanel(classes="right-panel")
            
    def on_mount(self):
        """Initialize targets screen"""
        pass