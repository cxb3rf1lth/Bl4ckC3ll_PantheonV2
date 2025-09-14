"""
Reports Management Screen for Bl4ckC3ll_PANTHEON TUI  
View and manage security assessment reports
"""

from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Static, Button, Label, DataTable, Tree, Select
from textual.widget import Widget
from textual import on
from pathlib import Path
from datetime import datetime
import json


class ReportListPanel(Static):
    """Display available security reports"""
    
    def compose(self):
        yield Label("Available Reports", classes="widget-title")
        
        # Create reports table
        table = DataTable(id="reports-table")
        table.add_columns("Report ID", "Date", "Targets", "Risk Level", "Vulnerabilities")
        
        # Load existing reports
        self.load_reports(table)
        
        yield table
        
        with Horizontal():
            yield Button("View Report", variant="primary", id="btn-view-report")
            yield Button("Export HTML", variant="success", id="btn-export-html")
            yield Button("Export PDF", variant="default", id="btn-export-pdf")
            yield Button("Delete Report", variant="error", id="btn-delete-report")
            
    def load_reports(self, table):
        """Load available reports from runs directory"""
        try:
            runs_dir = Path(__file__).parent.parent.parent / "runs"
            if runs_dir.exists():
                for run_dir in sorted(runs_dir.iterdir(), reverse=True):
                    if run_dir.is_dir():
                        report_file = run_dir / "report" / "report.json"
                        if report_file.exists():
                            try:
                                report_data = json.loads(report_file.read_text())
                                
                                run_id = report_data.get('run_id', run_dir.name)
                                date = report_data.get('timestamp', 'Unknown')
                                targets = str(report_data.get('executive_summary', {}).get('targets_scanned', 0))
                                risk_level = report_data.get('risk_assessment', {}).get('risk_level', 'Unknown')
                                
                                severity_counts = report_data.get('risk_assessment', {}).get('severity_breakdown', {})
                                total_vulns = sum(severity_counts.values())
                                
                                table.add_row(run_id, date, targets, risk_level, str(total_vulns))
                                
                            except Exception:
                                # Skip invalid reports
                                continue
        except Exception as e:
            logging.warning(f"Operation failed: {e}")
            # Consider if this error should be handled differently
    @on(Button.Pressed, "#btn-view-report")
    def view_selected_report(self):
        """View the selected report"""
        table = self.query_one("#reports-table", DataTable)
        if table.cursor_row is not None:
            row = table.get_row(table.cursor_row)
            report_id = row[0]
            
            # Switch to report viewer
            viewer = self.parent.query_one("#report-viewer")
            viewer.load_report(report_id)
            
    @on(Button.Pressed, "#btn-export-html")
    def export_html_report(self):
        """Export selected report as HTML"""
        # Implementation for HTML export
        pass
        
    @on(Button.Pressed, "#btn-export-pdf") 
    def export_pdf_report(self):
        """Export selected report as PDF"""
        # Implementation for PDF export
        pass
        
    @on(Button.Pressed, "#btn-delete-report")
    def delete_selected_report(self):
        """Delete the selected report"""
        table = self.query_one("#reports-table", DataTable)
        if table.cursor_row is not None:
            table.remove_row(table.cursor_row)


class ReportViewer(Static):
    """Display detailed report information"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.current_report = None
        
    def compose(self):
        yield Label("Report Viewer", classes="widget-title")
        
        with Vertical(id="report-content"):
            yield Label("Select a report to view details", classes="placeholder-text")
            
    def load_report(self, report_id):
        """Load and display a specific report"""
        try:
            runs_dir = Path(__file__).parent.parent.parent / "runs"
            report_file = None
            
            # Find the report file
            for run_dir in runs_dir.iterdir():
                if run_dir.is_dir() and (run_dir.name == report_id or report_id in run_dir.name):
                    report_file = run_dir / "report" / "report.json"
                    break
                    
            if not report_file or not report_file.exists():
                self.show_error("Report file not found")
                return
                
            report_data = json.loads(report_file.read_text())
            self.current_report = report_data
            
            # Clear existing content
            content_container = self.query_one("#report-content")
            content_container.remove_children()
            
            # Display report summary
            content_container.mount(Label(f"Report: {report_data.get('run_id', 'Unknown')}", classes="report-title"))
            content_container.mount(Label(f"Generated: {report_data.get('timestamp', 'Unknown')}", classes="report-meta"))
            
            # Executive Summary
            exec_summary = report_data.get('executive_summary', {})
            if exec_summary:
                content_container.mount(Label("Executive Summary", classes="section-title"))
                content_container.mount(Label(f"Targets Scanned: {exec_summary.get('targets_scanned', 0)}"))
                content_container.mount(Label(f"Subdomains Found: {exec_summary.get('subdomains_discovered', 0)}"))
                content_container.mount(Label(f"Open Ports: {exec_summary.get('open_ports_found', 0)}"))
                content_container.mount(Label(f"HTTP Services: {exec_summary.get('http_services_identified', 0)}"))
                
            # Risk Assessment
            risk_assessment = report_data.get('risk_assessment', {})
            if risk_assessment:
                content_container.mount(Label("Risk Assessment", classes="section-title"))
                content_container.mount(Label(f"Overall Risk Level: {risk_assessment.get('risk_level', 'Unknown')}"))
                
                severity_counts = risk_assessment.get('severity_breakdown', {})
                if severity_counts:
                    content_container.mount(Label("Vulnerability Breakdown:", classes="subsection-title"))
                    for severity, count in severity_counts.items():
                        if count > 0:
                            content_container.mount(Label(f"  {severity.title()}: {count}"))
                            
            # Key Findings
            key_findings = exec_summary.get('key_findings', [])
            if key_findings:
                content_container.mount(Label("Key Findings", classes="section-title"))
                for finding in key_findings[:10]:  # Show top 10
                    content_container.mount(Label(f"• {finding}"))
                    
        except Exception as e:
            self.show_error(f"Error loading report: {e}")
            
    def show_error(self, message):
        """Show error message in viewer"""
        content_container = self.query_one("#report-content")
        content_container.remove_children()
        content_container.mount(Label(f"Error: {message}", classes="error-text"))


class ReportFiltersPanel(Static):
    """Filter and search reports"""
    
    def compose(self):
        yield Label("Report Filters", classes="widget-title")
        
        with Vertical():
            yield Label("Filter by Risk Level:", classes="form-label")
            yield Select([
                ("All Levels", "all"),
                ("Critical", "critical"),
                ("High", "high"), 
                ("Medium", "medium"),
                ("Low", "low"),
                ("Informational", "informational")
            ], id="risk-filter")
            
            yield Label("Filter by Date Range:", classes="form-label")
            yield Select([
                ("All Time", "all"),
                ("Last 24 Hours", "24h"),
                ("Last Week", "week"),
                ("Last Month", "month"),
                ("Last Year", "year")
            ], id="date-filter")
            
            yield Label("Sort Order:", classes="form-label")
            yield Select([
                ("Newest First", "newest"),
                ("Oldest First", "oldest"),
                ("Risk Level", "risk"),
                ("Target Count", "targets")
            ], id="sort-order")
            
            with Horizontal():
                yield Button("Apply Filters", variant="primary", id="btn-apply-filters")
                yield Button("Reset", variant="default", id="btn-reset-filters")
                
    @on(Button.Pressed, "#btn-apply-filters")
    def apply_filters(self):
        """Apply selected filters to report list"""
        # Implementation for filtering reports
        pass
        
    @on(Button.Pressed, "#btn-reset-filters")
    def reset_filters(self):
        """Reset all filters to default"""
        # Reset all select widgets to default values
        pass


class ReportsScreen(Container):
    """Main reports management screen"""
    
    def compose(self):
        with Horizontal():
            with Vertical(classes="left-panel"):
                yield ReportListPanel()
                yield ReportFiltersPanel()
                
            yield ReportViewer(id="report-viewer", classes="right-panel")
            
    def on_mount(self):
        """Initialize reports screen"""
        pass