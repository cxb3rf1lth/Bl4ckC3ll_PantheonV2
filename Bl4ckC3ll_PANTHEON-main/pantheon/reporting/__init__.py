#!/usr/bin/env python3
"""
Enhanced Reporting Module for Bl4ckC3ll_PANTHEON
Advanced reporting capabilities with multiple formats
"""

import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

logger = logging.getLogger(__name__)

class EnhancedReporter:
    """Enhanced reporting with multiple output formats"""
    
    def __init__(self):
        self.supported_formats = ['json', 'html', 'csv']
        
    def generate_comprehensive_report(self, scan_results: Dict[str, Any], 
                                    output_dir: Path, formats: List[str] = None) -> Dict[str, Any]:
        """Generate comprehensive security report in multiple formats"""
        if formats is None:
            formats = ['json', 'html']
            
        report = {
            'metadata': {
                'report_id': f"pantheon_{int(time.time())}",
                'generated_at': time.time(),
                'version': '2.0.0',
                'formats': formats
            },
            'summary': self._generate_summary(scan_results),
            'findings': self._organize_findings(scan_results),
            'files_generated': []
        }
        
        # Generate reports in requested formats
        for fmt in formats:
            if fmt in self.supported_formats:
                file_path = self._generate_format(report, output_dir, fmt)
                if file_path:
                    report['files_generated'].append(str(file_path))
        
        return report
    
    def _generate_summary(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary"""
        summary = {
            'total_targets': 0,
            'vulnerabilities_found': 0,
            'severity_breakdown': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        }
        
        # Extract summary from various scan result formats
        if 'vulnerabilities' in scan_results:
            summary['vulnerabilities_found'] = len(scan_results['vulnerabilities'])
            
            for vuln in scan_results['vulnerabilities']:
                severity = vuln.get('severity', 'info').lower()
                if severity in summary['severity_breakdown']:
                    summary['severity_breakdown'][severity] += 1
        
        return summary
    
    def _organize_findings(self, scan_results: Dict[str, Any]) -> Dict[str, List]:
        """Organize findings by category"""
        findings = {
            'web_vulnerabilities': [],
            'container_issues': [],
            'api_security_issues': [],
            'cloud_misconfigurations': []
        }
        
        # Organize web vulnerabilities
        if 'vulnerabilities' in scan_results:
            findings['web_vulnerabilities'] = scan_results['vulnerabilities']
        
        return findings
    
    def _generate_format(self, report: Dict[str, Any], output_dir: Path, format_type: str) -> Optional[Path]:
        """Generate report in specific format"""
        try:
            if format_type == 'json':
                return self._generate_json_report(report, output_dir)
            elif format_type == 'html':
                return self._generate_html_report(report, output_dir)
            elif format_type == 'csv':
                return self._generate_csv_report(report, output_dir)
        except Exception as e:
            logger.error(f"Failed to generate {format_type} report: {e}")
        
        return None
    
    def _generate_json_report(self, report: Dict[str, Any], output_dir: Path) -> Path:
        """Generate JSON report"""
        file_path = output_dir / 'security-report.json'
        with open(file_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        return file_path
    
    def _generate_html_report(self, report: Dict[str, Any], output_dir: Path) -> Path:
        """Generate HTML report"""
        file_path = output_dir / 'security-report.html'
        
        html_content = f'''<!DOCTYPE html>
<html>
<head>
    <title>Bl4ckC3ll PANTHEON Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .critical {{ color: #e74c3c; font-weight: bold; }}
        .high {{ color: #f39c12; font-weight: bold; }}
        .medium {{ color: #f1c40f; }}
        .low {{ color: #27ae60; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Bl4ckC3ll PANTHEON Security Report</h1>
        <p>Generated: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(report['metadata']['generated_at']))}</p>
        <p>Report ID: {report['metadata']['report_id']}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Total Vulnerabilities:</strong> {report['summary']['vulnerabilities_found']}</p>
        <p><strong>Critical:</strong> <span class="critical">{report['summary']['severity_breakdown']['critical']}</span></p>
        <p><strong>High:</strong> <span class="high">{report['summary']['severity_breakdown']['high']}</span></p>
        <p><strong>Medium:</strong> <span class="medium">{report['summary']['severity_breakdown']['medium']}</span></p>
        <p><strong>Low:</strong> <span class="low">{report['summary']['severity_breakdown']['low']}</span></p>
    </div>
    
    <h2>Detailed Findings</h2>
    <p>Please see JSON report for detailed findings.</p>
    
    <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666;">
        <p>Generated by Bl4ckC3ll PANTHEON v{report['metadata']['version']}</p>
    </footer>
</body>
</html>'''
        
        with open(file_path, 'w') as f:
            f.write(html_content)
        
        return file_path
    
    def _generate_csv_report(self, report: Dict[str, Any], output_dir: Path) -> Path:
        """Generate CSV report"""
        file_path = output_dir / 'security-report.csv'
        
        # Simple CSV with vulnerability data
        csv_content = "Category,Severity,Title,Description\\n"
        
        for category, items in report['findings'].items():
            for item in items:
                severity = item.get('severity', 'info')
                title = item.get('title', item.get('type', 'Unknown')).replace(',', ';')
                description = item.get('description', '').replace(',', ';').replace('\\n', ' ')[:100]
                
                csv_content += f"{category},{severity},{title},{description}\\n"
        
        with open(file_path, 'w') as f:
            f.write(csv_content)
        
        return file_path

def generate_security_report(scan_results: Dict[str, Any], output_dir: Path, 
                           formats: List[str] = None) -> Dict[str, Any]:
    """Generate comprehensive security report"""
    reporter = EnhancedReporter()
    return reporter.generate_comprehensive_report(scan_results, output_dir, formats)

__all__ = ['EnhancedReporter', 'generate_security_report']