"""
Backend Integration for Bl4ckC3ll_PANTHEON TUI
Connects TUI interface with existing scanning functions
"""

import sys
import os
from pathlib import Path
import json
import threading
import subprocess
import time
import logging
from datetime import datetime

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

# Import main application functions
try:
    from bl4ckc3ll_p4nth30n import (
        load_cfg, env_with_lists, new_run, stage_recon, 
        stage_vuln_scan, stage_report, logger
    )
    BACKEND_AVAILABLE = True
except ImportError:
    BACKEND_AVAILABLE = False


class ScanManager:
    """Manages scan operations and provides status updates"""
    
    def __init__(self):
        self.current_scan = None
        self.scan_thread = None
        self.scan_active = False
        self.scan_progress = 0
        self.scan_phase = "Idle"
        self.scan_status = "Not Started"
        self.progress_callback = None
        
    def set_progress_callback(self, callback):
        """Set callback function for progress updates"""
        self.progress_callback = callback
        
    def update_progress(self, progress, phase=None, status=None):
        """Update scan progress and notify callback"""
        self.scan_progress = progress
        if phase:
            self.scan_phase = phase
        if status:
            self.scan_status = status
            
        if self.progress_callback:
            self.progress_callback(self.scan_progress, self.scan_phase, self.scan_status)
            
    def start_full_scan(self, targets=None):
        """Start a full security scan"""
        if not BACKEND_AVAILABLE:
            self.update_progress(0, "Error", "Backend not available")
            return False
            
        if self.scan_active:
            return False
            
        self.scan_active = True
        self.scan_thread = threading.Thread(
            target=self._run_full_scan,
            args=(targets,),
            daemon=True
        )
        self.scan_thread.start()
        return True
        
    def start_recon_scan(self, targets=None):
        """Start reconnaissance only"""
        if not BACKEND_AVAILABLE:
            self.update_progress(0, "Error", "Backend not available")
            return False
            
        if self.scan_active:
            return False
            
        self.scan_active = True
        self.scan_thread = threading.Thread(
            target=self._run_recon_scan,
            args=(targets,),
            daemon=True
        )
        self.scan_thread.start()
        return True
        
    def start_vuln_scan(self, targets=None):
        """Start vulnerability scan only"""
        if not BACKEND_AVAILABLE:
            self.update_progress(0, "Error", "Backend not available")
            return False
            
        if self.scan_active:
            return False
            
        self.scan_active = True
        self.scan_thread = threading.Thread(
            target=self._run_vuln_scan,
            args=(targets,),
            daemon=True
        )
        self.scan_thread.start()
        return True
        
    def stop_scan(self):
        """Stop the current scan"""
        if self.scan_active:
            self.scan_active = False
            self.update_progress(0, "Stopped", "Scan stopped by user")
            
    def _run_full_scan(self, targets):
        """Run full scan in background thread"""
        try:
            self.update_progress(5, "Initializing", "Starting full scan")
            
            # Load configuration
            cfg = load_cfg()
            env = env_with_lists()
            rd = new_run()
            
            self.current_scan = rd
            
            self.update_progress(10, "Environment Setup", "Environment configured")
            
            # Phase 1: Reconnaissance
            if self.scan_active:
                self.update_progress(20, "Reconnaissance", "Starting reconnaissance phase")
                stage_recon(rd, env, cfg)
                
            # Phase 2: Vulnerability Scanning  
            if self.scan_active:
                self.update_progress(60, "Vulnerability Scanning", "Scanning for vulnerabilities")
                stage_vuln_scan(rd, env, cfg)
                
            # Phase 3: Report Generation
            if self.scan_active:
                self.update_progress(90, "Report Generation", "Generating security report")
                stage_report(rd, env, cfg)
                
            if self.scan_active:
                self.update_progress(100, "Complete", "Full scan completed successfully")
                
        except Exception as e:
            self.update_progress(0, "Error", f"Scan failed: {str(e)}")
        finally:
            self.scan_active = False
            
    def _run_recon_scan(self, targets):
        """Run reconnaissance scan in background thread"""
        try:
            self.update_progress(5, "Initializing", "Starting reconnaissance")
            
            cfg = load_cfg()
            env = env_with_lists()
            rd = new_run()
            
            self.current_scan = rd
            
            if self.scan_active:
                self.update_progress(20, "Reconnaissance", "Performing reconnaissance")
                stage_recon(rd, env, cfg)
                
            if self.scan_active:
                self.update_progress(100, "Complete", "Reconnaissance completed")
                
        except Exception as e:
            self.update_progress(0, "Error", f"Reconnaissance failed: {str(e)}")
        finally:
            self.scan_active = False
            
    def _run_vuln_scan(self, targets):
        """Run vulnerability scan in background thread"""
        try:
            self.update_progress(5, "Initializing", "Starting vulnerability scan")
            
            cfg = load_cfg()
            env = env_with_lists()
            rd = new_run()
            
            self.current_scan = rd
            
            if self.scan_active:
                self.update_progress(20, "Vulnerability Scanning", "Scanning for vulnerabilities")
                stage_vuln_scan(rd, env, cfg)
                
            if self.scan_active:
                self.update_progress(100, "Complete", "Vulnerability scan completed")
                
        except Exception as e:
            self.update_progress(0, "Error", f"Vulnerability scan failed: {str(e)}")
        finally:
            self.scan_active = False
            

class ConfigManager:
    """Manages configuration operations for the TUI"""
    
    @staticmethod
    def load_config():
        """Load current configuration"""
        if BACKEND_AVAILABLE:
            return load_cfg()
        else:
            # Fallback configuration
            config_file = Path(__file__).parent.parent / "p4nth30n.cfg.json"
            if config_file.exists():
                with open(config_file) as f:
                    return json.load(f)
        return {}
        
    @staticmethod
    def save_config(config_data):
        """Save configuration to file"""
        try:
            config_file = Path(__file__).parent.parent / "p4nth30n.cfg.json"
            with open(config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
            return True
        except Exception:
            return False
            

class TargetManager:
    """Manages target operations for the TUI"""
    
    @staticmethod
    def load_targets():
        """Load targets from file"""
        try:
            targets_file = Path(__file__).parent.parent / "targets.txt"
            if targets_file.exists():
                content = targets_file.read_text().strip()
                if content:
                    return [line.strip() for line in content.split('\n') if line.strip()]
        except Exception as e:
            logging.warning(f"Failed to load targets: {e}")
        return []
        
    @staticmethod
    def save_targets(targets_list):
        """Save targets to file"""
        try:
            targets_file = Path(__file__).parent.parent / "targets.txt"
            targets_file.write_text('\n'.join(targets_list))
            return True
        except Exception:
            return False
            

class ReportManager:
    """Manages report operations for the TUI"""
    
    @staticmethod
    def get_available_reports():
        """Get list of available reports"""
        reports = []
        try:
            runs_dir = Path(__file__).parent.parent / "runs"
            if runs_dir.exists():
                for run_dir in sorted(runs_dir.iterdir(), reverse=True):
                    if run_dir.is_dir():
                        report_file = run_dir / "report" / "report.json"
                        if report_file.exists():
                            try:
                                report_data = json.loads(report_file.read_text())
                                reports.append({
                                    'id': run_dir.name,
                                    'path': run_dir,
                                    'data': report_data
                                })
                            except Exception:
                                continue
        except Exception as e:
            logging.warning(f"Failed to get available reports: {e}")
        return reports
        
    @staticmethod
    def load_report(report_id):
        """Load a specific report"""
        try:
            runs_dir = Path(__file__).parent.parent / "runs"
            for run_dir in runs_dir.iterdir():
                if run_dir.is_dir() and (run_dir.name == report_id or report_id in run_dir.name):
                    report_file = run_dir / "report" / "report.json"
                    if report_file.exists():
                        return json.loads(report_file.read_text())
        except Exception as e:
            logging.warning(f"Failed to load report: {e}")
        return None


# Global instances
scan_manager = ScanManager()
config_manager = ConfigManager()  
target_manager = TargetManager()
report_manager = ReportManager()