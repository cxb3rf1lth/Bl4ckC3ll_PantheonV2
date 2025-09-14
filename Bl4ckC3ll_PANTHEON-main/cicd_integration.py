#!/usr/bin/env python3
"""
CI/CD Integration Script for Bl4ckC3ll_PANTHEON
Provides automated security scanning capabilities for continuous integration
"""

import os
import sys
import json
import argparse
import subprocess
import time
from pathlib import Path
from typing import Dict, Any, List

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

def main():
    parser = argparse.ArgumentParser(description="CI/CD Security Scanner")
    parser.add_argument("--target", required=True, help="Target to scan")
    parser.add_argument("--scan-type", choices=["quick", "full", "api-only", "cloud-only"], 
                       default="quick", help="Type of scan to perform")
    parser.add_argument("--output-format", choices=["json", "sarif", "junit"], 
                       default="json", help="Output format")
    parser.add_argument("--output-file", help="Output file path")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], 
                       default="high", help="Fail CI on this severity or higher")
    parser.add_argument("--timeout", type=int, default=1800, help="Scan timeout in seconds")
    parser.add_argument("--config-file", help="Custom configuration file")
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = CICDScanner(
        target=args.target,
        scan_type=args.scan_type,
        output_format=args.output_format,
        output_file=args.output_file,
        fail_threshold=args.fail_on,
        timeout=args.timeout,
        config_file=args.config_file
    )
    
    # Run scan
    exit_code = scanner.run()
    sys.exit(exit_code)

class CICDScanner:
    def __init__(self, target: str, scan_type: str, output_format: str, 
                 output_file: str = None, fail_threshold: str = "high", 
                 timeout: int = 1800, config_file: str = None):
        self.target = target
        self.scan_type = scan_type
        self.output_format = output_format
        self.output_file = output_file or f"scan_results_{int(time.time())}.{output_format}"
        self.fail_threshold = fail_threshold
        self.timeout = timeout
        self.config_file = config_file
        self.start_time = time.time()
        
        # Severity levels for comparison
        self.severity_levels = {
            "info": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4
        }
        
        self.fail_level = self.severity_levels.get(fail_threshold, 3)
        
    def run(self) -> int:
        """Run the security scan and return exit code"""
        try:
            print(f"[CI/CD] Starting {self.scan_type} scan for {self.target}")
            print(f"[CI/CD] Output format: {self.output_format}")
            print(f"[CI/CD] Fail threshold: {self.fail_threshold}")
            
            # Prepare target file
            self._prepare_target_file()
            
            # Run scan based on type
            if self.scan_type == "quick":
                result = self._run_quick_scan()
            elif self.scan_type == "full":
                result = self._run_full_scan()
            elif self.scan_type == "api-only":
                result = self._run_api_scan()
            elif self.scan_type == "cloud-only":
                result = self._run_cloud_scan()
            else:
                raise ValueError(f"Unknown scan type: {self.scan_type}")
            
            # Process results
            exit_code = self._process_results(result)
            
            # Generate output
            self._generate_output(result)
            
            print(f"[CI/CD] Scan completed in {time.time() - self.start_time:.1f}s")
            print(f"[CI/CD] Results saved to: {self.output_file}")
            
            return exit_code
            
        except Exception as e:
            print(f"[CI/CD] ERROR: {e}")
            return 2  # Error exit code
    
    def _prepare_target_file(self):
        """Prepare targets.txt file with the target"""
        targets_file = Path(__file__).parent / "targets.txt"
        
        # Backup existing targets
        if targets_file.exists():
            backup_file = Path(__file__).parent / f"targets.txt.backup.{int(time.time())}"
            targets_file.rename(backup_file)
        
        # Write new target
        with open(targets_file, 'w') as f:
            f.write(f"{self.target}\n")
    
    def _run_quick_scan(self) -> Dict[str, Any]:
        """Run a quick security scan (recon + basic vuln scan)"""
        try:
            # Import the main scanner
            import bl4ckc3ll_p4nth30n as scanner
            
            # Load configuration
            cfg = scanner.load_cfg()
            
            # Override config for quick scan
            cfg["nuclei"]["severity"] = "medium,high,critical"
            cfg["limits"]["max_concurrent_scans"] = 4
            cfg["advanced_scanning"]["api_discovery"] = True
            cfg["advanced_scanning"]["security_headers"] = True
            cfg["advanced_scanning"]["cors_analysis"] = True
            
            # Disable slower scans for quick mode
            cfg["advanced_scanning"]["threat_intelligence"] = False
            cfg["advanced_scanning"]["compliance_checks"] = False
            cfg["ml_analysis"]["enabled"] = False
            
            # Create run directory
            run_dir = scanner.new_run()
            env = scanner.env_with_lists()
            
            # Run stages
            scanner.stage_recon(run_dir, env, cfg)
            scanner.stage_vuln_scan(run_dir, env, cfg)
            
            # Collect results
            return self._collect_scan_results(run_dir)
            
        except Exception as e:
            raise Exception(f"Quick scan failed: {e}")
    
    def _run_full_scan(self) -> Dict[str, Any]:
        """Run a comprehensive security scan"""
        try:
            # Import the main scanner
            import bl4ckc3ll_p4nth30n as scanner
            
            # Load configuration
            cfg = scanner.load_cfg()
            
            # Enable all scanning features
            cfg["advanced_scanning"]["api_discovery"] = True
            cfg["advanced_scanning"]["graphql_testing"] = True
            cfg["advanced_scanning"]["jwt_analysis"] = True
            cfg["advanced_scanning"]["cloud_storage_buckets"] = True
            cfg["advanced_scanning"]["threat_intelligence"] = True
            cfg["advanced_scanning"]["compliance_checks"] = True
            cfg["ml_analysis"]["enabled"] = True
            
            # Create run directory
            run_dir = scanner.new_run()
            env = scanner.env_with_lists()
            
            # Run full pipeline
            scanner.stage_recon(run_dir, env, cfg)
            scanner.stage_vuln_scan(run_dir, env, cfg)
            
            # Run plugins
            plugins = scanner.load_plugins()
            for plugin_name, plugin_data in plugins.items():
                if plugin_data.get("enabled", True):
                    try:
                        print(f"[CI/CD] Running plugin: {plugin_name}")
                        plugin_data["execute"](run_dir, env, cfg)
                    except Exception as e:
                        print(f"[CI/CD] Plugin {plugin_name} failed: {e}")
            
            # Collect results
            return self._collect_scan_results(run_dir)
            
        except Exception as e:
            raise Exception(f"Full scan failed: {e}")
    
    def _run_api_scan(self) -> Dict[str, Any]:
        """Run API-focused security scan"""
        try:
            # Import the main scanner
            import bl4ckc3ll_p4nth30n as scanner
            
            # Load configuration - focus on API testing
            cfg = scanner.load_cfg()
            cfg["advanced_scanning"] = {
                "api_discovery": True,
                "graphql_testing": True,
                "jwt_analysis": True,
                "security_headers": True,
                "cors_analysis": True,
                "ssl_analysis": True,
                "technology_detection": True
            }
            
            # Create run directory and run API-focused scan
            run_dir = scanner.new_run()
            env = scanner.env_with_lists()
            
            # Run basic recon
            scanner.stage_recon(run_dir, env, cfg)
            
            # Run vulnerability scan with API focus
            scanner.stage_vuln_scan(run_dir, env, cfg)
            
            # Run API security plugin
            try:
                plugins = scanner.load_plugins()
                if "api_security_scanner" in plugins:
                    plugins["api_security_scanner"]["execute"](run_dir, env, cfg)
            except Exception as e:
                print(f"[CI/CD] API plugin execution failed: {e}")
            
            return self._collect_scan_results(run_dir)
            
        except Exception as e:
            raise Exception(f"API scan failed: {e}")
    
    def _run_cloud_scan(self) -> Dict[str, Any]:
        """Run cloud-focused security scan"""
        try:
            # Import the main scanner
            import bl4ckc3ll_p4nth30n as scanner
            
            # Load configuration - focus on cloud security
            cfg = scanner.load_cfg()
            cfg["advanced_scanning"] = {
                "cloud_storage_buckets": True,
                "container_scanning": True,
                "certificate_transparency": True,
                "dns_enumeration": True,
                "subdomain_takeover": True
            }
            
            # Create run directory
            run_dir = scanner.new_run()
            env = scanner.env_with_lists()
            
            # Run minimal recon
            scanner.stage_recon(run_dir, env, cfg)
            
            # Run vulnerability scan with cloud focus
            scanner.stage_vuln_scan(run_dir, env, cfg)
            
            # Run cloud security plugin
            try:
                plugins = scanner.load_plugins()
                if "cloud_security_scanner" in plugins:
                    plugins["cloud_security_scanner"]["execute"](run_dir, env, cfg)
            except Exception as e:
                print(f"[CI/CD] Cloud plugin execution failed: {e}")
            
            return self._collect_scan_results(run_dir)
            
        except Exception as e:
            raise Exception(f"Cloud scan failed: {e}")
    
    def _collect_scan_results(self, run_dir: Path) -> Dict[str, Any]:
        """Collect and aggregate scan results"""
        results = {
            "scan_info": {
                "target": self.target,
                "scan_type": self.scan_type,
                "start_time": self.start_time,
                "end_time": time.time(),
                "duration": time.time() - self.start_time
            },
            "vulnerabilities": [],
            "summary": {
                "total_vulns": 0,
                "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            }
        }
        
        # Collect Nuclei results
        nuclei_files = list(run_dir.glob("**/nuclei_results.jsonl"))
        for nuclei_file in nuclei_files:
            try:
                with open(nuclei_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            vuln = json.loads(line)
                            
                            severity = vuln.get("info", {}).get("severity", "info").lower()
                            
                            vuln_info = {
                                "id": vuln.get("template-id", "unknown"),
                                "name": vuln.get("info", {}).get("name", "Unknown"),
                                "severity": severity,
                                "description": vuln.get("info", {}).get("description", ""),
                                "url": vuln.get("matched-at", ""),
                                "type": vuln.get("type", ""),
                                "tags": vuln.get("info", {}).get("tags", [])
                            }
                            
                            results["vulnerabilities"].append(vuln_info)
                            results["summary"]["total_vulns"] += 1
                            
                            if severity in results["summary"]["by_severity"]:
                                results["summary"]["by_severity"][severity] += 1
            
            except Exception as e:
                print(f"[CI/CD] Error reading Nuclei results: {e}")
        
        # Collect additional scan results
        additional_files = [
            "api_discovery.json",
            "graphql_security.json", 
            "jwt_analysis.json",
            "cloud_storage.json",
            "compliance_checks.json"
        ]
        
        for filename in additional_files:
            result_files = list(run_dir.glob(f"**/{filename}"))
            for result_file in result_files:
                try:
                    with open(result_file, 'r') as f:
                        data = json.load(f)
                        
                        # Process different result types
                        if filename == "compliance_checks.json":
                            self._process_compliance_results(data, results)
                        elif filename == "cloud_storage.json":
                            self._process_cloud_results(data, results)
                        elif filename in ["api_discovery.json", "graphql_security.json", "jwt_analysis.json"]:
                            self._process_api_results(data, results, filename)
                
                except Exception as e:
                    print(f"[CI/CD] Error reading {filename}: {e}")
        
        return results
    
    def _process_compliance_results(self, data: Dict[str, Any], results: Dict[str, Any]):
        """Process compliance check results"""
        if "owasp_top10" in data:
            for category, issues in data["owasp_top10"].items():
                if issues:  # If there are issues in this category
                    vuln_info = {
                        "id": f"owasp-{category}",
                        "name": f"OWASP Top 10: {category.replace('_', ' ').title()}",
                        "severity": "high",
                        "description": f"Potential {category} vulnerability detected",
                        "url": self.target,
                        "type": "compliance",
                        "tags": ["owasp", "compliance"]
                    }
                    results["vulnerabilities"].append(vuln_info)
                    results["summary"]["total_vulns"] += 1
                    results["summary"]["by_severity"]["high"] += 1
    
    def _process_cloud_results(self, data: Dict[str, Any], results: Dict[str, Any]):
        """Process cloud security results"""
        # Check for accessible buckets
        for bucket in data.get("accessible_buckets", []):
            if bucket.get("public_read") or bucket.get("public_write"):
                severity = "critical" if bucket.get("public_write") else "high"
                
                vuln_info = {
                    "id": "cloud-storage-exposure",
                    "name": "Exposed Cloud Storage Bucket",
                    "severity": severity,
                    "description": f"Cloud storage bucket '{bucket.get('name')}' is publicly accessible",
                    "url": bucket.get("url", self.target),
                    "type": "cloud_security",
                    "tags": ["cloud", "storage", "exposure"]
                }
                results["vulnerabilities"].append(vuln_info)
                results["summary"]["total_vulns"] += 1
                results["summary"]["by_severity"][severity] += 1
    
    def _process_api_results(self, data: Dict[str, Any], results: Dict[str, Any], filename: str):
        """Process API security results"""
        if filename == "graphql_security.json":
            for endpoint, info in data.items():
                if info.get("introspection_enabled"):
                    vuln_info = {
                        "id": "graphql-introspection",
                        "name": "GraphQL Introspection Enabled",
                        "severity": "medium",
                        "description": f"GraphQL introspection is enabled on {endpoint}",
                        "url": info.get("url", self.target),
                        "type": "api_security",
                        "tags": ["graphql", "introspection"]
                    }
                    results["vulnerabilities"].append(vuln_info)
                    results["summary"]["total_vulns"] += 1
                    results["summary"]["by_severity"]["medium"] += 1
    
    def _process_results(self, results: Dict[str, Any]) -> int:
        """Process results and determine exit code"""
        # Check if any vulnerabilities meet the fail threshold
        for vuln in results["vulnerabilities"]:
            vuln_severity = vuln.get("severity", "info")
            vuln_level = self.severity_levels.get(vuln_severity, 0)
            
            if vuln_level >= self.fail_level:
                print(f"[CI/CD] FAIL: Found {vuln_severity} severity vulnerability: {vuln['name']}")
                return 1  # Fail exit code
        
        print(f"[CI/CD] PASS: No vulnerabilities above {self.fail_threshold} threshold")
        return 0  # Success exit code
    
    def _generate_output(self, results: Dict[str, Any]):
        """Generate output in the specified format"""
        if self.output_format == "json":
            self._generate_json_output(results)
        elif self.output_format == "sarif":
            self._generate_sarif_output(results)
        elif self.output_format == "junit":
            self._generate_junit_output(results)
    
    def _generate_json_output(self, results: Dict[str, Any]):
        """Generate JSON output"""
        with open(self.output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
    
    def _generate_sarif_output(self, results: Dict[str, Any]):
        """Generate SARIF output for security tools integration"""
        sarif = {
            "version": "2.1.0",
            "schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Bl4ckC3ll_PANTHEON",
                        "version": "9.0.0-enhanced",
                        "informationUri": "https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON"
                    }
                },
                "results": []
            }]
        }
        
        for vuln in results["vulnerabilities"]:
            sarif_result = {
                "ruleId": vuln["id"],
                "message": {"text": vuln["description"]},
                "level": self._map_severity_to_sarif(vuln["severity"]),
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": vuln["url"]}
                    }
                }]
            }
            sarif["runs"][0]["results"].append(sarif_result)
        
        with open(self.output_file, 'w') as f:
            json.dump(sarif, f, indent=2)
    
    def _generate_junit_output(self, results: Dict[str, Any]):
        """Generate JUnit XML output"""
        junit_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="Security Scan" tests="{len(results['vulnerabilities'])}" failures="{len([v for v in results['vulnerabilities'] if self.severity_levels.get(v['severity'], 0) >= self.fail_level])}" time="{results['scan_info']['duration']:.2f}">
"""
        
        for vuln in results["vulnerabilities"]:
            test_name = f"{vuln['id']}: {vuln['name']}"
            
            if self.severity_levels.get(vuln["severity"], 0) >= self.fail_level:
                junit_xml += f"""  <testcase name="{test_name}" classname="SecurityScan">
    <failure message="{vuln['severity']} severity vulnerability">{vuln['description']}</failure>
  </testcase>
"""
            else:
                junit_xml += f"""  <testcase name="{test_name}" classname="SecurityScan" />
"""
        
        junit_xml += "</testsuite>"
        
        with open(self.output_file, 'w') as f:
            f.write(junit_xml)
    
    def _map_severity_to_sarif(self, severity: str) -> str:
        """Map severity levels to SARIF levels"""
        mapping = {
            "critical": "error",
            "high": "error", 
            "medium": "warning",
            "low": "note",
            "info": "note"
        }
        return mapping.get(severity, "note")

if __name__ == "__main__":
    main()