#!/usr/bin/env python3
"""
Container Security Scanning Module for Bl4ckC3ll_PANTHEON
Scans container images and Kubernetes manifests for vulnerabilities and misconfigurations
"""

import json
import subprocess
import tempfile
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging
import time

logger = logging.getLogger(__name__)

class ContainerSecurityScanner:
    """Container and Kubernetes security scanner"""
    
    def __init__(self):
        self.tools_available = self._check_available_tools()
        self.vulnerability_db_updated = False
    
    def _check_available_tools(self) -> Dict[str, bool]:
        """Check which container security tools are available"""
        tools = {
            'docker': self._check_tool('docker'),
            'trivy': self._check_tool('trivy'),
            'grype': self._check_tool('grype'),
            'kubectl': self._check_tool('kubectl'),
        }
        return tools
    
    def _check_tool(self, tool_name: str) -> bool:
        """Check if a specific tool is available"""
        try:
            result = subprocess.run(['which', tool_name], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
    
    def scan_container_image(self, image_name: str, output_dir: Path) -> Dict[str, Any]:
        """Scan container image for vulnerabilities and misconfigurations"""
        results = {
            'image': image_name,
            'vulnerabilities': [],
            'misconfigurations': [],
            'secrets': [],
            'timestamp': time.time()
        }
        
        print(f"Starting container scan for image: {image_name}")
        
        # Docker security best practices check
        if self.tools_available.get('docker'):
            docker_results = self._check_docker_security(image_name)
            if docker_results:
                results['misconfigurations'].extend(docker_results)
        
        # Trivy scan if available
        if self.tools_available.get('trivy'):
            trivy_results = self._scan_with_trivy_basic(image_name)
            if trivy_results:
                results.update(trivy_results)
        
        # Save results
        results_file = output_dir / f"container_scan_{image_name.replace(':', '_').replace('/', '_')}.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        return results
    
    def _scan_with_trivy_basic(self, image_name: str) -> Dict[str, Any]:
        """Basic Trivy scan"""
        try:
            cmd = ['trivy', 'image', '--format', 'json', '--quiet', image_name]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                return {'vulnerabilities': self._parse_trivy_vulnerabilities(data)}
        except Exception as e:
            logger.error(f"Trivy scan failed: {e}")
        
        return {}
    
    def _check_docker_security(self, image_name: str) -> List[Dict[str, Any]]:
        """Check Docker security best practices"""
        issues = []
        
        try:
            cmd = ['docker', 'inspect', image_name]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                image_info = json.loads(result.stdout)[0]
                config = image_info.get('Config', {})
                
                # Check for root user
                if config.get('User') == 'root' or not config.get('User'):
                    issues.append({
                        'type': 'security_misconfiguration',
                        'severity': 'medium',
                        'title': 'Running as root user',
                        'description': 'Container is configured to run as root user',
                        'recommendation': 'Use a non-root user in Dockerfile'
                    })
                
                # Check for health checks
                if not config.get('Healthcheck'):
                    issues.append({
                        'type': 'security_misconfiguration',
                        'severity': 'low',
                        'title': 'No health check configured',
                        'description': 'Container has no health check configured',
                        'recommendation': 'Add HEALTHCHECK instruction to Dockerfile'
                    })
        
        except Exception as e:
            logger.error(f"Docker security check failed: {e}")
        
        return issues
    
    def _parse_trivy_vulnerabilities(self, data: Dict) -> List[Dict[str, Any]]:
        """Parse Trivy vulnerability scan results"""
        vulnerabilities = []
        
        for result in data.get('Results', []):
            for vuln in result.get('Vulnerabilities', []):
                vulnerabilities.append({
                    'id': vuln.get('VulnerabilityID'),
                    'severity': vuln.get('Severity'),
                    'title': vuln.get('Title'),
                    'description': vuln.get('Description'),
                    'package': vuln.get('PkgName'),
                    'version': vuln.get('InstalledVersion'),
                    'fixed_version': vuln.get('FixedVersion'),
                })
        
        return vulnerabilities

# Container scanning functions for integration
def scan_container_images(images: List[str], output_dir: Path) -> Dict[str, Any]:
    """Scan multiple container images"""
    scanner = ContainerSecurityScanner()
    results = {}
    
    for image in images:
        try:
            results[image] = scanner.scan_container_image(image, output_dir)
        except Exception as e:
            logger.error(f"Failed to scan image {image}: {e}")
            results[image] = {'error': str(e)}
    
    return results

__all__ = ['ContainerSecurityScanner', 'scan_container_images']