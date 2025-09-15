#!/usr/bin/env python3
"""
Advanced API Security Testing Module for Bl4ckC3ll_PANTHEON
Enhanced API discovery, testing, and analysis for modern API-driven applications
"""

import json
import requests
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urljoin, urlparse, parse_qs
import logging

logger = logging.getLogger(__name__)

class APISecurityTester:
    """Advanced API security testing and analysis"""
    
    def __init__(self, timeout: int = 30, max_requests: int = 1000):
        self.timeout = timeout
        self.max_requests = max_requests
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Bl4ckC3ll-PANTHEON-API-Scanner/2.0'
        })
        self.discovered_endpoints = set()
        
    def discover_apis(self, base_url: str) -> Dict[str, Any]:
        """Comprehensive API discovery"""
        discovery_results = {
            'base_url': base_url,
            'endpoints': {},
            'schemas': {},
            'security_issues': [],
            'timestamp': time.time()
        }
        
        print(f"Starting API discovery for: {base_url}")
        
        # Common API paths
        api_paths = [
            '/api/', '/api/v1/', '/api/v2/', '/rest/',
            '/graphql/', '/swagger/', '/docs/'
        ]
        
        for path in api_paths:
            url = urljoin(base_url, path)
            self._discover_from_endpoint(url, discovery_results)
        
        return discovery_results
    
    def _discover_from_endpoint(self, url: str, results: Dict):
        """Discover API endpoints from a base URL"""
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '').lower()
                
                if 'application/json' in content_type:
                    self._analyze_json_response(url, response, results)
        
        except Exception as e:
            logger.debug(f"Failed to discover from {url}: {e}")
    
    def test_api_security(self, api_url: str, endpoints: Dict) -> Dict[str, Any]:
        """Comprehensive API security testing"""
        security_results = {
            'api_url': api_url,
            'vulnerabilities': [],
            'security_headers': {},
            'authentication_issues': [],
            'timestamp': time.time()
        }
        
        print(f"Starting API security testing for: {api_url}")
        
        # Test security headers
        self._test_security_headers(api_url, security_results)
        
        # Test authentication
        self._test_authentication(api_url, security_results)
        
        return security_results
    
    def _test_security_headers(self, api_url: str, results: Dict):
        """Test for security headers"""
        try:
            response = self.session.get(api_url, timeout=self.timeout, verify=False)
            headers = response.headers
            
            security_headers = {
                'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                'X-Frame-Options': headers.get('X-Frame-Options'),
                'Access-Control-Allow-Origin': headers.get('Access-Control-Allow-Origin'),
            }
            
            results['security_headers'] = security_headers
            
            # Check for insecure CORS
            cors_origin = headers.get('Access-Control-Allow-Origin')
            if cors_origin == '*':
                results['vulnerabilities'].append({
                    'type': 'insecure_cors',
                    'severity': 'high',
                    'title': 'Insecure CORS Configuration',
                    'description': 'Access-Control-Allow-Origin is set to wildcard (*)',
                    'recommendation': 'Restrict CORS to specific trusted domains'
                })
        
        except Exception as e:
            logger.debug(f"Security headers test failed: {e}")
    
    def _test_authentication(self, api_url: str, results: Dict):
        """Test authentication mechanisms"""
        try:
            response = self.session.get(api_url, timeout=self.timeout, verify=False)
            
            if response.status_code == 200:
                results['authentication_issues'].append({
                    'type': 'unauthenticated_access',
                    'severity': 'medium',
                    'endpoint': api_url,
                    'description': 'API endpoint accessible without authentication'
                })
        
        except Exception as e:
            logger.debug(f"Authentication test failed: {e}")
    
    def _analyze_json_response(self, url: str, response: requests.Response, results: Dict):
        """Analyze JSON API response"""
        try:
            data = response.json()
            
            results['endpoints'][url] = {
                'status_code': response.status_code,
                'content_type': response.headers.get('Content-Type'),
                'has_data': bool(data)
            }
        
        except Exception as e:
            logger.debug(f"JSON analysis failed for {url}: {e}")

# API testing functions for integration
def scan_api_endpoints(base_url: str, output_dir: Path) -> Dict[str, Any]:
    """Scan API endpoints for security issues"""
    tester = APISecurityTester()
    
    # Discover APIs
    discovery_results = tester.discover_apis(base_url)
    
    # Test discovered APIs
    security_results = tester.test_api_security(base_url, discovery_results['endpoints'])
    
    # Combine results
    results = {
        'discovery': discovery_results,
        'security': security_results,
        'timestamp': time.time()
    }
    
    # Save results
    results_file = output_dir / f"api_scan_{urlparse(base_url).netloc}.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    return results

__all__ = ['APISecurityTester', 'scan_api_endpoints']