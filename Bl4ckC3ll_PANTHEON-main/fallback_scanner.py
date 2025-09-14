#!/usr/bin/env python3
"""
Fallback Scanning System for Bl4ckC3ll_PANTHEON
Provides high-reliability scanning even when external tools are unavailable
"""

import os
import json
import time
import socket
import ssl
import threading
import requests
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
import concurrent.futures
from dataclasses import dataclass, field

@dataclass
class ScanResult:
    """Fallback scan result"""
    target: str
    scan_type: str
    success: bool
    findings: List[Dict] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)
    error: Optional[str] = None
    duration: float = 0.0

class FallbackScanner:
    """High-reliability fallback scanner that works without external tools"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
        
        # Common ports for scanning
        self.common_ports = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 8080, 8443]
        
        # DNS resolvers
        self.dns_resolvers = ['8.8.8.8', '1.1.1.1', '208.67.222.222']
        
    def scan_target(self, target: str, output_dir: Path) -> List[ScanResult]:
        """Perform comprehensive fallback scan of a target"""
        results = []
        
        # Determine target type
        if self._is_ip_address(target):
            results.extend(self._scan_ip(target, output_dir))
        elif self._is_domain(target):
            results.extend(self._scan_domain(target, output_dir))
        elif self._is_url(target):
            results.extend(self._scan_url(target, output_dir))
        else:
            # Try as domain first
            results.extend(self._scan_domain(target, output_dir))
        
        return results
    
    def _is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address"""
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            return False
    
    def _is_domain(self, target: str) -> bool:
        """Check if target is a domain"""
        return '.' in target and not target.startswith(('http://', 'https://'))
    
    def _is_url(self, target: str) -> bool:
        """Check if target is a URL"""
        return target.startswith(('http://', 'https://'))
    
    def _scan_ip(self, ip: str, output_dir: Path) -> List[ScanResult]:
        """Scan an IP address"""
        results = []
        
        # Port scan
        results.append(self._port_scan(ip, output_dir))
        
        # HTTP checks if common web ports are open
        for port in [80, 443, 8080, 8443]:
            if self._is_port_open(ip, port):
                protocol = 'https' if port in [443, 8443] else 'http'
                url = f"{protocol}://{ip}:{port}"
                results.extend(self._scan_web_service(url, output_dir))
        
        return [r for r in results if r is not None]
    
    def _scan_domain(self, domain: str, output_dir: Path) -> List[ScanResult]:
        """Scan a domain"""
        results = []
        
        # DNS enumeration
        results.append(self._dns_enumeration(domain, output_dir))
        
        # Subdomain discovery
        results.append(self._basic_subdomain_discovery(domain, output_dir))
        
        # HTTP/HTTPS checks
        for protocol in ['http', 'https']:
            url = f"{protocol}://{domain}"
            results.extend(self._scan_web_service(url, output_dir))
        
        # Try to resolve domain and scan IP
        try:
            ip = socket.gethostbyname(domain)
            results.append(self._port_scan(ip, output_dir, domain_context=domain))
        except socket.gaierror:
            pass
        
        return [r for r in results if r is not None]
    
    def _scan_url(self, url: str, output_dir: Path) -> List[ScanResult]:
        """Scan a URL"""
        results = []
        
        # Web service scan
        results.extend(self._scan_web_service(url, output_dir))
        
        # Extract domain and scan it
        parsed = urlparse(url)
        if parsed.hostname:
            results.extend(self._scan_domain(parsed.hostname, output_dir))
        
        return [r for r in results if r is not None]
    
    def _port_scan(self, ip: str, output_dir: Path, domain_context: str = None) -> ScanResult:
        """Basic port scan using socket connections"""
        start_time = time.time()
        open_ports = []
        
        def check_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(3)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        return port
            except:
                pass
            return None
        
        # Concurrent port scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_port, port) for port in self.common_ports]
            for future in concurrent.futures.as_completed(futures):
                port = future.result()
                if port:
                    open_ports.append(port)
        
        duration = time.time() - start_time
        
        # Save results
        target_name = domain_context or ip
        output_file = output_dir / f"portscan_{target_name.replace(':', '_')}.json"
        
        findings = []
        for port in sorted(open_ports):
            findings.append({
                'type': 'open_port',
                'port': port,
                'service': self._guess_service(port),
                'ip': ip
            })
        
        result_data = {
            'target': ip,
            'scan_type': 'port_scan',
            'open_ports': sorted(open_ports),
            'total_ports_scanned': len(self.common_ports),
            'findings': findings,
            'duration': duration
        }
        
        self._save_json_result(output_file, result_data)
        
        return ScanResult(
            target=target_name,
            scan_type='port_scan',
            success=True,
            findings=findings,
            metadata={'open_ports': len(open_ports), 'scanned_ports': len(self.common_ports)},
            duration=duration
        )
    
    def _dns_enumeration(self, domain: str, output_dir: Path) -> ScanResult:
        """DNS enumeration using standard DNS queries"""
        start_time = time.time()
        findings = []
        
        if DNS_AVAILABLE:
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    for answer in answers:
                        findings.append({
                            'type': 'dns_record',
                            'record_type': record_type,
                            'value': str(answer),
                            'domain': domain
                        })
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Exception):
                    pass
        else:
            # Basic DNS resolution without dnspython
            try:
                # A record
                ip = socket.gethostbyname(domain)
                findings.append({
                    'type': 'dns_record',
                    'record_type': 'A',
                    'value': ip,
                    'domain': domain
                })
                
                # Try reverse DNS
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                    findings.append({
                        'type': 'dns_record',
                        'record_type': 'PTR',
                        'value': hostname,
                        'domain': domain
                    })
                except:
                    pass
                    
            except socket.gaierror:
                findings.append({
                    'type': 'dns_error',
                    'error': 'Domain resolution failed',
                    'domain': domain
                })
        
        duration = time.time() - start_time
        
        # Save results
        output_file = output_dir / f"dns_{domain}.json"
        result_data = {
            'target': domain,
            'scan_type': 'dns_enumeration',
            'findings': findings,
            'duration': duration
        }
        
        self._save_json_result(output_file, result_data)
        
        return ScanResult(
            target=domain,
            scan_type='dns_enumeration',
            success=True,
            findings=findings,
            metadata={'records_found': len(findings)},
            duration=duration
        )
    
    def _basic_subdomain_discovery(self, domain: str, output_dir: Path) -> ScanResult:
        """Basic subdomain discovery using common subdomain list"""
        start_time = time.time()
        findings = []
        
        # Common subdomains to check
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
            'blog', 'shop', 'store', 'secure', 'portal', 'app', 'mobile',
            'vpn', 'remote', 'support', 'help', 'docs', 'wiki', 'cdn'
        ]
        
        def check_subdomain(subdomain):
            try:
                full_domain = f"{subdomain}.{domain}"
                ip = socket.gethostbyname(full_domain)
                return {'subdomain': full_domain, 'ip': ip}
            except socket.gaierror:
                return None
        
        # Concurrent subdomain checking
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in common_subdomains]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    findings.append({
                        'type': 'subdomain',
                        'subdomain': result['subdomain'],
                        'ip': result['ip']
                    })
        
        duration = time.time() - start_time
        
        # Save results
        output_file = output_dir / f"subdomains_{domain}.json"
        result_data = {
            'target': domain,
            'scan_type': 'subdomain_discovery',
            'findings': findings,
            'duration': duration
        }
        
        self._save_json_result(output_file, result_data)
        
        return ScanResult(
            target=domain,
            scan_type='subdomain_discovery',
            success=True,
            findings=findings,
            metadata={'subdomains_found': len(findings), 'checked_subdomains': len(common_subdomains)},
            duration=duration
        )
    
    def _scan_web_service(self, url: str, output_dir: Path) -> List[ScanResult]:
        """Scan web service for basic information"""
        results = []
        
        # HTTP response analysis
        results.append(self._http_response_analysis(url, output_dir))
        
        # SSL/TLS analysis for HTTPS
        if url.startswith('https://'):
            results.append(self._ssl_analysis(url, output_dir))
        
        # Directory enumeration
        results.append(self._basic_directory_enum(url, output_dir))
        
        return [r for r in results if r is not None]
    
    def _http_response_analysis(self, url: str, output_dir: Path) -> ScanResult:
        """Analyze HTTP response"""
        start_time = time.time()
        findings = []
        
        try:
            response = self.session.get(url, timeout=10, verify=False, allow_redirects=True)
            
            # Server information
            server = response.headers.get('Server', 'Unknown')
            findings.append({
                'type': 'server_info',
                'server': server,
                'status_code': response.status_code
            })
            
            # Security headers analysis
            security_headers = [
                'X-Content-Type-Options',
                'X-Frame-Options',
                'X-XSS-Protection',
                'Strict-Transport-Security',
                'Content-Security-Policy'
            ]
            
            missing_headers = []
            present_headers = []
            
            for header in security_headers:
                if header in response.headers:
                    present_headers.append(header)
                    findings.append({
                        'type': 'security_header',
                        'header': header,
                        'value': response.headers[header],
                        'status': 'present'
                    })
                else:
                    missing_headers.append(header)
                    findings.append({
                        'type': 'security_header',
                        'header': header,
                        'status': 'missing'
                    })
            
            # Technology detection
            tech_indicators = {
                'PHP': ['X-Powered-By: PHP', 'Set-Cookie: PHPSESSID'],
                'ASP.NET': ['X-AspNet-Version', 'X-AspNetMvc-Version'],
                'Apache': ['Server: Apache'],
                'Nginx': ['Server: nginx'],
                'IIS': ['Server: Microsoft-IIS'],
                'WordPress': ['wp-content', 'wp-includes'],
                'jQuery': ['jquery']
            }
            
            response_text = response.text.lower()
            headers_text = str(response.headers).lower()
            
            for tech, indicators in tech_indicators.items():
                for indicator in indicators:
                    if indicator.lower() in headers_text or indicator.lower() in response_text:
                        findings.append({
                            'type': 'technology',
                            'technology': tech,
                            'indicator': indicator
                        })
                        break
            
            success = True
            
        except Exception as e:
            findings.append({
                'type': 'error',
                'error': str(e)
            })
            success = False
        
        duration = time.time() - start_time
        
        # Save results
        parsed_url = urlparse(url)
        safe_filename = f"http_{parsed_url.hostname}_{parsed_url.port or ('443' if parsed_url.scheme == 'https' else '80')}.json"
        output_file = output_dir / safe_filename
        
        result_data = {
            'target': url,
            'scan_type': 'http_analysis',
            'findings': findings,
            'duration': duration
        }
        
        self._save_json_result(output_file, result_data)
        
        return ScanResult(
            target=url,
            scan_type='http_analysis',
            success=success,
            findings=findings,
            metadata={'findings_count': len(findings)},
            duration=duration
        )
    
    def _ssl_analysis(self, url: str, output_dir: Path) -> ScanResult:
        """Basic SSL/TLS analysis"""
        start_time = time.time()
        findings = []
        
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            port = parsed.port or 443
            
            # Get SSL certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    findings.append({
                        'type': 'ssl_certificate',
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'version': cert['version']
                    })
                    
                    # Check for SAN (Subject Alternative Names)
                    if 'subjectAltName' in cert:
                        san_list = [name[1] for name in cert['subjectAltName']]
                        findings.append({
                            'type': 'ssl_san',
                            'san_names': san_list
                        })
            
            success = True
            
        except Exception as e:
            findings.append({
                'type': 'ssl_error',
                'error': str(e)
            })
            success = False
        
        duration = time.time() - start_time
        
        # Save results
        parsed_url = urlparse(url)
        safe_filename = f"ssl_{parsed_url.hostname}.json"
        output_file = output_dir / safe_filename
        
        result_data = {
            'target': url,
            'scan_type': 'ssl_analysis',
            'findings': findings,
            'duration': duration
        }
        
        self._save_json_result(output_file, result_data)
        
        return ScanResult(
            target=url,
            scan_type='ssl_analysis',
            success=success,
            findings=findings,
            metadata={'cert_info': len([f for f in findings if f['type'] == 'ssl_certificate'])},
            duration=duration
        )
    
    def _basic_directory_enum(self, url: str, output_dir: Path) -> ScanResult:
        """Basic directory enumeration"""
        start_time = time.time()
        findings = []
        
        # Common directories and files to check
        common_paths = [
            'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin',
            'robots.txt', 'sitemap.xml', '.htaccess', 'config.php',
            'backup', 'test', 'dev', 'api', 'api/v1', 'api/v2',
            '.git', '.svn', 'changelog.txt', 'readme.txt'
        ]
        
        def check_path(path):
            try:
                test_url = f"{url.rstrip('/')}/{path}"
                response = self.session.head(test_url, timeout=5, verify=False, allow_redirects=False)
                if response.status_code in [200, 301, 302, 403]:
                    return {
                        'path': path,
                        'status_code': response.status_code,
                        'url': test_url
                    }
            except:
                pass
            return None
        
        # Concurrent path checking
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(check_path, path) for path in common_paths]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    findings.append({
                        'type': 'directory_enum',
                        'path': result['path'],
                        'status_code': result['status_code'],
                        'url': result['url']
                    })
        
        duration = time.time() - start_time
        
        # Save results
        parsed_url = urlparse(url)
        safe_filename = f"direnum_{parsed_url.hostname}.json"
        output_file = output_dir / safe_filename
        
        result_data = {
            'target': url,
            'scan_type': 'directory_enumeration',
            'findings': findings,
            'duration': duration
        }
        
        self._save_json_result(output_file, result_data)
        
        return ScanResult(
            target=url,
            scan_type='directory_enumeration',
            success=True,
            findings=findings,
            metadata={'paths_found': len(findings), 'paths_checked': len(common_paths)},
            duration=duration
        )
    
    def _is_port_open(self, ip: str, port: int) -> bool:
        """Check if a port is open"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(3)
                result = sock.connect_ex((ip, port))
                return result == 0
        except:
            return False
    
    def _guess_service(self, port: int) -> str:
        """Guess service running on port"""
        services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt'
        }
        return services.get(port, 'Unknown')
    
    def _save_json_result(self, file_path: Path, data: Dict):
        """Save JSON result to file"""
        try:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            print(f"Failed to save result to {file_path}: {e}")

# Integration with enhanced scanning
def run_fallback_scan(targets: List[str], output_dir: Path) -> Tuple[bool, int]:
    """Run fallback scan and return success status and findings count"""
    scanner = FallbackScanner()
    total_findings = 0
    successful_targets = 0
    
    for target in targets:
        try:
            results = scanner.scan_target(target, output_dir)
            if results:
                successful_targets += 1
                total_findings += sum(len(r.findings) for r in results)
        except Exception as e:
            print(f"Fallback scan failed for {target}: {e}")
    
    success_rate = successful_targets / len(targets) if targets else 0
    return success_rate >= 0.7, total_findings  # 70% success threshold

if __name__ == "__main__":
    # Test fallback scanner
    scanner = FallbackScanner()
    output_dir = Path("/tmp/fallback_test")
    
    test_targets = ["example.com", "8.8.8.8"]
    
    for target in test_targets:
        print(f"Testing {target}...")
        results = scanner.scan_target(target, output_dir)
        
        for result in results:
            print(f"  {result.scan_type}: {len(result.findings)} findings")
    
    print(f"Results saved to: {output_dir}")