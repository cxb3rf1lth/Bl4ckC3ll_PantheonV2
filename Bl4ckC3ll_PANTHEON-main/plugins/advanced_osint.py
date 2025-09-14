# Plugin: Advanced OSINT
# Provides enhanced open-source intelligence gathering capabilities
from pathlib import Path
from typing import Dict, Any
import json
import subprocess
import time
from urllib.parse import urlparse

plugin_info = {
    "name": "Advanced OSINT",
    "description": "Enhanced open-source intelligence gathering with multiple data sources",
    "version": "1.0.0",
    "author": "@cxb3rf1lth",
    "category": "reconnaissance",
    "requires_internet": True,
    "risk_level": "low"
}

def execute(run_dir: Path, env: Dict[str, str], cfg: Dict[str, Any]):
    """Execute advanced OSINT collection"""
    osint_dir = run_dir / "osint_enhanced"
    osint_dir.mkdir(exist_ok=True)
    
    # Read targets
    targets_file = Path(__file__).parent.parent / "targets.txt"
    if not targets_file.exists():
        print("[OSINT] No targets file found")
        return
    
    targets = []
    with open(targets_file, 'r') as f:
        for line in f:
            target = line.strip()
            if target and not target.startswith('#'):
                targets.append(target)
    
    if not targets:
        print("[OSINT] No targets found")
        return
    
    results = {}
    
    for target in targets:
        print(f"[OSINT] Processing target: {target}")
        target_results = {}
        
        # Extract domain
        if target.startswith('http'):
            parsed = urlparse(target)
            domain = parsed.netloc
        else:
            domain = target
        
        # 1. Certificate Transparency Logs
        try:
            cert_results = search_certificate_transparency(domain)
            target_results["certificate_transparency"] = cert_results
        except Exception as e:
            print(f"[OSINT] Certificate transparency error for {domain}: {e}")
        
        # 2. DNS History
        try:
            dns_history = get_dns_history(domain)
            target_results["dns_history"] = dns_history
        except Exception as e:
            print(f"[OSINT] DNS history error for {domain}: {e}")
        
        # 3. Subdomain Enumeration via External Sources
        try:
            external_subs = get_external_subdomains(domain)
            target_results["external_subdomains"] = external_subs
        except Exception as e:
            print(f"[OSINT] External subdomain error for {domain}: {e}")
        
        # 4. Social Media and Code Repositories
        try:
            social_results = search_social_presence(domain)
            target_results["social_presence"] = social_results
        except Exception as e:
            print(f"[OSINT] Social presence error for {domain}: {e}")
        
        # 5. Technology Stack Analysis
        try:
            tech_stack = analyze_technology_stack(target)
            target_results["technology_analysis"] = tech_stack
        except Exception as e:
            print(f"[OSINT] Technology analysis error for {target}: {e}")
        
        results[target] = target_results
    
    # Save comprehensive results
    output_file = osint_dir / "advanced_osint_results.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"[OSINT] Advanced OSINT results saved to: {output_file}")

def search_certificate_transparency(domain):
    """Search certificate transparency logs for subdomains"""
    results = {
        "subdomains_found": [],
        "certificates": [],
        "timestamp": time.time()
    }
    
    try:
        # Use crt.sh API for certificate transparency
        import urllib.request
        import urllib.parse
        
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                data = json.loads(response.read().decode())
                
                subdomains = set()
                for cert in data[:50]:  # Limit to avoid too much data
                    if 'name_value' in cert:
                        names = cert['name_value'].split('\n')
                        for name in names:
                            name = name.strip().lower()
                            if domain in name and name.endswith(f".{domain}"):
                                subdomains.add(name)
                    
                    results["certificates"].append({
                        "id": cert.get("id"),
                        "issuer": cert.get("issuer_name", ""),
                        "names": cert.get("name_value", "").split('\n'),
                        "not_before": cert.get("not_before"),
                        "not_after": cert.get("not_after")
                    })
                
                results["subdomains_found"] = list(subdomains)
                
        except Exception as e:
            results["error"] = str(e)
    
    except Exception as e:
        results["error"] = f"Certificate transparency search failed: {e}"
    
    return results

def get_dns_history(domain):
    """Get DNS history information"""
    results = {
        "historical_ips": [],
        "mx_records": [],
        "ns_records": [],
        "timestamp": time.time()
    }
    
    try:
        # Use dig for current DNS records
        dns_queries = [
            ("A", "a_records"),
            ("MX", "mx_records"), 
            ("NS", "ns_records"),
            ("TXT", "txt_records"),
            ("CNAME", "cname_records")
        ]
        
        for query_type, result_key in dns_queries:
            try:
                cmd = ["dig", "+short", f"@8.8.8.8", domain, query_type]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and result.stdout.strip():
                    results[result_key] = result.stdout.strip().split('\n')
            except Exception:
                results[result_key] = []
    
    except Exception as e:
        results["error"] = f"DNS history lookup failed: {e}"
    
    return results

def get_external_subdomains(domain):
    """Get subdomains from external sources"""
    results = {
        "sources": {},
        "total_unique": 0,
        "timestamp": time.time()
    }
    
    try:
        # Use various external APIs (rate-limited)
        sources = [
            "hackertarget",
            "threatcrowd", 
            "virustotal"
        ]
        
        all_subdomains = set()
        
        for source in sources:
            try:
                if source == "hackertarget":
                    # HackerTarget API
                    import urllib.request
                    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
                    
                    with urllib.request.urlopen(url, timeout=15) as response:
                        data = response.read().decode()
                        if "error" not in data.lower():
                            lines = data.split('\n')
                            source_subs = []
                            for line in lines:
                                if ',' in line:
                                    subdomain = line.split(',')[0].strip()
                                    if subdomain and domain in subdomain:
                                        source_subs.append(subdomain)
                                        all_subdomains.add(subdomain)
                            
                            results["sources"][source] = {
                                "count": len(source_subs),
                                "subdomains": source_subs[:20]  # Limit output
                            }
                
                # Add small delay between API calls
                time.sleep(1)
                
            except Exception as e:
                results["sources"][source] = {"error": str(e)}
        
        results["total_unique"] = len(all_subdomains)
        results["all_subdomains"] = list(all_subdomains)[:50]  # Limit output
    
    except Exception as e:
        results["error"] = f"External subdomain enumeration failed: {e}"
    
    return results

def search_social_presence(domain):
    """Search for social media and code repository presence"""
    results = {
        "github_repos": [],
        "social_accounts": [],
        "code_leaks": [],
        "timestamp": time.time()
    }
    
    try:
        # Search for GitHub repositories related to domain
        github_searches = [
            f'"{domain}"',
            f'"{domain.replace(".", "")}"',
            f'site:{domain}'
        ]
        
        # Note: This would need GitHub API token for actual implementation
        results["github_search_queries"] = github_searches
        
        # Search for common social media patterns
        social_platforms = ["twitter", "facebook", "linkedin", "instagram"]
        for platform in social_platforms:
            # This would be expanded with actual API calls
            results["social_accounts"].append({
                "platform": platform,
                "search_query": f"{domain} site:{platform}.com",
                "status": "manual_search_required"
            })
    
    except Exception as e:
        results["error"] = f"Social presence search failed: {e}"
    
    return results

def analyze_technology_stack(target):
    """Analyze technology stack in detail"""
    results = {
        "web_technologies": {},
        "server_info": {},
        "cms_detection": {},
        "timestamp": time.time()
    }
    
    try:
        # Enhanced HTTP header analysis
        try:
            cmd = ["curl", "-I", "-s", "-k", "--max-time", "10", target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                headers = {}
                for line in result.stdout.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip().lower()] = value.strip()
                
                # Analyze headers for technology indicators
                tech_indicators = {
                    "server": headers.get("server", ""),
                    "x-powered-by": headers.get("x-powered-by", ""),
                    "x-aspnet-version": headers.get("x-aspnet-version", ""),
                    "x-generator": headers.get("x-generator", ""),
                    "set-cookie": headers.get("set-cookie", "")
                }
                
                results["server_info"] = tech_indicators
                
                # Detect common technologies
                technologies = []
                if "nginx" in tech_indicators.get("server", "").lower():
                    technologies.append("Nginx")
                if "apache" in tech_indicators.get("server", "").lower():
                    technologies.append("Apache")
                if "php" in tech_indicators.get("x-powered-by", "").lower():
                    technologies.append("PHP")
                if "asp.net" in tech_indicators.get("x-powered-by", "").lower():
                    technologies.append("ASP.NET")
                if "jsessionid" in tech_indicators.get("set-cookie", "").lower():
                    technologies.append("Java/JSP")
                
                results["web_technologies"]["detected"] = technologies
        
        except Exception as e:
            results["server_info"]["error"] = str(e)
    
    except Exception as e:
        results["error"] = f"Technology analysis failed: {e}"
    
    return results