# Plugin: Enhanced Nuclei Template Manager
# Advanced nuclei template management and community integration
from pathlib import Path
from typing import Dict, Any, List
import json
import subprocess
import time
import requests
from urllib.parse import urlparse
import yaml

plugin_info = {
    "name": "Enhanced Nuclei Template Manager",
    "description": "Manage and integrate multiple community nuclei template sources",
    "version": "1.0.0", 
    "author": "@cxb3rf1lth",
    "category": "template_management",
    "requires_internet": True,
    "risk_level": "low"
}

def execute(run_dir: Path, env: Dict[str, str], cfg: Dict[str, Any]):
    """Execute comprehensive nuclei template management"""
    template_dir = run_dir / "nuclei_templates"
    template_dir.mkdir(exist_ok=True)
    
    print("[NUCLEI] Enhanced template management starting...")
    
    # Template repositories to manage
    template_repos = [
        {
            "name": "official",
            "url": "https://github.com/projectdiscovery/nuclei-templates.git",
            "path": Path.home() / "nuclei-templates"
        },
        {
            "name": "community",
            "url": "https://github.com/geeknik/the-nuclei-templates.git", 
            "path": Path.home() / "nuclei-community"
        },
        {
            "name": "fuzzing",
            "url": "https://github.com/projectdiscovery/fuzzing-templates.git",
            "path": Path.home() / "nuclei-fuzzing"
        },
        {
            "name": "custom",
            "url": "https://github.com/panch0r3d/nuclei-templates.git",
            "path": Path.home() / "custom-nuclei"
        },
        {
            "name": "ksec",
            "url": "https://github.com/knightsec/nuclei-templates-ksec.git",
            "path": Path.home() / "nuclei-ksec"
        }
    ]
    
    results = {
        "template_sources": {},
        "statistics": {},
        "custom_templates_created": 0,
        "total_templates": 0
    }
    
    # Update/clone template repositories
    for repo in template_repos:
        print(f"[NUCLEI] Managing {repo['name']} templates...")
        try:
            if repo["path"].exists() and (repo["path"] / ".git").exists():
                print(f"[NUCLEI] Updating {repo['name']} templates")
                subprocess.run(
                    ["git", "pull", "--quiet"], 
                    cwd=repo["path"], 
                    timeout=300,
                    capture_output=True
                )
            else:
                print(f"[NUCLEI] Cloning {repo['name']} templates")
                repo["path"].parent.mkdir(parents=True, exist_ok=True)
                subprocess.run([
                    "git", "clone", "--depth", "1", 
                    repo["url"], str(repo["path"])
                ], timeout=600, capture_output=True)
            
            # Count templates
            template_count = count_templates(repo["path"])
            results["template_sources"][repo["name"]] = {
                "path": str(repo["path"]),
                "template_count": template_count,
                "status": "success"
            }
            results["total_templates"] += template_count
            
        except Exception as e:
            print(f"[NUCLEI] Error managing {repo['name']}: {e}")
            results["template_sources"][repo["name"]] = {
                "status": "failed",
                "error": str(e)
            }
    
    # Create custom templates for common vulnerabilities
    custom_templates = create_custom_templates(template_dir)
    results["custom_templates_created"] = len(custom_templates)
    
    # Generate template statistics
    results["statistics"] = generate_template_statistics(template_repos)
    
    # Update nuclei templates cache
    try:
        print("[NUCLEI] Updating nuclei templates cache...")
        subprocess.run(["nuclei", "-update-templates"], timeout=300, capture_output=True)
        results["cache_updated"] = True
    except Exception as e:
        print(f"[NUCLEI] Failed to update cache: {e}")
        results["cache_updated"] = False
    
    # Save results
    results_file = template_dir / "template_management_results.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"[NUCLEI] Template management complete. Total templates: {results['total_templates']}")
    return results

def count_templates(template_path: Path) -> int:
    """Count nuclei templates in a directory"""
    if not template_path.exists():
        return 0
    
    template_count = 0
    for template_file in template_path.rglob("*.yaml"):
        try:
            with open(template_file, 'r') as f:
                content = f.read()
                if 'id:' in content and 'info:' in content:
                    template_count += 1
        except:
            continue
    
    return template_count

def create_custom_templates(template_dir: Path) -> List[str]:
    """Create custom nuclei templates for enhanced testing"""
    custom_dir = template_dir / "custom"
    custom_dir.mkdir(exist_ok=True)
    
    templates = []
    
    # Enhanced security headers template
    security_headers_template = """id: enhanced-security-headers

info:
  name: Enhanced Security Headers Check
  author: bl4ckc3ll-pantheon
  severity: info
  description: Comprehensive security headers analysis
  tags: headers,security,misconfiguration

requests:
  - method: GET
    path:
      - "{{BaseURL}}"
    
    matchers:
      - type: dsl
        dsl:
          - "!contains(tolower(header), 'x-frame-options')"
          - "!contains(tolower(header), 'x-content-type-options')"
          - "!contains(tolower(header), 'x-xss-protection')"
          - "!contains(tolower(header), 'strict-transport-security')"
          - "!contains(tolower(header), 'content-security-policy')"
        condition: or
        
    extractors:
      - type: kval
        kval:
          - header
"""
    
    template_file = custom_dir / "enhanced-security-headers.yaml"
    with open(template_file, 'w') as f:
        f.write(security_headers_template)
    templates.append(str(template_file))
    
    # Admin panel discovery template
    admin_discovery_template = """id: admin-panel-discovery

info:
  name: Admin Panel Discovery
  author: bl4ckc3ll-pantheon
  severity: info
  description: Discover common admin panel locations
  tags: admin,panel,discovery

requests:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
      - "{{BaseURL}}/administrator"
      - "{{BaseURL}}/admin.php"
      - "{{BaseURL}}/wp-admin"
      - "{{BaseURL}}/phpmyadmin"
      - "{{BaseURL}}/cpanel"
      - "{{BaseURL}}/control"
      - "{{BaseURL}}/dashboard"
      - "{{BaseURL}}/manager"
      - "{{BaseURL}}/admin-panel"
    
    matchers:
      - type: status
        status:
          - 200
          - 401
          - 403
        
      - type: word
        words:
          - "admin"
          - "login"
          - "dashboard"
          - "control panel"
        condition: or
"""
    
    template_file = custom_dir / "admin-panel-discovery.yaml"
    with open(template_file, 'w') as f:
        f.write(admin_discovery_template)
    templates.append(str(template_file))
    
    # Backup file discovery template  
    backup_discovery_template = """id: backup-file-discovery

info:
  name: Backup File Discovery
  author: bl4ckc3ll-pantheon
  severity: medium
  description: Discover common backup file locations
  tags: backup,files,exposure

requests:
  - method: GET
    path:
      - "{{BaseURL}}/backup.zip"
      - "{{BaseURL}}/backup.tar.gz" 
      - "{{BaseURL}}/backup.sql"
      - "{{BaseURL}}/database.sql"
      - "{{BaseURL}}/db.sql"
      - "{{BaseURL}}/site.zip"
      - "{{BaseURL}}/www.zip"
      - "{{BaseURL}}/backup.txt"
      - "{{BaseURL}}/.backup"
      - "{{BaseURL}}/backup/"
    
    matchers:
      - type: status
        status:
          - 200
        
      - type: word
        words:
          - "backup"
          - "database"
          - "dump"
        condition: or
"""
    
    template_file = custom_dir / "backup-file-discovery.yaml"
    with open(template_file, 'w') as f:
        f.write(backup_discovery_template)
    templates.append(str(template_file))
    
    return templates

def generate_template_statistics(template_repos: List[Dict]) -> Dict[str, Any]:
    """Generate statistics about available templates"""
    stats = {
        "total_repositories": len(template_repos),
        "categories": {},
        "severity_distribution": {}
    }
    
    # Analyze templates by category and severity
    for repo in template_repos:
        if not repo["path"].exists():
            continue
            
        for template_file in repo["path"].rglob("*.yaml"):
            try:
                with open(template_file, 'r') as f:
                    content = yaml.safe_load(f)
                    
                if not content or 'info' not in content:
                    continue
                    
                info = content['info']
                
                # Count by tags/categories
                tags = info.get('tags', [])
                if isinstance(tags, str):
                    tags = [tags]
                
                for tag in tags:
                    if tag not in stats["categories"]:
                        stats["categories"][tag] = 0
                    stats["categories"][tag] += 1
                
                # Count by severity
                severity = info.get('severity', 'unknown')
                if severity not in stats["severity_distribution"]:
                    stats["severity_distribution"][severity] = 0
                stats["severity_distribution"][severity] += 1
                
            except Exception:
                continue
    
    return stats