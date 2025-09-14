# Plugin: Enhanced Fuzzing Suite
# Comprehensive fuzzing with multiple tools and advanced wordlists
from pathlib import Path
from typing import Dict, Any, List
import json
import subprocess
import time
import shutil

plugin_info = {
    "name": "Enhanced Fuzzing Suite",
    "description": "Comprehensive directory and file fuzzing with multiple tools and wordlists",
    "version": "1.0.0", 
    "author": "@cxb3rf1lth",
    "category": "fuzzing",
    "requires_internet": False,
    "risk_level": "low"
}

def execute(run_dir: Path, env: Dict[str, str], cfg: Dict[str, Any]):
    """Execute comprehensive fuzzing with multiple tools"""
    fuzzing_dir = run_dir / "enhanced_fuzzing"
    fuzzing_dir.mkdir(exist_ok=True)
    
    # Read targets
    targets_file = Path(__file__).parent.parent / "targets.txt"
    if not targets_file.exists():
        print("[FUZZING] No targets file found")
        return
    
    targets = []
    with open(targets_file, 'r') as f:
        for line in f:
            target = line.strip()
            if target and not target.startswith('#'):
                targets.append(target)
    
    if not targets:
        print("[FUZZING] No targets found")
        return
    
    results = {
        "targets_scanned": len(targets),
        "tools_used": [],
        "total_endpoints_found": 0,
        "results_by_target": {}
    }
    
    # Get fuzzing configuration
    fuzzing_cfg = cfg.get("fuzzing", {})
    
    for target in targets:
        print(f"[FUZZING] Starting enhanced fuzzing for: {target}")
        target_results = {}
        
        target_url = target if target.startswith("http") else f"http://{target}"
        target_dir = fuzzing_dir / target.replace(".", "_").replace("/", "_")
        target_dir.mkdir(exist_ok=True)
        
        # 1. FFUF Fuzzing
        if fuzzing_cfg.get("enable_ffuf", True) and shutil.which("ffuf"):
            print("[FUZZING] Running FFUF directory fuzzing...")
            ffuf_results = run_ffuf_fuzzing(target_url, target_dir, env, fuzzing_cfg)
            target_results["ffuf"] = ffuf_results
            results["tools_used"].append("ffuf")
        
        # 2. Feroxbuster Fuzzing
        if fuzzing_cfg.get("enable_feroxbuster", True) and shutil.which("feroxbuster"):
            print("[FUZZING] Running Feroxbuster fuzzing...")
            ferox_results = run_feroxbuster_fuzzing(target_url, target_dir, env, fuzzing_cfg)
            target_results["feroxbuster"] = ferox_results
            results["tools_used"].append("feroxbuster")
        
        # 3. Gobuster Fuzzing
        if fuzzing_cfg.get("enable_gobuster", True) and shutil.which("gobuster"):
            print("[FUZZING] Running Gobuster directory fuzzing...")
            gobuster_results = run_gobuster_fuzzing(target_url, target_dir, env, fuzzing_cfg)
            target_results["gobuster"] = gobuster_results
            results["tools_used"].append("gobuster")
        
        # 4. Dirb Fuzzing  
        if fuzzing_cfg.get("enable_dirb", True) and shutil.which("dirb"):
            print("[FUZZING] Running Dirb fuzzing...")
            dirb_results = run_dirb_fuzzing(target_url, target_dir, env, fuzzing_cfg)
            target_results["dirb"] = dirb_results
            results["tools_used"].append("dirb")
        
        # 5. Parameter Fuzzing
        if fuzzing_cfg.get("parameter_fuzzing", True):
            print("[FUZZING] Running parameter fuzzing...")
            param_results = run_parameter_fuzzing(target_url, target_dir, env, fuzzing_cfg)
            target_results["parameters"] = param_results
        
        # 6. Subdomain Fuzzing
        if fuzzing_cfg.get("subdomain_fuzzing", True):
            print("[FUZZING] Running subdomain fuzzing...")
            subdomain_results = run_subdomain_fuzzing(target, target_dir, env, fuzzing_cfg)
            target_results["subdomains"] = subdomain_results
        
        # Count total endpoints found
        total_endpoints = 0
        for tool_results in target_results.values():
            if isinstance(tool_results, dict) and "endpoints_found" in tool_results:
                total_endpoints += tool_results["endpoints_found"]
        
        target_results["total_endpoints"] = total_endpoints
        results["results_by_target"][target] = target_results
        results["total_endpoints_found"] += total_endpoints
    
    # Remove duplicates from tools_used
    results["tools_used"] = list(set(results["tools_used"]))
    
    # Save comprehensive results
    results_file = fuzzing_dir / "enhanced_fuzzing_results.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"[FUZZING] Enhanced fuzzing complete. Total endpoints found: {results['total_endpoints_found']}")
    return results

def get_wordlists() -> Dict[str, Path]:
    """Get available wordlists for fuzzing"""
    base_path = Path(__file__).parent.parent
    wordlists = {}
    
    # Priority order wordlists
    wordlist_candidates = [
        # Merged lists (highest priority)
        base_path / "lists_merged" / "directories_merged.txt",
        base_path / "lists_merged" / "files_merged.txt",
        
        # SecLists
        base_path / "external_lists" / "SecLists" / "Discovery" / "Web-Content" / "directory-list-2.3-medium.txt",
        base_path / "external_lists" / "SecLists" / "Discovery" / "Web-Content" / "common.txt",
        base_path / "external_lists" / "SecLists" / "Discovery" / "Web-Content" / "raft-medium-files.txt",
        
        # OneListForAll
        base_path / "external_lists" / "OneListForAll" / "onelistforall.txt",
        
        # Custom wordlists
        base_path / "wordlists_extra" / "paths_extra.txt",
        
        # Fallback
        Path("/usr/share/wordlists/dirb/common.txt"),
        Path("/usr/share/dirb/wordlists/common.txt")
    ]
    
    for wordlist in wordlist_candidates:
        if wordlist.exists() and wordlist.stat().st_size > 0:
            category = "directories" if "directory" in wordlist.name.lower() else "files"
            if category not in wordlists:
                wordlists[category] = wordlist
    
    return wordlists

def run_ffuf_fuzzing(target: str, output_dir: Path, env: Dict[str, str], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Run FFUF fuzzing with enhanced configuration"""
    wordlists = get_wordlists()
    results = {"endpoints_found": 0, "status_codes": {}, "interesting_files": []}
    
    for category, wordlist in wordlists.items():
        output_file = output_dir / f"ffuf_{category}.json"
        
        target_fuzz = target.rstrip('/') + '/FUZZ'
        
        cmd = [
            "ffuf", 
            "-u", target_fuzz,
            "-w", str(wordlist),
            "-o", str(output_file),
            "-of", "json",
            "-mc", cfg.get("status_codes", "200,201,202,204,301,302,303,307,308,401,403,405"),
            "-fs", "0",
            "-t", str(cfg.get("threads", 50)),
            "-timeout", "10",
            "-s"  # Silent mode
        ]
        
        # Add extensions for file fuzzing
        if category == "files":
            extensions = cfg.get("extensions", "php,asp,aspx,jsp,html,htm,txt,bak,old,conf")
            cmd.extend(["-e", extensions])
        
        try:
            subprocess.run(cmd, timeout=1200, cwd=output_dir, env=env, capture_output=True)
            
            # Parse results
            if output_file.exists():
                with open(output_file, 'r') as f:
                    ffuf_data = json.load(f)
                    
                for result in ffuf_data.get("results", []):
                    results["endpoints_found"] += 1
                    status = result.get("status", 0)
                    if status not in results["status_codes"]:
                        results["status_codes"][status] = 0
                    results["status_codes"][status] += 1
                    
                    # Identify interesting files
                    url = result.get("url", "")
                    if any(ext in url.lower() for ext in [".bak", ".old", ".conf", ".config", ".sql", ".zip"]):
                        results["interesting_files"].append(url)
        
        except Exception as e:
            results[f"error_{category}"] = str(e)
    
    return results

def run_feroxbuster_fuzzing(target: str, output_dir: Path, env: Dict[str, str], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Run Feroxbuster fuzzing"""
    wordlists = get_wordlists()
    results = {"endpoints_found": 0, "directories": [], "files": []}
    
    wordlist = wordlists.get("directories")
    if not wordlist:
        return {"error": "No wordlist found for feroxbuster"}
    
    output_file = output_dir / "feroxbuster_results.txt"
    
    cmd = [
        "feroxbuster",
        "-u", target,
        "-w", str(wordlist),
        "-o", str(output_file),
        "-t", str(cfg.get("threads", 50)),
        "-s", cfg.get("status_codes", "200,204,301,302,307,308,401,403,405,500"),
        "--auto-tune",
        "--no-recursion" if not cfg.get("recursive_fuzzing", True) else "-r"
    ]
    
    # Add extensions
    extensions = cfg.get("extensions", "php,asp,aspx,jsp,html,htm,txt")
    if extensions:
        cmd.extend(["-x", extensions])
    
    try:
        subprocess.run(cmd, timeout=1200, cwd=output_dir, env=env, capture_output=True)
        
        # Parse results
        if output_file.exists():
            with open(output_file, 'r') as f:
                for line in f:
                    if "200" in line or "301" in line or "302" in line:
                        results["endpoints_found"] += 1
                        if line.strip().endswith('/'):
                            results["directories"].append(line.strip())
                        else:
                            results["files"].append(line.strip())
    
    except Exception as e:
        results["error"] = str(e)
    
    return results

def run_gobuster_fuzzing(target: str, output_dir: Path, env: Dict[str, str], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Run Gobuster directory fuzzing"""
    wordlists = get_wordlists()
    results = {"endpoints_found": 0, "directories": [], "files": []}
    
    wordlist = wordlists.get("directories")
    if not wordlist:
        return {"error": "No wordlist found for gobuster"}
    
    output_file = output_dir / "gobuster_results.txt"
    
    cmd = [
        "gobuster", "dir",
        "-u", target,
        "-w", str(wordlist),
        "-o", str(output_file),
        "-t", str(cfg.get("threads", 50)),
        "-s", cfg.get("status_codes", "200,204,301,302,307,308,401,403,405,500"),
        "-q"  # Quiet mode
    ]
    
    # Add extensions
    extensions = cfg.get("extensions", "php,asp,aspx,jsp,html,htm,txt")
    if extensions:
        cmd.extend(["-x", extensions])
    
    try:
        subprocess.run(cmd, timeout=1200, cwd=output_dir, env=env, capture_output=True)
        
        # Parse results
        if output_file.exists():
            with open(output_file, 'r') as f:
                for line in f:
                    if "(Status:" in line:
                        results["endpoints_found"] += 1
                        if line.strip().endswith('/'):
                            results["directories"].append(line.strip())
                        else:
                            results["files"].append(line.strip())
    
    except Exception as e:
        results["error"] = str(e)
    
    return results

def run_dirb_fuzzing(target: str, output_dir: Path, env: Dict[str, str], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Run Dirb fuzzing"""
    wordlists = get_wordlists()
    results = {"endpoints_found": 0, "directories": []}
    
    wordlist = wordlists.get("directories")
    if not wordlist:
        # Fallback to system wordlist
        wordlist = Path("/usr/share/wordlists/dirb/common.txt")
        if not wordlist.exists():
            return {"error": "No wordlist found for dirb"}
    
    output_file = output_dir / "dirb_results.txt"
    
    cmd = [
        "dirb", target, str(wordlist),
        "-o", str(output_file),
        "-w"  # Don't stop on warning
    ]
    
    try:
        subprocess.run(cmd, timeout=1200, cwd=output_dir, env=env, capture_output=True)
        
        # Parse results  
        if output_file.exists():
            with open(output_file, 'r') as f:
                content = f.read()
                # Count found directories
                lines = content.split('\n')
                for line in lines:
                    if "==> DIRECTORY:" in line or "CODE:200" in line:
                        results["endpoints_found"] += 1
                        results["directories"].append(line.strip())
    
    except Exception as e:
        results["error"] = str(e)
    
    return results

def run_parameter_fuzzing(target: str, output_dir: Path, env: Dict[str, str], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Run parameter fuzzing"""
    results = {"parameters_found": 0, "parameters": []}
    
    # Use arjun if available
    if shutil.which("arjun"):
        output_file = output_dir / "arjun_parameters.txt"
        
        cmd = [
            "arjun",
            "-u", target,
            "-o", str(output_file),
            "-t", str(cfg.get("threads", 20))
        ]
        
        try:
            subprocess.run(cmd, timeout=600, cwd=output_dir, env=env, capture_output=True)
            
            if output_file.exists():
                with open(output_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            results["parameters_found"] += 1
                            results["parameters"].append(line.strip())
        
        except Exception as e:
            results["error"] = str(e)
    
    return results

def run_subdomain_fuzzing(target: str, output_dir: Path, env: Dict[str, str], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Run subdomain fuzzing"""
    results = {"subdomains_found": 0, "subdomains": []}
    
    # Extract domain from target
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    
    # Get subdomain wordlist
    base_path = Path(__file__).parent.parent
    subdomain_wordlists = [
        base_path / "external_lists" / "SecLists" / "Discovery" / "DNS" / "subdomains-top1million-110000.txt",
        base_path / "external_lists" / "commonspeak2-wordlists" / "subdomains" / "subdomains.txt"
    ]
    
    wordlist = None
    for wl in subdomain_wordlists:
        if wl.exists():
            wordlist = wl
            break
    
    if not wordlist:
        return {"error": "No subdomain wordlist found"}
    
    # Use ffuf for subdomain fuzzing
    if shutil.which("ffuf"):
        output_file = output_dir / "subdomain_fuzzing.json"
        
        cmd = [
            "ffuf",
            "-u", f"http://FUZZ.{domain}",
            "-w", str(wordlist),
            "-o", str(output_file),
            "-of", "json",
            "-mc", "200,201,202,204,301,302,303,307,308,401,403,405",
            "-t", str(cfg.get("threads", 50)),
            "-timeout", "10",
            "-s"
        ]
        
        try:
            subprocess.run(cmd, timeout=600, cwd=output_dir, env=env, capture_output=True)
            
            if output_file.exists():
                with open(output_file, 'r') as f:
                    ffuf_data = json.load(f)
                    
                for result in ffuf_data.get("results", []):
                    results["subdomains_found"] += 1
                    subdomain = result.get("input", {}).get("FUZZ", "")
                    if subdomain:
                        results["subdomains"].append(f"{subdomain}.{domain}")
        
        except Exception as e:
            results["error"] = str(e)
    
    return results