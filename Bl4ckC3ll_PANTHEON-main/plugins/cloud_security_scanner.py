# Plugin: Cloud Security Scanner
# Comprehensive cloud security assessment for AWS, Azure, GCP
from pathlib import Path
from typing import Dict, Any, List
import json
import subprocess
import time
from urllib.parse import urlparse
import re

plugin_info = {
    "name": "Cloud Security Scanner",
    "description": "Multi-cloud security assessment including storage buckets, metadata, and misconfigurations",
    "version": "1.0.0",
    "author": "@cxb3rf1lth", 
    "category": "cloud_security",
    "requires_internet": True,
    "risk_level": "medium"
}

def execute(run_dir: Path, env: Dict[str, str], cfg: Dict[str, Any]):
    """Execute comprehensive cloud security scanning"""
    cloud_dir = run_dir / "cloud_security"
    cloud_dir.mkdir(exist_ok=True)
    
    # Read targets
    targets_file = Path(__file__).parent.parent / "targets.txt"
    if not targets_file.exists():
        print("[CLOUD] No targets file found")
        return
    
    targets = []
    with open(targets_file, 'r') as f:
        for line in f:
            target = line.strip()
            if target and not target.startswith('#'):
                targets.append(target)
    
    if not targets:
        print("[CLOUD] No targets found")
        return
    
    results = {}
    
    for target in targets:
        print(f"[CLOUD] Scanning target: {target}")
        target_results = {}
        
        # Extract domain for generating potential cloud resource names
        if target.startswith('http'):
            parsed = urlparse(target)
            domain = parsed.netloc
        else:
            domain = target
        
        base_name = domain.replace('.', '-').replace('_', '-')
        
        # 1. AWS S3 Bucket Discovery and Testing
        try:
            s3_results = scan_aws_s3_buckets(base_name, domain)
            target_results["aws_s3"] = s3_results
        except Exception as e:
            print(f"[CLOUD] AWS S3 scanning error: {e}")
        
        # 2. Azure Storage Account Testing
        try:
            azure_results = scan_azure_storage(base_name, domain)
            target_results["azure_storage"] = azure_results
        except Exception as e:
            print(f"[CLOUD] Azure storage scanning error: {e}")
        
        # 3. Google Cloud Storage Testing
        try:
            gcs_results = scan_gcp_storage(base_name, domain)
            target_results["gcp_storage"] = gcs_results
        except Exception as e:
            print(f"[CLOUD] GCP storage scanning error: {e}")
        
        # 4. Cloud Metadata Service Testing
        try:
            metadata_results = test_cloud_metadata(target)
            target_results["cloud_metadata"] = metadata_results
        except Exception as e:
            print(f"[CLOUD] Metadata service testing error: {e}")
        
        # 5. Container Registry Discovery
        try:
            registry_results = scan_container_registries(base_name)
            target_results["container_registries"] = registry_results
        except Exception as e:
            print(f"[CLOUD] Container registry scanning error: {e}")
        
        # 6. Kubernetes/Docker Exposure Detection
        try:
            k8s_results = scan_kubernetes_exposure(target)
            target_results["kubernetes_exposure"] = k8s_results
        except Exception as e:
            print(f"[CLOUD] Kubernetes exposure scanning error: {e}")
        
        results[target] = target_results
    
    # Save results
    output_file = cloud_dir / "cloud_security_results.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"[CLOUD] Cloud security results saved to: {output_file}")

def scan_aws_s3_buckets(base_name: str, domain: str) -> Dict[str, Any]:
    """Scan for AWS S3 bucket misconfigurations"""
    results = {
        "buckets_tested": [],
        "accessible_buckets": [],
        "bucket_policies": [],
        "timestamp": time.time()
    }
    
    # Generate potential bucket names
    bucket_variations = [
        base_name,
        f"{base_name}-backup",
        f"{base_name}-backups", 
        f"{base_name}-data",
        f"{base_name}-files",
        f"{base_name}-images",
        f"{base_name}-assets",
        f"{base_name}-static",
        f"{base_name}-uploads",
        f"{base_name}-dev",
        f"{base_name}-prod",
        f"{base_name}-production",
        f"{base_name}-test",
        f"{base_name}-staging",
        f"{base_name}-logs",
        f"{base_name}-config",
        f"{base_name}-private",
        f"{base_name}-public"
    ]
    
    for bucket_name in bucket_variations:
        try:
            # Test bucket existence and accessibility
            s3_urls = [
                f"https://{bucket_name}.s3.amazonaws.com/",
                f"https://s3.amazonaws.com/{bucket_name}/",
                f"https://{bucket_name}.s3-us-west-2.amazonaws.com/",
                f"https://{bucket_name}.s3-eu-west-1.amazonaws.com/"
            ]
            
            for s3_url in s3_urls:
                bucket_info = {
                    "name": bucket_name,
                    "url": s3_url,
                    "accessible": False,
                    "public_read": False,
                    "public_write": False,
                    "contents": []
                }
                
                # Test bucket accessibility
                cmd = ["curl", "-s", "-I", "--max-time", "10", s3_url]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                
                if result.returncode == 0:
                    status_line = result.stdout.split('\n')[0] if result.stdout else ""
                    
                    if "200" in status_line:
                        bucket_info["accessible"] = True
                        bucket_info["public_read"] = True
                        
                        # Get bucket contents
                        content_cmd = ["curl", "-s", "--max-time", "15", s3_url]
                        content_result = subprocess.run(content_cmd, capture_output=True, text=True, timeout=20)
                        
                        if content_result.returncode == 0 and content_result.stdout:
                            # Parse XML response for file listings
                            content = content_result.stdout
                            
                            # Look for XML keys indicating files
                            key_pattern = r'<Key>([^<]+)</Key>'
                            files = re.findall(key_pattern, content)
                            bucket_info["contents"] = files[:20]  # Limit to first 20 files
                            
                            # Look for sensitive files
                            sensitive_patterns = [
                                'config', 'secret', 'key', 'password', 'credential',
                                '.env', 'backup', 'dump', 'database', 'private'
                            ]
                            
                            sensitive_files = []
                            for file in files:
                                if any(pattern in file.lower() for pattern in sensitive_patterns):
                                    sensitive_files.append(file)
                            
                            bucket_info["sensitive_files"] = sensitive_files
                        
                        results["accessible_buckets"].append(bucket_info)
                    
                    elif "403" in status_line:
                        bucket_info["accessible"] = False
                        bucket_info["exists"] = True
                        bucket_info["status"] = "exists_but_protected"
                        results["accessible_buckets"].append(bucket_info)
                
                results["buckets_tested"].append(bucket_name)
                
                # Test write permissions (carefully)
                if bucket_info.get("accessible"):
                    test_write_cmd = [
                        "curl", "-s", "-X", "PUT", 
                        "--max-time", "10",
                        f"{s3_url}test-write-permission.txt",
                        "-d", "test"
                    ]
                    
                    write_result = subprocess.run(test_write_cmd, capture_output=True, text=True, timeout=15)
                    
                    if write_result.returncode == 0 and "200" in str(write_result.stdout):
                        bucket_info["public_write"] = True
                        
                        # Clean up test file
                        delete_cmd = ["curl", "-s", "-X", "DELETE", f"{s3_url}test-write-permission.txt"]
                        subprocess.run(delete_cmd, capture_output=True, text=True, timeout=10)
                
                break  # Found the bucket, no need to test other URL formats
                
        except Exception as e:
            continue
    
    return results

def scan_azure_storage(base_name: str, domain: str) -> Dict[str, Any]:
    """Scan for Azure Storage Account misconfigurations"""
    results = {
        "accounts_tested": [],
        "accessible_accounts": [],
        "timestamp": time.time()
    }
    
    # Generate potential storage account names
    account_variations = [
        base_name.replace('-', ''),  # Azure storage accounts don't allow hyphens
        f"{base_name.replace('-', '')}data",
        f"{base_name.replace('-', '')}files",
        f"{base_name.replace('-', '')}backup",
        f"{base_name.replace('-', '')}storage",
        f"{base_name.replace('-', '')}dev",
        f"{base_name.replace('-', '')}prod"
    ]
    
    for account_name in account_variations:
        # Remove any invalid characters
        clean_name = re.sub(r'[^a-z0-9]', '', account_name.lower())[:24]  # Max 24 chars
        
        if len(clean_name) < 3:  # Minimum length requirement
            continue
        
        try:
            # Test blob storage
            blob_url = f"https://{clean_name}.blob.core.windows.net/"
            
            account_info = {
                "name": clean_name,
                "blob_url": blob_url,
                "accessible": False,
                "containers": []
            }
            
            # Test account accessibility
            cmd = ["curl", "-s", "-I", "--max-time", "10", blob_url]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                if "200" in result.stdout or "400" in result.stdout:
                    account_info["accessible"] = True
                    
                    # Test common container names
                    container_names = ["public", "files", "images", "data", "backup", "logs"]
                    
                    for container in container_names:
                        container_url = f"{blob_url}{container}/"
                        
                        container_cmd = ["curl", "-s", "-I", "--max-time", "10", container_url]
                        container_result = subprocess.run(container_cmd, capture_output=True, text=True, timeout=15)
                        
                        if container_result.returncode == 0 and "200" in container_result.stdout:
                            account_info["containers"].append({
                                "name": container,
                                "url": container_url,
                                "public": True
                            })
                    
                    results["accessible_accounts"].append(account_info)
            
            results["accounts_tested"].append(clean_name)
            
        except Exception as e:
            continue
    
    return results

def scan_gcp_storage(base_name: str, domain: str) -> Dict[str, Any]:
    """Scan for Google Cloud Storage misconfigurations"""
    results = {
        "buckets_tested": [],
        "accessible_buckets": [],
        "timestamp": time.time()
    }
    
    # Generate potential bucket names
    bucket_variations = [
        base_name,
        f"{base_name}-backup",
        f"{base_name}-data",
        f"{base_name}-files",
        f"{base_name}-static",
        f"{base_name}-uploads",
        f"{base_name}-dev",
        f"{base_name}-prod",
        f"{domain.replace('.', '-')}"
    ]
    
    for bucket_name in bucket_variations:
        try:
            # Test GCS bucket
            gcs_urls = [
                f"https://storage.googleapis.com/{bucket_name}/",
                f"https://{bucket_name}.storage.googleapis.com/"
            ]
            
            for gcs_url in gcs_urls:
                bucket_info = {
                    "name": bucket_name,
                    "url": gcs_url,
                    "accessible": False,
                    "public": False,
                    "objects": []
                }
                
                cmd = ["curl", "-s", "-I", "--max-time", "10", gcs_url]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                
                if result.returncode == 0:
                    if "200" in result.stdout:
                        bucket_info["accessible"] = True
                        bucket_info["public"] = True
                        
                        # Get bucket contents
                        content_cmd = ["curl", "-s", "--max-time", "15", gcs_url]
                        content_result = subprocess.run(content_cmd, capture_output=True, text=True, timeout=20)
                        
                        if content_result.returncode == 0 and content_result.stdout:
                            # Parse XML response
                            content = content_result.stdout
                            
                            # Look for object names
                            name_pattern = r'<Name>([^<]+)</Name>'
                            objects = re.findall(name_pattern, content)
                            bucket_info["objects"] = objects[:20]
                        
                        results["accessible_buckets"].append(bucket_info)
                    
                    elif "403" in result.stdout:
                        bucket_info["accessible"] = False
                        bucket_info["exists"] = True
                        results["accessible_buckets"].append(bucket_info)
                
                break
            
            results["buckets_tested"].append(bucket_name)
            
        except Exception as e:
            continue
    
    return results

def test_cloud_metadata(target: str) -> Dict[str, Any]:
    """Test for cloud metadata service exposure"""
    results = {
        "aws_metadata": {},
        "azure_metadata": {},
        "gcp_metadata": {},
        "timestamp": time.time()
    }
    
    # This would typically be tested from within a cloud instance
    # Here we'll test for SSRF that could lead to metadata access
    
    metadata_urls = [
        "http://169.254.169.254/",  # AWS/Azure metadata
        "http://169.254.169.254/latest/meta-data/",  # AWS
        "http://169.254.169.254/metadata/instance/",  # Azure
        "http://metadata.google.internal/",  # GCP
        "http://metadata/computeMetadata/v1/"  # GCP
    ]
    
    base_url = target.rstrip('/')
    
    # Test if target might be vulnerable to SSRF leading to metadata access
    test_endpoints = ["/proxy", "/fetch", "/url", "/redirect", "/image"]
    
    for endpoint in test_endpoints:
        test_url = f"{base_url}{endpoint}"
        
        for metadata_url in metadata_urls:
            try:
                # Test SSRF to metadata service
                cmd = ["curl", "-s", "--max-time", "10", f"{test_url}?url={metadata_url}"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                
                if result.returncode == 0 and result.stdout:
                    content = result.stdout.lower()
                    
                    # Check for metadata indicators
                    metadata_indicators = [
                        'ami-id', 'instance-id', 'security-credentials',
                        'hostname', 'local-ipv4', 'public-ipv4',
                        'subscription', 'resourcegroupname', 'vmid',
                        'project-id', 'numeric-project-id', 'service-accounts'
                    ]
                    
                    if any(indicator in content for indicator in metadata_indicators):
                        if '169.254.169.254' in metadata_url:
                            if 'ami-' in content or 'instance-' in content:
                                results["aws_metadata"]["ssrf_possible"] = True
                                results["aws_metadata"]["endpoint"] = endpoint
                            elif 'subscription' in content or 'resourcegroup' in content:
                                results["azure_metadata"]["ssrf_possible"] = True
                                results["azure_metadata"]["endpoint"] = endpoint
                        elif 'metadata.google.internal' in metadata_url:
                            results["gcp_metadata"]["ssrf_possible"] = True
                            results["gcp_metadata"]["endpoint"] = endpoint
            
            except Exception:
                continue
    
    return results

def scan_container_registries(base_name: str) -> Dict[str, Any]:
    """Scan for exposed container registries"""
    results = {
        "docker_hub": [],
        "aws_ecr": [],
        "azure_acr": [],
        "gcp_gcr": [],
        "timestamp": time.time()
    }
    
    # Test Docker Hub
    docker_orgs = [base_name, base_name.replace('-', '')]
    
    for org in docker_orgs:
        try:
            # Docker Hub API
            hub_url = f"https://hub.docker.com/v2/repositories/{org}/"
            
            cmd = ["curl", "-s", "--max-time", "10", hub_url]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0 and result.stdout:
                try:
                    data = json.loads(result.stdout)
                    if "results" in data:
                        results["docker_hub"].append({
                            "organization": org,
                            "repositories": len(data.get("results", [])),
                            "public": True
                        })
                except Exception as e:
                    logging.warning(f"Unexpected error: {e}")
                    # Consider if this error should be handled differently
        except Exception:
            continue
    
    # Test AWS ECR (public registries)
    ecr_names = [base_name, f"{base_name}-app"]
    
    for registry in ecr_names:
        try:
            ecr_url = f"https://gallery.ecr.aws/{registry}"
            
            cmd = ["curl", "-s", "-I", "--max-time", "10", ecr_url]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0 and "200" in result.stdout:
                results["aws_ecr"].append({
                    "registry": registry,
                    "url": ecr_url,
                    "accessible": True
                })
        
        except Exception:
            continue
    
    return results

def scan_kubernetes_exposure(target: str) -> Dict[str, Any]:
    """Scan for Kubernetes API and Dashboard exposure"""
    results = {
        "api_server": {},
        "dashboard": {},
        "etcd": {},
        "timestamp": time.time()
    }
    
    base_url = target.rstrip('/')
    parsed = urlparse(target if target.startswith('http') else f"http://{target}")
    host = parsed.netloc or target
    
    # Common Kubernetes ports and endpoints
    k8s_tests = [
        {"port": "6443", "endpoint": "/api/v1", "service": "API Server"},
        {"port": "8080", "endpoint": "/api", "service": "Insecure API"},
        {"port": "10250", "endpoint": "/pods", "service": "Kubelet API"},
        {"port": "2379", "endpoint": "/v2/keys", "service": "etcd"},
        {"port": "8001", "endpoint": "/api/v1/namespaces/kube-system/services/kubernetes-dashboard/proxy/", "service": "Dashboard Proxy"}
    ]
    
    for test in k8s_tests:
        try:
            test_url = f"http://{host}:{test['port']}{test['endpoint']}"
            
            cmd = ["curl", "-s", "-k", "--max-time", "10", "-w", "%{http_code}", test_url]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                status_code = lines[-1] if lines else "000"
                content = '\n'.join(lines[:-1]) if len(lines) > 1 else ""
                
                if status_code.startswith(('2', '4')):  # 2xx or 4xx responses indicate service is running
                    service_info = {
                        "port": test["port"],
                        "endpoint": test["endpoint"],
                        "status_code": status_code,
                        "accessible": True
                    }
                    
                    # Check for authentication
                    if "unauthorized" in content.lower() or "forbidden" in content.lower():
                        service_info["authentication"] = "required"
                    elif status_code.startswith('2'):
                        service_info["authentication"] = "none"
                        service_info["response_sample"] = content[:500]
                    
                    if test["service"] == "API Server":
                        results["api_server"] = service_info
                    elif test["service"] == "etcd":
                        results["etcd"] = service_info
                    elif "Dashboard" in test["service"]:
                        results["dashboard"] = service_info
        
        except Exception:
            continue
    
    # Test for Docker daemon exposure
    try:
        docker_url = f"http://{host}:2376/version"
        
        cmd = ["curl", "-s", "--max-time", "10", docker_url]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0 and "docker" in result.stdout.lower():
            results["docker_daemon"] = {
                "port": "2376",
                "accessible": True,
                "version_info": result.stdout
            }
    
    except Exception as e:
            logging.warning(f"Operation failed: {e}")
            # Consider if this error should be handled differently
    return results