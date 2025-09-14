# Plugin: API Security Scanner
# Advanced API security testing and vulnerability detection
from pathlib import Path
from typing import Dict, Any, List
import json
import subprocess
import time
from urllib.parse import urlparse, urljoin
import re

plugin_info = {
    "name": "API Security Scanner",
    "description": "Comprehensive API security testing including REST, GraphQL, and SOAP",
    "version": "1.0.0", 
    "author": "@cxb3rf1lth",
    "category": "vulnerability_scanning",
    "requires_internet": True,
    "risk_level": "medium"
}

def execute(run_dir: Path, env: Dict[str, str], cfg: Dict[str, Any]):
    """Execute comprehensive API security scanning"""
    api_dir = run_dir / "api_security"
    api_dir.mkdir(exist_ok=True)
    
    # Read targets
    targets_file = Path(__file__).parent.parent / "targets.txt"
    if not targets_file.exists():
        print("[API] No targets file found")
        return
    
    targets = []
    with open(targets_file, 'r') as f:
        for line in f:
            target = line.strip()
            if target and not target.startswith('#'):
                targets.append(target)
    
    if not targets:
        print("[API] No targets found")
        return
    
    results = {}
    
    for target in targets:
        print(f"[API] Scanning target: {target}")
        target_results = {}
        
        # 1. API Endpoint Discovery
        try:
            endpoints = discover_api_endpoints(target)
            target_results["endpoint_discovery"] = endpoints
        except Exception as e:
            print(f"[API] Endpoint discovery error: {e}")
        
        # 2. REST API Testing
        try:
            rest_results = test_rest_api_security(target)
            target_results["rest_api_security"] = rest_results
        except Exception as e:
            print(f"[API] REST API testing error: {e}")
        
        # 3. GraphQL Security Testing
        try:
            graphql_results = test_graphql_security(target)
            target_results["graphql_security"] = graphql_results
        except Exception as e:
            print(f"[API] GraphQL testing error: {e}")
        
        # 4. Authentication and Authorization Testing
        try:
            auth_results = test_authentication_security(target)
            target_results["authentication_security"] = auth_results
        except Exception as e:
            print(f"[API] Authentication testing error: {e}")
        
        # 5. Rate Limiting and DoS Testing
        try:
            rate_limit_results = test_rate_limiting(target)
            target_results["rate_limiting"] = rate_limit_results
        except Exception as e:
            print(f"[API] Rate limiting testing error: {e}")
        
        results[target] = target_results
    
    # Save results
    output_file = api_dir / "api_security_results.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"[API] API security results saved to: {output_file}")

def discover_api_endpoints(target: str) -> Dict[str, Any]:
    """Discover API endpoints through various methods"""
    results = {
        "discovered_endpoints": [],
        "swagger_docs": [],
        "openapi_specs": [],
        "common_paths": [],
        "timestamp": time.time()
    }
    
    # Common API paths to check
    api_paths = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/rest", "/graphql", "/swagger", "/swagger.json",
        "/openapi.json", "/api-docs", "/docs",
        "/spec", "/swagger-ui", "/redoc",
        "/.well-known/openapi", "/health", "/status",
        "/metrics", "/admin/api", "/v1", "/v2"
    ]
    
    base_url = target.rstrip('/')
    
    for path in api_paths:
        try:
            test_url = urljoin(base_url, path)
            cmd = ["curl", "-s", "-I", "--max-time", "10", "-w", "%{http_code}", test_url]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                status_code = lines[-1] if lines else "000"
                
                if status_code.startswith(('2', '3', '4')):  # Any response
                    endpoint_info = {
                        "path": path,
                        "url": test_url,
                        "status_code": status_code,
                        "discovered_method": "path_enumeration"
                    }
                    
                    # Check content for API indicators
                    content_cmd = ["curl", "-s", "--max-time", "10", test_url]
                    content_result = subprocess.run(content_cmd, capture_output=True, text=True, timeout=15)
                    
                    if content_result.returncode == 0:
                        content = content_result.stdout.lower()
                        
                        # Check for Swagger/OpenAPI
                        if any(term in content for term in ['swagger', 'openapi', 'api-docs']):
                            endpoint_info["type"] = "documentation"
                            if 'swagger' in content:
                                results["swagger_docs"].append(endpoint_info)
                            if 'openapi' in content:
                                results["openapi_specs"].append(endpoint_info)
                        
                        # Check for API responses
                        elif any(term in content for term in ['{"', '"api"', '"version"', '"data"']):
                            endpoint_info["type"] = "api_endpoint"
                            endpoint_info["response_type"] = "json"
                        
                        # Check for GraphQL
                        elif 'graphql' in content or 'query' in content:
                            endpoint_info["type"] = "graphql"
                    
                    results["discovered_endpoints"].append(endpoint_info)
            
        except Exception as e:
            continue
    
    # Additional endpoint discovery through robots.txt
    try:
        robots_url = urljoin(base_url, "/robots.txt")
        cmd = ["curl", "-s", "--max-time", "10", robots_url]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0 and result.stdout:
            # Parse robots.txt for API paths
            for line in result.stdout.split('\n'):
                if 'disallow:' in line.lower():
                    path = line.split(':', 1)[1].strip()
                    if any(api_term in path.lower() for api_term in ['api', 'rest', 'graphql']):
                        results["discovered_endpoints"].append({
                            "path": path,
                            "url": urljoin(base_url, path),
                            "discovered_method": "robots_txt",
                            "type": "potential_api"
                        })
    
    except Exception as e:
            logging.warning(f"Operation failed: {e}")
            # Consider if this error should be handled differently
    return results

def test_rest_api_security(target: str) -> Dict[str, Any]:
    """Test REST API security vulnerabilities"""
    results = {
        "injection_tests": [],
        "method_tampering": [],
        "parameter_pollution": [],
        "mass_assignment": [],
        "timestamp": time.time()
    }
    
    base_url = target.rstrip('/')
    
    # Test for SQL injection in API endpoints
    sql_payloads = [
        "' OR '1'='1",
        "' UNION SELECT null--",
        "'; DROP TABLE users--",
        "1' AND 1=1--",
        "admin'/*"
    ]
    
    api_endpoints = ["/api/users", "/api/login", "/api/search"]
    
    for endpoint in api_endpoints:
        test_url = urljoin(base_url, endpoint)
        
        # Test SQL injection
        for payload in sql_payloads:
            try:
                # Test in query parameters
                cmd = ["curl", "-s", "--max-time", "10", f"{test_url}?id={payload}"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                
                if result.returncode == 0 and result.stdout:
                    content = result.stdout.lower()
                    if any(error in content for error in ['sql', 'mysql', 'postgres', 'oracle', 'error']):
                        results["injection_tests"].append({
                            "endpoint": endpoint,
                            "payload": payload,
                            "method": "GET",
                            "vulnerability": "potential_sql_injection",
                            "evidence": result.stdout[:200]
                        })
            except Exception:
                continue
        
        # Test HTTP method tampering
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
        for method in methods:
            try:
                cmd = ["curl", "-s", "-X", method, "--max-time", "10", "-w", "%{http_code}", test_url]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    status_code = lines[-1] if lines else "000"
                    
                    results["method_tampering"].append({
                        "endpoint": endpoint,
                        "method": method,
                        "status_code": status_code,
                        "allowed": not status_code.startswith('405')
                    })
            except Exception:
                continue
    
    return results

def test_graphql_security(target: str) -> Dict[str, Any]:
    """Test GraphQL specific security vulnerabilities"""
    results = {
        "introspection_enabled": False,
        "depth_limit_test": {},
        "query_complexity": {},
        "field_suggestions": [],
        "timestamp": time.time()
    }
    
    base_url = target.rstrip('/')
    graphql_endpoints = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]
    
    for endpoint in graphql_endpoints:
        test_url = urljoin(base_url, endpoint)
        
        # Test introspection
        introspection_query = {
            "query": "{ __schema { queryType { name } } }"
        }
        
        try:
            cmd = [
                "curl", "-s", "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", json.dumps(introspection_query),
                "--max-time", "10", test_url
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0 and result.stdout:
                try:
                    response = json.loads(result.stdout)
                    if "data" in response and "__schema" in str(response):
                        results["introspection_enabled"] = True
                        results["introspection_endpoint"] = endpoint
                        
                        # Get full schema if introspection is enabled
                        full_schema_query = {
                            "query": "{ __schema { types { name fields { name type { name } } } } }"
                        }
                        
                        schema_cmd = [
                            "curl", "-s", "-X", "POST",
                            "-H", "Content-Type: application/json", 
                            "-d", json.dumps(full_schema_query),
                            "--max-time", "15", test_url
                        ]
                        
                        schema_result = subprocess.run(schema_cmd, capture_output=True, text=True, timeout=20)
                        
                        if schema_result.returncode == 0:
                            try:
                                schema_response = json.loads(schema_result.stdout)
                                if "data" in schema_response:
                                    results["schema_dump"] = schema_response
                            except Exception as e:
                                logging.warning(f"Unexpected error: {e}")
                                # Consider if this error should be handled differently
                except json.JSONDecodeError:
                    pass
        
        except Exception:
            continue
        
        # Test depth limit (DoS protection)
        deep_query = {
            "query": "{ user { posts { comments { replies { replies { replies { id } } } } } } }"
        }
        
        try:
            cmd = [
                "curl", "-s", "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", json.dumps(deep_query),
                "--max-time", "10", test_url
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                if "depth" in result.stdout.lower() or "limit" in result.stdout.lower():
                    results["depth_limit_test"]["protected"] = True
                else:
                    results["depth_limit_test"]["protected"] = False
                    results["depth_limit_test"]["response"] = result.stdout[:500]
        
        except Exception:
            continue
    
    return results

def test_authentication_security(target: str) -> Dict[str, Any]:
    """Test authentication and authorization mechanisms"""
    results = {
        "jwt_vulnerabilities": [],
        "session_management": {},
        "oauth_tests": {},
        "bypass_attempts": [],
        "timestamp": time.time()
    }
    
    base_url = target.rstrip('/')
    auth_endpoints = ["/login", "/auth", "/api/login", "/api/auth", "/oauth"]
    
    # Test for common authentication bypasses
    bypass_payloads = [
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password"},
        {"username": "' OR '1'='1", "password": "anything"},
        {"username": "admin'--", "password": ""},
        {"username": "admin", "password": "' OR '1'='1"}
    ]
    
    for endpoint in auth_endpoints:
        test_url = urljoin(base_url, endpoint)
        
        for payload in bypass_payloads:
            try:
                # Test with POST data
                post_data = json.dumps(payload)
                cmd = [
                    "curl", "-s", "-X", "POST",
                    "-H", "Content-Type: application/json",
                    "-d", post_data,
                    "--max-time", "10", test_url
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                
                if result.returncode == 0:
                    content = result.stdout.lower()
                    
                    # Check for successful login indicators
                    success_indicators = ['token', 'success', 'welcome', 'dashboard', 'jwt']
                    if any(indicator in content for indicator in success_indicators):
                        results["bypass_attempts"].append({
                            "endpoint": endpoint,
                            "payload": payload,
                            "response": result.stdout[:300],
                            "potential_bypass": True
                        })
            
            except Exception:
                continue
    
    # Test JWT token handling
    # Look for JWT tokens in responses
    try:
        cmd = ["curl", "-s", "--max-time", "10", base_url]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            # Search for JWT pattern
            jwt_pattern = r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
            jwt_matches = re.findall(jwt_pattern, result.stdout)
            
            for jwt_token in jwt_matches:
                if len(jwt_token) > 20:  # Basic JWT length check
                    results["jwt_vulnerabilities"].append({
                        "token": jwt_token[:50] + "...",  # Truncate for safety
                        "location": "response_body",
                        "tests": ["none_algorithm", "weak_secret", "key_confusion"]
                    })
    
    except Exception as e:
            logging.warning(f"Operation failed: {e}")
            # Consider if this error should be handled differently
    return results

def test_rate_limiting(target: str) -> Dict[str, Any]:
    """Test rate limiting and DoS protection"""
    results = {
        "rate_limit_status": {},
        "dos_protection": {},
        "concurrent_requests": {},
        "timestamp": time.time()
    }
    
    base_url = target.rstrip('/')
    test_endpoints = ["/api", "/login", "/api/login"]
    
    for endpoint in test_endpoints:
        test_url = urljoin(base_url, endpoint)
        
        # Test rapid sequential requests
        try:
            response_codes = []
            response_times = []
            
            for i in range(10):  # Limited to avoid being too aggressive
                start_time = time.time()
                
                cmd = ["curl", "-s", "-w", "%{http_code}:%{time_total}", "--max-time", "5", test_url]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                end_time = time.time()
                
                if result.returncode == 0:
                    output = result.stdout.strip().split('\n')[-1]
                    if ':' in output:
                        status_code, response_time = output.split(':', 1)
                        response_codes.append(status_code)
                        response_times.append(float(response_time))
                
                time.sleep(0.1)  # Small delay between requests
            
            # Analyze results
            if response_codes:
                rate_limited = any(code in ['429', '503', '502'] for code in response_codes)
                
                results["rate_limit_status"][endpoint] = {
                    "rate_limited": rate_limited,
                    "response_codes": response_codes,
                    "avg_response_time": sum(response_times) / len(response_times) if response_times else 0,
                    "total_requests": len(response_codes)
                }
        
        except Exception as e:
            results["rate_limit_status"][endpoint] = {"error": str(e)}
    
    return results