# 🛡️ Bl4ckC3ll_PANTHEON v2.0

## Advanced Security Testing Framework - Enhanced Edition

[![Security](https://img.shields.io/badge/security-penetration%20testing-red)](https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-Educational-green)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0-brightgreen)](https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON)

**Bl4ckC3ll_PANTHEON v2.0** is a next-generation comprehensive security testing orchestrator designed for **authorized** penetration testing, security research, and vulnerability assessments. This production-grade framework integrates multiple security tools and methodologies into a unified testing platform with enhanced modular architecture.

> **⚠️ IMPORTANT NOTICE:** This tool is intended **exclusively** for authorized security testing, educational purposes, and legitimate bug bounty programs. Users are responsible for ensuring they have proper authorization before testing any systems.

## ✨ New in Version 2.0

### 🏗️ Enhanced Architecture
- **Modular Package Structure** - Organized codebase with dedicated modules for each security domain
- **Enhanced Security Controls** - Stricter command validation and allow-listing for security
- **Improved Error Handling** - Comprehensive error management and logging
- **Performance Optimization** - Better resource management and concurrent processing

### 🐳 Container Security Scanning
- **Docker Image Analysis** - Comprehensive vulnerability scanning for container images
- **Kubernetes Manifest Security** - Security assessment of K8s configurations
- **Container Compliance Checking** - Industry standard compliance validation
- **Integration with Trivy, Grype, and Docker security tools**

### 🌐 Advanced API Security Testing
- **API Discovery & Enumeration** - Automatic discovery of REST, GraphQL, and SOAP endpoints
- **OpenAPI/Swagger Analysis** - Comprehensive specification parsing and testing
- **Authentication & Authorization Testing** - Advanced auth mechanism validation
- **Input Validation & Injection Testing** - Comprehensive security vulnerability detection

### ☁️ Cloud Security Assessment
- **Multi-Cloud Support** - AWS, Azure, and GCP security assessments
- **Misconfiguration Detection** - Automated cloud resource security analysis
- **Compliance Framework Mapping** - CIS, NIST, and other standard alignments
- **Cloud Resource Enumeration** - Comprehensive cloud asset discovery

### 🔄 Enhanced CI/CD Integration
- **Multi-Platform Support** - GitHub Actions, GitLab CI, Jenkins, Azure DevOps
- **Flexible Scan Types** - Quick, standard, comprehensive scan configurations
- **SARIF Integration** - Security scan results format for better tool integration
- **Automated Pipeline Generation** - One-command CI/CD setup

### 📊 Advanced Reporting & Analytics
- **Multiple Report Formats** - JSON, HTML, CSV, SARIF, XML output options
- **Interactive Dashboards** - Rich HTML reports with security metrics
- **Executive Summaries** - Business-focused security assessment reports
- **Compliance Reporting** - Detailed compliance status and gap analysis

## 🚀 Quick Start

### Prerequisites
- **OS**: Linux or macOS (Ubuntu 20.04+ recommended)
- **Python**: 3.9+ (3.11+ recommended)
- **Go**: 1.20+ for security tools
- **Memory**: 4GB+ RAM (8GB+ recommended)
- **Storage**: 10GB+ free space
- **Docker**: For container security scanning (optional)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON.git
cd Bl4ckC3ll_PANTHEON
```

2. **Run automated setup**
```bash
chmod +x install.sh
./install.sh
```

3. **Test enhanced features**
```bash
python3 pantheon_enhanced_demo.py
```

4. **Launch the framework**
```bash
python3 bl4ckc3ll_p4nth30n.py
```

### Docker Deployment

```bash
# Build container with enhanced features
docker build -t bl4ckc3ll-pantheon:v2.0 .

# Run with enhanced capabilities
docker run -it --privileged -v $(pwd)/results:/app/results bl4ckc3ll-pantheon:v2.0

# Container security scanning
docker run -v /var/run/docker.sock:/var/run/docker.sock bl4ckc3ll-pantheon:v2.0 \
  python3 -c "from pantheon.containers import scan_container_images; print('Container scanning ready')"
```

## 🎯 Enhanced Usage Examples

### Traditional Security Scanning
```bash
# Quick reconnaissance
python3 bl4ckc3ll_p4nth30n.py
# Select: 3. Enhanced Reconnaissance

# Full vulnerability assessment
python3 bl4ckc3ll_p4nth30n.py
# Select: 5. Full Pipeline (Recon + Vuln + Report)
```

### Container Security Assessment
```bash
# Scan Docker images
python3 -c "
from pantheon.containers import scan_container_images
from pathlib import Path
results = scan_container_images(['nginx:latest', 'alpine:latest'], Path('results'))
print(f'Scanned {len(results)} containers')
"

# Kubernetes manifest analysis
python3 -c "
from pantheon.containers import scan_kubernetes_manifests
from pathlib import Path
results = scan_kubernetes_manifests(Path('k8s-manifests'), Path('results'))
print('Kubernetes security assessment completed')
"
```

### API Security Testing
```bash
# Comprehensive API security assessment
python3 -c "
from pantheon.api import scan_api_endpoints
from pathlib import Path
results = scan_api_endpoints('https://api.example.com', Path('results'))
print(f'API scan completed: {len(results[\"discovery\"][\"endpoints\"])} endpoints analyzed')
"
```

### Cloud Security Assessment
```bash
# AWS security assessment
python3 -c "
from pantheon.cloud import scan_cloud_infrastructure
from pathlib import Path
results = scan_cloud_infrastructure('aws', Path('results'))
print(f'AWS assessment: {len(results.get(\"misconfigurations\", []))} issues found')
"
```

### CI/CD Integration Setup
```bash
# Generate GitHub Actions workflow
python3 -c "
from pantheon.cicd import generate_cicd_integration
from pathlib import Path
result = generate_cicd_integration('github', 'standard', Path('.'))
print(f'CI/CD setup: {result[\"files_created\"]}')
"

# Generate GitLab CI configuration
python3 -c "
from pantheon.cicd import generate_cicd_integration
from pathlib import Path
result = generate_cicd_integration('gitlab', 'comprehensive', Path('.'))
print('GitLab CI configuration generated')
"
```

### Enhanced Reporting
```bash
# Generate comprehensive security reports
python3 -c "
from pantheon.reporting import generate_security_report
from pathlib import Path
import json

# Sample scan results
scan_data = {
    'vulnerabilities': [
        {'severity': 'high', 'title': 'SQL Injection', 'description': 'Database injection vulnerability'}
    ],
    'container_scans': {},
    'api_scans': {},
    'cloud_scans': {}
}

report = generate_security_report(scan_data, Path('results'), ['json', 'html', 'csv'])
print(f'Generated reports: {report[\"files_generated\"]}')
"
```

## 📁 Enhanced Project Structure

```
Bl4ckC3ll_PANTHEON/
├── pantheon/                          # 🆕 Modular package structure
│   ├── core/                         # Core security and configuration modules
│   │   ├── security.py              # Enhanced security controls & validation
│   │   ├── logger.py                # Advanced logging & audit trails
│   │   └── config.py                # Configuration management
│   ├── containers/                   # 🆕 Container security scanning
│   │   └── __init__.py              # Docker/K8s security assessment
│   ├── api/                         # 🆕 API security testing
│   │   └── __init__.py              # REST/GraphQL/SOAP security testing
│   ├── cloud/                       # 🆕 Cloud security assessment
│   │   └── __init__.py              # AWS/Azure/GCP security analysis
│   ├── cicd/                        # 🆕 CI/CD integration
│   │   └── __init__.py              # Pipeline configuration generation
│   ├── reporting/                   # 🆕 Enhanced reporting
│   │   └── __init__.py              # Multi-format report generation
│   └── __init__.py                  # Main package initialization
├── bl4ckc3ll_p4nth30n.py            # Main orchestrator (enhanced)
├── pantheon_enhanced_demo.py         # 🆕 Feature demonstration script
├── requirements.txt                  # 🆕 Enhanced dependencies
├── install.sh                       # 🆕 Improved installation script
└── README.md                        # 🆕 Updated documentation
```

## ⚙️ Enhanced Configuration

The framework uses `p4nth30n.cfg.json` with new security and feature configurations:

```json
{
  "version": "2.0.0",
  "security": {
    "strict_mode": true,
    "command_validation": true,
    "rate_limiting": true,
    "audit_logging": true,
    "max_scan_duration": 3600
  },
  "containers": {
    "scan_images": true,
    "check_k8s_manifests": true,
    "vulnerability_db_update": true
  },
  "api": {
    "enable_api_discovery": true,
    "test_endpoints": true,
    "include_swagger": true,
    "max_api_requests": 1000
  },
  "cloud": {
    "aws_enabled": false,
    "azure_enabled": false,
    "gcp_enabled": false,
    "check_misconfigurations": true
  },
  "reporting": {
    "formats": ["html", "json", "csv", "sarif"],
    "auto_open_html": true,
    "include_screenshots": false,
    "severity_filter": "medium"
  }
}
```

## 🔌 Enhanced Plugin System

Extend functionality with the new modular plugin architecture:

```python
# plugins/custom_scanner.py
from pantheon.core import SecurityManager, PantheonLogger

plugin_info = {
    "name": "custom_scanner",
    "description": "Custom security scanner plugin",
    "version": "2.0.0",
    "author": "Your Name",
    "dependencies": ["requests", "beautifulsoup4"]
}

def execute(target: str, output_dir: Path, config: Dict[str, Any]):
    logger = PantheonLogger("custom_scanner")
    security = SecurityManager()
    
    # Enhanced plugin implementation with security controls
    logger.log(f"Starting custom scan for {target}", "INFO")
    # ... plugin logic ...
    
    return {"status": "completed", "findings": []}
```

## 📊 Enhanced Reporting Capabilities

Generated reports now include:
- **Interactive HTML Dashboards** - Rich visualizations and metrics
- **SARIF Integration** - Security scanning results format
- **Executive Summaries** - Business-focused security assessments
- **Compliance Mapping** - Detailed compliance status reports
- **Multi-format Output** - JSON, HTML, CSV, XML, SARIF support
- **Vulnerability Correlation** - Cross-module vulnerability analysis

Reports are saved under `runs/<run-id>/` with comprehensive vulnerability data, remediation guidance, and security metrics.

## 🧪 Enhanced Testing & Validation

Run the comprehensive test suite:

```bash
# Test enhanced modules
python3 pantheon_enhanced_demo.py

# Core functionality tests
python3 enhanced_test_suite.py

# Integration tests with new modules
python3 final_integration_test.py

# Automated testing with enhanced features
python3 test_automation_integration.py
```

## 🛠️ Enhanced Tool Dependencies

The framework now supports enhanced integration with:

### Container Security Tools
- **Trivy** - Comprehensive container vulnerability scanner
- **Grype** - Container vulnerability scanner
- **Docker** - Container runtime security analysis
- **kube-score** - Kubernetes security scoring
- **Polaris** - Kubernetes best practices validation

### API Security Tools  
- **Postman/Newman** - API testing automation
- **OWASP ZAP API** - API security testing
- **Swagger Parser** - OpenAPI specification analysis
- **GraphQL Introspection** - GraphQL schema analysis

### Cloud Security Tools
- **AWS CLI** - AWS security assessment
- **Azure CLI** - Azure security analysis
- **Google Cloud CLI** - GCP security evaluation
- **Prowler** - Cloud security auditing
- **Scout Suite** - Multi-cloud security assessment

### Core Security Tools (Unchanged)
- **Reconnaissance**: subfinder, amass, naabu, httpx
- **Vulnerability Scanning**: nuclei, nikto, sqlmap
- **Web Crawling**: katana, gau, waybackurls, gospider
- **Directory Fuzzing**: gobuster, dirb, ffuf
- **Subdomain Takeover**: subjack, subzy

## 📚 Enhanced Documentation

- **[USAGE_GUIDE.md](USAGE_GUIDE.md)** - Comprehensive usage instructions with v2.0 features
- **[CONTAINER_SECURITY.md](CONTAINER_SECURITY.md)** - 🆕 Container security scanning guide
- **[API_SECURITY.md](API_SECURITY.md)** - 🆕 API security testing documentation
- **[CLOUD_SECURITY.md](CLOUD_SECURITY.md)** - 🆕 Cloud security assessment guide
- **[CICD_INTEGRATION.md](CICD_INTEGRATION.md)** - 🆕 CI/CD integration instructions
- **[BCAR_USAGE_GUIDE.md](BCAR_USAGE_GUIDE.md)** - BCAR-specific features and setup
- **[SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md)** - Security best practices
- **[CHANGELOG.md](CHANGELOG.md)** - Version history and v2.0 updates

## 🚦 CI/CD Integration Examples

### GitHub Actions
```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run PANTHEON Security Scan
        run: |
          git clone https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON.git
          cd Bl4ckC3ll_PANTHEON
          ./install.sh
          python3 cicd_integration.py --target ${{ github.event.repository.html_url }}
```

### GitLab CI
```yaml
security_scan:
  stage: security
  script:
    - git clone https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON.git
    - cd Bl4ckC3ll_PANTHEON && ./install.sh
    - python3 cicd_integration.py --target $CI_PROJECT_URL --scan-type comprehensive
```

## ⚖️ Legal Notice

This tool is designed for **authorized security testing only**. Users must:
- Obtain explicit permission before testing any systems
- Comply with all applicable laws and regulations
- Use the tool responsibly and ethically
- Respect system owners' rights and privacy

**The maintainers assume no liability for misuse of this software.**

## 🤝 Contributing

We welcome contributions to PANTHEON v2.0! Please:
1. Open an issue to discuss proposed changes
2. Follow the modular architecture patterns
3. Include comprehensive tests for new features
4. Update documentation for new capabilities
5. Ensure compatibility with existing functionality

## 🔄 Migration from v1.x

To upgrade from PANTHEON v1.x:

```bash
# Backup existing configuration
cp p4nth30n.cfg.json p4nth30n.cfg.json.backup

# Update to v2.0
git pull origin main
./install.sh

# Test new features
python3 pantheon_enhanced_demo.py
```

## 🙏 Acknowledgments

This project builds upon excellent open-source tools from the security community, including:
- ProjectDiscovery suite (nuclei, subfinder, httpx, etc.)
- Container security tools (Trivy, Grype, Docker)
- Cloud security frameworks (Prowler, Scout Suite)
- API security testing tools (OWASP ZAP, Postman)
- The broader cybersecurity open-source ecosystem

---

**Made with ❤️ for the cybersecurity community**

*Bl4ckC3ll_PANTHEON v2.0 - Enhanced Security Testing Framework*
