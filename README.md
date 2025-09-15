# 🛡️ Bl4ckC3ll_PANTHEON v2.0

### **Next-Generation Cybersecurity Testing Framework**

[![Security](https://img.shields.io/badge/security-penetration%20testing-red)](https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-Educational-green)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0-brightgreen)](https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON)
[![Docker](https://img.shields.io/badge/docker-supported-blue)](https://docker.com)

Bl4ckC3ll_PANTHEON v2.0 is a comprehensive, production-grade cybersecurity testing orchestrator that unifies multiple security tools and methodologies into an advanced testing platform. Designed for authorized penetration testing, security research, vulnerability assessments, and educational purposes.

---

## 🚨 **IMPORTANT LEGAL NOTICE**

> **This tool is intended EXCLUSIVELY for:**
> - ✅ **Authorized penetration testing** with proper written permission
> - ✅ **Educational purposes** and security research  
> - ✅ **Legitimate bug bounty programs**
> - ✅ **Testing your own systems and infrastructure**
> 
> **❌ UNAUTHORIZED USAGE IS STRICTLY PROHIBITED**
> 
> Users are **solely responsible** for ensuring they have explicit authorization before testing any systems. The maintainers assume **no liability** for misuse of this software.

---

## 📋 **Table of Contents**

- [Features Overview](#-features-overview)
- [Prerequisites](#-prerequisites) 
- [Quick Installation](#-quick-installation)
- [Getting Started](#-getting-started)
- [Usage Examples](#-usage-examples)
- [Advanced Features](#-advanced-features)
- [Configuration](#-configuration)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [Documentation](#-documentation)
- [License](#-license)

---

## 🌟 **Features Overview**

### **Core Capabilities**
- 🔍 **Advanced Reconnaissance** - Subdomain enumeration, port scanning, service detection
- 🛡️ **Vulnerability Assessment** - 5000+ security checks via Nuclei templates
- 🐳 **Container Security** - Docker/Kubernetes security scanning and compliance
- 🌐 **API Security Testing** - REST, GraphQL, SOAP endpoint analysis  
- ☁️ **Cloud Security** - Multi-cloud (AWS, Azure, GCP) misconfiguration detection
- 📊 **Enhanced Reporting** - Interactive dashboards, multiple export formats
- 🔄 **CI/CD Integration** - GitHub Actions, GitLab CI, Jenkins automation
- 🔧 **Modular Architecture** - Plugin system for extensible functionality

### **What's New in v2.0**
- ✨ **Modular Package Structure** - Organized codebase with dedicated security modules
- 🔒 **Enhanced Security Controls** - Strict command validation and allow-listing
- ⚡ **Performance Optimization** - Better resource management and concurrent processing  
- 🎨 **Advanced TUI Interface** - Professional terminal interface with real-time monitoring
- 🤖 **AI-Enhanced Scanning** - Intelligent vulnerability correlation and analysis

## 🔧 **Prerequisites**

Before installing Bl4ckC3ll_PANTHEON, ensure your system meets these requirements:

### **System Requirements**
| Component | Requirement | Recommended |
|-----------|-------------|-------------|
| **Operating System** | Linux/macOS | Ubuntu 20.04+ |
| **Python** | 3.9+ | 3.11+ |
| **Memory (RAM)** | 4GB minimum | 8GB+ |
| **Storage** | 10GB free space | 20GB+ |
| **Go Language** | 1.20+ | 1.21+ |
| **Docker** | Optional | Latest stable |

### **Supported Operating Systems**
- ✅ **Kali Linux** (Recommended for pentesting)
- ✅ **Ubuntu 20.04+** 
- ✅ **Debian 11+**
- ✅ **Arch Linux**
- ✅ **macOS** (with Homebrew)
- ⚠️ **Other Linux distributions** (limited support)

### **Required Permissions**
- Standard user account (DO NOT run as root)
- Internet access for tool downloads
- Permission to install packages (sudo access)

---

## ⚡ **Quick Installation**

### **Method 1: Automated Setup (Recommended)**

```bash
# 1. Clone the repository
git clone https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON.git
cd Bl4ckC3ll_PANTHEON

# 2. Run the quick start script  
chmod +x quickstart.sh
./quickstart.sh

# 3. Follow the interactive prompts
# The script will automatically:
# - Check system compatibility
# - Install Python dependencies
# - Download security tools
# - Set up the environment
```

### **Method 2: Manual Installation**

```bash
# 1. Clone repository
git clone https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON.git
cd Bl4ckC3ll_PANTHEON

# 2. Install Python dependencies
pip3 install -r requirements.txt

# 3. Run the installer
chmod +x install.sh
./install.sh

# 4. Test installation
python3 test_installation.py
```

### **Method 3: Docker Installation**

```bash
# Build the container
docker build -t bl4ckc3ll-pantheon:v2.0 .

# Run with mounted results directory
docker run -it --privileged \
  -v $(pwd)/results:/app/results \
  bl4ckc3ll-pantheon:v2.0
```

### **Installation Verification**

After installation, verify everything is working:

```bash
# Quick functionality test
python3 test_installation.py

# Tool availability check
python3 -c "
from enhanced_tool_manager import check_tool_availability
check_tool_availability()
"

# Run feature demonstration
python3 pantheon_enhanced_demo.py
```

---

## 🚀 **Getting Started**

### **First Time Setup**

1. **Configure Targets**
   ```bash
   # Edit the targets file with domains you're authorized to test
   echo "example.com" > targets.txt
   echo "subdomain.example.com" >> targets.txt
   
   # ⚠️ CRITICAL: Only add domains you own or have written permission to test!
   ```

2. **Basic Configuration**
   ```bash
   # Check default configuration
   cat p4nth30n.cfg.json
   
   # Optional: Customize settings for your environment
   nano p4nth30n.cfg.json
   ```

3. **Launch the Application**
   ```bash
   # Start the main interface
   python3 bl4ckc3ll_p4nth30n.py
   
   # Or use the TUI interface
   python3 bl4ckc3ll_p4nth30n.py --tui
   ```

### **Quick Scan Tutorial**

Here's a step-by-step tutorial for your first security scan:

```bash
# 1. Start the application
python3 bl4ckc3ll_p4nth30n.py

# 2. Select scan type (when prompted):
#    → Option 3: Enhanced Reconnaissance
#    → Option 5: Full Pipeline (Recon + Vuln + Report)
#    → Option 7: Generate Report

# 3. View results
ls runs/*/           # Scan results directory
firefox runs/*/report.html  # Open HTML report
```

---

## 💡 **Usage Examples**

### **Traditional Security Scanning**

```bash
# Interactive CLI Mode (Recommended for beginners)
python3 bl4ckc3ll_p4nth30n.py
# Follow the menu prompts:
# → 3. Enhanced Reconnaissance
# → 5. Full Pipeline (Recon + Vuln + Report)

# Command Line Mode (For automation)
python3 bl4ckc3ll_p4nth30n.py --target example.com

# Advanced TUI Interface  
python3 bl4ckc3ll_p4nth30n.py --tui
```

### **Container Security Assessment**
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
# Scan Docker images for vulnerabilities
python3 -c "
from pantheon.containers import scan_container_images
from pathlib import Path
results = scan_container_images(['nginx:latest', 'alpine:latest'], Path('results'))
print(f'Scanned {len(results)} containers')
"

# Analyze Kubernetes manifests
python3 -c "
from pantheon.containers import scan_kubernetes_manifests  
from pathlib import Path
results = scan_kubernetes_manifests(Path('k8s-manifests'), Path('results'))
print('Kubernetes security assessment completed')
"
```

### **API Security Testing**
```bash
# Comprehensive API security assessment
python3 -c "
from pantheon.api import scan_api_endpoints
from pathlib import Path
results = scan_api_endpoints('https://api.example.com', Path('results'))
print(f'API scan completed: {len(results[\"discovery\"][\"endpoints\"])} endpoints analyzed')
"
```

### **Cloud Security Assessment**
```bash
# AWS security assessment (requires AWS credentials)
python3 -c "
from pantheon.cloud import scan_cloud_infrastructure
from pathlib import Path
results = scan_cloud_infrastructure('aws', Path('results'))
print(f'AWS assessment: {len(results.get(\"misconfigurations\", []))} issues found')
"

# Multi-cloud security scan
python3 -c "
from pantheon.cloud import scan_cloud_infrastructure
for provider in ['aws', 'azure', 'gcp']:
    try:
        results = scan_cloud_infrastructure(provider, Path('results'))
        print(f'{provider.upper()} scan completed')
    except Exception as e:
        print(f'{provider.upper()} scan failed: {e}')
"
```

### **Advanced Reporting**
```bash
# Generate comprehensive security reports
python3 -c "
from pantheon.reporting import generate_security_report
from pathlib import Path

# Generate multiple report formats
report = generate_security_report(
    scan_data={'vulnerabilities': [], 'metadata': {}}, 
    output_dir=Path('results'),
    formats=['json', 'html', 'csv', 'sarif']
)
print(f'Generated reports: {report[\"files_generated\"]}')
"
```

---

## 🔧 **Advanced Features**

### **Modular Architecture**

The framework uses a modular package structure:

```
pantheon/
├── core/           # Security controls, logging, configuration
├── containers/     # Docker/Kubernetes security scanning  
├── api/           # REST/GraphQL/SOAP security testing
├── cloud/         # AWS/Azure/GCP security assessment
├── cicd/          # CI/CD pipeline integration
├── reporting/     # Multi-format report generation
├── recon/         # Reconnaissance and enumeration
├── scanning/      # Vulnerability scanning engines
└── utils/         # Utility functions and helpers
```

### **Plugin System**

Create custom security scanners:

```python
# plugins/custom_scanner.py
from pantheon.core import SecurityManager, PantheonLogger

plugin_info = {
    "name": "custom_scanner",
    "description": "Custom security scanner plugin", 
    "version": "2.0.0",
    "author": "Your Name"
}

def execute(target: str, output_dir: Path, config: Dict[str, Any]):
    logger = PantheonLogger("custom_scanner")
    security = SecurityManager()
    
    logger.log(f"Starting custom scan for {target}", "INFO")
    # ... your plugin logic here ...
    
    return {"status": "completed", "findings": []}
```

### **CI/CD Integration**

Automate security testing in your pipelines:

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

---

## ⚙️ **Configuration**

### **Main Configuration File**

The framework uses `p4nth30n.cfg.json` for comprehensive configuration:

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

### **Environment Variables**

Set these environment variables for enhanced functionality:

```bash
# Cloud provider credentials (optional)
export AWS_ACCESS_KEY_ID="your-aws-key"
export AWS_SECRET_ACCESS_KEY="your-aws-secret"
export AZURE_CLIENT_ID="your-azure-client-id"  
export GCP_SERVICE_ACCOUNT_KEY="path/to/service-account.json"

# API keys for threat intelligence (optional)
export SHODAN_API_KEY="your-shodan-key"
export CENSYS_API_ID="your-censys-id"
export CENSYS_API_SECRET="your-censys-secret"

# Performance tuning
export PANTHEON_MAX_THREADS="10"
export PANTHEON_TIMEOUT="300"
```

### **Custom Target Lists**

Configure your authorized targets:

```bash
# Basic target configuration
echo "example.com" > targets.txt
echo "subdomain.example.com" >> targets.txt

# Advanced target configuration with annotations
cat > targets.txt << EOF
# Production environment (handle with care)
prod.example.com

# Staging environment 
staging.example.com

# Development environment
dev.example.com
EOF
```

---

## 🐛 **Troubleshooting**

### **Common Installation Issues**

| Problem | Solution |
|---------|----------|
| **Python version error** | Install Python 3.9+ with `sudo apt install python3.11` |
| **Permission denied** | Don't run as root, use `sudo` only when prompted |
| **Go tools missing** | Run `./install.sh` again or install Go manually |
| **Memory issues** | Increase available RAM or reduce concurrent scans |
| **Network timeouts** | Check internet connection and firewall settings |

### **Diagnostic Commands**

```bash
# Check system status
python3 diagnostics.py

# Validate installation
python3 test_installation.py

# Check tool availability
python3 -c "
from enhanced_tool_manager import check_tool_availability
check_tool_availability()
"

# View detailed logs
tail -f logs/pantheon.log
```

### **Performance Optimization**

```bash
# Reduce memory usage
export PANTHEON_MAX_THREADS="5"

# Limit scan scope
python3 bl4ckc3ll_p4nth30n.py --quick-scan

# Clean old results
rm -rf runs/old-*/
```

### **Getting Help**

1. **Check Documentation**: Review `USAGE_GUIDE.md` for detailed instructions
2. **Run Diagnostics**: Use `python3 diagnostics.py` for system analysis  
3. **Enable Debug Mode**: Set `DEBUG=1` environment variable for verbose output
4. **Community Support**: Open an issue on GitHub with diagnostic output

---

## 🤝 **Contributing**

We welcome contributions to enhance Bl4ckC3ll_PANTHEON! Here's how to get involved:

### **Development Setup**

```bash
# Fork the repository and clone your fork
git clone https://github.com/YOUR-USERNAME/Bl4ckC3ll_PANTHEON.git
cd Bl4ckC3ll_PANTHEON

# Create a development branch
git checkout -b feature/your-feature-name

# Install development dependencies
pip install -r requirements.txt
pip install black isort mypy pytest pre-commit

# Set up pre-commit hooks
pre-commit install
```

### **Contribution Guidelines**

1. **Open an Issue First** - Discuss your proposed changes before coding
2. **Follow Code Standards** - Use Black for formatting, follow PEP 8
3. **Add Tests** - Include comprehensive tests for new features
4. **Update Documentation** - Keep docs current with code changes
5. **Security First** - Ensure new features maintain security standards

### **Development Workflow**

```bash
# Run tests before submitting
python3 -m pytest tests/
python3 enhanced_test_suite.py

# Format code
black .
isort .

# Type checking
mypy pantheon/

# Submit pull request with:
# - Clear description of changes
# - Test results
# - Documentation updates
```

---

## 📚 **Documentation**

### **Complete Documentation Suite**

| Document | Description |
|----------|-------------|
| **[USAGE_GUIDE.md](USAGE_GUIDE.md)** | Comprehensive usage instructions with v2.0 features |
| **[AUTOMATION_GUIDE.md](AUTOMATION_GUIDE.md)** | Automation and CI/CD integration guide |
| **[BCAR_USAGE_GUIDE.md](BCAR_USAGE_GUIDE.md)** | BCAR-specific features and setup |
| **[SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md)** | Security best practices and guidelines |
| **[CHANGELOG.md](CHANGELOG.md)** | Version history and feature updates |

### **API Documentation**

```bash
# Generate API documentation
python3 -c "
from pantheon.core import generate_api_docs
generate_api_docs('docs/api/')
"

# View plugin documentation
python3 -c "
from pantheon.plugins import list_available_plugins
print(list_available_plugins())
"
```

### **Example Configurations**

- **CI/CD Examples**: `.github/workflows/` and `.gitlab-ci.yml`
- **Docker Examples**: `Dockerfile` and `docker-compose.yml` 
- **Plugin Examples**: `plugins/example_plugin.py`
- **Configuration Examples**: `examples/config/`

---

## 🔒 **Security & Legal**

### **Responsible Usage**

This tool is designed for **authorized security testing only**. Users must:

- ✅ **Obtain explicit written permission** before testing any systems
- ✅ **Comply with all applicable laws** and regulations in your jurisdiction
- ✅ **Respect system owners' rights** and privacy 
- ✅ **Use the tool responsibly** and ethically
- ✅ **Follow responsible disclosure** for any vulnerabilities found

### **Legal Disclaimer**

**THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.** The maintainers and contributors assume **no liability** for:
- Misuse of this software
- Legal consequences of unauthorized testing
- Damage to systems or data
- Any illegal activities performed with this tool

### **Reporting Security Issues**

If you discover security vulnerabilities in Bl4ckC3ll_PANTHEON itself:

1. **DO NOT** open a public issue
2. Email security concerns to: [security@example.com] 
3. Include detailed reproduction steps
4. Allow time for responsible disclosure

---

## 📄 **License**

This project is licensed under the **Educational License** - see the [LICENSE](LICENSE) file for details.

### **License Summary**
- ✅ **Educational use** permitted
- ✅ **Security research** permitted  
- ✅ **Authorized penetration testing** permitted
- ❌ **Commercial use** requires permission
- ❌ **Malicious use** strictly prohibited

---

## 🙏 **Acknowledgments**

This project builds upon excellent open-source tools from the cybersecurity community:

### **Core Security Tools**
- **ProjectDiscovery** - nuclei, subfinder, httpx, naabu, katana
- **OWASP** - ZAP, dependency-check, security testing methodologies
- **Docker Security** - Trivy, Grype, container scanning tools
- **Cloud Security** - Prowler, Scout Suite, cloud assessment frameworks

### **Special Thanks**
- The **cybersecurity community** for continuous tool development
- **Bug bounty hunters** and **ethical hackers** for security research
- **Open source contributors** who make tools like this possible
- **Security researchers** advancing the field of cybersecurity

---

## 📊 **Project Statistics**

![GitHub stars](https://img.shields.io/github/stars/cxb3rf1lth/Bl4ckC3ll_PANTHEON)
![GitHub forks](https://img.shields.io/github/forks/cxb3rf1lth/Bl4ckC3ll_PANTHEON)
![GitHub issues](https://img.shields.io/github/issues/cxb3rf1lth/Bl4ckC3ll_PANTHEON)
![GitHub license](https://img.shields.io/github/license/cxb3rf1lth/Bl4ckC3ll_PANTHEON)

---

<div align="center">

**Made with ❤️ for the cybersecurity community**

*Bl4ckC3ll_PANTHEON v2.0 - Next-Generation Security Testing Framework*

**⭐ Star this repository if you find it useful!**

</div>
