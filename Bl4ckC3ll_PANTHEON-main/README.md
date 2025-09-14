# 🛡️ Bl4ckC3ll_PANTHEON

## Advanced Security Testing Framework

[![Security](https://img.shields.io/badge/security-penetration%20testing-red)](https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-Educational-green)](LICENSE)

**Bl4ckC3ll_PANTHEON** is a comprehensive security testing orchestrator designed for **authorized** penetration testing, security research, and vulnerability assessments. This production-grade framework integrates multiple security tools and methodologies into a unified testing platform.

> **⚠️ IMPORTANT NOTICE:** This tool is intended **exclusively** for authorized security testing, educational purposes, and legitimate bug bounty programs. Users are responsible for ensuring they have proper authorization before testing any systems.

## ✨ Key Features

### 🔍 Advanced Reconnaissance
- **Multi-source subdomain discovery** with subfinder, amass, and certificate transparency
- **Enhanced port scanning** with naabu and intelligent rate limiting
- **HTTP fingerprinting** with technology detection and response analysis
- **Endpoint harvesting** from multiple sources (gau, katana, waybackurls, gospider)
- **DNS enumeration** with historical data analysis

### 🚨 Vulnerability Assessment
- **Nuclei integration** with enhanced template management and custom rules
- **Web application security** testing (XSS, SQLi, CSRF, etc.)
- **API security** testing for REST, GraphQL, and SOAP endpoints
- **Cloud security** assessment for AWS, Azure, and GCP resources
- **SSL/TLS analysis** and certificate validation

### 🤖 AI-Powered Analysis
- **Machine learning** false positive reduction
- **Intelligent vulnerability prioritization** with risk scoring
- **Pattern recognition** for vulnerability clustering
- **Automated threat correlation** and impact assessment

### 📊 Professional Reporting
- **Multiple output formats**: HTML, JSON, CSV, SARIF
- **Executive summaries** with business impact analysis
- **Interactive dashboards** with risk visualization
- **Compliance mapping** (OWASP, NIST, PCI-DSS)

### 🔧 DevOps Integration
- **CI/CD pipeline** integration with GitHub Actions
- **Docker containerization** for scalable deployment
- **API endpoints** for programmatic access
- **Webhook notifications** and automated reporting

## 🚀 Quick Start

### Prerequisites
- **OS**: Linux or macOS (Ubuntu 20.04+ recommended)
- **Python**: 3.9+ (3.11+ recommended)
- **Go**: 1.20+ for security tools
- **Memory**: 4GB+ RAM (8GB+ recommended)
- **Storage**: 10GB+ free space

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON.git
cd Bl4ckC3ll_PANTHEON
```

2. **Run automated setup**
```bash
./quickstart.sh
```

3. **Configure targets**
```bash
echo "example.com" > targets.txt
```

4. **Launch the framework**
```bash
python3 bl4ckc3ll_p4nth30n.py
```

### Docker Deployment

```bash
# Build container
docker build -t bl4ckc3ll-pantheon .

# Run interactive mode
docker run -it -v $(pwd)/results:/app/results bl4ckc3ll-pantheon

# Automated scan
docker run -v $(pwd)/results:/app/results bl4ckc3ll-pantheon \
  python3 cicd_integration.py --target example.com --scan-type full
```

## 🎯 Usage Examples

### Basic Security Scan
```bash
# Quick reconnaissance
python3 bl4ckc3ll_p4nth30n.py
# Select: 3. Enhanced Reconnaissance

# Full vulnerability assessment
python3 bl4ckc3ll_p4nth30n.py
# Select: 5. Full Pipeline (Recon + Vuln + Report)
```

### CI/CD Integration
```bash
# Quick security scan for CI/CD
python3 cicd_integration.py \
  --target your-target.com \
  --scan-type quick \
  --output-format sarif \
  --fail-on high

# Comprehensive assessment
python3 cicd_integration.py \
  --target your-target.com \
  --scan-type full \
  --output-format json \
  --timeout 3600
```

### BCAR Enhanced Reconnaissance
```bash
# Run BCAR-specific setup
./setup_bcar.sh

# Launch with BCAR capabilities
python3 bl4ckc3ll_p4nth30n.py
# Select: 24. BCAR Enhanced Reconnaissance
```

## 📁 Project Structure

```
Bl4ckC3ll_PANTHEON/
├── bl4ckc3ll_p4nth30n.py          # Main orchestrator
├── bl4ckc3ll_pantheon_master.py   # Master CLI/TUI application
├── bcar.py                        # BCAR reconnaissance module
├── plugins/                       # Extensible plugin system
├── tui/                          # Terminal user interface
├── nuclei-templates/             # Vulnerability templates
├── runs/                         # Scan results and reports
├── logs/                         # Application logs
├── install.sh                    # Automated installer
├── quickstart.sh                 # Quick setup script
├── Dockerfile                    # Container deployment
└── requirements.txt              # Python dependencies
```

## ⚙️ Configuration

The framework uses `p4nth30n.cfg.json` for configuration:

```json
{
  "limits": {
    "parallel_jobs": 20,
    "http_timeout": 15,
    "rps": 500,
    "max_concurrent_scans": 8
  },
  "nuclei": {
    "enabled": true,
    "severity": "low,medium,high,critical",
    "rps": 800,
    "conc": 150
  },
  "endpoints": {
    "use_gau": true,
    "use_katana": true,
    "max_urls_per_target": 5000
  },
  "report": {
    "formats": ["html", "json", "csv"],
    "auto_open_html": true
  }
}
```

## 🔌 Plugin System

Extend functionality with custom plugins:

```python
# plugins/example.py
plugin_info = {
    "name": "example",
    "description": "Example plugin",
    "version": "1.0.0",
    "author": "Your Name"
}

def execute(run_dir: Path, env: Dict[str, str], cfg: Dict[str, Any]):
    # Plugin implementation
    pass
```

## 📊 Reporting

Generated reports include:
- **HTML**: Interactive dashboard with executive summary
- **JSON**: Structured data for programmatic consumption
- **CSV**: Flattened findings for analysis
- **SARIF**: Security scanning results format for tool integration

Reports are saved under `runs/<run-id>/report/` with comprehensive vulnerability data and remediation guidance.

## 🧪 Testing

Run the test suite to validate installation:

```bash
# Core functionality tests
python3 enhanced_test_suite.py

# Integration tests
python3 final_integration_test.py

# Automated testing chain
python3 test_automation_integration.py
```

## 🛠️ Tool Dependencies

Core security tools (auto-installed via `install.sh`):
- **Reconnaissance**: subfinder, amass, naabu, httpx
- **Vulnerability Scanning**: nuclei, nikto, sqlmap
- **Web Crawling**: katana, gau, waybackurls, gospider
- **Directory Fuzzing**: gobuster, dirb, ffuf
- **Subdomain Takeover**: subjack, subzy

## 📚 Documentation

- **[USAGE_GUIDE.md](USAGE_GUIDE.md)** - Comprehensive usage instructions
- **[BCAR_USAGE_GUIDE.md](BCAR_USAGE_GUIDE.md)** - BCAR-specific features and setup
- **[SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md)** - Security best practices
- **[CHANGELOG.md](CHANGELOG.md)** - Version history and updates

## ⚖️ Legal Notice

This tool is designed for **authorized security testing only**. Users must:
- Obtain explicit permission before testing any systems
- Comply with all applicable laws and regulations
- Use the tool responsibly and ethically
- Respect system owners' rights and privacy

**The maintainers assume no liability for misuse of this software.**

## 🤝 Contributing

We welcome contributions! Please:
1. Open an issue to discuss proposed changes
2. Follow the existing code style and patterns
3. Include comprehensive tests for new features
4. Update documentation as needed

## 🙏 Acknowledgments

This project builds upon excellent open-source tools from the security community, including:
- ProjectDiscovery suite (nuclei, subfinder, httpx, etc.)
- Tom Hudson's utilities (waybackurls, etc.)
- The broader cybersecurity open-source ecosystem

---

**Made with ❤️ for the cybersecurity community**
