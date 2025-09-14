# Bl4ckC3ll PANTHEON MASTER - Complete Usage Guide

## 🚀 Quick Start Guide

### Installation & Setup

```bash
# 1. Clone the repository
git clone https://github.com/cxb3rf1lth/Bl4ckC3ll_PANTHEON.git
cd Bl4ckC3ll_PANTHEON

# 2. Install dependencies  
pip install -r requirements.txt

# 3. Make executable
chmod +x bl4ckc3ll_pantheon_master.py

# 4. Run the master tool
python3 bl4ckc3ll_pantheon_master.py
```

## 🎛️ Usage Modes

### 1. Interactive CLI Mode (Default)
```bash
python3 bl4ckc3ll_pantheon_master.py
```
- Full menu system with 17 specialized modules
- Step-by-step guided workflow  
- Comprehensive help and documentation

### 2. Advanced TUI Interface
```bash
python3 bl4ckc3ll_pantheon_master.py --tui
```
- Professional terminal interface
- Real-time system monitoring
- Tabbed navigation (Dashboard, Targets, Scanner, Reports, Settings)
- Interactive data tables and progress tracking

### 3. Quick Target Scan
```bash
python3 bl4ckc3ll_pantheon_master.py --target example.com
```
- Immediate reconnaissance on specified target
- BCAR certificate transparency search
- Subdomain enumeration and takeover detection

### 4. Command Line Options
```bash
python3 bl4ckc3ll_pantheon_master.py --verbose --target example.com
python3 bl4ckc3ll_pantheon_master.py --quiet
python3 bl4ckc3ll_pantheon_master.py --config custom_config.json
```

## 📋 Complete Menu System

### Main Menu Overview
```
🎯 [1]  Target Management      - Add, edit, manage scan targets
🔍 [2]  BCAR Reconnaissance    - Certificate transparency discovery  
🌐 [3]  Advanced Port Scanning - Comprehensive port detection
🛡️ [4]  Technology Detection   - Framework identification
⚡ [5]  Subdomain Takeover     - Vulnerability assessment
🔒 [6]  Security Validation    - Input sanitization testing
📊 [7]  Vulnerability Assessment - AI-powered analysis
☁️ [8]  Cloud Security Testing - Multi-cloud assessment
🔗 [9]  API Security Testing   - REST/GraphQL/SOAP testing
🤖 [10] Automated Testing Chain - Complete automation
💉 [11] Payload Management     - Advanced payload systems
🎨 [12] TUI Interface          - Launch terminal interface
📈 [13] Generate Reports       - Professional reporting
⚙️ [14] Configuration          - Framework settings
🔧 [15] Tool Diagnostics       - System status check
📚 [16] Help & Documentation   - Usage guidance
🚪 [17] Exit                   - Close application
```

## 🎯 Module-by-Module Guide

### 1. Target Management
**Purpose**: Add and manage scan targets

**Workflow**:
1. Select `[1] Target Management`
2. Choose `1. Add single target`
3. Enter domain (e.g., `example.com`) or IP address
4. Target is validated and added to configuration

**Features**:
- Domain and IP validation
- Target list management
- Multiple target support
- Input sanitization

### 2. BCAR Reconnaissance  
**Purpose**: Advanced subdomain discovery and reconnaissance

**What it does**:
- Certificate Transparency (CT) log searches
- Advanced subdomain enumeration
- Subdomain takeover vulnerability detection
- Multi-source subdomain discovery

**Example Output**:
```
🔍 Searching certificate transparency logs...
✅ Found 247 subdomains from CT logs
🔍 Performing advanced subdomain enumeration...  
✅ Found 18 subdomains via enumeration
🔍 Checking for subdomain takeover vulnerabilities...
⚠️  Found 2 potential takeover vulnerabilities!
  - dev.example.com -> GitHub Pages
  - staging.example.com -> AWS S3
```

### 3. Advanced Port Scanning
**Purpose**: Multi-threaded port discovery

**Features**:
- Fast multi-threaded scanning
- Top 1000 ports by default
- Service detection
- Open port enumeration

**Example**:
```
🎯 Target: example.com
✅ Open ports (12): 22, 25, 53, 80, 110, 143, 443, 587, 993, 995, 3306, 5432
```

### 4. Technology Detection
**Purpose**: Web technology and framework identification

**Detects**:
- Web servers (Apache, Nginx, IIS)
- Frameworks (WordPress, Drupal, Joomla)
- Programming languages (PHP, ASP.NET, Python)
- Content Management Systems

**Example Output**:
```
🔗 URL: http://example.com
📊 Status: 200
🖥️  Server: nginx/1.18.0
📝 Title: Example Domain
⚙️  Technologies: Nginx, PHP, WordPress
```

### 5. Subdomain Takeover Check
**Purpose**: Detect subdomain takeover vulnerabilities

**Checks for**:
- AWS S3 bucket takeovers
- GitHub Pages misconfigurations
- Heroku app takeovers
- Azure website takeovers
- 13+ cloud service signatures

### 6. Security Validation
**Purpose**: Test input validation and sanitization

**Tests**:
- Domain validation
- IP address validation  
- XSS prevention
- SQL injection prevention
- Path traversal protection
- Command injection prevention

**Example Demonstration**:
```
🔍 Testing: <script>alert('xss')</script>
   Domain validation: ❌ FAIL
   IP validation: ❌ FAIL
   Sanitized: ltscriptgtalert#x27xss#x27lt/scriptgt

🔍 Testing: '; DROP TABLE users; --
   Domain validation: ❌ FAIL
   IP validation: ❌ FAIL
   Sanitized: #x27  TABLE users 
```

### 7. Vulnerability Assessment
**Purpose**: AI-powered vulnerability analysis

**Capabilities**:
- Machine learning vulnerability prioritization
- False positive reduction
- Risk scoring and correlation
- Pattern recognition
- Intelligent threat assessment

### 8. Cloud Security Testing  
**Purpose**: Multi-cloud security assessment

**Supports**:
- AWS S3 bucket enumeration
- Azure Blob storage detection
- Google Cloud Storage scanning
- Container registry analysis
- Kubernetes exposure testing
- Cloud metadata SSRF testing

### 9. API Security Testing
**Purpose**: Comprehensive API security assessment

**Tests**:
- REST API endpoint discovery
- GraphQL schema analysis  
- SOAP service enumeration
- JWT token validation
- Authentication bypass detection
- API rate limiting testing

### 10. Automated Testing Chain
**Purpose**: Complete automated security pipeline

**Workflow**:
1. BCAR Reconnaissance (Step 1/4)
2. Port Scanning (Step 2/4)  
3. Technology Detection (Step 3/4)
4. Security Assessment (Step 4/4)

**Example**:
```
🎯 Processing target: example.com
  Step 1/4: BCAR Reconnaissance...
    ✅ Found 247 subdomains
  Step 2/4: Port Scanning...
    ✅ Found 12 open ports
  Step 3/4: Technology Detection...
    ✅ Detected 5 technologies
  Step 4/4: Security Assessment...
    ✅ Assessment completed
```

### 11. Payload Management
**Purpose**: Advanced payload generation and management

**Features**:
- Multi-platform reverse shell payloads
- XSS payload generation
- SQL injection payloads
- Command injection payloads
- Custom payload templates
- Payload encoding and obfuscation

### 12. TUI Interface
**Purpose**: Launch advanced terminal user interface

**Features**:
- Professional tabbed interface
- Real-time system monitoring
- Interactive target management
- Live scan progress tracking
- Configuration management

### 13. Generate Reports
**Purpose**: Comprehensive security assessment reports

**Formats**:
- HTML reports with visualizations
- JSON structured data export
- CSV data export  
- Executive summary
- Technical findings
- Risk assessment matrix
- Remediation recommendations

### 14. Configuration
**Purpose**: Framework settings and preferences

**Displays**:
- General settings (threads, timeout, retries)
- Scanning configuration (wordlist size, port ranges)
- Security settings (validation, sanitization, rate limiting)
- Reporting preferences (formats, screenshots)

### 15. Tool Diagnostics
**Purpose**: System status and capability check

**Shows**:
- Python library availability
- System information (OS, Python version, architecture)
- Resource usage (CPU, memory, disk)
- Framework status

**Example**:
```
📚 Python Library Status:
  requests             ✅ AVAILABLE    - HTTP client library
  psutil              ✅ AVAILABLE    - System monitoring
  textual             ✅ AVAILABLE    - Terminal UI framework
  numpy/pandas/sklearn ✅ AVAILABLE    - Machine learning capabilities
  matplotlib/plotly   ✅ AVAILABLE    - Data visualization
  cryptography        ✅ AVAILABLE    - Cryptographic functions

🖥️  System Information:
  OS: Linux 6.11.0-1018-azure
  Python: 3.12.3
  Architecture: x86_64
  CPU Cores: 4
  Memory: 15GB
```

### 16. Help & Documentation
**Purpose**: Usage guide and documentation

**Provides**:
- Framework overview
- Capability descriptions
- Security features explanation
- Usage examples
- Important disclaimer and legal notice

## 🎨 TUI Interface Guide

### Navigation
- **Tabs**: Use F1-F5 or click to switch between tabs
- **Keyboard Shortcuts**: 
  - `Ctrl+Q` - Quit application
  - `Ctrl+D` - Toggle dark mode
  - `Ctrl+R` - Refresh current view

### Dashboard Tab
- System information display
- Resource usage monitoring (CPU, Memory, Disk)
- Framework status indicators
- Real-time updates

### Targets Tab  
- Add new targets via input field
- Target validation (domain/IP)
- Interactive target table
- Target management controls

### Scanner Tab
- Scan configuration checkboxes
- Start scan button
- Real-time progress bar
- Live scan log output

### Reports Tab
- Scan results table
- Report generation controls
- Export options

### Settings Tab
- Configuration parameters
- Framework preferences
- Save settings functionality

## 🔧 Configuration Guide

### Default Configuration
```json
{
  "general": {
    "max_threads": 50,
    "timeout": 30,
    "retries": 3,
    "verbose": true,
    "output_format": "json"
  },
  "scanning": {
    "subdomain_wordlist_size": 10000,
    "port_scan_top_ports": 1000,
    "http_timeout": 10,
    "max_crawl_depth": 3
  },
  "security": {
    "validate_inputs": true,
    "sanitize_outputs": true,
    "rate_limiting": true,
    "max_payload_size": 1048576
  },
  "reporting": {
    "generate_html": true,
    "generate_json": true,
    "generate_csv": true,
    "include_screenshots": false
  }
}
```

### Environment Variables
```bash
export PANTHEON_CONFIG="/path/to/config.json"
export PANTHEON_LOG_LEVEL="DEBUG"
export PANTHEON_MAX_THREADS="100"
export PANTHEON_TIMEOUT="60"
```

## 🎯 Common Workflows

### Workflow 1: Basic Domain Assessment
1. Launch tool: `python3 bl4ckc3ll_pantheon_master.py`
2. Select `[1] Target Management` → Add domain
3. Select `[2] BCAR Reconnaissance` → Run discovery
4. Select `[13] Generate Reports` → Export results

### Workflow 2: Comprehensive Security Assessment
1. Select `[10] Automated Testing Chain`
2. Ensure targets are configured
3. Watch automated execution of all phases
4. Review comprehensive results

### Workflow 3: TUI-Based Interactive Assessment
1. Launch TUI: `python3 bl4ckc3ll_pantheon_master.py --tui`
2. Navigate to Targets tab → Add target
3. Navigate to Scanner tab → Configure scan → Start
4. Monitor progress in real-time
5. Review results in Reports tab

### Workflow 4: Security Validation Testing
1. Select `[6] Security Validation`
2. Observe input validation demonstrations
3. Review sanitization examples
4. Understand security measures

## 🛡️ Security Best Practices

### Before Using the Tool
- ✅ Ensure you have proper authorization
- ✅ Review target scope and boundaries  
- ✅ Understand legal implications
- ✅ Configure appropriate rate limiting

### During Assessment
- ✅ Monitor resource usage
- ✅ Respect target systems
- ✅ Use appropriate thread limits
- ✅ Follow responsible disclosure

### After Assessment
- ✅ Secure assessment data
- ✅ Generate professional reports
- ✅ Follow up on findings
- ✅ Document remediation steps

## ❗ Important Notes

### Legal Disclaimer
- This tool is for **educational and authorized testing only**
- Users are **solely responsible** for ensuring proper authorization
- **Not intended** for unauthorized scanning or malicious activities
- Follow all local laws and regulations

### Technical Notes
- Requires Python 3.8 or higher
- Internet connection needed for external services
- Some features require additional Python libraries
- Performance scales with system resources

### Support & Resources
- Documentation: README_MASTER.md
- Issues: GitHub Issues page
- Community: GitHub Discussions
- Author: @cxb3rf1lth

---

**Made with ❤️ for the security research community**  
**Bl4ckC3ll PANTHEON MASTER v10.0.0-MASTER-CONSOLIDATED**