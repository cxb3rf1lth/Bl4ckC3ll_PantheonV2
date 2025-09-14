#!/bin/bash
# Bl4ckC3ll_PANTHEON Automated Setup Script
# Author: @cxb3rf1lth
# Purpose: Automate installation and setup of all dependencies

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   log_error "This script should not be run as root for security reasons"
   exit 1
fi

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

log_info "Starting Bl4ckC3ll_PANTHEON automated setup..."

# Check Python version
check_python() {
    log_info "Checking Python version..."
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
        
        if [[ $PYTHON_MAJOR -ge 3 && $PYTHON_MINOR -ge 9 ]]; then
            log_success "Python $PYTHON_VERSION detected (requirement: 3.9+)"
        else
            log_error "Python 3.9+ required, found $PYTHON_VERSION"
            exit 1
        fi
    else
        log_error "Python3 not found. Please install Python 3.9 or newer"
        exit 1
    fi
}

# Detect operating system
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_ID="$ID"
        OS_VERSION="$VERSION_ID"
        OS_LIKE="$ID_LIKE"
        
        case "$OS_ID" in
            "kali")
                OS_TYPE="kali"
                PACKAGE_MANAGER="apt"
                log_info "Detected Kali Linux"
                ;;
            "arch")
                OS_TYPE="arch"
                PACKAGE_MANAGER="pacman"
                log_info "Detected Arch Linux"
                ;;
            "ubuntu"|"debian")
                OS_TYPE="debian"
                PACKAGE_MANAGER="apt"
                log_info "Detected $OS_ID Linux"
                ;;
            *)
                if [[ "$OS_LIKE" == *"debian"* ]] || [[ "$OS_LIKE" == *"ubuntu"* ]]; then
                    OS_TYPE="debian"
                    PACKAGE_MANAGER="apt"
                    log_info "Detected Debian-based system"
                elif [[ "$OS_LIKE" == *"arch"* ]]; then
                    OS_TYPE="arch"
                    PACKAGE_MANAGER="pacman"
                    log_info "Detected Arch-based system"
                else
                    OS_TYPE="unknown"
                    PACKAGE_MANAGER="unknown"
                    log_warning "Unknown OS detected: $OS_ID"
                fi
                ;;
        esac
    else
        OS_TYPE="unknown"
        PACKAGE_MANAGER="unknown"
        log_warning "Could not detect operating system"
    fi
}

# Check if environment is externally managed (PEP 668)
is_externally_managed() {
    python3 -c "import sys; exit(0 if hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix else 1)" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        return 1  # In virtual environment
    fi
    
    # Check for EXTERNALLY-MANAGED file
    local python_path=$(python3 -c "import sys; print(sys.prefix)")
    if [[ -f "$python_path/EXTERNALLY-MANAGED" ]] || [[ -f "$python_path/lib/python*/site-packages/EXTERNALLY-MANAGED" ]]; then
        return 0  # Externally managed
    fi
    
    return 1  # Not externally managed
}

# Install system packages via package manager
install_system_packages() {
    log_info "Installing system packages for Python dependencies..."
    
    case "$PACKAGE_MANAGER" in
        "apt")
            sudo apt update -qq
            local packages=("python3-pip" "python3-dev" "python3-psutil" "python3-distro" "python3-requests")
            for pkg in "${packages[@]}"; do
                if ! dpkg -l | grep -q "^ii  $pkg "; then
                    log_info "Installing $pkg..."
                    sudo apt install -y "$pkg" &>/dev/null || log_warning "Failed to install $pkg"
                else
                    log_info "✓ $pkg already installed"
                fi
            done
            ;;
        "pacman")
            sudo pacman -Sy --noconfirm
            local packages=("python-pip" "python-psutil" "python-distro" "python-requests")
            for pkg in "${packages[@]}"; do
                if ! pacman -Q "$pkg" &>/dev/null; then
                    log_info "Installing $pkg..."
                    sudo pacman -S --noconfirm "$pkg" &>/dev/null || log_warning "Failed to install $pkg"
                else
                    log_info "✓ $pkg already installed"
                fi
            done
            ;;
        *)
            log_warning "Unknown package manager, attempting pip installation with fallbacks"
            ;;
    esac
}

# Upgrade pip and install Python dependencies
install_python_deps() {
    log_info "Installing Python dependencies..."
    
    # Detect OS first
    detect_os
    
    # Try system packages first for known distributions
    if [[ "$PACKAGE_MANAGER" != "unknown" ]]; then
        install_system_packages
    fi
    
    # Check if environment is externally managed
    local pip_flags=""
    if is_externally_managed; then
        log_warning "Detected externally managed Python environment"
        if [[ "$OS_TYPE" == "kali" ]]; then
            log_info "Using --break-system-packages for Kali Linux"
            pip_flags="--break-system-packages"
        else
            log_info "Creating virtual environment..."
            if ! command -v python3-venv &>/dev/null; then
                case "$PACKAGE_MANAGER" in
                    "apt") sudo apt install -y python3-venv ;;
                    "pacman") sudo pacman -S --noconfirm python-virtualenv ;;
                esac
            fi
            
            # Create and activate virtual environment
            if ! [[ -d "venv" ]]; then
                python3 -m venv venv
                log_success "Virtual environment created"
            fi
            
            # Source virtual environment
            source venv/bin/activate
            log_info "Activated virtual environment"
        fi
    fi
    
    # Upgrade pip
    python3 -m pip install --upgrade pip --user $pip_flags 2>/dev/null || \
    python3 -m pip install --upgrade pip $pip_flags
    
    # Install requirements
    if [[ -f "requirements.txt" ]]; then
        if [[ -n "$pip_flags" ]]; then
            python3 -m pip install -r requirements.txt $pip_flags
        else
            python3 -m pip install -r requirements.txt --user
        fi
        log_success "Python dependencies installed"
    else
        log_warning "requirements.txt not found, installing basic dependencies"
        local basic_deps=("psutil" "distro" "requests")
        for dep in "${basic_deps[@]}"; do
            if [[ -n "$pip_flags" ]]; then
                python3 -m pip install "$dep" $pip_flags 2>/dev/null || true
            else
                python3 -m pip install "$dep" --user 2>/dev/null || true
            fi
        done
    fi
}

# Check and install Go
install_go() {
    log_info "Checking Go installation..."
    
    if command -v go &> /dev/null; then
        GO_VERSION=$(go version | grep -oP 'go\d+\.\d+' | sed 's/go//')
        log_success "Go $GO_VERSION found"
    else
        log_info "Go not found. Installing Go..."
        
        # Detect architecture
        ARCH=$(uname -m)
        case $ARCH in
            x86_64) GO_ARCH="amd64" ;;
            aarch64|arm64) GO_ARCH="arm64" ;;
            armv7l) GO_ARCH="armv6l" ;;
            *) log_error "Unsupported architecture: $ARCH"; exit 1 ;;
        esac
        
        # Download and install Go
        GO_VERSION="1.21.3"
        GO_TAR="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"
        
        cd /tmp
        wget -q "https://golang.org/dl/${GO_TAR}"
        
        # Install to user directory if no sudo access
        if sudo -n true 2>/dev/null; then
            sudo rm -rf /usr/local/go
            sudo tar -C /usr/local -xzf "$GO_TAR"
            log_success "Go installed system-wide"
        else
            mkdir -p "$HOME/go-installation"
            tar -C "$HOME/go-installation" -xzf "$GO_TAR"
            echo 'export PATH=$HOME/go-installation/go/bin:$PATH' >> "$HOME/.bashrc"
            log_success "Go installed to user directory"
        fi
        
        rm -f "$GO_TAR"
        cd "$SCRIPT_DIR"
    fi
}

# Setup Go environment
setup_go_env() {
    log_info "Setting up Go environment..."
    
    # Determine Go installation path
    if command -v go &> /dev/null; then
        GO_ROOT=$(go env GOROOT)
    elif [[ -d "/usr/local/go" ]]; then
        export PATH="/usr/local/go/bin:$PATH"
    elif [[ -d "$HOME/go-installation/go" ]]; then
        export PATH="$HOME/go-installation/go/bin:$PATH"
    fi
    
    # Setup GOPATH and GOBIN
    export GOPATH="$HOME/go"
    export GOBIN="$GOPATH/bin"
    mkdir -p "$GOPATH" "$GOBIN"
    
    # Add to PATH if not already there
    if [[ ":$PATH:" != *":$GOBIN:"* ]]; then
        export PATH="$GOBIN:$PATH"
    fi
    
    # Add to shell profile for persistence
    SHELL_PROFILE=""
    if [[ -f "$HOME/.bashrc" ]]; then
        SHELL_PROFILE="$HOME/.bashrc"
    elif [[ -f "$HOME/.zshrc" ]]; then
        SHELL_PROFILE="$HOME/.zshrc"
    elif [[ -f "$HOME/.profile" ]]; then
        SHELL_PROFILE="$HOME/.profile"
    fi
    
    if [[ -n "$SHELL_PROFILE" ]]; then
        if ! grep -q "GOPATH.*$HOME/go" "$SHELL_PROFILE" 2>/dev/null; then
            echo '' >> "$SHELL_PROFILE"
            echo '# Go environment' >> "$SHELL_PROFILE"
            echo 'export GOPATH="$HOME/go"' >> "$SHELL_PROFILE"
            echo 'export GOBIN="$GOPATH/bin"' >> "$SHELL_PROFILE"
            echo 'export PATH="$GOBIN:$HOME/.local/bin:/usr/local/bin:$PATH"' >> "$SHELL_PROFILE"
            log_success "Go environment added to $SHELL_PROFILE"
        fi
    fi
    
    log_success "Go environment configured"
}

# Install Go-based security tools
install_go_tools() {
    log_info "Installing Go-based security tools..."
    
    # Ensure Go is available
    if ! command -v go &> /dev/null; then
        log_error "Go not available in PATH"
        exit 1
    fi
    
    # List of tools to install
    declare -A tools=(
        ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
        ["naabu"]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
        ["gau"]="github.com/lc/gau/v2/cmd/gau@latest"
        ["ffuf"]="github.com/ffuf/ffuf/v2@latest"
        ["feroxbuster"]="github.com/epi052/feroxbuster@latest"
        ["gobuster"]="github.com/OJ/gobuster/v3@latest"
        ["subjack"]="github.com/haccer/subjack@latest"
        ["subzy"]="github.com/LukaSikic/subzy@latest"
        ["waybackurls"]="github.com/tomnomnom/waybackurls@latest"
        ["gospider"]="github.com/jaeles-project/gospider@latest"
        ["paramspider"]="github.com/devanshbatham/paramspider@latest"
        ["dalfox"]="github.com/hahwul/dalfox/v2@latest"
        ["amass"]="github.com/owasp-amass/amass/v4/cmd/amass@master"
    )
    
    for tool in "${!tools[@]}"; do
        log_info "Installing $tool..."
        if go install "${tools[$tool]}"; then
            log_success "$tool installed successfully"
        else
            log_warning "Failed to install $tool, continuing..."
        fi
    done
    
    # Update nuclei templates
    if command -v nuclei &> /dev/null; then
        log_info "Updating Nuclei templates..."
        nuclei -update-templates || log_warning "Failed to update Nuclei templates"
    fi
}

# Create necessary directories
create_directories() {
    log_info "Creating necessary directories..."
    
    directories=(
        "runs"
        "logs"
        "external_lists"
        "lists_merged"
        "payloads"
        "exploits"
        "plugins"
        "backups"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
    done
    
    log_success "Directory structure created"
}

# Validate installation
# Install additional tools via system package manager and pip
install_additional_tools() {
    log_info "Installing additional security tools..."
    
    # System tools via apt (if available)
    if command -v apt &> /dev/null; then
        log_info "Installing system packages..."
        
        # Update package list
        if sudo -n true 2>/dev/null; then
            sudo apt update -qq 2>/dev/null || log_warning "Failed to update package list"
            
            # Install tools
            declare -a apt_tools=(
                "nmap"
                "sqlmap" 
                "nikto"
                "dirb"
                "masscan"
                "whatweb"
                "whois"
                "dig"
                "curl"
                "wget"
                "git"
            )
            
            for tool in "${apt_tools[@]}"; do
                if ! command -v "$tool" &> /dev/null; then
                    log_info "Installing $tool..."
                    sudo apt install -y "$tool" 2>/dev/null || log_warning "Failed to install $tool"
                fi
            done
        else
            log_warning "No sudo access, skipping system package installation"
        fi
    fi
    
    # Python tools via pip
    log_info "Installing Python-based tools..."
    
    declare -a pip_tools=(
        "XSStrike"
        "dirsearch"
        "arjun"
        "sqliv"
    )
    
    for tool in "${pip_tools[@]}"; do
        log_info "Installing $tool via pip..."
        python3 -m pip install "$tool" --user 2>/dev/null || log_warning "Failed to install $tool"
    done
    
    log_success "Additional tools installation completed"
}

# Create enhanced wordlists and payloads
create_payloads() {
    log_info "Creating enhanced payload collections..."
    
    mkdir -p "payloads/xss"
    mkdir -p "payloads/sqli"
    mkdir -p "payloads/nuclei"
    
    # XSS payloads
    cat > "payloads/xss/basic_xss.txt" << 'EOF'
<script>alert('XSS')</script>
javascript:alert('XSS')
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
';alert('XSS');//
"><script>alert('XSS')</script>
<iframe src=javascript:alert('XSS')>
<body onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>
'><svg/onload=alert('XSS')>
"><img/src/onerror=alert('XSS')>
EOF
    
    # SQLi payloads
    cat > "payloads/sqli/basic_sqli.txt" << 'EOF'
' OR '1'='1
' OR 1=1--
' OR '1'='1'/*
admin'--
admin'/*
' OR 1=1#
' OR 1=1/*
') OR ('1'='1
1' OR '1'='1
1 OR 1=1
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
'; WAITFOR DELAY '00:00:10'--
EOF
    
    log_success "Enhanced payloads created"
}

# Enhanced tool validation with auto-installation option
validate_installation() {
    log_info "Validating installation..."
    
    # Check Python script
    if [[ -f "bl4ckc3ll_p4nth30n.py" ]]; then
        log_success "Main script found: bl4ckc3ll_p4nth30n.py"
        # Test Python syntax
        if python3 -m py_compile bl4ckc3ll_p4nth30n.py 2>/dev/null; then
            log_success "Python script syntax is valid"
        else
            log_error "Python script has syntax errors"
            python3 -m py_compile bl4ckc3ll_p4nth30n.py
            exit 1
        fi
    else
        log_error "Main script not found"
        exit 1
    fi
    
    # Check configuration
    if [[ -f "p4nth30n.cfg.json" ]]; then
        log_success "Configuration file found"
        # Validate JSON syntax
        if python3 -c "import json; json.load(open('p4nth30n.cfg.json'))" 2>/dev/null; then
            log_success "Configuration file is valid JSON"
        else
            log_warning "Configuration file has invalid JSON, will be recreated"
            rm -f "p4nth30n.cfg.json"
        fi
    else
        log_warning "Configuration file not found, will be created on first run"
    fi
    
    # Check and create targets file
    if [[ -f "targets.txt" ]]; then
        log_success "Targets file found"
        # Validate targets format
        if [[ -s "targets.txt" ]]; then
            while IFS= read -r line; do
                if [[ -n "$line" && ! "$line" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$ ]]; then
                    log_warning "Invalid target format detected: $line"
                fi
            done < targets.txt
        fi
    else
        log_warning "Creating default targets.txt with example.com"
        echo "example.com" > targets.txt
    fi
    
    # Enhanced tool checking with installation suggestions
    tools_found=0
    missing_tools=()
    
    declare -A tool_info=(
        ["subfinder"]="Passive subdomain enumeration"
        ["httpx"]="Fast HTTP probe utility"
        ["naabu"]="Fast port scanner"
        ["nuclei"]="Vulnerability scanner"
        ["katana"]="Web crawling framework"
        ["gau"]="GetAllUrls - fetch URLs"
        ["ffuf"]="Fast web fuzzer"
        ["feroxbuster"]="Content discovery tool"
        ["gobuster"]="URI/DNS brute-forcer"
        ["subjack"]="Subdomain takeover tool"
        ["subzy"]="Subdomain takeover checker"
        ["nmap"]="Network discovery/security auditing"
        ["sqlmap"]="SQL injection testing tool"
        ["nikto"]="Web server scanner"
        ["dirb"]="Web content scanner"
        ["amass"]="Network mapping tool"
        ["waybackurls"]="Fetch URLs from Wayback Machine"
        ["gospider"]="Web spider"
        ["paramspider"]="Parameter discovery"
        ["dalfox"]="XSS scanning tool"
        ["assetfinder"]="Find domains and subdomains"
        ["findomain"]="Fast subdomain enumerator"
        ["masscan"]="High-speed port scanner"
        ["sslscan"]="SSL/TLS scanner"
        ["testssl.sh"]="SSL/TLS tester"
        ["sslyze"]="SSL configuration scanner"
        ["dnsrecon"]="DNS enumeration script"
    )
    
    total_tools=${#tool_info[@]}
    
    log_info "Checking ${total_tools} security tools..."
    
    for tool in "${!tool_info[@]}"; do
        if command -v "$tool" &> /dev/null; then
            log_success "$tool is available - ${tool_info[$tool]}"
            ((tools_found++))
        else
            log_warning "$tool not found - ${tool_info[$tool]}"
            missing_tools+=("$tool")
        fi
    done
    
    log_info "Found $tools_found/$total_tools security tools"
    
    # Provide installation recommendations
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_info "Missing tools can be installed using:"
        echo ""
        
        # Group tools by installation method
        declare -a go_tools=("subfinder" "httpx" "naabu" "nuclei" "katana" "assetfinder" "findomain")
        declare -a apt_tools=("nmap" "sqlmap" "nikto" "dirb" "masscan" "sslscan" "dnsrecon")
        declare -a pip_tools=("paramspider")
        declare -a manual_tools=("amass" "waybackurls" "gospider" "dalfox" "feroxbuster" "gobuster" "ffuf" "testssl.sh" "sslyze")
        
        # Go tools
        local missing_go=()
        for tool in "${go_tools[@]}"; do
            if [[ " ${missing_tools[*]} " =~ " ${tool} " ]]; then
                missing_go+=("$tool")
            fi
        done
        
        if [[ ${#missing_go[@]} -gt 0 ]]; then
            echo -e "${BLUE}Go tools:${NC}"
            for tool in "${missing_go[@]}"; do
                echo "  go install -v github.com/projectdiscovery/${tool}/v2/cmd/${tool}@latest"
            done
            echo ""
        fi
        
        # APT tools
        local missing_apt=()
        for tool in "${apt_tools[@]}"; do
            if [[ " ${missing_tools[*]} " =~ " ${tool} " ]]; then
                missing_apt+=("$tool")
            fi
        done
        
        if [[ ${#missing_apt[@]} -gt 0 ]]; then
            echo -e "${BLUE}APT packages:${NC}"
            echo "  sudo apt update && sudo apt install -y ${missing_apt[*]}"
            echo ""
        fi
        
        # PIP tools
        local missing_pip=()
        for tool in "${pip_tools[@]}"; do
            if [[ " ${missing_tools[*]} " =~ " ${tool} " ]]; then
                missing_pip+=("$tool")
            fi
        done
        
        if [[ ${#missing_pip[@]} -gt 0 ]]; then
            echo -e "${BLUE}Python packages:${NC}"
            echo "  pip3 install ${missing_pip[*]}"
            echo ""
        fi
        
        # Manual installation needed
        local missing_manual=()
        for tool in "${manual_tools[@]}"; do
            if [[ " ${missing_tools[*]} " =~ " ${tool} " ]]; then
                missing_manual+=("$tool")
            fi
        done
        
        if [[ ${#missing_manual[@]} -gt 0 ]]; then
            echo -e "${BLUE}Manual installation required:${NC}"
            for tool in "${missing_manual[@]}"; do
                case "$tool" in
                    "amass")
                        echo "  # Amass: https://github.com/OWASP/Amass/releases"
                        ;;
                    "waybackurls")
                        echo "  go install github.com/tomnomnom/waybackurls@latest"
                        ;;
                    "gospider")
                        echo "  go install github.com/jaeles-project/gospider@latest"
                        ;;
                    "dalfox")
                        echo "  go install github.com/hahwul/dalfox/v2@latest"
                        ;;
                    "feroxbuster")
                        echo "  # Feroxbuster: https://github.com/epi052/feroxbuster/releases"
                        ;;
                    "gobuster")
                        echo "  go install github.com/OJ/gobuster/v3@latest"
                        ;;
                    "ffuf")
                        echo "  go install github.com/ffuf/ffuf@latest"
                        ;;
                    "testssl.sh")
                        echo "  git clone --depth 1 https://github.com/drwetter/testssl.sh.git"
                        ;;
                    "sslyze")
                        echo "  pip3 install sslyze"
                        ;;
                esac
            done
            echo ""
        fi
        
        if [[ $tools_found -eq 0 ]]; then
            log_error "No security tools found. Install at least basic tools to continue."
            exit 1
        elif [[ $tools_found -lt 5 ]]; then
            log_warning "Very few security tools found. The framework will have limited functionality."
        elif [[ $tools_found -ge 15 ]]; then
            log_success "Excellent tool coverage detected!"
        elif [[ $tools_found -ge 10 ]]; then
            log_success "Good tool coverage detected!"
        else
            log_info "Moderate tool coverage detected."
        fi
    else
        log_success "All security tools are installed!"
    fi
    
    # Check for wordlists and create them if missing
    if [[ ! -d "wordlists_extra" ]] || [[ -z "$(ls -A wordlists_extra 2>/dev/null)" ]]; then
        log_info "Creating essential wordlists..."
        mkdir -p wordlists_extra
        
        # Create basic directory wordlist
        cat > wordlists_extra/common_directories.txt << 'EOF'
admin
api
app
backup
config
data
db
debug
dev
docs
downloads
files
images
includes
js
login
logs
old
phpinfo
setup
temp
test
tmp
upload
uploads
www
EOF
        
        # Create parameter wordlist
        cat > wordlists_extra/common_parameters.txt << 'EOF'
id
user
username
name
email
password
passwd
token
key
api_key
access_token
file
path
url
redirect
callback
return
next
debug
admin
test
search
query
q
s
EOF
        
        log_success "Essential wordlists created"
    fi
}

# Enhanced automated tool installation
install_security_tools() {
    log_info "Starting comprehensive automated security tool installation..."
    
    local install_success=0
    local install_failed=0
    
    # Install Go if not present
    if ! command -v go &> /dev/null; then
        log_warning "Go not found - installing Go first..."
        install_go
        setup_go_env
    fi
    
    # Enhanced APT tools based on OS detection
    log_info "Installing system-based security tools..."
    
    case "$PACKAGE_MANAGER" in
        "apt")
            local system_tools=(
                "nmap" "sqlmap" "nikto" "dirb" "masscan" "dnsrecon" "whois" 
                "curl" "wget" "git" "unzip" "jq" "whatweb" "commix"
                "sslscan" "sslyze" "testssl.sh" "fierce" "dnsutils"
                "netcat-openbsd" "socat" "tcpdump" "wireshark-common"
            )
            
            if sudo apt update -qq; then
                for tool in "${system_tools[@]}"; do
                    if ! command -v "${tool%%-*}" &> /dev/null && ! dpkg -l | grep -q "^ii  $tool "; then
                        log_info "Installing $tool..."
                        if sudo apt install -y "$tool" &> /dev/null; then
                            log_success "✓ $tool installed successfully"
                            ((install_success++))
                        else
                            log_warning "✗ Failed to install $tool"
                            ((install_failed++))
                        fi
                    else
                        log_info "✓ $tool already installed"
                    fi
                done
            fi
            ;;
        "pacman")
            local system_tools=(
                "nmap" "sqlmap" "nikto" "dirb" "masscan" "dnsrecon" "whois"
                "curl" "wget" "git" "unzip" "jq" "whatweb"
                "sslscan" "netcat" "socat" "tcpdump" "wireshark-cli"
            )
            
            for tool in "${system_tools[@]}"; do
                if ! command -v "$tool" &> /dev/null && ! pacman -Q "$tool" &> /dev/null; then
                    log_info "Installing $tool..."
                    if sudo pacman -S --noconfirm "$tool" &> /dev/null; then
                        log_success "✓ $tool installed successfully"
                        ((install_success++))
                    else
                        log_warning "✗ Failed to install $tool"
                        ((install_failed++))
                    fi
                else
                    log_info "✓ $tool already installed"
                fi
            done
            ;;
        *)
            log_warning "Unknown package manager, skipping system tools"
            ;;
    esac
    
    # Install Go-based security tools (comprehensive list)
    log_info "Installing Go-based security tools..."
    local go_tools=(
        # Core ProjectDiscovery Tools
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest" 
        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/projectdiscovery/katana/cmd/katana@latest"
        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        "github.com/projectdiscovery/notify/cmd/notify@latest"
        "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
        
        # Web Discovery and Fuzzing
        "github.com/ffuf/ffuf/v2@latest"
        "github.com/OJ/gobuster/v3@latest"
        "github.com/epi052/feroxbuster@latest"
        "github.com/hahwul/dalfox/v2@latest"
        
        # URL and Asset Discovery
        "github.com/lc/gau/v2/cmd/gau@latest"
        "github.com/tomnomnom/waybackurls@latest"
        "github.com/jaeles-project/gospider@latest"
        "github.com/tomnomnom/assetfinder@latest"
        "github.com/findomain/findomain@latest"
        
        # Subdomain Takeover and Security
        "github.com/haccer/subjack@latest"
        "github.com/LukaSikic/subzy@latest"
        
        # Parameter Discovery and Testing
        "github.com/devanshbatham/paramspider@latest"
        "github.com/maK-/parameth@latest"
        
        # Additional Tools
        "github.com/tomnomnom/httprobe@latest"
        "github.com/tomnomnom/meg@latest"
        "github.com/tomnomnom/unfurl@latest"
        "github.com/tomnomnom/anew@latest"
        "github.com/hakluke/hakrawler@latest"
        "github.com/michenriksen/aquatone@latest"
        "github.com/sensepost/gowitness@latest"
        
        # OWASP Tools
        "github.com/owasp-amass/amass/v4/cmd/amass@master"
    )
    
    for tool_url in "${go_tools[@]}"; do
        tool_name=$(basename "${tool_url%@*}")
        if ! command -v "$tool_name" &> /dev/null; then
            log_info "Installing $tool_name..."
            if timeout 180 go install -v "$tool_url" &> /dev/null; then
                log_success "✓ $tool_name installed successfully"
                ((install_success++))
            else
                log_warning "✗ Failed to install $tool_name (timeout or error)"
                ((install_failed++))
            fi
        else
            log_info "✓ $tool_name already installed"
        fi
    done
    
    # Install Python tools (using the pip flags determined earlier)
    log_info "Installing Python-based security tools..."
    local python_tools=(
        "arjun" "dirsearch" "xsstrike" "sqlmap" "commix"
        "sublist3r" "droopescan" "wappalyzer" "shodan"
        "censys" "builtwith" "wafw00f" "whatweb"
        "requests" "beautifulsoup4" "lxml" "selenium"
    )
    
    for tool in "${python_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null && ! python3 -c "import $tool" &> /dev/null 2>&1; then
            log_info "Installing $tool..."
            
            # Use the same pip installation method as the dependency installation
            local pip_cmd="pip3 install"
            if [[ -n "$pip_flags" ]]; then
                pip_cmd="pip3 install $pip_flags"
            else
                pip_cmd="pip3 install --user"
            fi
            
            if $pip_cmd "$tool" &> /dev/null; then
                log_success "✓ $tool installed successfully"
                ((install_success++))
            else
                log_warning "✗ Failed to install $tool"
                ((install_failed++))
            fi
        else
            log_info "✓ $tool already available"
        fi
    done
    
    # Install Node.js tools (if npm is available)
    if command -v npm &> /dev/null; then
        log_info "Installing Node.js-based security tools..."
        local npm_tools=("wappalyzer" "retire" "@zap/cli" "ssl-checker")
        
        for tool in "${npm_tools[@]}"; do
            if ! npm list -g "$tool" &> /dev/null; then
                log_info "Installing $tool..."
                if sudo npm install -g "$tool" &> /dev/null; then
                    log_success "✓ $tool installed successfully"
                    ((install_success++))
                else
                    log_warning "✗ Failed to install $tool"
                    ((install_failed++))
                fi
            else
                log_info "✓ $tool already installed"
            fi
        done
    else
        log_warning "npm not found, skipping Node.js tools"
    fi
    
    # Install Rust tools (if cargo is available)
    if command -v cargo &> /dev/null; then
        log_info "Installing Rust-based security tools..."
        local rust_tools=("rustscan" "ripgrep" "fd-find")
        
        for tool in "${rust_tools[@]}"; do
            if ! command -v "$tool" &> /dev/null; then
                log_info "Installing $tool..."
                if timeout 300 cargo install "$tool" &> /dev/null; then
                    log_success "✓ $tool installed successfully"
                    ((install_success++))
                else
                    log_warning "✗ Failed to install $tool"
                    ((install_failed++))
                fi
            else
                log_info "✓ $tool already installed"
            fi
        done
    else
        log_info "cargo not found, skipping Rust tools (optional)"
    fi
    
    # Update nuclei templates
    if command -v nuclei &> /dev/null; then
        log_info "Updating nuclei templates..."
        nuclei -ut &> /dev/null || log_warning "Failed to update nuclei templates"
    fi
    
    # Update Go module cache
    if command -v go &> /dev/null; then
        log_info "Cleaning Go module cache..."
        go clean -modcache &> /dev/null || true
    fi
    
    log_info "Comprehensive tool installation complete:"
    log_info "  ✓ $install_success tools installed successfully"
    if [[ $install_failed -gt 0 ]]; then
        log_warning "  ✗ $install_failed tools failed to install"
    fi
    
    # Final tool validation
    log_info "Validating installed tools..."
    local core_tools=("subfinder" "httpx" "naabu" "nuclei" "katana" "gau" "ffuf" "nmap")
    local available_core=0
    
    for tool in "${core_tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            ((available_core++))
        fi
    done
    
    log_info "Core tools available: $available_core/${#core_tools[@]}"
    
    if [[ $available_core -ge 6 ]]; then
        log_success "Excellent tool coverage achieved!"
    elif [[ $available_core -ge 4 ]]; then
        log_success "Good tool coverage achieved!"
    elif [[ $available_core -ge 2 ]]; then
        log_warning "Moderate tool coverage. Some features may be limited."
    else
        log_error "Poor tool coverage. Many features will be unavailable."
    fi
}

# Enhanced wordlist creation and management
create_enhanced_wordlists() {
    log_info "Creating and downloading essential wordlists..."
    
    mkdir -p wordlists_extra lists_merged external_lists payloads
    
    # Create comprehensive directory wordlist
    if [[ ! -f "wordlists_extra/directories_comprehensive.txt" ]]; then
        cat > wordlists_extra/directories_comprehensive.txt << 'EOF'
admin
administrator
api
app
application
assets
backup
backups
bin
blog
cache
cgi-bin
config
configuration
console
content
data
database
db
debug
dev
development
doc
docs
download
downloads
etc
files
home
html
images
img
includes
js
lib
library
log
login
logs
mail
manager
media
old
panel
phpinfo
private
public
setup
src
static
temp
test
tmp
upload
uploads
user
users
var
web
www
xml
EOF
    fi
    
    # Create comprehensive parameter wordlist
    if [[ ! -f "wordlists_extra/parameters_comprehensive.txt" ]]; then
        cat > wordlists_extra/parameters_comprehensive.txt << 'EOF'
id
user
username
name
email
password
passwd
pwd
token
key
api_key
access_token
auth_token
session
sessionid
file
filename
path
filepath
url
redirect_url
redirect
callback
return_url
return
next
debug
admin
test
search
query
q
s
page
limit
offset
sort
order
filter
category
type
action
method
format
version
lang
language
locale
EOF
    fi
    
    # Create subdomain wordlist
    if [[ ! -f "wordlists_extra/subdomains_comprehensive.txt" ]]; then
        cat > wordlists_extra/subdomains_comprehensive.txt << 'EOF'
www
mail
ftp
admin
api
dev
test
staging
prod
blog
shop
store
app
mobile
m
secure
vpn
remote
support
help
docs
wiki
portal
dashboard
panel
cpanel
webmail
email
smtp
pop
imap
ns1
ns2
dns
cdn
static
assets
media
images
img
css
js
ajax
json
xml
rss
forum
news
beta
alpha
demo
sandbox
EOF
    fi
    
    log_success "Enhanced wordlists created"
}

# Safe wordlist downloading
download_wordlists_safely() {
    log_info "Downloading essential external wordlists..."
    
    local wordlist_urls=(
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt:external_lists/directories_medium.txt"
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt:external_lists/directories_common.txt"
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt:external_lists/subdomains_top5k.txt"
    )
    
    for entry in "${wordlist_urls[@]}"; do
        local url="${entry%:*}"
        local filename="${entry#*:}"
        
        if [[ ! -f "$filename" ]]; then
            log_info "Downloading $(basename "$filename")..."
            if timeout 60 curl -s -L -o "$filename" "$url" 2>/dev/null; then
                if [[ -s "$filename" ]]; then
                    log_success "✓ Downloaded $(basename "$filename")"
                else
                    log_warning "✗ Downloaded file is empty: $(basename "$filename")"
                    rm -f "$filename"
                fi
            else
                log_warning "✗ Failed to download $(basename "$filename")"
            fi
        fi
    done
}

# Create a quick test script
create_test_script() {
    log_info "Creating test script..."
    
    cat > test_installation.py << 'EOF'
#!/usr/bin/env python3
"""Test script to validate Bl4ckC3ll_PANTHEON installation"""

import sys
import subprocess
import shutil
from pathlib import Path

def test_python_deps():
    """Test Python dependencies"""
    try:
        import psutil
        import distro
        print("✓ Python dependencies available")
        return True
    except ImportError as e:
        print(f"✗ Python dependency missing: {e}")
        return False

def test_go_tools():
    """Test Go tools availability"""
    tools = ['subfinder', 'httpx', 'naabu', 'nuclei', 'katana', 'gau']
    available = []
    
    for tool in tools:
        if shutil.which(tool):
            available.append(tool)
    
    print(f"✓ {len(available)}/{len(tools)} Go tools available: {', '.join(available)}")
    return len(available) > 0

def test_main_script():
    """Test main script syntax"""
    try:
        result = subprocess.run([sys.executable, '-m', 'py_compile', 'bl4ckc3ll_p4nth30n.py'], 
                               capture_output=True, text=True)
        if result.returncode == 0:
            print("✓ Main script syntax is valid")
            return True
        else:
            print(f"✗ Main script syntax error: {result.stderr}")
            return False
    except Exception as e:
        print(f"✗ Error testing main script: {e}")
        return False

if __name__ == "__main__":
    print("Testing Bl4ckC3ll_PANTHEON installation...\n")
    
    tests = [
        test_python_deps,
        test_go_tools, 
        test_main_script
    ]
    
    passed = 0
    for test in tests:
        if test():
            passed += 1
        print()
    
    print(f"Tests passed: {passed}/{len(tests)}")
    
    if passed == len(tests):
        print("🎉 Installation appears to be successful!")
        sys.exit(0)
    else:
        print("⚠️  Some tests failed. Check the output above.")
        sys.exit(1)
EOF
    
    chmod +x test_installation.py
    log_success "Test script created: test_installation.py"
}

# Main installation flow
main() {
    log_info "Bl4ckC3ll_PANTHEON Automated Setup"
    log_info "=================================="
    
    check_python
    install_python_deps
    install_go
    setup_go_env
    install_go_tools
    install_additional_tools
    
    # Enhanced installation features
    log_info ""
    log_info "Enhanced Installation Phase"
    log_info "==========================="
    
    # Auto-install missing security tools
    install_security_tools
    
    # Create enhanced wordlists
    create_enhanced_wordlists
    
    # Download external wordlists safely
    download_wordlists_safely
    
    create_directories
    create_payloads
    create_test_script
    validate_installation
    
    echo ""
    log_success "Setup completed successfully!"
    echo ""
    log_info "Next steps:"
    echo "  1. Source your shell profile or restart your terminal:"
    echo "     source ~/.bashrc  # or ~/.zshrc"
    echo ""
    echo "  2. Test the installation:"
    echo "     python3 test_installation.py"
    echo ""
    echo "  3. Run the main script:"
    echo "     python3 bl4ckc3ll_p4nth30n.py"
    echo ""
    echo "  4. For missing tools, run with --install flag:"
    echo "     ./install.sh --install-tools"
    echo ""
    log_info "For troubleshooting, check the generated test_installation.py script"
}

# Run main function
main "$@"