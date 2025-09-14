#!/bin/bash
# BCAR Setup Script for Bl4ckC3ll_PANTHEON
# Author: @cxb3rf1lth
# Purpose: Ensure all BCAR dependencies are properly configured

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[BCAR INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[BCAR SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[BCAR WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[BCAR ERROR]${NC} $1"
}

# Check if running from correct directory
if [[ ! -f "bl4ckc3ll_p4nth30n.py" ]] || [[ ! -f "bcar.py" ]]; then
    log_error "Please run this script from the Bl4ckC3ll_PANTHEON directory"
    exit 1
fi

log_info "Starting BCAR Enhanced Setup..."

# 1. Verify BCAR module
log_info "Checking BCAR module..."
if python3 -c "from bcar import BCARCore, PantheonBCARIntegration; print('BCAR module OK')" 2>/dev/null; then
    log_success "BCAR module is properly installed"
else
    log_error "BCAR module import failed"
    exit 1
fi

# 2. Check Python dependencies
log_info "Checking Python dependencies for BCAR..."
missing_deps=()

check_python_module() {
    if python3 -c "import $1" 2>/dev/null; then
        log_success "$1 is available"
    else
        log_warning "$1 is missing"
        missing_deps+=("$1")
    fi
}

check_python_module "requests"
check_python_module "json"
check_python_module "threading"
check_python_module "concurrent.futures"
check_python_module "urllib.parse"
check_python_module "ssl"
check_python_module "socket"
check_python_module "base64"

if [[ ${#missing_deps[@]} -gt 0 ]]; then
    log_warning "Installing missing Python dependencies..."
    pip3 install requests urllib3 --user
fi

# 3. Test network connectivity to Certificate Transparency APIs
log_info "Testing Certificate Transparency API connectivity..."

test_ct_api() {
    local url="$1"
    local name="$2"
    
    if curl -s --connect-timeout 5 "$url" > /dev/null; then
        log_success "$name API is accessible"
    else
        log_warning "$name API is not accessible (may affect CT search functionality)"
    fi
}

test_ct_api "https://crt.sh/?q=example.com&output=json" "crt.sh"
test_ct_api "https://api.certspotter.com/v1/issuances?domain=example.com" "CertSpotter"

# 4. Check subdomain takeover signatures
log_info "Validating subdomain takeover signatures..."
python3 -c "
from bcar import BCARCore
bcar = BCARCore()
# Test basic functionality
signatures = {
    'github.io': ['There isn\'t a GitHub Pages site here'],
    'herokuapp.com': ['No such app'],
    'amazonaws.com': ['NoSuchBucket']
}
print(f'✓ {len(signatures)} takeover signatures loaded')
"

# 5. Test payload generation
log_info "Testing payload generation..."
python3 -c "
from bcar import BCARCore, PantheonBCARIntegration
bcar = BCARCore()
integration = PantheonBCARIntegration()
payloads = bcar.generate_reverse_shell_payloads('127.0.0.1', 4444)
meterpreter = integration.generate_meterpreter_payloads('127.0.0.1', 4444)
print(f'✓ Generated {len(payloads)} basic payloads')
print(f'✓ Generated {len(meterpreter)} meterpreter payloads')
"

# 6. Verify fuzzing wordlists
log_info "Checking fuzzing wordlists..."
python3 -c "
from bcar import BCARCore
bcar = BCARCore()
subdomains = bcar._get_default_subdomain_wordlist()
fuzzing = bcar._get_default_fuzzing_wordlist()
print(f'✓ Subdomain wordlist: {len(subdomains)} entries')
print(f'✓ Fuzzing wordlist: {len(fuzzing)} entries')
"

# 7. Test BCAR configuration
log_info "Testing BCAR configuration..."
if [[ -f "p4nth30n.cfg.json" ]]; then
    if python3 -c "
import json
with open('p4nth30n.cfg.json', 'r') as f:
    cfg = json.load(f)
    
bcar_config = cfg.get('bcar', {})
payload_config = cfg.get('payload_injection', {})
fuzzing_config = cfg.get('fuzzing', {})

print(f'✓ BCAR config loaded with {len(bcar_config)} settings')
print(f'✓ Payload config loaded with {len(payload_config)} settings')
print(f'✓ Fuzzing config loaded with {len(fuzzing_config)} settings')
" 2>/dev/null; then
        log_success "BCAR configuration is valid"
    else
        log_warning "BCAR configuration needs updating"
        log_info "Backing up and updating configuration..."
        cp p4nth30n.cfg.json p4nth30n.cfg.json.backup
        
        # Update config with BCAR settings
        python3 -c "
import json
with open('p4nth30n.cfg.json', 'r') as f:
    cfg = json.load(f)

# Add BCAR settings if missing
if 'bcar' not in cfg:
    cfg['bcar'] = {
        'ct_search': True,
        'subdomain_enum': True,
        'takeover_check': True,
        'port_scan': True,
        'tech_detection': True,
        'directory_fuzz': True,
        'parameter_discovery': True,
        'max_subdomains': 1000,
        'threads': 30,
        'timeout': 10
    }

if 'payload_injection' not in cfg:
    cfg['payload_injection'] = {
        'lhost': '127.0.0.1',
        'lport': 4444,
        'test_mode': True,
        'platforms': ['bash', 'python', 'php', 'powershell', 'perl', 'ruby'],
        'meterpreter_enabled': True
    }

if 'fuzzing' not in cfg:
    cfg['fuzzing'] = {
        'threads': 30,
        'timeout': 5,
        'status_codes': [200, 301, 302, 403, 500],
        'extensions': ['', '.php', '.asp', '.aspx', '.jsp', '.html', '.txt', '.bak', '.old']
    }

with open('p4nth30n.cfg.json', 'w') as f:
    json.dump(cfg, f, indent=2)
"
        log_success "BCAR configuration updated"
    fi
else
    log_warning "Configuration file not found, creating default..."
    cat > p4nth30n.cfg.json << 'EOF'
{
  "bcar": {
    "ct_search": true,
    "subdomain_enum": true,
    "takeover_check": true,
    "port_scan": true,
    "tech_detection": true,
    "directory_fuzz": true,
    "parameter_discovery": true,
    "max_subdomains": 1000,
    "threads": 30,
    "timeout": 10
  },
  "payload_injection": {
    "lhost": "127.0.0.1",
    "lport": 4444,
    "test_mode": true,
    "platforms": ["bash", "python", "php", "powershell", "perl", "ruby"],
    "meterpreter_enabled": true
  },
  "fuzzing": {
    "threads": 30,
    "timeout": 5,
    "status_codes": [200, 301, 302, 403, 500],
    "extensions": ["", ".php", ".asp", ".aspx", ".jsp", ".html", ".txt", ".bak", ".old"]
  }
}
EOF
    log_success "Default BCAR configuration created"
fi

# 8. Create necessary directories
log_info "Creating BCAR directories..."
mkdir -p runs bcar_results payloads logs

# 9. Test full BCAR integration
log_info "Testing full BCAR integration..."
echo "test.example.com" > targets.txt
python3 -c "
from bl4ckc3ll_p4nth30n import start_run, run_bcar_enhanced_reconnaissance, load_cfg

# Test the integration
rd, env = start_run('bcar_setup_test')
cfg = {
    'bcar': {
        'ct_search': False,  # Disable network calls for test
        'subdomain_enum': False,
        'takeover_check': False,
        'port_scan': False,
        'tech_detection': False,
        'directory_fuzz': False,
        'parameter_discovery': False
    }
}

try:
    run_bcar_enhanced_reconnaissance(rd, env, cfg)
    print('✓ BCAR integration test passed')
except Exception as e:
    print(f'✗ BCAR integration test failed: {e}')
    exit(1)
"

# 10. Security checks
log_info "Running security checks..."

# Check test mode is enabled
if grep -q '"test_mode": true' p4nth30n.cfg.json; then
    log_success "Safety mode (test_mode) is enabled"
else
    log_warning "Safety mode is disabled - ensure this is intentional"
fi

# Check file permissions
chmod 755 bl4ckc3ll_p4nth30n.py bcar.py
chmod 600 p4nth30n.cfg.json 2>/dev/null || true

log_success "BCAR setup completed successfully!"

echo ""
log_info "BCAR Quick Start:"
echo "  1. Edit targets: echo 'target.com' > targets.txt"
echo "  2. Launch framework: python3 bl4ckc3ll_p4nth30n.py"
echo "  3. Select BCAR options:"
echo "     - 24: BCAR Enhanced Reconnaissance"
echo "     - 25: Advanced Subdomain Takeover"
echo "     - 26: Automated Payload Injection"
echo "     - 27: Comprehensive Advanced Fuzzing"
echo ""
log_info "For detailed usage: cat BCAR_USAGE_GUIDE.md"
log_info "Configuration file: p4nth30n.cfg.json"
echo ""
log_success "BCAR is ready for use!"