#!/bin/bash
# Bug Bounty Automation Commands for Bl4ckC3ll_PANTHEON v2.0
# Author: @cxb3rf1lth
# Description: Enhanced comprehensive bug bounty reconnaissance and testing automation

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/bug_bounty_results"
PAYLOADS_DIR="${SCRIPT_DIR}/payloads"
WORDLISTS_DIR="${SCRIPT_DIR}/wordlists_extra"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="${RESULTS_DIR}/bug_bounty_${TIMESTAMP}.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Create results directory
mkdir -p "${RESULTS_DIR}"
mkdir -p "${RESULTS_DIR}/partial"

# Enhanced logging function
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "${LOG_FILE}"
}

# Enhanced error handling with recovery and backup
error_exit() {
    log "${RED}[ERROR] $1${NC}" >&2
    # Try to save any partial results
    save_partial_results
    # Create error report
    create_error_report "$1"
    exit 1
}

# Save partial results to prevent data loss
save_partial_results() {
    local partial_dir="${RESULTS_DIR}/partial/recovery_${TIMESTAMP}"
    mkdir -p "$partial_dir"
    
    # Copy any existing results
    if [[ -d "${RESULTS_DIR}" ]]; then
        find "${RESULTS_DIR}" -name "*.txt" -o -name "*.json" -o -name "*.xml" 2>/dev/null | \
        while read -r file; do
            if [[ -s "$file" ]]; then
                cp "$file" "$partial_dir/" 2>/dev/null || true
            fi
        done
        log "${YELLOW}[RECOVERY] Partial results saved to: $partial_dir${NC}"
    fi
}

# Create error report with context
create_error_report() {
    local error_msg="$1"
    local error_report="${RESULTS_DIR}/error_report_${TIMESTAMP}.txt"
    
    {
        echo "=== Bl4ckC3ll_PANTHEON Error Report ==="
        echo "Timestamp: $(date)"
        echo "Error: $error_msg"
        echo "Script: ${BASH_SOURCE[0]}"
        echo "Working Directory: $(pwd)"
        echo "Available Tools:"
        command -v subfinder >/dev/null 2>&1 && echo "  ✓ subfinder" || echo "  ✗ subfinder"
        command -v nuclei >/dev/null 2>&1 && echo "  ✓ nuclei" || echo "  ✗ nuclei"
        command -v httpx >/dev/null 2>&1 && echo "  ✓ httpx" || echo "  ✗ httpx"
        command -v ffuf >/dev/null 2>&1 && echo "  ✓ ffuf" || echo "  ✗ ffuf"
        command -v nmap >/dev/null 2>&1 && echo "  ✓ nmap" || echo "  ✗ nmap"
        echo "System Info:"
        uname -a
        echo "Disk Space:"
        df -h . 2>/dev/null || echo "Unable to check disk space"
        echo "Memory Usage:"
        free -h 2>/dev/null || echo "Unable to check memory"
    } > "$error_report"
    
    log "${YELLOW}[ERROR REPORT] Created: $error_report${NC}"
}

# Enhanced error handler with exponential backoff retry capability
handle_error() {
    local cmd="$1"
    local attempt="$2"
    local max_attempts="${3:-3}"
    
    if [[ $attempt -lt $max_attempts ]]; then
        local wait_time=$((attempt * attempt * 2))  # Exponential backoff
        warning "Command failed (attempt $attempt/$max_attempts): $cmd"
        warning "Retrying in ${wait_time} seconds..."
        sleep $wait_time
        return 1
    else
        error_exit "Command failed after $max_attempts attempts: $cmd"
    fi
}

# Save partial results on error
save_partial_results() {
    local backup_dir="${RESULTS_DIR}/partial_backup_$(date +%s)"
    mkdir -p "$backup_dir"
    
    # Copy any existing results
    if [[ -d "${RESULTS_DIR}" ]]; then
        find "${RESULTS_DIR}" -name "*.txt" -o -name "*.json" -o -name "*.xml" 2>/dev/null | \
        while IFS= read -r file; do
            [[ -f "$file" ]] && cp "$file" "$backup_dir/" 2>/dev/null
        done
        success "Partial results saved to: $backup_dir"
    fi
}

# Enhanced tool availability check with fallbacks
check_tool_with_fallback() {
    local primary_tool="$1"
    shift
    local fallback_tools=("$@")
    
    if command -v "$primary_tool" &> /dev/null; then
        echo "$primary_tool"
        return 0
    fi
    
    for tool in "${fallback_tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            warning "Primary tool '$primary_tool' not found, using fallback: $tool"
            echo "$tool"
            return 0
        fi
    done
    
    warning "Neither $primary_tool nor fallback tools (${fallback_tools[*]}) are available"
    return 1
}

# Success logging
success() {
    log "${GREEN}[SUCCESS] $1${NC}"
}

# Warning logging
warning() {
    log "${YELLOW}[WARNING] $1${NC}"
}

# Info logging
info() {
    log "${BLUE}[INFO] $1${NC}"
}

# Check if tools are installed
check_tools() {
    local missing_tools=()
    
    # Core bug bounty tools
    local tools=(
        "subfinder" "httpx" "naabu" "nuclei" "katana" "gau"
        "amass" "masscan" "nmap" "sqlmap" "ffuf" "gobuster"
        "waybackurls" "subjack" "subzy" "whatweb" "nikto"
        "paramspider" "dalfox" "arjun" "feroxbuster"
    )
    
    for tool in "${tools[@]}"; do
        if ! command -v "${tool}" &> /dev/null; then
            missing_tools+=("${tool}")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        warning "Missing tools: ${missing_tools[*]}"
        info "Run install.sh to install missing tools"
    else
        success "All bug bounty tools are available"
    fi
}

# Enhanced subdomain enumeration with multiple tools and error handling
subdomain_enum() {
    local target="$1"
    local output_dir="${RESULTS_DIR}/subdomains"
    mkdir -p "${output_dir}"
    
    info "Starting enhanced subdomain enumeration for ${target}"
    
    # Validate target domain
    if ! [[ "$target" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$ ]]; then
        error_exit "Invalid domain format: $target"
    fi
    
    local tool_count=0
    local success_count=0
    
    # Subfinder - passive subdomain enumeration with enhanced sources
    if subfinder_tool=$(check_tool_with_fallback "subfinder"); then
        info "Running $subfinder_tool with enhanced sources..."
        attempt=1
        while [[ $attempt -le 3 ]]; do
            if timeout 600 "$subfinder_tool" -d "${target}" -all -recursive \
               -o "${output_dir}/subfinder_${target}.txt" -silent; then
                success "Subfinder completed successfully"
                ((success_count++))
                break
            else
                handle_error "$subfinder_tool" "$attempt" 3 || break
                ((attempt++))
            fi
        done
        ((tool_count++))
    fi
    
    # Amass - comprehensive subdomain enumeration with passive and active modes
    if amass_tool=$(check_tool_with_fallback "amass"); then
        info "Running $amass_tool enum with enhanced configuration..."
        attempt=1
        while [[ $attempt -le 3 ]]; do
            # Try passive first, then active if needed
            if timeout 900 "$amass_tool" enum -passive -d "${target}" \
               -o "${output_dir}/amass_passive_${target}.txt"; then
                success "Amass passive enumeration completed"
                
                # Run active enumeration if passive found results
                if [[ -s "${output_dir}/amass_passive_${target}.txt" ]]; then
                    info "Running amass active enumeration..."
                    timeout 1200 "$amass_tool" enum -active -d "${target}" \
                        -o "${output_dir}/amass_active_${target}.txt" || \
                        warning "Amass active enumeration timed out or failed"
                fi
                ((success_count++))
                break
            else
                handle_error "$amass_tool" "$attempt" 3 || break
                ((attempt++))
            fi
        done
        ((tool_count++))
    fi
    
    # Assetfinder - additional passive subdomain discovery
    if assetfinder_tool=$(check_tool_with_fallback "assetfinder"); then
        info "Running $assetfinder_tool..."
        attempt=1
        while [[ $attempt -le 3 ]]; do
            if timeout 300 "$assetfinder_tool" "${target}" > "${output_dir}/assetfinder_${target}.txt"; then
                success "Assetfinder completed successfully"
                ((success_count++))
                break
            else
                handle_error "$assetfinder_tool" "$attempt" 3 || break
                ((attempt++))
            fi
        done
        ((tool_count++))
    fi
    
    # Findomain - fast passive subdomain discovery
    if findomain_tool=$(check_tool_with_fallback "findomain"); then
        info "Running $findomain_tool..."
        attempt=1
        while [[ $attempt -le 3 ]]; do
            if timeout 300 "$findomain_tool" -t "${target}" -o "${output_dir}/findomain_${target}.txt"; then
                success "Findomain completed successfully"
                ((success_count++))
                break
            else
                handle_error "$findomain_tool" "$attempt" 3 || break
                ((attempt++))
            fi
        done
        ((tool_count++))
    fi
    
    # DNSRecon for additional DNS enumeration
    if dnsrecon_tool=$(check_tool_with_fallback "dnsrecon" "python3 -m dnsrecon"); then
        info "Running $dnsrecon_tool for DNS enumeration..."
        if timeout 300 python3 -c "
import dnsrecon
# Custom DNS enumeration logic here
" 2>/dev/null || timeout 300 dnsrecon -d "${target}" -t brt \
           -D /usr/share/dnsrecon/namelist.txt -o "${output_dir}/dnsrecon_${target}.xml" 2>/dev/null; then
            success "DNSRecon completed successfully"
            ((success_count++))
        else
            warning "DNSRecon failed or timed out"
        fi
        ((tool_count++))
    fi
    
    # Certificate transparency logs using crt.sh
    info "Checking certificate transparency logs..."
    if command -v curl &> /dev/null; then
        if curl -s "https://crt.sh/?q=%.${target}&output=json" | \
           jq -r '.[].name_value' 2>/dev/null | \
           sort -u > "${output_dir}/crtsh_${target}.txt" 2>/dev/null; then
            success "Certificate transparency logs checked"
            ((success_count++))
        else
            warning "Certificate transparency check failed"
        fi
        ((tool_count++))
    fi
    
    # Combine and deduplicate results with enhanced processing
    if ls "${output_dir}"/*"${target}".txt &> /dev/null; then
        # Combine all results
        cat "${output_dir}"/*"${target}".txt 2>/dev/null | \
        grep -E '^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$' | \
        grep -v '^-' | \
        sort -u > "${output_dir}/all_subdomains_${target}.txt"
        
        # Remove invalid entries and clean up
        grep -E "\\b${target}\\b" "${output_dir}/all_subdomains_${target}.txt" > \
            "${output_dir}/valid_subdomains_${target}.txt" || touch "${output_dir}/valid_subdomains_${target}.txt"
        
        local count=$(wc -l < "${output_dir}/valid_subdomains_${target}.txt" 2>/dev/null || echo "0")
        
        if [[ $count -gt 0 ]]; then
            success "Found ${count} unique valid subdomains for ${target}"
            success "Tools used: ${success_count}/${tool_count} successful"
            
            # Create summary report
            {
                echo "# Subdomain Enumeration Report for ${target}"
                echo "Generated: $(date)"
                echo "Tools successful: ${success_count}/${tool_count}"
                echo "Total subdomains found: ${count}"
                echo ""
                echo "## Subdomains:"
                cat "${output_dir}/valid_subdomains_${target}.txt"
            } > "${output_dir}/subdomain_report_${target}.md"
        else
            warning "No valid subdomains found for ${target}"
        fi
    else
        warning "No subdomain enumeration results found for ${target}"
    fi
}

# Port scanning
port_scan() {
    local targets_file="$1"
    local output_dir="${RESULTS_DIR}/ports"
    mkdir -p "${output_dir}"
    
    info "Starting port scanning"
    
    # Naabu - fast port scanner
    if command -v naabu &> /dev/null && [[ -f "${targets_file}" ]]; then
        info "Running naabu port scan..."
        naabu -list "${targets_file}" -p - -o "${output_dir}/naabu_ports.txt" -silent
        success "Naabu scan completed"
    fi
    
    # Masscan - high-speed port scanner
    if command -v masscan &> /dev/null && [[ -f "${targets_file}" ]]; then
        info "Running masscan..."
        # Only scan top ports to avoid overwhelming the target
        masscan -iL "${targets_file}" -p1-1000 --rate=1000 -oG "${output_dir}/masscan_ports.txt" || warning "Masscan failed"
    fi
}

# HTTP probing
http_probe() {
    local targets_file="$1"
    local output_dir="${RESULTS_DIR}/http"
    mkdir -p "${output_dir}"
    
    info "Starting HTTP probing"
    
    # HTTPx - fast HTTP prober
    if command -v httpx &> /dev/null && [[ -f "${targets_file}" ]]; then
        info "Running httpx probe..."
        httpx -list "${targets_file}" -o "${output_dir}/live_hosts.txt" -silent \
              -title -tech-detect -status-code -content-length
        success "HTTPx probing completed"
    fi
}

# Directory and file discovery
directory_bruteforce() {
    local targets_file="$1"
    local output_dir="${RESULTS_DIR}/directories"
    mkdir -p "${output_dir}"
    
    info "Starting directory bruteforce"
    
    # FFUF - fast web fuzzer
    if command -v ffuf &> /dev/null && [[ -f "${targets_file}" ]]; then
        local wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        if [[ ! -f "${wordlist}" ]]; then
            wordlist="${SCRIPT_DIR}/wordlists_extra/common_directories.txt"
        fi
        
        if [[ -f "${wordlist}" ]]; then
            info "Running ffuf directory bruteforce..."
            while IFS= read -r url; do
                [[ -z "${url}" ]] && continue
                ffuf -u "${url}/FUZZ" -w "${wordlist}" -o "${output_dir}/ffuf_$(basename "${url}").json" \
                     -of json -t 10 -mc 200,301,302,403 -fs 0 -silent || warning "FFUF failed for ${url}"
            done < <(head -10 "${targets_file}") # Limit to first 10 targets to avoid overwhelming
            success "FFUF directory bruteforce completed"
        fi
    fi
    
    # Feroxbuster - recursive directory scanner
    if command -v feroxbuster &> /dev/null && [[ -f "${targets_file}" ]]; then
        info "Running feroxbuster..."
        while IFS= read -r url; do
            [[ -z "${url}" ]] && continue
            feroxbuster -u "${url}" -o "${output_dir}/ferox_$(basename "${url}").txt" \
                       -t 10 -C 404 -x php,html,js,txt,xml -q || warning "Feroxbuster failed for ${url}"
        done < <(head -5 "${targets_file}") # Limit to first 5 targets
    fi
}

# Parameter discovery
param_discovery() {
    local targets_file="$1"
    local output_dir="${RESULTS_DIR}/parameters"
    mkdir -p "${output_dir}"
    
    info "Starting parameter discovery"
    
    # Arjun - HTTP parameter discovery
    if command -v arjun &> /dev/null && [[ -f "${targets_file}" ]]; then
        info "Running arjun parameter discovery..."
        while IFS= read -r url; do
            [[ -z "${url}" ]] && continue
            arjun -u "${url}" -o "${output_dir}/arjun_$(basename "${url}").txt" \
                  -t 10 -q || warning "Arjun failed for ${url}"
        done < <(head -5 "${targets_file}")
        success "Arjun parameter discovery completed"
    fi
    
    # ParamSpider - parameter mining from web archives
    if command -v paramspider &> /dev/null && [[ -f "${targets_file}" ]]; then
        info "Running paramspider..."
        while IFS= read -r url; do
            [[ -z "${url}" ]] && continue
            paramspider -d "$(echo "${url}" | sed 's|^https\?://||' | cut -d'/' -f1)" \
                       -o "${output_dir}/paramspider_$(basename "${url}").txt" || warning "ParamSpider failed for ${url}"
        done < <(head -3 "${targets_file}")
    fi
}

# Enhanced vulnerability scanning with comprehensive test coverage
vuln_scan() {
    local targets_file="$1"
    local output_dir="${RESULTS_DIR}/vulnerabilities"
    mkdir -p "${output_dir}"
    
    info "Starting enhanced vulnerability scanning"
    
    if [[ ! -f "${targets_file}" ]]; then
        warning "Targets file not found: ${targets_file}"
        return 1
    fi
    
    local target_count=$(wc -l < "${targets_file}" 2>/dev/null || echo "0")
    info "Scanning ${target_count} targets for vulnerabilities"
    
    local scan_success=0
    local total_scans=0
    
    # Nuclei - enhanced vulnerability scanner with comprehensive templates
    if nuclei_tool=$(check_tool_with_fallback "nuclei"); then
        info "Running $nuclei_tool with enhanced template coverage..."
        ((total_scans++))
        
        # Update nuclei templates first
        info "Updating nuclei templates..."
        "$nuclei_tool" -update-templates >/dev/null 2>&1 || warning "Failed to update nuclei templates"
        
        # Run multiple nuclei scans with different categories and enhanced coverage
        local nuclei_success=0
        
        # Critical and High severity scan with enhanced rate limiting
        info "Running critical/high severity nuclei scan..."
        if timeout 2400 "$nuclei_tool" -list "${targets_file}" \
           -o "${output_dir}/nuclei_critical_high.txt" \
           -severity critical,high -silent -stats -rate-limit 30 -c 15 \
           -exclude-severity info -interactsh-disable; then
            ((nuclei_success++))
            success "Nuclei critical/high severity scan completed"
        else
            warning "Nuclei critical/high severity scan failed"
        fi
        
        # Medium and Low severity with broader coverage
        info "Running medium/low severity nuclei scan..."
        if timeout 3600 "$nuclei_tool" -list "${targets_file}" \
           -o "${output_dir}/nuclei_medium_low.txt" \
           -severity medium,low -silent -stats -rate-limit 50 -c 25 \
           -interactsh-disable; then
            ((nuclei_success++))
            success "Nuclei medium/low severity scan completed"
        else
            warning "Nuclei medium/low severity scan failed"
        fi
        
        # Technology-specific templates with enhanced detection
        info "Running technology-specific nuclei scan..."
        if timeout 1800 "$nuclei_tool" -list "${targets_file}" \
           -o "${output_dir}/nuclei_tech_specific.txt" \
           -tags tech,cms,framework -silent -stats -rate-limit 40 -c 20 \
           -interactsh-disable; then
            ((nuclei_success++))
            success "Nuclei technology-specific scan completed"
        else
            warning "Nuclei technology-specific scan failed"
        fi
        
        # Custom templates if available
        local custom_templates_dir="${SCRIPT_DIR}/nuclei-templates/custom"
        if [[ -d "$custom_templates_dir" ]]; then
            info "Running custom nuclei templates..."
            if timeout 1200 "$nuclei_tool" -list "${targets_file}" \
               -o "${output_dir}/nuclei_custom.txt" \
               -t "$custom_templates_dir" -silent -stats -rate-limit 30 -c 15 \
               -interactsh-disable; then
                ((nuclei_success++))
                success "Custom nuclei templates scan completed"
            else
                warning "Custom nuclei templates scan failed"
            fi
        fi
        
        # Fuzzing templates for enhanced coverage
        info "Running nuclei fuzzing templates..."
        if timeout 1800 "$nuclei_tool" -list "${targets_file}" \
           -o "${output_dir}/nuclei_fuzzing.txt" \
           -tags fuzz,injection,sqli,xss -silent -stats -rate-limit 25 -c 12 \
           -interactsh-disable; then
            ((nuclei_success++))
            success "Nuclei fuzzing scan completed"
        else
            warning "Nuclei fuzzing scan failed"
        fi
        
        # Combine nuclei results with deduplication
        if [[ $nuclei_success -gt 0 ]]; then
            cat "${output_dir}"/nuclei_*.txt 2>/dev/null | sort -u > "${output_dir}/nuclei_all_results.txt"
            local vuln_count=$(wc -l < "${output_dir}/nuclei_all_results.txt" 2>/dev/null || echo "0")
            success "Nuclei found ${vuln_count} total vulnerabilities"
            ((scan_success++))
        fi
    fi
    
    # Enhanced SQLMap testing with multiple injection points
    if sqlmap_tool=$(check_tool_with_fallback "sqlmap"); then
        info "Running enhanced $sqlmap_tool testing..."
        ((total_scans++))
        
        local params_file="${RESULTS_DIR}/parameters/all_parameters.txt"
        local sqlmap_results="${output_dir}/sqlmap_results"
        mkdir -p "$sqlmap_results"
        
        local sql_success=0
        local tested_urls=0
        
        while IFS= read -r url && [[ $tested_urls -lt 20 ]]; do
            [[ -z "${url}" ]] && continue
            ((tested_urls++))
            
            local url_safe=$(echo "$url" | tr '/' '_' | tr ':' '_')
            local result_dir="${sqlmap_results}/${url_safe}"
            
            info "Testing URL $tested_urls: $url"
            
            # Test GET parameters
            if timeout 300 "$sqlmap_tool" -u "${url}" --batch --random-agent \
               --level=2 --risk=2 --threads=3 --technique=BEUSTQ \
               --output-dir="$result_dir" --no-logging 2>/dev/null; then
                ((sql_success++))
            fi
            
            # Test POST parameters if form data available
            if [[ -f "${params_file}" ]] && grep -q "${url}" "${params_file}" 2>/dev/null; then
                timeout 300 "$sqlmap_tool" -u "${url}" --batch --random-agent \
                   --level=3 --risk=2 --data="id=1&name=test" \
                   --output-dir="$result_dir" --no-logging 2>/dev/null && ((sql_success++))
            fi
            
        done < <(head -20 "${targets_file}")
        
        if [[ $sql_success -gt 0 ]]; then
            success "SQLMap completed with $sql_success successful tests"
            ((scan_success++))
        else
            warning "SQLMap found no vulnerabilities or failed"
        fi
    fi
    
    # Enhanced XSS testing with comprehensive payloads
    if dalfox_tool=$(check_tool_with_fallback "dalfox" "xsser"); then
        info "Running enhanced XSS testing with $dalfox_tool..."
        ((total_scans++))
        
        local xss_results="${output_dir}/xss_results"
        mkdir -p "$xss_results"
        
        local xss_success=0
        local tested_xss=0
        
        # Use enhanced XSS payloads if available
        local xss_payloads_file="${PAYLOADS_DIR}/xss/advanced_xss.txt"
        
        while IFS= read -r url && [[ $tested_xss -lt 15 ]]; do
            [[ -z "${url}" ]] && continue
            ((tested_xss++))
            
            local url_safe=$(echo "$url" | tr '/' '_' | tr ':' '_')
            
            if [[ "$dalfox_tool" == "dalfox" ]]; then
                # Use custom payloads if available
                if [[ -f "$xss_payloads_file" ]]; then
                    if timeout 240 dalfox url "${url}" \
                       --custom-payload "$xss_payloads_file" \
                       --output "${xss_results}/dalfox_${url_safe}.txt" \
                       --silence --worker 3 --delay 150 --timeout 15 \
                       --format json --mining-dom --mining-dict; then
                        ((xss_success++))
                    fi
                else
                    # Standard dalfox scan
                    if timeout 180 dalfox url "${url}" \
                       --output "${xss_results}/dalfox_${url_safe}.txt" \
                       --silence --worker 5 --delay 100 --timeout 10 \
                       --format json; then
                        ((xss_success++))
                    fi
                fi
            else
                # Fallback to xsser with custom payloads
                if [[ -f "$xss_payloads_file" ]]; then
                    if timeout 180 xsser --url="${url}" \
                       --payload-list="$xss_payloads_file" \
                       --output="${xss_results}/xsser_${url_safe}.txt" 2>/dev/null; then
                        ((xss_success++))
                    fi
                else
                    # Standard xsser scan
                    if timeout 180 xsser --url="${url}" \
                       --output="${xss_results}/xsser_${url_safe}.txt" 2>/dev/null; then
                        ((xss_success++))
                    fi
                fi
            fi
        done < <(head -15 "${targets_file}")
        
        if [[ $xss_success -gt 0 ]]; then
            success "XSS testing completed with $xss_success successful tests"
            ((scan_success++))
        else
            warning "XSS testing found no vulnerabilities or failed"
        fi
    fi
    
    # Enhanced SQL injection testing with advanced payloads
    if sqlmap_tool=$(check_tool_with_fallback "sqlmap"); then
        info "Running enhanced SQL injection testing with $sqlmap_tool..."
        ((total_scans++))
        
        local params_file="${RESULTS_DIR}/parameters/all_parameters.txt"
        local sqlmap_results="${output_dir}/sqlmap_results"
        mkdir -p "$sqlmap_results"
        
        local sql_success=0
        local tested_urls=0
        
        # Use advanced SQLi payloads if available
        local sqli_payloads_file="${PAYLOADS_DIR}/sqli/advanced_sqli.txt"
        
        while IFS= read -r url && [[ $tested_urls -lt 20 ]]; do
            [[ -z "${url}" ]] && continue
            ((tested_urls++))
            
            local url_safe=$(echo "$url" | tr '/' '_' | tr ':' '_')
            local output_file="${sqlmap_results}/sqlmap_${url_safe}"
            
            # Enhanced SQLMap options with custom payloads
            local sqlmap_options=(
                "--batch"
                "--random-agent"  
                "--timeout=30"
                "--retries=2"
                "--level=2"
                "--risk=2"
                "--threads=3"
                "--technique=BEUSTQ"
            )
            
            # Add custom payloads if available
            if [[ -f "$sqli_payloads_file" ]]; then
                sqlmap_options+=("--tamper=space2comment,randomcase")
            fi
            
            # Test GET parameters
            if timeout 300 "$sqlmap_tool" -u "${url}*" \
               "${sqlmap_options[@]}" \
               --output-dir="$output_file" 2>/dev/null; then
                ((sql_success++))
            fi
            
            # Test with parameters file if available
            if [[ -f "$params_file" ]] && [[ -s "$params_file" ]]; then
                local param_count=0
                while IFS= read -r param && [[ $param_count -lt 5 ]]; do
                    [[ -z "$param" ]] && continue
                    ((param_count++))
                    
                    local test_url="${url}?${param}=1"
                    if timeout 240 "$sqlmap_tool" -u "$test_url" \
                       "${sqlmap_options[@]}" \
                       --output-dir="${output_file}_param_${param}" 2>/dev/null; then
                        ((sql_success++))
                    fi
                done < "$params_file"
            fi
            
        done < <(head -20 "${targets_file}")
        
        if [[ $sql_success -gt 0 ]]; then
            success "SQL injection testing completed with $sql_success successful tests"
            ((scan_success++))
        else
            warning "SQL injection testing found no vulnerabilities or failed"
        fi
    fi
    
    # Enhanced Directory traversal testing with comprehensive payloads
    if command -v curl &> /dev/null; then
        info "Testing for directory traversal vulnerabilities with enhanced payloads..."
        ((total_scans++))
        
        local dt_results="${output_dir}/directory_traversal.txt"
        local dt_success=0
        local dt_tested=0
        
        # Enhanced payload list
        local payloads=(
            "../../../etc/passwd"
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
            "....//....//....//etc//passwd"
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
            "..%252f..%252f..%252fetc%252fpasswd"
            "php://filter/convert.base64-encode/resource=index.php"
            "file:///etc/passwd"
            "/var/www/html/config.php"
            "C:\\boot.ini"
            "../../../../../../../../../etc/passwd%00"
        )
        
        # Use custom LFI payloads if available
        local lfi_payloads_file="${PAYLOADS_DIR}/lfi/directory_traversal.txt"
        if [[ -f "$lfi_payloads_file" ]]; then
            mapfile -t payloads < "$lfi_payloads_file"
        fi
        
        while IFS= read -r url && [[ $dt_tested -lt 10 ]]; do
            [[ -z "${url}" ]] && continue
            ((dt_tested++))
            
            for payload in "${payloads[@]}"; do
                [[ -z "$payload" ]] && continue
                
                # Test multiple parameter names
                for param in "file" "path" "page" "include" "doc" "document"; do
                    local test_url="${url}?${param}=${payload}"
                    if response=$(timeout 15 curl -s -k --max-time 10 "$test_url" 2>/dev/null); then
                        if echo "$response" | grep -qE "(root:|admin:|administrator:|boot loader|kernel)" 2>/dev/null; then
                            echo "[VULNERABILITY] Directory Traversal found: $test_url" >> "$dt_results"
                            echo "Response preview: $(echo "$response" | head -3)" >> "$dt_results"
                            ((dt_success++))
                        fi
                    fi
                done
            done
        done < <(head -10 "${targets_file}")
        
        if [[ $dt_success -gt 0 ]]; then
            success "Directory traversal testing found $dt_success potential vulnerabilities"
            ((scan_success++))
        fi
    fi
    
    # SSL/TLS vulnerability testing
    if sslscan_tool=$(check_tool_with_fallback "sslscan" "testssl.sh" "sslyze"); then
        info "Running SSL/TLS vulnerability assessment..."
        ((total_scans++))
        
        local ssl_results="${output_dir}/ssl_vulnerabilities"
        mkdir -p "$ssl_results"
        
        local ssl_success=0
        local ssl_tested=0
        
        while IFS= read -r url && [[ $ssl_tested -lt 5 ]]; do
            [[ -z "${url}" ]] && continue
            
            # Extract hostname for SSL testing
            local hostname=$(echo "$url" | sed -E 's|^https?://||' | sed 's|/.*||' | sed 's|:.*||')
            [[ -z "$hostname" ]] && continue
            
            ((ssl_tested++))
            
            case "$sslscan_tool" in
                "sslscan")
                    if timeout 120 sslscan --xml="${ssl_results}/${hostname}_sslscan.xml" "$hostname:443" 2>/dev/null; then
                        ((ssl_success++))
                    fi
                    ;;
                "testssl.sh")
                    if timeout 180 testssl.sh --jsonfile="${ssl_results}/${hostname}_testssl.json" "$hostname:443" 2>/dev/null; then
                        ((ssl_success++))
                    fi
                    ;;
                "sslyze")
                    if timeout 120 sslyze --json_out="${ssl_results}/${hostname}_sslyze.json" "$hostname:443" 2>/dev/null; then
                        ((ssl_success++))
                    fi
                    ;;
            esac
        done < <(grep -E '^https://' "${targets_file}" | head -5)
        
        if [[ $ssl_success -gt 0 ]]; then
            success "SSL/TLS testing completed on $ssl_success hosts"
            ((scan_success++))
        fi
    fi
    
    # Generate comprehensive vulnerability report
    {
        echo "# Comprehensive Vulnerability Assessment Report"
        echo "Generated: $(date)"
        echo "Targets scanned: ${target_count}"
        echo "Successful scan modules: ${scan_success}/${total_scans}"
        echo ""
        
        # Nuclei results
        if [[ -f "${output_dir}/nuclei_all_results.txt" ]]; then
            local nuclei_count=$(wc -l < "${output_dir}/nuclei_all_results.txt")
            echo "## Nuclei Vulnerability Scan Results: ${nuclei_count} findings"
            echo '```'
            head -20 "${output_dir}/nuclei_all_results.txt" 2>/dev/null
            if [[ $nuclei_count -gt 20 ]]; then
                echo "... (${nuclei_count} total findings)"
            fi
            echo '```'
            echo ""
        fi
        
        # SQLMap results
        if [[ -d "${output_dir}/sqlmap_results" ]]; then
            local sql_files=$(find "${output_dir}/sqlmap_results" -type f -name "*.csv" 2>/dev/null | wc -l)
            echo "## SQL Injection Test Results: ${sql_files} test files generated"
            echo ""
        fi
        
        # XSS results
        if [[ -d "${output_dir}/xss_results" ]]; then
            local xss_files=$(find "${output_dir}/xss_results" -type f 2>/dev/null | wc -l)
            echo "## XSS Test Results: ${xss_files} test files generated"
            echo ""
        fi
        
        # Directory traversal results
        if [[ -f "${output_dir}/directory_traversal.txt" ]]; then
            local dt_count=$(wc -l < "${output_dir}/directory_traversal.txt" 2>/dev/null || echo "0")
            echo "## Directory Traversal Results: ${dt_count} potential vulnerabilities"
            if [[ $dt_count -gt 0 ]]; then
                echo '```'
                cat "${output_dir}/directory_traversal.txt"
                echo '```'
            fi
            echo ""
        fi
        
        # SSL/TLS results
        if [[ -d "${output_dir}/ssl_vulnerabilities" ]]; then
            local ssl_files=$(find "${output_dir}/ssl_vulnerabilities" -type f 2>/dev/null | wc -l)
            echo "## SSL/TLS Assessment Results: ${ssl_files} host assessments completed"
            echo ""
        fi
        
        echo "## Summary"
        echo "This comprehensive scan used multiple tools and techniques to identify potential security vulnerabilities."
        echo "Review all results carefully and verify findings manually."
        
    } > "${output_dir}/comprehensive_vulnerability_report.md"
    
    success "Enhanced vulnerability scanning completed: ${scan_success}/${total_scans} modules successful"
    success "Comprehensive report generated: ${output_dir}/comprehensive_vulnerability_report.md"
}

# XSS testing
xss_testing() {
    local targets_file="$1"
    local output_dir="${RESULTS_DIR}/xss"
    mkdir -p "${output_dir}"
    
    info "Starting XSS testing"
    
    # Dalfox - XSS scanner
    if command -v dalfox &> /dev/null && [[ -f "${targets_file}" ]]; then
        info "Running dalfox XSS scanner..."
        while IFS= read -r url; do
            [[ -z "${url}" ]] && continue
            dalfox url "${url}" --output "${output_dir}/dalfox_$(basename "${url}").txt" \
                  --silence --worker 10 || warning "Dalfox failed for ${url}"
        done < <(head -5 "${targets_file}")
        success "Dalfox XSS scanning completed"
    fi
}

# Subdomain takeover check
subdomain_takeover() {
    local subdomains_file="$1"
    local output_dir="${RESULTS_DIR}/takeover"
    mkdir -p "${output_dir}"
    
    info "Checking for subdomain takeovers"
    
    # Subjack - subdomain takeover scanner
    if command -v subjack &> /dev/null && [[ -f "${subdomains_file}" ]]; then
        info "Running subjack..."
        subjack -w "${subdomains_file}" -o "${output_dir}/subjack_results.txt" -ssl
        success "Subjack completed"
    fi
    
    # Subzy - subdomain takeover scanner
    if command -v subzy &> /dev/null && [[ -f "${subdomains_file}" ]]; then
        info "Running subzy..."
        subzy run --targets "${subdomains_file}" --output "${output_dir}/subzy_results.txt"
        success "Subzy completed"
    fi
}

# Technology detection
tech_detection() {
    local targets_file="$1"
    local output_dir="${RESULTS_DIR}/technology"
    mkdir -p "${output_dir}"
    
    info "Starting technology detection"
    
    # WhatWeb - web technology scanner
    if command -v whatweb &> /dev/null && [[ -f "${targets_file}" ]]; then
        info "Running whatweb..."
        while IFS= read -r url; do
            [[ -z "${url}" ]] && continue
            whatweb "${url}" --log-brief="${output_dir}/whatweb_$(basename "${url}").txt" || warning "WhatWeb failed for ${url}"
        done < <(head -10 "${targets_file}")
        success "WhatWeb technology detection completed"
    fi
}

# Web crawling and URL collection
web_crawling() {
    local target_domain="$1"
    local output_dir="${RESULTS_DIR}/crawling"
    mkdir -p "${output_dir}"
    
    info "Starting web crawling for ${target_domain}"
    
    # GAU - Get All URLs from web archives
    if command -v gau &> /dev/null; then
        info "Running gau for URL collection..."
        gau "${target_domain}" > "${output_dir}/gau_urls.txt"
        success "GAU URL collection completed"
    fi
    
    # Waybackurls - Wayback Machine URL collection
    if command -v waybackurls &> /dev/null; then
        info "Running waybackurls..."
        waybackurls "${target_domain}" > "${output_dir}/wayback_urls.txt"
        success "Waybackurls completed"
    fi
    
    # Katana - web crawler
    if command -v katana &> /dev/null; then
        info "Running katana crawler..."
        echo "https://${target_domain}" | katana -o "${output_dir}/katana_urls.txt" -d 2 -silent
        success "Katana crawling completed"
    fi
    
    # Combine all URLs
    if ls "${output_dir}"/*.txt &> /dev/null; then
        cat "${output_dir}"/*.txt | sort -u > "${output_dir}/all_urls_${target_domain}.txt"
        local count=$(wc -l < "${output_dir}/all_urls_${target_domain}.txt")
        success "Collected ${count} unique URLs for ${target_domain}"
    fi
}

# Generate comprehensive report
generate_report() {
    local target="$1"
    local report_file="${RESULTS_DIR}/bug_bounty_report_${target}_${TIMESTAMP}.md"
    
    info "Generating comprehensive bug bounty report..."
    
    cat > "${report_file}" << EOF
# Bug Bounty Assessment Report - ${target}

**Generated:** $(date)
**Target:** ${target}

## Executive Summary

This report contains the results of automated bug bounty reconnaissance and vulnerability assessment.

## Subdomains Discovered

EOF
    
    if [[ -f "${RESULTS_DIR}/subdomains/all_subdomains_${target}.txt" ]]; then
        echo "- **Total Subdomains:** $(wc -l < "${RESULTS_DIR}/subdomains/all_subdomains_${target}.txt")" >> "${report_file}"
        echo "- **Live Hosts:** $(wc -l < "${RESULTS_DIR}/http/live_hosts.txt" 2>/dev/null || echo "0")" >> "${report_file}"
    fi
    
    cat >> "${report_file}" << EOF

## Vulnerabilities Found

EOF
    
    if [[ -f "${RESULTS_DIR}/vulnerabilities/nuclei_results.txt" ]]; then
        local vuln_count=$(wc -l < "${RESULTS_DIR}/vulnerabilities/nuclei_results.txt")
        echo "- **Nuclei Vulnerabilities:** ${vuln_count}" >> "${report_file}"
    fi
    
    cat >> "${report_file}" << EOF

## Technology Stack

EOF
    
    if [[ -d "${RESULTS_DIR}/technology" ]]; then
        echo "Technology detection results available in: \`${RESULTS_DIR}/technology/\`" >> "${report_file}"
    fi
    
    cat >> "${report_file}" << EOF

## URLs and Endpoints

EOF
    
    if [[ -f "${RESULTS_DIR}/crawling/all_urls_${target}.txt" ]]; then
        local url_count=$(wc -l < "${RESULTS_DIR}/crawling/all_urls_${target}.txt")
        echo "- **Total URLs Collected:** ${url_count}" >> "${report_file}"
    fi
    
    cat >> "${report_file}" << EOF

## Takeover Opportunities

EOF
    
    if [[ -f "${RESULTS_DIR}/takeover/subjack_results.txt" ]]; then
        local takeover_count=$(grep -c "VULNERABLE" "${RESULTS_DIR}/takeover/subjack_results.txt" 2>/dev/null || echo "0")
        echo "- **Potential Takeovers:** ${takeover_count}" >> "${report_file}"
    fi
    
    success "Report generated: ${report_file}"
}

# Main execution function
main() {
    local target="${1:-}"
    
    if [[ -z "${target}" ]]; then
        echo "Usage: $0 <target-domain>"
        echo "Example: $0 example.com"
        exit 1
    fi
    
    info "Starting bug bounty automation for ${target}"
    
    # Check tool availability
    check_tools
    
    # Phase 1: Reconnaissance
    info "=== Phase 1: Reconnaissance ==="
    subdomain_enum "${target}"
    
    local subdomains_file="${RESULTS_DIR}/subdomains/all_subdomains_${target}.txt"
    
    if [[ -f "${subdomains_file}" ]]; then
        port_scan "${subdomains_file}"
        http_probe "${subdomains_file}"
    fi
    
    # Phase 2: Discovery
    info "=== Phase 2: Discovery ==="
    local live_hosts="${RESULTS_DIR}/http/live_hosts.txt"
    
    if [[ -f "${live_hosts}" ]]; then
        directory_bruteforce "${live_hosts}"
        param_discovery "${live_hosts}"
        tech_detection "${live_hosts}"
    fi
    
    # Phase 3: Crawling
    info "=== Phase 3: Web Crawling ==="
    web_crawling "${target}"
    
    # Phase 4: Vulnerability Assessment
    info "=== Phase 4: Vulnerability Assessment ==="
    if [[ -f "${live_hosts}" ]]; then
        vuln_scan "${live_hosts}"
        xss_testing "${live_hosts}"
    fi
    
    if [[ -f "${subdomains_file}" ]]; then
        subdomain_takeover "${subdomains_file}"
    fi
    
    # Phase 5: Reporting
    info "=== Phase 5: Reporting ==="
    generate_report "${target}"
    
    success "Bug bounty automation completed for ${target}"
    info "Results available in: ${RESULTS_DIR}"
    info "Log file: ${LOG_FILE}"
}

# Script execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi