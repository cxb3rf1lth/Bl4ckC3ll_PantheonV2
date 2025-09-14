# Security Configuration for Bl4ckC3ll_PANTHEON

# Command execution security
ALLOWED_COMMANDS = {
    'nuclei', 'subfinder', 'httpx', 'naabu', 'amass', 
    'nmap', 'sqlmap', 'ffuf', 'gobuster', 'whatweb',
    'dig', 'whois', 'curl', 'wget', 'ping', 'host'
}

# Rate limiting settings
RATE_LIMITS = {
    'default_rps': 10,
    'burst_limit': 50,
    'timeout_seconds': 30
}

# Input validation settings  
INPUT_LIMITS = {
    'max_domain_length': 255,
    'max_url_length': 2000,
    'max_filename_length': 255,
    'allowed_url_schemes': ['http', 'https']
}

# File operation security
FILE_SECURITY = {
    'allowed_extensions': ['.txt', '.json', '.csv', '.html', '.xml'],
    'max_file_size': 100 * 1024 * 1024,  # 100MB
    'forbidden_paths': ['/etc/', '/bin/', '/sbin/', '/usr/bin/', '/root/']
}

# Logging security
LOGGING_CONFIG = {
    'sanitize_logs': True,
    'max_log_entry_length': 1000,
    'log_security_events': True
}
