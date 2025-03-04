import subprocess
import tempfile
import shutil
import os
import re
import sys
import json
import csv
import argparse
import logging
import requests
import base64
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
import datetime

# Set up logging for detailed feedback
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# Define vulnerability patterns for different script types
patterns = {
    '.py': [
        (re.compile(r'\beval\('), 'Use of eval() - Potential code injection risk'),
        (re.compile(r'\bpickle\.load\('), 'Use of pickle.load() - Risk of arbitrary code execution'),
        (re.compile(r'\b(os|subprocess)\.(system|call|popen)\('), 'Use of os.system/subprocess.call - Possible command injection'),
        (re.compile(r'(password|pwd|secret|key|token|api_key)\s*=\s*["\'].+["\']', re.IGNORECASE), 'Potential hardcoded credential'),
        (re.compile(r'open\(.+,\s*[\'"]w[\'"]\)'), 'Unsafe file write - Check for path traversal'),
        (re.compile(r'yaml\.load\((?!.*Loader=yaml\.SafeLoader)'), 'Unsafe YAML load - Use yaml.safe_load()'),
        (re.compile(r'request\.get\(.+verify\s*=\s*False'), 'SSL verification disabled'),
        (re.compile(r'DEBUG\s*=\s*True'), 'Debug mode enabled in production code'),
    ],
    '.ps1': [
        (re.compile(r'Invoke-Expression'), 'Use of Invoke-Expression - Possible code injection risk'),
        (re.compile(r'\$\w*(password|pwd|secret|key|token|apikey)\w*\s*=\s*["\'].+["\']', re.IGNORECASE), 'Potential hardcoded credential'),
        (re.compile(r'New-Object\s+System\.Net\.WebClient'), 'WebClient usage without proper error handling'),
        (re.compile(r'Set-ExecutionPolicy\s+Bypass'), 'Bypassing execution policy - Security risk'),
    ],
    '.sh': [
        (re.compile(r'\beval \$'), 'Use of eval - Potential command injection risk'),
        (re.compile(r'\w*(PASSWORD|PWD|SECRET|KEY|TOKEN|APIKEY)\w*=["\'].+["\']', re.IGNORECASE), 'Potential hardcoded credential'),
        (re.compile(r'curl\s+.*-k\s'), 'Insecure curl request (SSL verification disabled)'),
        (re.compile(r'chmod\s+777'), 'Overly permissive file permissions'),
    ],
    '.js': [
        (re.compile(r'\beval\('), 'Use of eval() - Potential code injection risk'),
        (re.compile(r'(password|pwd|secret|key|token|apiKey)\s*[:=]\s*["\'].+["\']', re.IGNORECASE), 'Potential hardcoded credential'),
        (re.compile(r'document\.write\('), 'Use of document.write() - XSS risk'),
        (re.compile(r'innerHTML\s*='), 'Direct innerHTML manipulation - XSS risk'),
        (re.compile(r'localStorage\.setItem\(.*password'), 'Storing sensitive data in localStorage'),
    ],
    '.rb': [
        (re.compile(r'\beval\('), 'Use of eval() - Potential code injection risk'),
        (re.compile(r'(password|pwd|secret|key|token|api_key)\s*=\s*["\'].+["\']', re.IGNORECASE), 'Potential hardcoded credential'),
        (re.compile(r'\.html_safe'), 'Use of html_safe - Potential XSS risk'),
        (re.compile(r'params\[\w+\](?!\.permit)'), 'Mass assignment vulnerability'),
    ],
    '.php': [
        (re.compile(r'\beval\('), 'Use of eval() - Potential code injection risk'),
        (re.compile(r'(password|pwd|secret|key|token|api_key)\s*=\s*["\'].+["\']', re.IGNORECASE), 'Potential hardcoded credential'),
        (re.compile(r'\bexec\('), 'Use of exec() - Potential command execution risk'),
        (re.compile(r'\$_GET\[[\'"].*[\'"]\]'), 'Unfiltered GET parameter - Injection risk'),
        (re.compile(r'\$_POST\[[\'"].*[\'"]\]'), 'Unfiltered POST parameter - Injection risk'),
        (re.compile(r'mysql_query'), 'Deprecated mysql_query - SQL injection risk'),
    ],
    '.pl': [
        (re.compile(r'\beval\('), 'Use of eval() - Potential code injection risk'),
        (re.compile(r'(password|pwd|secret|key|token|api_key)\s*=\s*["\'].+["\']', re.IGNORECASE), 'Potential hardcoded credential'),
        (re.compile(r'\bsystem\('), 'Use of system() - Possible command injection'),
    ],
    '.go': [
        (re.compile(r'(password|pwd|secret|key|token|apiKey)\s*[:=]\s*[`"\'].+[`"\']', re.IGNORECASE), 'Potential hardcoded credential'),
        (re.compile(r'sql\.Open\(.+\)\s*$'), 'SQL connection without error checking'),
        (re.compile(r'http\.ListenAndServe\(.+nil\)'), 'Using nil as HTTP handler'),
    ],
    '.java': [
        (re.compile(r'(password|pwd|secret|key|token|apiKey)\s*=\s*["\'].+["\']', re.IGNORECASE), 'Potential hardcoded credential'),
        (re.compile(r'Runtime\.getRuntime\(\)\.exec\('), 'Use of Runtime.exec() - Command injection risk'),
        (re.compile(r'\.printStackTrace\(\)'), 'Exposing stack traces'),
    ],
    '.cs': [
        (re.compile(r'(password|pwd|secret|key|token|apiKey)\s*=\s*["\'].+["\']', re.IGNORECASE), 'Potential hardcoded credential'),
        (re.compile(r'Process\.Start\('), 'Process.Start() - Command injection risk'),
        (re.compile(r'SqlCommand.*CommandType\.Text'), 'Potential SQL injection with string commands'),
    ],
    'Dockerfile': [
        (re.compile(r'FROM\s+.*latest'), 'Using latest tag - version pinning issue'),
        (re.compile(r'(ENV|ARG)\s+(PASSWORD|SECRET|KEY|TOKEN|APIKEY)=', re.IGNORECASE), 'Environment variable with sensitive data'),
        (re.compile(r'RUN\s+.*curl\s+.*\|\s*sh'), 'Piping curl to shell - security risk'),
        (re.compile(r'USER\s+root'), 'Running as root user'),
        (re.compile(r'COPY\s+.*\.env'), 'Copying .env file into container'),
    ],
    '.tf': [
        (re.compile(r'(password|pwd|secret|key|token|apiKey)\s*=\s*["\'].+["\']', re.IGNORECASE), 'Potential hardcoded credential in Terraform'),
        (re.compile(r'resource\s+"aws_s3_bucket".*\s+acl\s*=\s*"public-read"'), 'Public S3 bucket - security risk'),
        (re.compile(r'resource\s+"aws_security_group_rule".*\s+cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]'), 'Open security group - security risk'),
    ],
    '.yml': [
        (re.compile(r'(password|pwd|secret|key|token|apiKey):\s*["\'].+["\']', re.IGNORECASE), 'Potential hardcoded credential in YAML'),
    ],
    '.yaml': [
        (re.compile(r'(password|pwd|secret|key|token|apiKey):\s*["\'].+["\']', re.IGNORECASE), 'Potential hardcoded credential in YAML'),
    ],
}

# Define secret patterns for detection
secret_patterns = [
    (re.compile(r'(?i)(?:access_key|access_token|admin_pass|admin_user|algolia_api_key|alias_pass|api[_\s]key|api[_\s]secret|api[_\s]token|apidocs|apikey|apiSecret|app_key|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_config|aws_key|aws_secret|aws_token|AWSSecretKey|bearer|bot_access_token|bucket_password|client_secret|cloudfront|codecov_token|config|conn.login|connectionstring|consumer_key|consumer_secret|credentials|database_password|database_schema_test|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean|discord|dot-files|dotfiles|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|FB_SECRET|firebase|ftp|gh_token|github_key|github_token|gitlab|gmail_password|gmail_username|api\.googleusercontent\.com|herokuapp|internal|irc_pass|JEKYLL_GITHUB_TOKEN|key|keyPassword|ldap_password|ldap_username|login|mailchimp|mailgun|master_key|mydotfiles|mysql|node_env|npm_api_key|npm_password|npmrc|oauth_token|pass|passwd|password|passwords|pem private|preprod|private_key|prod|pwd|pwnd|redis_password|root_password|rsa private|secret|secret[_\s]access_key|secret[_\s]key|secret[_\s]token|secretkey|secrets|secure|security|send.keys|send_keys|sendkeys|sf_username|slack_api|slack_token|sql_password|ssh|ssh2_auth_password|sshpass|staging|stg|storePassword|stripe|swagger|testuser|token|x-api-key|xoxb|xoxp)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|\']|[\s|\"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:\'|\"|\s|=|\x60){0,5}([a-z0-9=_\-\+/]{8,64})(?:[\'|\"|\\n|\\r|\s|\x60|;]|$)'), 'Potential API key or token'),
    (re.compile(r'(?:"|\'|`)?((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})(?:"|\'|`)?'), 'AWS Access Key ID'),
    (re.compile(r'(?i)(?:aws[ ._-]?(?:access[ ._-]?)?key[ ._-]?id|aws[ ._-]?account[ ._-]?id)[ ]*(?:=|:)[ ]*(?:"|\')?([A-Z0-9]{20})(?:"|\')?'), 'AWS Access Key ID'),
    (re.compile(r'(?i)(?:aws[ ._-]?(?:account[ ._-]?|secret[ ._-]?)?access[ ._-]?key|aws[ ._-]?secret[ ._-]?(?:access[ ._-]?)?key|secret[ ._-]?access[ ._-]?key|secret[ ._-]?key)[ ]*(?:=|:)[ ]*(?:"|\')?([A-Za-z0-9/+=]{40})(?:"|\')?'), 'AWS Secret Access Key'),
    (re.compile(r'(?:"|\'|`)?([a-zA-Z0-9_-]*\.apps\.googleusercontent\.com)(?:"|\'|`)?'), 'Google OAuth Client ID'),
    (re.compile(r'(?:"|\'|`)?([a-zA-Z0-9-_]{24}(?:[a-zA-Z0-9-_]{8})?)(?:"|\'|`)?(?:[ ]{0,})?(?:=|>|:=|\|\|:|<=|=>|:)(?:[ ]{0,})?(?:"|\'|`)?([a-zA-Z0-9-_]{24}[a-zA-Z0-9-_]{8})(?:"|\'|`)?'), 'Google API Key'),
    (re.compile(r'(?:"|\'|`)?(?:gh[a-z]{1,4}|github)(?:_| )(?:token|key|secret|password|pat)(?:"|\'|`)?(?:[ ]{0,})?(?:=|>|:=|\|\|:|<=|=>|:)(?:[ ]{0,})?(?:"|\'|`)?([a-zA-Z0-9_]{35,40})(?:"|\'|`)?'), 'GitHub Token'),
    (re.compile(r'(?:"|\'|`)?(?:heroku)(?:_| )(?:token|key|secret|password)(?:"|\'|`)?(?:[ ]{0,})?(?:=|>|:=|\|\|:|<=|=>|:)(?:[ ]{0,})?(?:"|\'|`)?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(?:"|\'|`)?'), 'Heroku API Key'),
    (re.compile(r'(?:"|\'|`)?(?:slack)(?:_| )(?:token|api|key|secret|password)(?:"|\'|`)?(?:[ ]{0,})?(?:=|>|:=|\|\|:|<=|=>|:)(?:[ ]{0,})?(?:"|\'|`)?xox(?:a|b|p|r|s)-(?:[a-z0-9]{10,48})(?:"|\'|`)?'), 'Slack Token'),
    (re.compile(r'(?:"|\'|`)?(?:twilio)(?:_| )(?:token|key|secret|password|sid)(?:"|\'|`)?(?:[ ]{0,})?(?:=|>|:=|\|\|:|<=|=>|:)(?:[ ]{0,})?(?:"|\'|`)?(?:SK|AC)[a-z0-9]{32}(?:"|\'|`)?'), 'Twilio API Key'),
    (re.compile(r'(?:"|\'|`)?(?:firebase)(?:_| )(?:token|key|secret|password|database)(?:"|\'|`)?(?:[ ]{0,})?(?:=|>|:=|\|\|:|<=|=>|:)(?:[ ]{0,})?(?:"|\'|`)?AIza[a-zA-Z0-9_-]{35}(?:"|\'|`)?'), 'Firebase API Key'),
    (re.compile(r'(?:"|\'|`)?(?:stripe)(?:_| )(?:token|key|secret|password)(?:"|\'|`)?(?:[ ]{0,})?(?:=|>|:=|\|\|:|<=|=>|:)(?:[ ]{0,})?(?:"|\'|`)?(?:sk|pk)_(?:test|live)_[a-zA-Z0-9]{24,34}(?:"|\'|`)?'), 'Stripe API Key'),
    (re.compile(r'(?:"|\'|`)?(?:sq0csp|sq0idp)-[a-zA-Z0-9_-]{22,43}(?:"|\'|`)?'), 'Square Access Token'),
    (re.compile(r'(?:"|\'|`)?(?:basic|bearer|token|auth|authorization|password|passwd|pwd)(?:"|\'|`)?(?:[ ]{0,})?(?:=|>|:=|\|\|:|<=|=>|:)(?:[ ]{0,})?(?:"|\'|`)?([a-zA-Z0-9_\-\.=]{8,64})(?:"|\'|`)?'), 'Authorization Token'),
    (re.compile(r'eyJ[a-zA-Z0-9]{8,}\.eyJ[a-zA-Z0-9]{8,}\.[a-zA-Z0-9_-]{8,}'), 'JWT Token'),
    (re.compile(r'(?i)(?:key|token|sig|secret|signature|password|pass|pwd)[ ]*(?:=|:)[ ]*(?:"|\')?([a-f0-9]{32,})(?:"|\')?'), 'MD5/SHA Hash'),
    (re.compile(r'(?i)(?:private[ ._-]?key)[ ]*(?:=|:)[ ]*(?:"|\')?([-]+BEGIN[ A-Z]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END[ A-Z]+ PRIVATE KEY[-]+)(?:"|\')?'), 'Private Key'),
]

# Define common open source licenses and their patterns
license_patterns = {
    'MIT': re.compile(r'MIT License|Permission is hereby granted, free of charge'),
    'Apache-2.0': re.compile(r'Apache License, Version 2.0|Licensed under the Apache License'),
    'GPL-3.0': re.compile(r'GNU General Public License v3|GNU GPL version 3'),
    'GPL-2.0': re.compile(r'GNU General Public License v2|GNU GPL version 2'),
    'LGPL': re.compile(r'GNU Lesser General Public License|GNU LGPL'),
    'BSD-3-Clause': re.compile(r'BSD 3-Clause License|Redistribution and use in source and binary'),
    'BSD-2-Clause': re.compile(r'BSD 2-Clause License'),
    'AGPL': re.compile(r'GNU Affero General Public License|GNU AGPL'),
    'MPL': re.compile(r'Mozilla Public License'),
    'Unlicense': re.compile(r'This is free and unencumbered software released into the public domain'),
    'CC0': re.compile(r'Creative Commons Zero|CC0'),
    'CC-BY': re.compile(r'Creative Commons Attribution'),
    'CC-BY-SA': re.compile(r'Creative Commons Attribution-ShareAlike'),
    'CC-BY-NC': re.compile(r'Creative Commons Attribution-NonCommercial'),
    'Proprietary': re.compile(r'All rights reserved|Proprietary and confidential'),
}

# Define license compatibility issues
license_compatibility = {
    'GPL-3.0': ['MIT', 'Apache-2.0', 'LGPL', 'GPL-2.0', 'GPL-3.0'],  # GPL-3.0 can include these
    'GPL-2.0': ['MIT', 'LGPL', 'GPL-2.0'],  # GPL-2.0 can include these
    'AGPL': ['MIT', 'GPL-3.0', 'GPL-2.0', 'LGPL', 'AGPL'],  # AGPL can include these
    'LGPL': ['MIT', 'LGPL'],  # LGPL can include these
    'Apache-2.0': ['MIT', 'BSD-3-Clause', 'BSD-2-Clause'],  # Apache-2.0 can include these
    'MIT': ['MIT', 'BSD-3-Clause', 'BSD-2-Clause'],  # MIT can include these
    'BSD-3-Clause': ['MIT', 'BSD-3-Clause', 'BSD-2-Clause'],  # BSD-3-Clause can include these
    'BSD-2-Clause': ['MIT', 'BSD-2-Clause'],  # BSD-2-Clause can include these
    'MPL': ['MIT', 'BSD-3-Clause', 'BSD-2-Clause', 'MPL'],  # MPL can include these
}

# Define severity levels for different types of vulnerabilities
severity_mapping = {
    'code injection': 'Critical',
    'arbitrary code execution': 'Critical',
    'command injection': 'Critical',
    'eval': 'Critical',
    'exec': 'Critical',
    'hardcoded credential': 'High',
    'API key': 'High',
    'token': 'High',
    'secret': 'High',
    'password': 'High',
    'private key': 'High',
    'AWS': 'High',
    'injection risk': 'High',
    'XSS risk': 'High',
    'SQL injection': 'High',
    'security risk': 'Medium',
    'outdated dependency': 'Medium',
    'unsafe': 'Medium',
    'insecure': 'Medium',
    'debug mode': 'Low',
    'exposing': 'Low',
    'version pinning': 'Low',
    'permissive': 'Low',
}

# Define remediation suggestions for different types of vulnerabilities
remediation_suggestions = {
    'eval': 'Replace eval() with safer alternatives like JSON.parse() for JSON data or dedicated parsers for specific formats.',
    'pickle.load': 'Use safer serialization formats like JSON, YAML with safe_load, or protocol buffers instead of pickle.',
    'command injection': 'Use subprocess.run() with shell=False and pass arguments as a list instead of a string.',
    'hardcoded credential': 'Move sensitive data to environment variables or a secure vault/keystore service.',
    'API key': 'Use environment variables or a secure secret management service instead of hardcoding API keys.',
    'token': 'Store tokens in environment variables or use a secure credential manager.',
    'XSS risk': 'Use proper output encoding and content security policies. Consider using template systems that auto-escape output.',
    'SQL injection': 'Use parameterized queries or an ORM instead of string concatenation for SQL queries.',
    'SSL verification': 'Always verify SSL certificates in production. Never disable SSL verification.',
    'debug mode': 'Ensure debug mode is disabled in production environments.',
    'unsafe file': 'Validate and sanitize file paths. Use os.path.abspath() and os.path.join() for safe path handling.',
    'yaml.load': 'Use yaml.safe_load() instead of yaml.load() to prevent arbitrary code execution.',
    'overly permissive': 'Use the principle of least privilege. Grant only the permissions necessary for operation.',
    'version pinning': 'Pin to specific versions rather than using "latest" to ensure consistency and security.',
    'outdated dependency': 'Update to the latest stable version to get security patches and bug fixes.',
    'license compatibility': 'Ensure all included libraries have compatible licenses. Consider consulting legal advice.',
    'missing license': 'Add a LICENSE file to clarify the terms under which your code can be used.',
}

def check_tool_availability(tool_name, install_command):
    """Check if a tool is installed; log a warning and installation instructions if not."""
    if shutil.which(tool_name) is None:
        logging.warning(f"{tool_name} not installed. Install it with: {install_command}")
        return False
    return True

def clone_repo(repo_url, token=None):
    """Clone a GitHub repository to a temporary directory with shallow cloning."""
    temp_dir = tempfile.mkdtemp()
    clone_url = repo_url
    if token:
        clone_url = clone_url.replace('https://', f'https://{token}@')
    try:
        subprocess.run(['git', 'clone', '--depth=1', clone_url, temp_dir], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return temp_dir
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to clone repository: {e.stderr.decode()}")
        sys.exit(1)

def scan_file(file_path, file_patterns):
    """Scan a file for vulnerabilities using regex patterns."""
    vulnerabilities = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, start=1):
                for pattern, description in file_patterns:
                    if pattern.search(line.strip()):
                        vulnerabilities.append((file_path, line_num, description, line.strip()))
    except UnicodeDecodeError:
        logging.warning(f"Skipping {file_path}: Not a text file or encoding issue")
    except Exception as e:
        logging.error(f"Error scanning {file_path}: {e}")
    return vulnerabilities

def run_bandit(file_path):
    """Run Bandit on a Python file for static analysis."""
    if not check_tool_availability('bandit', 'pip install bandit'):
        return []
    try:
        result = subprocess.run(['bandit', '-f', 'json', file_path], capture_output=True, text=True)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            return [(file_path, issue['line_number'], issue['issue_text'], '') for issue in data.get('results', [])]
        return []
    except Exception as e:
        logging.error(f"Error running Bandit on {file_path}: {e}")
        return []

def run_shellcheck(file_path):
    """Run ShellCheck on a shell script for static analysis."""
    if not check_tool_availability('shellcheck', 'apt install shellcheck'):
        return []
    try:
        result = subprocess.run(['shellcheck', '--format=json', file_path], capture_output=True, text=True)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            return [(file_path, issue['line'], issue['message'], '') for issue in data]
        return []
    except Exception as e:
        logging.error(f"Error running ShellCheck on {file_path}: {e}")
        return []

def run_eslint(file_path):
    """Run ESLint on a JavaScript file for static analysis."""
    if not check_tool_availability('eslint', 'npm install -g eslint'):
        return []
    try:
        result = subprocess.run(['eslint', '--format', 'json', file_path], capture_output=True, text=True)
        data = json.loads(result.stdout)
        vulnerabilities = []
        for file in data:
            for msg in file['messages']:
                if msg['severity'] == 2:  # Errors only
                    vulnerabilities.append((file_path, msg['line'], msg['message'], ''))
        return vulnerabilities
    except Exception as e:
        logging.error(f"Error running ESLint on {file_path}: {e}")
        return []

def run_rubocop(file_path):
    """Run RuboCop on a Ruby file for static analysis."""
    if not check_tool_availability('rubocop', 'gem install rubocop'):
        return []
    try:
        result = subprocess.run(['rubocop', '--format', 'json', file_path], capture_output=True, text=True)
        data = json.loads(result.stdout)
        vulnerabilities = []
        for file in data['files']:
            for offense in file['offenses']:
                vulnerabilities.append((file_path, offense['location']['line'], offense['message'], ''))
        return vulnerabilities
    except Exception as e:
        logging.error(f"Error running RuboCop on {file_path}: {e}")
        return []

def run_psscriptanalyzer(file_path):
    """Run PSScriptAnalyzer on a PowerShell file for static analysis."""
    if not check_tool_availability('pwsh', 'Install PowerShell (e.g., apt install powershell)'):
        logging.warning("PowerShell not available. Install PowerShell to enable PSScriptAnalyzer.")
        return []
    
    # Check if PSScriptAnalyzer module is available
    module_check = subprocess.run(['pwsh', '-Command', 'Get-Module -ListAvailable -Name PSScriptAnalyzer'], capture_output=True)
    if module_check.returncode != 0:
        logging.warning("PSScriptAnalyzer module not available. Install with: Install-Module -Name PSScriptAnalyzer -Force")
        return []
    
    try:
        # Run PSScriptAnalyzer with error handling
        result = subprocess.run(
            ['pwsh', '-Command', f'$results = Invoke-ScriptAnalyzer -Path "{file_path}" -ErrorAction SilentlyContinue; if ($results) {{ $results | ConvertTo-Json }} else {{ "[]" }}'], 
            capture_output=True, 
            text=True,
            timeout=30  # Add timeout to prevent hanging
        )
        
        # Check if output is empty or whitespace
        if not result.stdout or result.stdout.isspace():
            return []
            
        # Try to parse JSON output
        try:
            data = json.loads(result.stdout)
            # Handle both array and single object responses
            if isinstance(data, dict):
                data = [data]
            return [(file_path, issue.get('Line', 0), issue.get('Message', 'Unknown issue'), '') for issue in data]
        except json.JSONDecodeError:
            logging.warning(f"Invalid JSON output from PSScriptAnalyzer for {file_path}")
            return []
            
    except subprocess.TimeoutExpired:
        logging.warning(f"PSScriptAnalyzer timed out analyzing {file_path}")
        return []
    except Exception as e:
        logging.error(f"Error running PSScriptAnalyzer on {file_path}: {e}")
        return []

def scan_for_secrets(file_path):
    """Scan a file for potential secrets and API keys."""
    secrets = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')
            for line_num, line in enumerate(lines, start=1):
                for pattern, description in secret_patterns:
                    matches = pattern.findall(line)
                    if matches:
                        for match in matches:
                            # Skip if match is a common false positive
                            if isinstance(match, tuple):
                                match = match[0]  # Extract the first group if it's a tuple
                            
                            # Skip if it's likely a false positive
                            if len(match) < 8:  # Too short to be a real secret
                                continue
                                
                            if re.match(r'^[a-zA-Z0-9_.-]+$', match) and len(match) < 12:
                                # Simple alphanumeric strings that are short are likely false positives
                                continue
                                
                            # Check if it's a base64 encoded string and try to decode it
                            is_base64 = False
                            if re.match(r'^[A-Za-z0-9+/]+={0,2}$', match):
                                try:
                                    decoded = base64.b64decode(match).decode('utf-8')
                                    # If decoded string is printable ASCII, it might be a real secret
                                    if all(32 <= ord(c) <= 126 for c in decoded):
                                        is_base64 = True
                                except:
                                    pass
                            
                            # Add the secret with context
                            context = line.strip()
                            secrets.append((file_path, line_num, f"{description}: {match[:5]}...{match[-5:]}", context))
    except UnicodeDecodeError:
        logging.warning(f"Skipping {file_path}: Not a text file or encoding issue")
    except Exception as e:
        logging.error(f"Error scanning for secrets in {file_path}: {e}")
    return secrets

def scan_file_wrapper(args):
    """Wrapper function for scan_file to be used with ThreadPoolExecutor."""
    file_path, file_patterns = args
    try:
        return scan_file(file_path, file_patterns)
    except Exception as e:
        logging.error(f"Error scanning file {file_path}: {e}")
        return []

def scan_dependencies(temp_dir):
    """Scan for vulnerable dependencies in package files."""
    vulnerabilities = []
    
    # Check for package.json (Node.js)
    package_json_files = []
    for root, _, files in os.walk(temp_dir):
        if 'package.json' in files and 'node_modules' not in root:
            package_json_files.append(os.path.join(root, 'package.json'))
    
    for package_file in package_json_files:
        try:
            with open(package_file, 'r') as f:
                data = json.load(f)
                deps = {}
                if 'dependencies' in data:
                    deps.update(data['dependencies'])
                if 'devDependencies' in data:
                    deps.update(data['devDependencies'])
                
                for pkg, version in deps.items():
                    # Remove version prefixes like ^, ~, etc.
                    clean_version = re.sub(r'^[^0-9]*', '', version)
                    # Check against NPM advisory database
                    try:
                        response = requests.get(f"https://registry.npmjs.org/-/npm/v1/security/advisories/{pkg}")
                        if response.status_code == 200:
                            advisories = response.json()
                            for advisory in advisories:
                                if 'vulnerable_versions' in advisory and re.match(advisory['vulnerable_versions'], clean_version):
                                    vulnerabilities.append((
                                        package_file,
                                        0,  # No specific line
                                        f"Vulnerable dependency: {pkg}@{version} - {advisory.get('title', 'Security vulnerability')}",
                                        f"Severity: {advisory.get('severity', 'unknown')}"
                                    ))
                    except Exception as e:
                        logging.warning(f"Error checking NPM advisory for {pkg}: {e}")
        except Exception as e:
            logging.error(f"Error parsing {package_file}: {e}")
    
    # Check for requirements.txt (Python)
    req_files = []
    for root, _, files in os.walk(temp_dir):
        if 'requirements.txt' in files:
            req_files.append(os.path.join(root, 'requirements.txt'))
    
    for req_file in req_files:
        try:
            with open(req_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Extract package name and version
                        match = re.match(r'([a-zA-Z0-9_.-]+)([=<>!~]+)([0-9a-zA-Z.-]+)', line)
                        if match:
                            pkg, op, version = match.groups()
                            # Check against PyPI Safety database
                            try:
                                response = requests.get(f"https://pypi.org/pypi/{pkg}/json")
                                if response.status_code == 200:
                                    pkg_data = response.json()
                                    if 'info' in pkg_data and 'version' in pkg_data['info']:
                                        latest = pkg_data['info']['version']
                                        if version != latest:
                                            vulnerabilities.append((
                                                req_file,
                                                line_num,
                                                f"Outdated dependency: {pkg}{op}{version} (latest: {latest})",
                                                line
                                            ))
                            except Exception as e:
                                logging.warning(f"Error checking PyPI for {pkg}: {e}")
        except Exception as e:
            logging.error(f"Error parsing {req_file}: {e}")
    
    # Check for Gemfile.lock (Ruby)
    gemfile_locks = []
    for root, _, files in os.walk(temp_dir):
        if 'Gemfile.lock' in files:
            gemfile_locks.append(os.path.join(root, 'Gemfile.lock'))
    
    for gemfile in gemfile_locks:
        try:
            with open(gemfile, 'r') as f:
                content = f.read()
                # Simple regex to extract gem versions
                gems = re.findall(r'^\s{4}([a-zA-Z0-9_-]+) \(([0-9.]+)\)', content, re.MULTILINE)
                for gem, version in gems:
                    # Check against RubyGems advisory database
                    try:
                        response = requests.get(f"https://rubygems.org/api/v1/versions/{gem}.json")
                        if response.status_code == 200:
                            versions = response.json()
                            if versions and versions[0]['number'] != version:
                                vulnerabilities.append((
                                    gemfile,
                                    0,  # No specific line
                                    f"Outdated gem: {gem} {version} (latest: {versions[0]['number']})",
                                    f"{gem} ({version})"
                                ))
                    except Exception as e:
                        logging.warning(f"Error checking RubyGems for {gem}: {e}")
        except Exception as e:
            logging.error(f"Error parsing {gemfile}: {e}")
    
    return vulnerabilities

def analyze_git_history(temp_dir):
    """Analyze git history for sensitive information that may have been committed in the past."""
    logging.info("Analyzing git history for sensitive information...")
    vulnerabilities = []
    
    try:
        # Get list of all commits
        result = subprocess.run(['git', '-C', temp_dir, 'log', '--pretty=format:%H'], 
                               capture_output=True, text=True, check=True)
        commits = result.stdout.strip().split('\n')
        
        # Limit to last 50 commits to avoid excessive processing
        commits = commits[:50]
        
        for commit in commits:
            # Get the diff for this commit
            diff_result = subprocess.run(['git', '-C', temp_dir, 'show', '--pretty=format:%an <%ae> %ad', '--date=short', commit], 
                                        capture_output=True, text=True)
            
            if diff_result.returncode == 0:
                diff_content = diff_result.stdout
                commit_info = diff_content.split('\n')[0]
                
                # Look for sensitive patterns in the diff
                for pattern, description in secret_patterns:
                    matches = pattern.findall(diff_content)
                    if matches:
                        for match in matches:
                            if isinstance(match, tuple):
                                match = match[0]
                            
                            # Skip if it's likely a false positive
                            if len(match) < 8:
                                continue
                                
                            if re.match(r'^[a-zA-Z0-9_.-]+$', match) and len(match) < 12:
                                continue
                            
                            # Extract file name from diff
                            file_match = re.search(r'diff --git a/(.*) b/', diff_content)
                            file_path = file_match.group(1) if file_match else "Unknown file"
                            
                            # Add to vulnerabilities with commit info
                            vulnerabilities.append((
                                os.path.join(temp_dir, file_path),
                                0,  # No specific line
                                f"Historical secret in commit {commit[:7]}: {description}",
                                f"Author: {commit_info}, Secret: {match[:5]}...{match[-5:]}"
                            ))
    except Exception as e:
        logging.error(f"Error analyzing git history: {e}")
    
    return vulnerabilities

def scan_for_licenses(temp_dir):
    """Scan repository for license information and compliance issues."""
    logging.info("Scanning for license information...")
    licenses_found = {}
    license_files = []
    
    # Look for common license files
    for root, _, files in os.walk(temp_dir):
        for file in files:
            if file.lower() in ['license', 'license.txt', 'license.md', 'copying', 'copying.txt']:
                license_files.append(os.path.join(root, file))
    
    # Scan license files to identify license types
    for license_file in license_files:
        try:
            with open(license_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                for license_name, pattern in license_patterns.items():
                    if pattern.search(content):
                        licenses_found[license_name] = license_file
        except Exception as e:
            logging.error(f"Error reading license file {license_file}: {e}")
    
    # Look for license headers in source files
    source_licenses = {}
    for root, _, files in os.walk(temp_dir):
        for file in files:
            if file.endswith(('.py', '.js', '.java', '.c', '.cpp', '.h', '.cs', '.go', '.rb', '.php')):
                try:
                    with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                        # Read first 50 lines to look for license headers
                        header = ''.join([next(f) for _ in range(50) if f])
                        for license_name, pattern in license_patterns.items():
                            if pattern.search(header):
                                if license_name not in source_licenses:
                                    source_licenses[license_name] = []
                                source_licenses[license_name].append(os.path.join(root, file))
                except Exception:
                    pass  # Skip files that can't be read
    
    # Check for package-specific license information
    package_licenses = {}
    
    # Check package.json for Node.js projects
    for root, _, files in os.walk(temp_dir):
        if 'package.json' in files and 'node_modules' not in root:
            try:
                with open(os.path.join(root, 'package.json'), 'r') as f:
                    data = json.load(f)
                    if 'license' in data:
                        package_licenses['Node.js Project'] = data['license']
            except Exception as e:
                logging.error(f"Error reading package.json: {e}")
    
    # Analyze license compatibility issues
    compliance_issues = []
    
    # If multiple licenses found, check compatibility
    all_licenses = set(licenses_found.keys()) | set(source_licenses.keys()) | set(package_licenses.values())
    if len(all_licenses) > 1:
        # Check if there's a primary license
        primary_license = next(iter(licenses_found.keys())) if licenses_found else None
        
        if primary_license and primary_license in license_compatibility:
            compatible_licenses = license_compatibility[primary_license]
            for license_name in all_licenses:
                if license_name != primary_license and license_name not in compatible_licenses:
                    compliance_issues.append((
                        os.path.join(temp_dir, "LICENSE"),
                        0,
                        f"License compatibility issue: {license_name} may not be compatible with {primary_license}",
                        f"Found licenses: {', '.join(all_licenses)}"
                    ))
    
    # Check for missing license
    if not licenses_found and not package_licenses:
        compliance_issues.append((
            os.path.join(temp_dir, ""),
            0,
            "Missing license file: No license file found in the repository",
            "Consider adding a LICENSE file to clarify usage terms"
        ))
    
    # Check for inconsistent licenses
    if len(all_licenses) > 1:
        compliance_issues.append((
            os.path.join(temp_dir, ""),
            0,
            f"Multiple licenses detected: {', '.join(all_licenses)}",
            "Consider standardizing on a single license"
        ))
    
    return compliance_issues

def scan_infrastructure_as_code(temp_dir):
    """Scan infrastructure-as-code files for security misconfigurations."""
    logging.info("Scanning infrastructure-as-code files...")
    vulnerabilities = []
    
    # Define IaC file patterns
    iac_files = {
        'terraform': ['.tf', '.tfvars'],
        'cloudformation': ['.yaml', '.yml', '.template', '.json'],
        'kubernetes': ['.yaml', '.yml']
    }
    
    # Define common IaC vulnerabilities
    terraform_vulnerabilities = [
        (re.compile(r'resource\s+"aws_s3_bucket".*\s+acl\s*=\s*"public-read"'), 'Public S3 bucket - security risk'),
        (re.compile(r'resource\s+"aws_security_group_rule".*\s+cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]'), 'Open security group - security risk'),
        (re.compile(r'resource\s+"aws_security_group".*\s+ingress\s*{.*\s+cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]'), 'Open security group ingress - security risk'),
        (re.compile(r'resource\s+"aws_db_instance".*\s+publicly_accessible\s*=\s*true'), 'Publicly accessible database - security risk'),
        (re.compile(r'resource\s+"aws_db_instance".*\s+storage_encrypted\s*=\s*false'), 'Unencrypted database storage - security risk'),
        (re.compile(r'resource\s+"aws_instance".*\s+associate_public_ip_address\s*=\s*true'), 'Public IP address on EC2 - potential security risk'),
        (re.compile(r'resource\s+"aws_alb".*\s+internal\s*=\s*false'), 'Public-facing load balancer - potential security risk'),
        (re.compile(r'resource\s+"aws_iam_policy".*\s+"Action"\s*:\s*"\*"'), 'Overly permissive IAM policy - security risk'),
    ]
    
    cloudformation_vulnerabilities = [
        (re.compile(r'"AccessControl"\s*:\s*"PublicRead"'), 'Public S3 bucket - security risk'),
        (re.compile(r'"CidrIp"\s*:\s*"0\.0\.0\.0/0"'), 'Open security group - security risk'),
        (re.compile(r'"PubliclyAccessible"\s*:\s*true'), 'Publicly accessible database - security risk'),
        (re.compile(r'"StorageEncrypted"\s*:\s*false'), 'Unencrypted database storage - security risk'),
        (re.compile(r'"Effect"\s*:\s*"Allow".*"Action"\s*:\s*"\*"'), 'Overly permissive IAM policy - security risk'),
    ]
    
    kubernetes_vulnerabilities = [
        (re.compile(r'privileged:\s*true'), 'Privileged container - security risk'),
        (re.compile(r'allowPrivilegeEscalation:\s*true'), 'Privilege escalation allowed - security risk'),
        (re.compile(r'readOnlyRootFilesystem:\s*false'), 'Writable root filesystem - security risk'),
        (re.compile(r'runAsUser:\s*0'), 'Running as root - security risk'),
        (re.compile(r'hostNetwork:\s*true'), 'Host network access - security risk'),
        (re.compile(r'hostPID:\s*true'), 'Host PID access - security risk'),
        (re.compile(r'hostIPC:\s*true'), 'Host IPC access - security risk'),
        (re.compile(r'capabilities:.*\s+add:.*\s+- "?ALL"?'), 'Container with ALL capabilities - security risk'),
    ]
    
    # Find all IaC files
    for root, _, files in os.walk(temp_dir):
        for file in files:
            file_path = os.path.join(root, file)
            file_ext = os.path.splitext(file)[1].lower()
            
            # Terraform files
            if file_ext in iac_files['terraform']:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for line_num, line in enumerate(content.split('\n'), 1):
                            for pattern, description in terraform_vulnerabilities:
                                if pattern.search(line):
                                    vulnerabilities.append((
                                        file_path,
                                        line_num,
                                        f"Terraform vulnerability: {description}",
                                        line.strip()
                                    ))
                except Exception as e:
                    logging.error(f"Error scanning Terraform file {file_path}: {e}")
            
            # CloudFormation files
            elif file_ext in iac_files['cloudformation']:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        # Check if it's a CloudFormation template
                        if '"AWSTemplateFormatVersion"' in content or '"Resources"' in content:
                            for line_num, line in enumerate(content.split('\n'), 1):
                                for pattern, description in cloudformation_vulnerabilities:
                                    if pattern.search(line):
                                        vulnerabilities.append((
                                            file_path,
                                            line_num,
                                            f"CloudFormation vulnerability: {description}",
                                            line.strip()
                                        ))
                except Exception as e:
                    logging.error(f"Error scanning CloudFormation file {file_path}: {e}")
            
            # Kubernetes files
            elif file_ext in iac_files['kubernetes']:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        # Check if it's a Kubernetes manifest
                        if 'apiVersion:' in content and ('kind:' in content):
                            for line_num, line in enumerate(content.split('\n'), 1):
                                for pattern, description in kubernetes_vulnerabilities:
                                    if pattern.search(line):
                                        vulnerabilities.append((
                                            file_path,
                                            line_num,
                                            f"Kubernetes vulnerability: {description}",
                                            line.strip()
                                        ))
                            
                            # Parse YAML to check for missing security contexts
                            try:
                                docs = list(yaml.safe_load_all(content))
                                for doc in docs:
                                    if doc and doc.get('kind') in ['Deployment', 'StatefulSet', 'DaemonSet', 'Pod']:
                                        # Check for missing security context
                                        containers = []
                                        if doc.get('spec', {}).get('template', {}).get('spec', {}).get('containers'):
                                            containers = doc['spec']['template']['spec']['containers']
                                        elif doc.get('spec', {}).get('containers'):
                                            containers = doc['spec']['containers']
                                            
                                        for container in containers:
                                            if 'securityContext' not in container:
                                                vulnerabilities.append((
                                                    file_path,
                                                    0,  # No specific line
                                                    f"Kubernetes vulnerability: Missing container security context in {container.get('name', 'unnamed')}",
                                                    "No security context defined for container"
                                                ))
                            except Exception as e:
                                logging.warning(f"Error parsing Kubernetes YAML in {file_path}: {e}")
                except Exception as e:
                    logging.error(f"Error scanning Kubernetes file {file_path}: {e}")
    
    return vulnerabilities

def scan_web_configs(temp_dir):
    """Scan for insecure configurations in web frameworks and application config files."""
    logging.info("Scanning web framework configurations...")
    vulnerabilities = []
    
    # Django settings.py
    django_vulnerabilities = [
        (re.compile(r'DEBUG\s*=\s*True'), 'Debug mode enabled in Django settings'),
        (re.compile(r'SECRET_KEY\s*=\s*["\'].+["\']'), 'Hardcoded Django SECRET_KEY'),
        (re.compile(r'ALLOWED_HOSTS\s*=\s*\[\s*["\'][*]["\']'), 'Overly permissive ALLOWED_HOSTS in Django'),
        (re.compile(r'CSRF_COOKIE_SECURE\s*=\s*False'), 'CSRF cookie not secure in Django'),
        (re.compile(r'SESSION_COOKIE_SECURE\s*=\s*False'), 'Session cookie not secure in Django'),
        (re.compile(r'SECURE_BROWSER_XSS_FILTER\s*=\s*False'), 'XSS filter disabled in Django'),
        (re.compile(r'SECURE_CONTENT_TYPE_NOSNIFF\s*=\s*False'), 'Content type sniffing not prevented in Django'),
    ]
    
    # Flask config
    flask_vulnerabilities = [
        (re.compile(r'DEBUG\s*=\s*True'), 'Debug mode enabled in Flask'),
        (re.compile(r'SECRET_KEY\s*=\s*["\'].+["\']'), 'Hardcoded Flask SECRET_KEY'),
        (re.compile(r'SESSION_COOKIE_SECURE\s*=\s*False'), 'Session cookie not secure in Flask'),
        (re.compile(r'SESSION_COOKIE_HTTPONLY\s*=\s*False'), 'Session cookie not HttpOnly in Flask'),
    ]
    
    # Express.js config
    express_vulnerabilities = [
        (re.compile(r'app\.use\(express\.static\(["\']'), 'Static file serving without proper security headers'),
        (re.compile(r'app\.disable\(["\']x-powered-by["\']\)'), 'X-Powered-By header not disabled'),
        (re.compile(r'cookie:\s*{\s*secure:\s*false'), 'Cookies not secure in Express'),
        (re.compile(r'cookie:\s*{\s*httpOnly:\s*false'), 'Cookies not HttpOnly in Express'),
    ]
    
    # Spring Boot application.properties/yml
    spring_vulnerabilities = [
        (re.compile(r'server\.ssl\.enabled\s*=\s*false'), 'SSL disabled in Spring Boot'),
        (re.compile(r'security\.basic\.enabled\s*=\s*false'), 'Basic security disabled in Spring Boot'),
        (re.compile(r'management\.security\.enabled\s*=\s*false'), 'Management security disabled in Spring Boot'),
        (re.compile(r'spring\.security\.csrf\.enabled\s*=\s*false'), 'CSRF protection disabled in Spring Boot'),
    ]
    
    # Rails config
    rails_vulnerabilities = [
        (re.compile(r'config\.force_ssl\s*=\s*false'), 'SSL not forced in Rails'),
        (re.compile(r'config\.action_controller\.default_protect_from_forgery\s*=\s*false'), 'CSRF protection disabled in Rails'),
        (re.compile(r'config\.action_dispatch\.default_headers\.clear'), 'Security headers cleared in Rails'),
    ]
    
    # Web server configs
    nginx_vulnerabilities = [
        (re.compile(r'ssl_protocols.*TLSv1\s'), 'Outdated TLS protocol in Nginx'),
        (re.compile(r'add_header\s+X-Frame-Options'), 'Missing X-Frame-Options header in Nginx'),
        (re.compile(r'add_header\s+X-Content-Type-Options'), 'Missing X-Content-Type-Options header in Nginx'),
        (re.compile(r'add_header\s+Content-Security-Policy'), 'Missing Content-Security-Policy header in Nginx'),
    ]
    
    apache_vulnerabilities = [
        (re.compile(r'SSLProtocol.*TLSv1\s'), 'Outdated TLS protocol in Apache'),
        (re.compile(r'Header\s+set\s+X-Frame-Options'), 'Missing X-Frame-Options header in Apache'),
        (re.compile(r'Header\s+set\s+X-Content-Type-Options'), 'Missing X-Content-Type-Options header in Apache'),
        (re.compile(r'Header\s+set\s+Content-Security-Policy'), 'Missing Content-Security-Policy header in Apache'),
    ]
    
    # Find configuration files
    for root, _, files in os.walk(temp_dir):
        for file in files:
            file_path = os.path.join(root, file)
            file_name = file.lower()
            
            # Django settings
            if file_name == 'settings.py':
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        if 'INSTALLED_APPS' in content or 'DATABASES' in content:  # Likely a Django settings file
                            for line_num, line in enumerate(content.split('\n'), 1):
                                for pattern, description in django_vulnerabilities:
                                    if pattern.search(line):
                                        vulnerabilities.append((
                                            file_path,
                                            line_num,
                                            f"Django vulnerability: {description}",
                                            line.strip()
                                        ))
                except Exception as e:
                    logging.error(f"Error scanning Django settings file {file_path}: {e}")
            
            # Flask config
            elif 'flask' in file_name and file_name.endswith('.py'):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        if 'Flask(' in content or 'flask.Flask(' in content:  # Likely a Flask app
                            for line_num, line in enumerate(content.split('\n'), 1):
                                for pattern, description in flask_vulnerabilities:
                                    if pattern.search(line):
                                        vulnerabilities.append((
                                            file_path,
                                            line_num,
                                            f"Flask vulnerability: {description}",
                                            line.strip()
                                        ))
                except Exception as e:
                    logging.error(f"Error scanning Flask config file {file_path}: {e}")
            
            # Express.js config
            elif file_name.endswith('.js'):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        if 'express' in content and ('require(' in content or 'import ' in content):  # Likely an Express app
                            for line_num, line in enumerate(content.split('\n'), 1):
                                for pattern, description in express_vulnerabilities:
                                    if pattern.search(line):
                                        vulnerabilities.append((
                                            file_path,
                                            line_num,
                                            f"Express.js vulnerability: {description}",
                                            line.strip()
                                        ))
                except Exception as e:
                    logging.error(f"Error scanning Express.js config file {file_path}: {e}")
            
            # Spring Boot config
            elif file_name == 'application.properties' or file_name == 'application.yml':
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for line_num, line in enumerate(content.split('\n'), 1):
                            for pattern, description in spring_vulnerabilities:
                                if pattern.search(line):
                                    vulnerabilities.append((
                                        file_path,
                                        line_num,
                                        f"Spring Boot vulnerability: {description}",
                                        line.strip()
                                    ))
                except Exception as e:
                    logging.error(f"Error scanning Spring Boot config file {file_path}: {e}")
            
            # Rails config
            elif 'config/environments/' in file_path and file_name.endswith('.rb'):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for line_num, line in enumerate(content.split('\n'), 1):
                            for pattern, description in rails_vulnerabilities:
                                if pattern.search(line):
                                    vulnerabilities.append((
                                        file_path,
                                        line_num,
                                        f"Rails vulnerability: {description}",
                                        line.strip()
                                    ))
                except Exception as e:
                    logging.error(f"Error scanning Rails config file {file_path}: {e}")
            
            # Nginx config
            elif file_name.endswith('.conf') and ('nginx' in file_path.lower() or 'nginx' in file_name):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for line_num, line in enumerate(content.split('\n'), 1):
                            for pattern, description in nginx_vulnerabilities:
                                if pattern.search(line):
                                    vulnerabilities.append((
                                        file_path,
                                        line_num,
                                        f"Nginx vulnerability: {description}",
                                        line.strip()
                                    ))
                except Exception as e:
                    logging.error(f"Error scanning Nginx config file {file_path}: {e}")
            
            # Apache config
            elif file_name.endswith(('.conf', '.htaccess')) and ('apache' in file_path.lower() or 'httpd' in file_path.lower()):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for line_num, line in enumerate(content.split('\n'), 1):
                            for pattern, description in apache_vulnerabilities:
                                if pattern.search(line):
                                    vulnerabilities.append((
                                        file_path,
                                        line_num,
                                        f"Apache vulnerability: {description}",
                                        line.strip()
                                    ))
                except Exception as e:
                    logging.error(f"Error scanning Apache config file {file_path}: {e}")
    
    return vulnerabilities

def scan_repository(temp_dir):
    """Scan all files in the repository for vulnerabilities."""
    vulnerabilities = []
    
    # Scan all files in the repository
    file_paths = []
    for root, _, files in os.walk(temp_dir):
        for file in files:
            file_path = os.path.join(root, file)
            file_ext = os.path.splitext(file_path)[1].lower()
            if file_ext in patterns:
                file_paths.append((file_path, patterns[file_ext]))
    
    # Use ThreadPoolExecutor for parallel scanning
    with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
        future_to_file = {executor.submit(scan_file_wrapper, args): args for args in file_paths}
        for future in as_completed(future_to_file):
            file_vulnerabilities = future.result()
            if file_vulnerabilities:
                vulnerabilities.extend(file_vulnerabilities)
    
    # Run specialized scanners
    try:
        # Run Bandit on Python files
        for root, _, files in os.walk(temp_dir):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    bandit_results = run_bandit(file_path)
                    if bandit_results:
                        vulnerabilities.extend(bandit_results)
                elif file.endswith('.sh'):
                    file_path = os.path.join(root, file)
                    shellcheck_results = run_shellcheck(file_path)
                    if shellcheck_results:
                        vulnerabilities.extend(shellcheck_results)
                elif file.endswith('.js'):
                    file_path = os.path.join(root, file)
                    eslint_results = run_eslint(file_path)
                    if eslint_results:
                        vulnerabilities.extend(eslint_results)
                elif file.endswith('.rb'):
                    file_path = os.path.join(root, file)
                    rubocop_results = run_rubocop(file_path)
                    if rubocop_results:
                        vulnerabilities.extend(rubocop_results)
                elif file.endswith('.ps1'):
                    file_path = os.path.join(root, file)
                    psscriptanalyzer_results = run_psscriptanalyzer(file_path)
                    if psscriptanalyzer_results:
                        vulnerabilities.extend(psscriptanalyzer_results)
    except Exception as e:
        logging.error(f"Error running specialized scanners: {str(e)}")
    
    # Scan for dependencies
    try:
        dependency_vulnerabilities = scan_dependencies(temp_dir)
        if dependency_vulnerabilities:
            vulnerabilities.extend(dependency_vulnerabilities)
    except Exception as e:
        logging.error(f"Error scanning dependencies: {str(e)}")
    
    # Skip git history analysis for this run to avoid long processing time
    # git_vulnerabilities = analyze_git_history(temp_dir)
    # if git_vulnerabilities:
    #     vulnerabilities.extend(git_vulnerabilities)
    logging.info("Skipping git history analysis to save time")
    
    # Scan for licenses
    try:
        license_vulnerabilities = scan_for_licenses(temp_dir)
        if license_vulnerabilities:
            vulnerabilities.extend(license_vulnerabilities)
    except Exception as e:
        logging.error(f"Error scanning for licenses: {str(e)}")
    
    # Scan infrastructure-as-code files
    try:
        iac_vulnerabilities = scan_infrastructure_as_code(temp_dir)
        if iac_vulnerabilities:
            vulnerabilities.extend(iac_vulnerabilities)
    except Exception as e:
        logging.error(f"Error scanning infrastructure-as-code files: {str(e)}")
    
    # Scan web framework configurations
    try:
        web_config_vulnerabilities = scan_web_configs(temp_dir)
        if web_config_vulnerabilities:
            vulnerabilities.extend(web_config_vulnerabilities)
    except Exception as e:
        logging.error(f"Error scanning web framework configurations: {str(e)}")
    
    return vulnerabilities

def classify_severity(description):
    """Classify the severity of a vulnerability based on its description."""
    for key, severity in severity_mapping.items():
        if key.lower() in description.lower():
            return severity
    return 'Info'  # Default severity

def calculate_risk_score(severity):
    """Calculate a numeric risk score based on severity."""
    severity_scores = {
        'Critical': 10,
        'High': 8,
        'Medium': 5,
        'Low': 3,
        'Info': 1
    }
    return severity_scores.get(severity, 1)

def enrich_vulnerabilities(vulnerabilities):
    """Enrich vulnerability data with severity and risk score."""
    enriched = []
    for vuln in vulnerabilities:
        file_path, line_num, description, context = vuln
        severity = classify_severity(description)
        risk_score = calculate_risk_score(severity)
        enriched.append((file_path, line_num, description, context, severity, risk_score))
    
    # Sort by risk score (highest first)
    return sorted(enriched, key=lambda x: x[5], reverse=True)

def generate_pdf_report(vulnerabilities, repo_url, output_file='report.pdf', temp_dir=None):
    """Generate a professional PDF report of the findings, designed for non-technical audiences."""
    doc = SimpleDocTemplate(output_file, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph("Security Scan Report", styles['Title']))
    story.append(Spacer(1, 12))

    # Executive Summary
    story.append(Paragraph("Executive Summary", styles['Heading2']))
    severity_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
    for _, _, _, _, severity, _ in vulnerabilities:
        severity_count[severity] += 1
    
    summary = f"This report summarizes a security scan of the GitHub repository: {repo_url}. We found {len(vulnerabilities)} potential security issues. "
    summary += f"Breakdown: {severity_count['Critical']} Critical, {severity_count['High']} High, {severity_count['Medium']} Medium, {severity_count['Low']} Low, {severity_count['Info']} Informational issues."
    story.append(Paragraph(summary, styles['Normal']))
    story.append(Spacer(1, 12))

    # Risk Score
    total_risk_score = sum(vuln[5] for vuln in vulnerabilities)
    max_possible_score = 10 * len(vulnerabilities)  # If all were critical
    normalized_score = (total_risk_score / max_possible_score) * 100 if max_possible_score > 0 else 0
    
    risk_level = "Low"
    if normalized_score > 75:
        risk_level = "Critical"
    elif normalized_score > 50:
        risk_level = "High"
    elif normalized_score > 25:
        risk_level = "Medium"
    
    story.append(Paragraph("Overall Risk Assessment", styles['Heading2']))
    story.append(Paragraph(f"Risk Score: {normalized_score:.1f}/100 ({risk_level} Risk)", styles['Normal']))
    story.append(Spacer(1, 12))

    # Detailed Findings
    story.append(Paragraph("What We Found", styles['Heading2']))
    if vulnerabilities:
        # Group by severity for better organization
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            severity_vulns = [v for v in vulnerabilities if v[4] == severity]
            if severity_vulns:
                story.append(Paragraph(f"{severity} Severity Issues ({len(severity_vulns)})", styles['Heading3']))
                story.append(Spacer(1, 6))
                
                data = [['File', 'Line', 'Issue', 'Context']]
                for vuln in severity_vulns:
                    file_path, line_num, desc, snippet, _, _ = vuln
                    # Use a safe relative path calculation that doesn't require temp_dir
                    if temp_dir and os.path.isabs(file_path):
                        try:
                            relative_path = os.path.relpath(file_path, temp_dir)
                        except ValueError:
                            # If paths are on different drives
                            relative_path = os.path.basename(file_path)
                    else:
                        relative_path = os.path.basename(file_path)
                    data.append([relative_path, str(line_num), desc, Paragraph(snippet[:50] + '...' if len(snippet) > 50 else snippet, styles['Normal'])])
                
                table = Table(data, colWidths=[1.5*inch, 0.5*inch, 2*inch, 2*inch])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                story.append(table)
                story.append(Spacer(1, 12))
    else:
        story.append(Paragraph("Great news! No security issues were found in the scanned files.", styles['Normal']))
    story.append(Spacer(1, 12))

    # Recommendations
    story.append(Paragraph("What You Can Do", styles['Heading2']))
    recommendations = [
        "Avoid using risky functions like 'eval()' that can run harmful code.",
        "Keep passwords and secrets out of your code—use secure storage instead.",
        "Run this scan regularly to catch issues early.",
        "Ask your team to follow safe coding habits."
    ]
    for rec in recommendations:
        story.append(Paragraph(f"• {rec}", styles['Normal']))
    story.append(Spacer(1, 12))

    # Footer
    story.append(Paragraph("Note: This tool is very thorough, but it's always a good idea to have an expert double-check important systems.", styles['Italic']))

    doc.build(story)
    logging.info(f"PDF report generated: {output_file}")

def generate_github_workflow(output_path='.github/workflows/security-scan.yml'):
    """Generate a GitHub Actions workflow file for automated security scanning."""
    workflow_content = """name: Security Scan

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]
  schedule:
    - cron: '0 0 * * 0'  # Run weekly on Sunday at midnight

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Fetch all history for git history analysis
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install reportlab requests
          # Install additional tools for static analysis
          pip install bandit
          sudo apt-get update
          sudo apt-get install -y shellcheck
      
      - name: Run security scan
        run: |
          python githubscan.py ${{ github.repository }} --output-format json --output-file scan-results.json --min-severity medium
      
      - name: Check for critical or high severity issues
        run: |
          if grep -q '"severity":"Critical"\\|"severity":"High"' scan-results.json; then
            echo "::error::Critical or high severity security issues found!"
            exit 1
          fi
      
      - name: Upload scan results
        uses: actions/upload-artifact@v3
        with:
          name: security-scan-results
          path: scan-results.json
"""
    
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w') as f:
        f.write(workflow_content)
    
    logging.info(f"GitHub Actions workflow file generated at {output_path}")
    return output_path

def get_remediation_suggestion(description):
    """Get a remediation suggestion for a vulnerability based on its description."""
    for key, suggestion in remediation_suggestions.items():
        if key.lower() in description.lower():
            return suggestion
    return "Review the code and consider refactoring to follow security best practices."

def interactive_remediation(vulnerabilities, temp_dir):
    """Interactive mode to review and get remediation suggestions for each vulnerability."""
    print("\n=== Interactive Remediation Mode ===")
    print(f"Found {len(vulnerabilities)} potential security issues.\n")
    
    # Group vulnerabilities by file for better organization
    vulnerabilities_by_file = {}
    for vuln in vulnerabilities:
        file_path, line_num, desc, _, severity, _ = vuln
        rel_path = os.path.relpath(file_path, temp_dir)
        if rel_path not in vulnerabilities_by_file:
            vulnerabilities_by_file[rel_path] = []
        vulnerabilities_by_file[rel_path].append((line_num, desc, severity))
    
    # Sort files by number of vulnerabilities (descending)
    sorted_files = sorted(vulnerabilities_by_file.keys(), 
                         key=lambda x: len(vulnerabilities_by_file[x]), 
                         reverse=True)
    
    for file_path in sorted_files:
        print(f"\n\033[1mFile: {file_path}\033[0m")
        
        # Sort vulnerabilities by line number
        file_vulns = sorted(vulnerabilities_by_file[file_path], key=lambda x: x[0])
        
        for line_num, desc, severity in file_vulns:
            # Color-code severity
            if severity == 'Critical':
                severity_color = '\033[91m'  # Red
            elif severity == 'High':
                severity_color = '\033[93m'  # Yellow
            elif severity == 'Medium':
                severity_color = '\033[94m'  # Blue
            else:
                severity_color = '\033[92m'  # Green
            
            print(f"  Line {line_num}: {severity_color}[{severity}]\033[0m {desc}")
            
            # Get remediation suggestion
            suggestion = get_remediation_suggestion(desc)
            print(f"    \033[96mRemediation:\033[0m {suggestion}")
            
            # If it's a code file, try to show the vulnerable line
            abs_path = os.path.join(temp_dir, file_path)
            if os.path.exists(abs_path) and line_num > 0:
                try:
                    with open(abs_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        if line_num <= len(lines):
                            context_start = max(0, line_num - 2)
                            context_end = min(len(lines), line_num + 1)
                            
                            print("    \033[90mCode context:\033[0m")
                            for i in range(context_start, context_end):
                                line_prefix = "  > " if i == line_num - 1 else "    "
                                print(f"    {line_prefix}\033[90m{i+1}:\033[0m {lines[i].rstrip()}")
                except Exception:
                    pass  # Skip if can't read the file
            
            # Ask if user wants to continue to next issue
            if input("\n  Press Enter to continue, 'q' to quit: ").lower() == 'q':
                return

def generate_sarif_report(vulnerabilities, repo_url, output_file='report.sarif'):
    """Generate a SARIF (Static Analysis Results Interchange Format) report for integration with code scanning tools."""
    logging.info("Generating SARIF report...")
    
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "GitHubScan",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/your-username/githubscan",
                        "rules": []
                    }
                },
                "results": [],
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "commandLine": f"githubscan.py {repo_url}",
                        "startTimeUtc": datetime.datetime.utcnow().isoformat(),
                        "endTimeUtc": datetime.datetime.utcnow().isoformat()
                    }
                ]
            }
        ]
    }
    
    # Create a dictionary to track unique rule IDs
    rule_ids = {}
    rule_index = 1
    
    # Process vulnerabilities
    for vuln in vulnerabilities:
        file_path, line_num, description, context, severity, risk_score = vuln
        
        # Create a unique rule ID for each type of vulnerability
        rule_key = description.split(':')[0] if ':' in description else description
        if rule_key not in rule_ids:
            rule_id = f"GHSCAN{rule_index:04d}"
            rule_ids[rule_key] = rule_id
            rule_index += 1
            
            # Add rule to the rules array
            sarif["runs"][0]["tool"]["driver"]["rules"].append({
                "id": rule_id,
                "shortDescription": {
                    "text": rule_key
                },
                "fullDescription": {
                    "text": description
                },
                "help": {
                    "text": get_remediation_suggestion(description)
                },
                "properties": {
                    "tags": [severity.lower(), "security"],
                    "precision": "high" if severity in ["Critical", "High"] else "medium"
                },
                "defaultConfiguration": {
                    "level": "error" if severity in ["Critical", "High"] else 
                             "warning" if severity == "Medium" else "note"
                }
            })
        else:
            rule_id = rule_ids[rule_key]
        
        # Add result
        relative_path = os.path.relpath(file_path, temp_dir)
        sarif["runs"][0]["results"].append({
            "ruleId": rule_id,
            "level": "error" if severity in ["Critical", "High"] else 
                     "warning" if severity == "Medium" else "note",
            "message": {
                "text": description
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": relative_path,
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": line_num,
                            "snippet": {
                                "text": context
                            }
                        }
                    }
                }
            ],
            "properties": {
                "severity": severity,
                "riskScore": risk_score
            }
        })
    
    # Write SARIF report to file
    with open(output_file, 'w') as f:
        json.dump(sarif, f, indent=2)
    
    logging.info(f"SARIF report generated: {output_file}")
    return output_file

def main():
    # Command-line arguments
    parser = argparse.ArgumentParser(description="Scan GitHub repositories for script vulnerabilities.")
    parser.add_argument('repo_url', help="GitHub repository URL (e.g., https://github.com/user/repo.git)")
    parser.add_argument('--token', help="GitHub token for private repositories")
    parser.add_argument('--output-format', choices=['text', 'json', 'csv', 'pdf', 'sarif'], default='pdf', help="Output format (default: pdf)")
    parser.add_argument('--output-file', help="File to save output (defaults: report.pdf for PDF, report.sarif for SARIF, else stdout)")
    parser.add_argument('--min-severity', choices=['critical', 'high', 'medium', 'low', 'info'], default='low', 
                        help="Minimum severity level to include in results (default: low)")
    parser.add_argument('--ci-mode', action='store_true', help="CI mode: exit with non-zero code if issues found")
    parser.add_argument('--fail-on-severity', choices=['critical', 'high', 'medium', 'low'], default='high',
                        help="In CI mode, exit with error if issues of this severity or higher are found (default: high)")
    parser.add_argument('--generate-workflow', action='store_true', 
                        help="Generate a GitHub Actions workflow file for automated scanning")
    parser.add_argument('--workflow-path', default='.github/workflows/security-scan.yml',
                        help="Path for the generated GitHub Actions workflow file")
    parser.add_argument('--interactive', action='store_true',
                        help="Interactive mode: review issues one by one with remediation suggestions")
    
    args = parser.parse_args()
    
    # Generate GitHub Actions workflow if requested
    if args.generate_workflow:
        workflow_path = generate_github_workflow(args.workflow_path)
        logging.info(f"GitHub Actions workflow file generated at {workflow_path}")
        if not args.repo_url.startswith('http'):
            return 0  # Exit if only generating workflow

    # Clone the repository
    logging.info(f"Starting scan for: {args.repo_url}")
    temp_dir = clone_repo(args.repo_url, args.token)
    
    exit_code = 0  # Default exit code
    
    try:
        # Scan the repository
        logging.info("Scanning files for security issues...")
        vulnerabilities = scan_repository(temp_dir)
        
        # Enrich and filter vulnerabilities
        enriched_vulnerabilities = enrich_vulnerabilities(vulnerabilities)
        
        # Filter by minimum severity if specified
        severity_levels = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        min_severity_level = severity_levels.get(args.min_severity.lower(), 0)
        severity_map = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}
        
        filtered_vulnerabilities = [v for v in enriched_vulnerabilities 
                                   if severity_map.get(v[4], 0) >= min_severity_level]
        
        # Interactive mode if requested
        if args.interactive and filtered_vulnerabilities:
            interactive_remediation(filtered_vulnerabilities, temp_dir)
        else:
            # Prepare output
            output_file = args.output_file
            if not output_file:
                if args.output_format == 'pdf':
                    output_file = 'report.pdf'
                elif args.output_format == 'sarif':
                    output_file = 'report.sarif'
            
            if args.output_format == 'pdf':
                generate_pdf_report(filtered_vulnerabilities, args.repo_url, output_file, temp_dir)
            elif args.output_format == 'sarif':
                generate_sarif_report(filtered_vulnerabilities, args.repo_url, output_file)
            else:
                if filtered_vulnerabilities:
                    if args.output_format == 'text':
                        output = '\n'.join(f"{os.path.relpath(v[0], temp_dir)}:{v[1]} - [{v[4]}] {v[2]}" for v in filtered_vulnerabilities)
                    elif args.output_format == 'json':
                        output = json.dumps([{
                            'file': os.path.relpath(v[0], temp_dir), 
                            'line': v[1], 
                            'description': v[2],
                            'severity': v[4],
                            'risk_score': v[5],
                            'remediation': get_remediation_suggestion(v[2])
                        } for v in filtered_vulnerabilities], indent=4)
                    elif args.output_format == 'csv':
                        output = 'File,Line,Description,Severity,Risk Score,Remediation\n' + '\n'.join(
                            f'"{os.path.relpath(v[0], temp_dir)}",{v[1]},"{v[2]}",{v[4]},{v[5]},"{get_remediation_suggestion(v[2])}"' 
                            for v in filtered_vulnerabilities)
                    
                    if output_file:
                        with open(output_file, 'w') as f:
                            f.write(output)
                        logging.info(f"Results saved to {output_file}")
                    else:
                        print(output)
                        
                    # Handle CI mode exit code
                    if args.ci_mode:
                        fail_level = severity_levels.get(args.fail_on_severity.lower(), 3)  # Default to high
                        for vuln in filtered_vulnerabilities:
                            if severity_map.get(vuln[4], 0) >= fail_level:
                                logging.error(f"Security issues of {args.fail_on_severity} or higher severity found. Exiting with error.")
                                exit_code = 1
                                break
                else:
                    logging.info("No security issues found matching the specified severity level.")
    
    finally:
        # Clean up
        shutil.rmtree(temp_dir, ignore_errors=True)
        logging.info("Scan completed and temporary files cleaned up.")
    
    return exit_code

if __name__ == "__main__":
    sys.exit(main())