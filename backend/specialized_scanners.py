"""
Specialized Scanners for Different File Types
Format-specific vulnerability detection patterns
"""

import re
from typing import List, Dict, Any
from pathlib import Path


class SpecializedScanner:
    """File-type specific vulnerability scanners."""
    
    @staticmethod
    def scan_json_config(content: str, filename: str) -> List[Dict[str, Any]]:
        """Scan JSON configuration files for secrets and misconfigurations."""
        
        findings = []
        lines = content.split('\n')
        
        # Patterns for JSON configs
        patterns = {
            "aws-access-key": {
                "regex": r'"(access_key|aws_access_key_id|ACCESS_KEY)":\s*"(AKIA[0-9A-Z]{16})"',
                "severity": "CRITICAL",
                "message": "AWS Access Key exposed in configuration"
            },
            "aws-secret-key": {
                "regex": r'"(secret|aws_secret|secret_access_key)":\s*"([A-Za-z0-9/+=]{40})"',
                "severity": "CRITICAL",
                "message": "AWS Secret Key exposed in configuration"
            },
            "stripe-key": {
                "regex": r'"(stripe_secret|stripe_key)":\s*"(sk_live_[a-zA-Z0-9]{24,})"',
                "severity": "CRITICAL",
                "message": "Stripe Secret Key in configuration"
            },
            "database-password": {
                "regex": r'"(password|db_password|database_password)":\s*"([^"]{8,})"',
                "severity": "HIGH",
                "message": "Database password hardcoded in JSON config"
            },
            "jwt-secret": {
                "regex": r'"(jwt_secret|secret_key|session_secret)":\s*"([^"]{10,})"',
                "severity": "HIGH",
                "message": "JWT/Session secret exposed"
            },
            "api-token": {
                "regex": r'"(api_key|api_token|token)":\s*"([a-zA-Z0-9_-]{20,})"',
                "severity": "HIGH",
                "message": "API token hardcoded in configuration"
            },
            "debug-enabled": {
                "regex": r'"(debug|DEBUG|enable_debug)":\s*true',
                "severity": "MEDIUM",
                "message": "Debug mode enabled in configuration (information disclosure risk)"
            },
            "disable-security": {
                "regex": r'"(disable|skip)_(auth|csrf|validation|ssl)":\s*true',
                "severity": "HIGH",
                "message": "Security feature disabled in configuration"
            }
        }
        
        for line_num, line in enumerate(lines, 1):
            for pattern_id, pattern_data in patterns.items():
                if re.search(pattern_data["regex"], line, re.IGNORECASE):
                    findings.append({
                        "id": f"json-config/{pattern_id}",
                        "engine": "specialized-json",
                        "category": "Configuration Security",
                        "severity": pattern_data["severity"],
                        "message": pattern_data["message"],
                        "file": filename,
                        "line_start": line_num,
                        "snippet": line.strip()[:200],
                        "cwe": "CWE-798"
                    })
        
        return findings
    
    @staticmethod
    def scan_yaml_k8s(content: str, filename: str) -> List[Dict[str, Any]]:
        """Scan YAML/Kubernetes files for misconfigurations."""
        
        findings = []
        lines = content.split('\n')
        
        patterns = {
            "privileged-container": {
                "regex": r'privileged:\s*true',
                "severity": "CRITICAL",
                "message": "Kubernetes container running in privileged mode (full host access)"
            },
            "run-as-root": {
                "regex": r'runAsUser:\s*0',
                "severity": "HIGH",
                "message": "Container running as root user (security risk)"
            },
            "host-network": {
                "regex": r'hostNetwork:\s*true',
                "severity": "HIGH",
                "message": "Pod using host network (bypasses network policies)"
            },
            "host-path-mount": {
                "regex": r'hostPath:',
                "severity": "HIGH",
                "message": "Mounting host filesystem into container (potential escape)"
            },
            "no-resource-limits": {
                "regex": r'kind:\s*Deployment',
                "severity": "MEDIUM",
                "message": "Deployment without resource limits (DoS risk)"
            },
            "exposed-secret": {
                "regex": r'value:\s*["\']([^"\']{15,})["\']',
                "severity": "CRITICAL",
                "message": "Hardcoded secret in Kubernetes manifest (use Secret resource)"
            },
            "allow-privilege-escalation": {
                "regex": r'allowPrivilegeEscalation:\s*true',
                "severity": "HIGH",
                "message": "Privilege escalation enabled"
            },
            "capabilities-added": {
                "regex": r'add:\s*-\s*(SYS_ADMIN|NET_ADMIN|SYS_PTRACE)',
                "severity": "HIGH",
                "message": "Dangerous Linux capabilities added to container"
            }
        }
        
        for line_num, line in enumerate(lines, 1):
            for pattern_id, pattern_data in patterns.items():
                if re.search(pattern_data["regex"], line, re.IGNORECASE):
                    findings.append({
                        "id": f"k8s/{pattern_id}",
                        "engine": "specialized-k8s",
                        "category": "Infrastructure Security",
                        "severity": pattern_data["severity"],
                        "message": pattern_data["message"],
                        "file": filename,
                        "line_start": line_num,
                        "snippet": line.strip()[:200],
                        "cwe": "CWE-732"
                    })
        
        return findings
    
    @staticmethod
    def scan_env_file(content: str, filename: str) -> List[Dict[str, Any]]:
        """Scan .env files for exposed secrets."""
        
        findings = []
        lines = content.split('\n')
        
        secret_patterns = {
            "aws-key": r'AWS.*KEY.*=.*(AKIA[0-9A-Z]{16})',
            "stripe": r'STRIPE.*=.*(sk_live_[a-zA-Z0-9]{24,})',
            "sendgrid": r'SENDGRID.*=.*(SG\.[a-zA-Z0-9_-]{22,})',
            "twilio": r'TWILIO.*=.*(AC[a-f0-9]{32}|[a-f0-9]{32})',
            "github-token": r'GITHUB.*=.*(ghp_[a-zA-Z0-9]{36,})',
            "google-api": r'GOOGLE.*KEY.*=.*(AIza[a-zA-Z0-9_-]{35})',
            "slack": r'SLACK.*=.*(xox[baprs]-[a-zA-Z0-9-]{10,})',
            "database-pass": r'(DB|DATABASE).*PASS.*=.*["\']?([^"\'\s]{8,})',
            "jwt-secret": r'JWT.*SECRET.*=.*["\']?([^"\'\s]{10,})',
            "private-key": r'PRIVATE.*KEY.*=.*-----BEGIN'
        }
        
        for line_num, line in enumerate(lines, 1):
            if line.strip().startswith('#') or '=' not in line:
                continue
            
            for pattern_name, pattern_regex in secret_patterns.items():
                if re.search(pattern_regex, line, re.IGNORECASE):
                    findings.append({
                        "id": f"env-secret/{pattern_name}",
                        "engine": "specialized-env",
                        "category": "Secrets",
                        "severity": "CRITICAL",
                        "message": f"Exposed secret in .env file: {pattern_name.replace('-', ' ').title()}",
                        "file": filename,
                        "line_start": line_num,
                        "snippet": line.split('=')[0] + "=***REDACTED***",
                        "cwe": "CWE-798"
                    })
                    break  # One finding per line
        
        return findings
    
    @staticmethod
    def scan_html_web(content: str, filename: str) -> List[Dict[str, Any]]:
        """Scan HTML files for XSS and client-side vulnerabilities."""
        
        findings = []
        lines = content.split('\n')
        
        patterns = {
            "inline-event-handler": {
                "regex": r'on(click|load|error|mouseover)\s*=\s*["\'].*\+.*["\']',
                "severity": "HIGH",
                "message": "Inline event handler with concatenation (XSS risk)"
            },
            "eval-in-script": {
                "regex": r'eval\s*\(',
                "severity": "CRITICAL",
                "message": "eval() usage in client-side JavaScript (code injection)"
            },
            "innerhtml-assignment": {
                "regex": r'innerHTML\s*=',
                "severity": "HIGH",
                "message": "Direct innerHTML assignment (XSS vulnerability)"
            },
            "document-write": {
                "regex": r'document\.write\s*\(',
                "severity": "MEDIUM",
                "message": "document.write() usage (XSS risk)"
            },
            "exposed-api-key": {
                "regex": r'(api_key|apiKey|API_KEY)\s*=\s*["\']([a-zA-Z0-9_-]{20,})',
                "severity": "CRITICAL",
                "message": "API key exposed in client-side code"
            },
            "http-not-https": {
                "regex": r'(src|href|action)\s*=\s*["\']http://(?!localhost)',
                "severity": "MEDIUM",
                "message": "Insecure HTTP URL (use HTTPS)"
            },
            "unsafe-redirect": {
                "regex": r'window\.location\s*=\s*[^;]*(?:params|query|hash)',
                "severity": "HIGH",
                "message": "Open redirect vulnerability"
            },
            "localstorage-sensitive": {
                "regex": r'localStorage\.setItem.*password|token|secret',
                "severity": "HIGH",
                "message": "Storing sensitive data in localStorage"
            }
        }
        
        for line_num, line in enumerate(lines, 1):
            for pattern_id, pattern_data in patterns.items():
                if re.search(pattern_data["regex"], line, re.IGNORECASE):
                    findings.append({
                        "id": f"html/{pattern_id}",
                        "engine": "specialized-html",
                        "category": "Web Security",
                        "severity": pattern_data["severity"],
                        "message": pattern_data["message"],
                        "file": filename,
                        "line_start": line_num,
                        "snippet": line.strip()[:200],
                        "cwe": "CWE-79"
                    })
        
        return findings
    
    @staticmethod
    def scan_xml_config(content: str, filename: str) -> List[Dict[str, Any]]:
        """Scan XML files for XXE and configuration issues."""
        
        findings = []
        lines = content.split('\n')
        
        patterns = {
            "xxe-entity": {
                "regex": r'<!ENTITY.*SYSTEM\s*["\']',
                "severity": "CRITICAL",
                "message": "XXE (XML External Entity) attack vector detected"
            },
            "external-dtd": {
                "regex": r'<!DOCTYPE.*SYSTEM',
                "severity": "HIGH",
                "message": "External DTD reference (XXE risk)"
            },
            "hardcoded-password": {
                "regex": r'<password>([^<]{8,})</password>',
                "severity": "CRITICAL",
                "message": "Password hardcoded in XML"
            },
            "api-key-xml": {
                "regex": r'<(api_key|secret|token)>([^<]{15,})</',
                "severity": "CRITICAL",
                "message": "API key exposed in XML configuration"
            },
            "connection-string": {
                "regex": r'<connection.*password=',
                "severity": "HIGH",
                "message": "Database connection string with password in XML"
            }
        }
        
        for line_num, line in enumerate(lines, 1):
            for pattern_id, pattern_data in patterns.items():
                if re.search(pattern_data["regex"], line, re.IGNORECASE):
                    findings.append({
                        "id": f"xml/{pattern_id}",
                        "engine": "specialized-xml",
                        "category": "Configuration Security",
                        "severity": pattern_data["severity"],
                        "message": pattern_data["message"],
                        "file": filename,
                        "line_start": line_num,
                        "snippet": line.strip()[:200],
                        "cwe": "CWE-611"
                    })
        
        return findings
    
    @staticmethod
    def scan_shell_script(content: str, filename: str) -> List[Dict[str, Any]]:
        """Scan shell scripts for command injection and secrets."""
        
        findings = []
        lines = content.split('\n')
        
        patterns = {
            "unquoted-variable": {
                "regex": r'\$[A-Z_]+[^"\']',
                "severity": "HIGH",
                "message": "Unquoted variable in command (command injection risk)"
            },
            "eval-usage": {
                "regex": r'\beval\s+',
                "severity": "CRITICAL",
                "message": "eval command with user input (arbitrary code execution)"
            },
            "hardcoded-password": {
                "regex": r'(PASSWORD|PASS|SECRET)\s*=\s*["\']([^"\']{8,})',
                "severity": "CRITICAL",
                "message": "Hardcoded password in shell script"
            },
            "chmod-777": {
                "regex": r'chmod\s+(777|666)',
                "severity": "HIGH",
                "message": "Insecure file permissions (world-writable)"
            },
            "curl-pipe-bash": {
                "regex": r'curl.*\|\s*(bash|sh)',
                "severity": "CRITICAL",
                "message": "Piping curl to bash (arbitrary code execution risk)"
            },
            "rm-rf-variable": {
                "regex": r'rm\s+-rf\s+\$',
                "severity": "CRITICAL",
                "message": "rm -rf with variable (potential data destruction)"
            },
            "no-input-validation": {
                "regex": r'\$\d+(?!\s*\))',
                "severity": "MEDIUM",
                "message": "Using script arguments without validation"
            }
        }
        
        for line_num, line in enumerate(lines, 1):
            if line.strip().startswith('#'):
                continue
            
            for pattern_id, pattern_data in patterns.items():
                if re.search(pattern_data["regex"], line):
                    findings.append({
                        "id": f"shell/{pattern_id}",
                        "engine": "specialized-shell",
                        "category": "Script Security",
                        "severity": pattern_data["severity"],
                        "message": pattern_data["message"],
                        "file": filename,
                        "line_start": line_num,
                        "snippet": line.strip()[:200],
                        "cwe": "CWE-78"
                    })
        
        return findings
    
    @staticmethod
    def scan_requirements_txt(content: str, filename: str) -> List[Dict[str, Any]]:
        """Scan Python requirements.txt for vulnerable packages."""
        
        findings = []
        lines = content.split('\n')
        
        # Known vulnerable package versions (simplified - in production use vulnerability DB)
        vulnerable_packages = {
            "django": {"2.2.0": "CVE-2019-12781", "2.2.1": "CVE-2019-14234"},
            "flask": {"0.12.0": "CVE-2019-1010083", "0.12.1": "CVE-2018-1000656"},
            "requests": {"2.6.0": "CVE-2018-18074", "2.19.0": "CVE-2018-18074"},
            "pillow": {"6.0.0": "CVE-2020-5312", "7.0.0": "CVE-2020-10177"},
            "pyyaml": {"3.12": "CVE-2017-18342", "5.3": "CVE-2020-1747"},
            "jinja2": {"2.10.0": "CVE-2019-10906", "2.11.0": "CVE-2020-28493"},
            "sqlalchemy": {"1.2.0": "CVE-2019-7548"},
            "cryptography": {"2.3": "Multiple CVEs"},
            "urllib3": {"1.24.0": "CVE-2019-11324"},
            "lxml": {"4.2.0": "CVE-2018-19787"}
        }
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Parse package==version
            if '==' in line:
                parts = line.split('==')
                package_name = parts[0].strip().lower()
                version = parts[1].strip() if len(parts) > 1 else ""
                
                if package_name in vulnerable_packages:
                    if version in vulnerable_packages[package_name] or not version:
                        cve = vulnerable_packages[package_name].get(version, "Known vulnerabilities")
                        findings.append({
                            "id": f"pypi/{package_name}",
                            "engine": "specialized-pypi",
                            "category": "SCA",
                            "severity": "HIGH",
                            "message": f"Vulnerable package: {package_name}=={version} ({cve})",
                            "file": filename,
                            "line_start": line_num,
                            "snippet": line,
                            "package": package_name,
                            "installed_version": version,
                            "cve": cve
                        })
        
        return findings
    
    @staticmethod
    def scan_package_json(content: str, filename: str) -> List[Dict[str, Any]]:
        """Scan package.json for vulnerable npm packages."""
        
        findings = []
        
        vulnerable_npm = {
            "express": {"4.16.0": "CVE-2019-7609"},
            "lodash": {"4.17.4": "CVE-2019-10744"},
            "axios": {"0.18.0": "CVE-2019-10742"},
            "moment": {"2.19.0": "CVE-2022-24785"},
            "jsonwebtoken": {"8.1.0": "CVE-2022-23529"},
            "mongoose": {"5.0.0": "CVE-2019-17426"},
            "ws": {"6.0.0": "CVE-2021-32640"}
        }
        
        try:
            import json
            data = json.loads(content)
            
            for dep_type in ['dependencies', 'devDependencies']:
                if dep_type in data:
                    for package, version in data[dep_type].items():
                        # Clean version (remove ^ ~ etc)
                        clean_version = version.replace('^', '').replace('~', '').replace('>=', '').replace('<=', '')
                        
                        if package in vulnerable_npm:
                            if clean_version in vulnerable_npm[package]:
                                cve = vulnerable_npm[package][clean_version]
                                findings.append({
                                    "id": f"npm/{package}",
                                    "engine": "specialized-npm",
                                    "category": "SCA",
                                    "severity": "HIGH",
                                    "message": f"Vulnerable npm package: {package}@{clean_version} ({cve})",
                                    "file": filename,
                                    "line_start": 0,
                                    "package": package,
                                    "installed_version": clean_version,
                                    "cve": cve
                                })
        except:
            pass
        
        return findings
    
    @staticmethod
    def scan_dockerfile(content: str, filename: str) -> List[Dict[str, Any]]:
        """Scan Dockerfiles for security issues."""
        
        findings = []
        lines = content.split('\n')
        
        patterns = {
            "run-as-root": {
                "regex": r'^USER\s+root',
                "severity": "HIGH",
                "message": "Container runs as root user"
            },
            "latest-tag": {
                "regex": r'FROM.*:latest',
                "severity": "MEDIUM",
                "message": "Using 'latest' tag (non-deterministic builds)"
            },
            "exposed-secret": {
                "regex": r'(ENV|ARG)\s+.*(?:PASSWORD|SECRET|KEY|TOKEN)\s*=',
                "severity": "CRITICAL",
                "message": "Secret exposed in Dockerfile ENV/ARG"
            },
            "curl-pipe": {
                "regex": r'curl.*\|.*bash',
                "severity": "HIGH",
                "message": "Piping curl to bash in Dockerfile"
            },
            "no-health-check": {
                "regex": r'FROM',
                "severity": "LOW",
                "message": "No HEALTHCHECK instruction (missing health monitoring)"
            }
        }
        
        for line_num, line in enumerate(lines, 1):
            for pattern_id, pattern_data in patterns.items():
                if re.search(pattern_data["regex"], line, re.IGNORECASE):
                    findings.append({
                        "id": f"dockerfile/{pattern_id}",
                        "engine": "specialized-docker",
                        "category": "Container Security",
                        "severity": pattern_data["severity"],
                        "message": pattern_data["message"],
                        "file": filename,
                        "line_start": line_num,
                        "snippet": line.strip()
                    })
        
        return findings
    
    @staticmethod
    def scan_file_by_type(file_path: str, content: str) -> List[Dict[str, Any]]:
        """Route to appropriate specialized scanner based on file type."""
        
        filename = Path(file_path).name
        ext = Path(file_path).suffix.lower()
        
        specialized_findings = []
        
        # Route to specialized scanners
        if ext == '.json' or 'config.json' in filename.lower():
            specialized_findings.extend(SpecializedScanner.scan_json_config(content, filename))
        
        if ext in ['.yaml', '.yml'] or 'k8s' in filename.lower() or 'docker-compose' in filename.lower():
            specialized_findings.extend(SpecializedScanner.scan_yaml_k8s(content, filename))
        
        if ext == '.env' or filename == '.env':
            specialized_findings.extend(SpecializedScanner.scan_env_file(content, filename))
        
        if ext in ['.html', '.htm']:
            specialized_findings.extend(SpecializedScanner.scan_html_web(content, filename))
        
        if ext == '.xml':
            specialized_findings.extend(SpecializedScanner.scan_xml_config(content, filename))
        
        if ext == '.sh' or filename.endswith('.bash'):
            specialized_findings.extend(SpecializedScanner.scan_shell_script(content, filename))
        
        if filename == 'requirements.txt':
            specialized_findings.extend(SpecializedScanner.scan_requirements_txt(content, filename))
        
        if filename == 'package.json':
            specialized_findings.extend(SpecializedScanner.scan_package_json(content, filename))
        
        if filename.lower() == 'dockerfile' or ext == '.dockerfile':
            specialized_findings.extend(SpecializedScanner.scan_dockerfile(content, filename))
        
        return specialized_findings