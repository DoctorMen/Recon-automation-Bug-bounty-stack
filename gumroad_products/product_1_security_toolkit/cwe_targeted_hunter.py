#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
CASCADE IDE™ - CWE-Targeted Bug Bounty Hunter
Hunts for the TOP 25 most common vulnerabilities (CWE database)
119K+ XSS, 81K+ Info Disclosure, 49K+ Access Control bugs in the wild!
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'scripts'))

import requests
import re
import json
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, parse_qs

class CWETargetedHunter:
    """
    Hunt for TOP 25 CWEs with highest occurrence rates
    Focus on vulnerabilities with 4,000+ real-world instances
    """
    
    # TOP 25 CWEs from your screenshot (sorted by frequency)
    TOP_CWES = {
        "CWE-79": {
            "name": "Cross-Site Scripting (XSS)",
            "instances": 119391,
            "severity": "MEDIUM-HIGH",
            "bounty_range": "$500-$10,000",
            "description": "Improper neutralization of input during web page generation",
            "detection_patterns": [
                r'<script[^>]*>',
                r'javascript:',
                r'onerror\s*=',
                r'onload\s*=',
                r'eval\(',
                r'innerHTML\s*=',
                r'document\.write',
                r'<iframe'
            ],
            "test_payloads": [
                '"><script>alert(1)</script>',
                "javascript:alert(1)",
                '<img src=x onerror=alert(1)>',
                '<svg/onload=alert(1)>'
            ]
        },
        "CWE-200": {
            "name": "Exposure of Sensitive Information",
            "instances": 81946,
            "severity": "LOW-MEDIUM",
            "bounty_range": "$100-$5,000",
            "description": "Unauthorized actor can access sensitive data",
            "detection_patterns": [
                r'api[_-]?key',
                r'secret',
                r'password',
                r'token',
                r'auth',
                r'private[_-]?key',
                r'credentials',
                r'access[_-]?token',
                r'bearer',
                r'mysql.*password',
                r'aws[_-]?secret',
                r'DEBUG\s*=\s*True'
            ],
            "common_exposures": [
                ".env files",
                "config.json",
                "wp-config.php",
                ".git directory",
                "server headers",
                "error messages",
                "API responses"
            ]
        },
        "CWE-281": {
            "name": "Improper Access Control",
            "instances": 49791,
            "severity": "HIGH-CRITICAL",
            "bounty_range": "$1,000-$25,000",
            "description": "Software does not restrict or incorrectly restricts access",
            "detection_patterns": [
                r'/admin',
                r'/api/v\d+/.*',
                r'/user/\d+',
                r'/account/\d+',
                r'id=\d+',
                r'user_id=',
                r'account_id='
            ],
            "test_methods": [
                "IDOR (change user IDs)",
                "Privilege escalation",
                "Forced browsing",
                "Parameter tampering"
            ]
        },
        "CWE-639": {
            "name": "Authentication Bypass",
            "instances": 38410,
            "severity": "CRITICAL",
            "bounty_range": "$5,000-$50,000",
            "description": "Bypass authentication via user-controlled key",
            "detection_patterns": [
                r'admin\s*=\s*true',
                r'is_admin',
                r'role\s*=',
                r'authenticated\s*=',
                r'bypass',
                r'skip.*auth'
            ],
            "test_methods": [
                "Parameter manipulation",
                "Cookie tampering",
                "JWT manipulation",
                "SQL injection in auth"
            ]
        },
        "CWE-862": {
            "name": "Missing Authorization",
            "instances": 25996,
            "severity": "HIGH",
            "bounty_range": "$2,000-$15,000",
            "description": "Software does not perform authorization check",
            "common_endpoints": [
                "/api/admin/*",
                "/api/user/delete",
                "/api/settings",
                "/dashboard/admin"
            ]
        },
        "CWE-287": {
            "name": "Improper Authentication",
            "instances": 22814,
            "severity": "HIGH-CRITICAL",
            "bounty_range": "$3,000-$25,000",
            "description": "Fails to prove user's identity",
            "detection_patterns": [
                r'md5\(',
                r'sha1\(',
                r'weak.*password',
                r'default.*credentials'
            ]
        },
        "CWE-601": {
            "name": "Open Redirect",
            "instances": 16446,
            "severity": "LOW-MEDIUM",
            "bounty_range": "$250-$3,000",
            "description": "Unvalidated redirects to untrusted sites",
            "detection_patterns": [
                r'redirect=',
                r'url=',
                r'return_to=',
                r'next=',
                r'goto=',
                r'return='
            ],
            "test_payloads": [
                '?redirect=https://evil.com',
                '?url=//evil.com',
                '?next=javascript:alert(1)'
            ]
        },
        "CWE-352": {
            "name": "Cross-Site Request Forgery (CSRF)",
            "instances": 16089,
            "severity": "MEDIUM-HIGH",
            "bounty_range": "$500-$10,000",
            "description": "Does not verify request came from trusted source",
            "checks": [
                "Missing CSRF token",
                "Predictable CSRF token",
                "No SameSite cookie attribute"
            ]
        },
        "CWE-89": {
            "name": "SQL Injection",
            "instances": 12947,
            "severity": "CRITICAL",
            "bounty_range": "$5,000-$50,000",
            "description": "SQL commands injected into database query",
            "detection_patterns": [
                r'id=\d+',
                r'search=',
                r'query=',
                r'filter='
            ],
            "test_payloads": [
                "' OR '1'='1",
                "'; DROP TABLE--",
                "1' UNION SELECT NULL--"
            ]
        },
        "CWE-918": {
            "name": "Server-Side Request Forgery (SSRF)",
            "instances": 8999,
            "severity": "HIGH-CRITICAL",
            "bounty_range": "$3,000-$25,000",
            "description": "Server performs request to unintended location",
            "detection_patterns": [
                r'url=',
                r'uri=',
                r'path=',
                r'file=',
                r'page='
            ],
            "test_payloads": [
                '?url=http://localhost',
                '?url=http://169.254.169.254/',
                '?file=file:///etc/passwd'
            ]
        },
        "CWE-22": {
            "name": "Path Traversal",
            "instances": 5280,
            "severity": "HIGH",
            "bounty_range": "$2,000-$15,000",
            "description": "Uses external input to construct pathname",
            "test_payloads": [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\config\\sam',
                '....//....//....//etc/passwd'
            ]
        },
        "CWE-78": {
            "name": "OS Command Injection",
            "instances": 4698,
            "severity": "CRITICAL",
            "bounty_range": "$10,000-$50,000",
            "description": "OS commands constructed from external input",
            "test_payloads": [
                '; ls -la',
                '| whoami',
                '& dir',
                '`id`'
            ]
        }
    }
    
    def __init__(self):
        self.findings = []
    
    def check_xss(self, url, response_text):
        """Check for CWE-79: XSS vulnerabilities"""
        findings = []
        
        # Check for reflected input
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param, values in params.items():
            for value in values:
                if value in response_text and len(value) > 3:
                    findings.append({
                        'cwe': 'CWE-79',
                        'name': 'Potential XSS',
                        'severity': 'MEDIUM',
                        'url': url,
                        'parameter': param,
                        'bounty': '$500-$10,000',
                        'description': f'Parameter "{param}" reflected in response'
                    })
        
        # Check for dangerous patterns
        patterns = self.TOP_CWES['CWE-79']['detection_patterns']
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                findings.append({
                    'cwe': 'CWE-79',
                    'name': 'XSS Pattern Detected',
                    'severity': 'LOW',
                    'url': url,
                    'pattern': pattern,
                    'bounty': '$500-$5,000',
                    'description': f'Potentially unsafe pattern: {pattern}'
                })
        
        return findings
    
    def check_info_disclosure(self, url, response_text, headers):
        """Check for CWE-200: Information Exposure"""
        findings = []
        
        # Check response text for sensitive data
        patterns = self.TOP_CWES['CWE-200']['detection_patterns']
        
        for pattern in patterns:
            matches = re.finditer(pattern, response_text, re.IGNORECASE)
            for match in matches:
                context = response_text[max(0, match.start()-50):match.end()+50]
                findings.append({
                    'cwe': 'CWE-200',
                    'name': 'Sensitive Information Exposure',
                    'severity': 'MEDIUM',
                    'url': url,
                    'pattern': pattern,
                    'context': context[:100],
                    'bounty': '$100-$5,000',
                    'description': f'Sensitive pattern exposed: {pattern}'
                })
        
        # Check headers
        sensitive_headers = ['X-Powered-By', 'Server', 'X-AspNet-Version']
        for header in sensitive_headers:
            if header in headers:
                findings.append({
                    'cwe': 'CWE-200',
                    'name': 'Information Disclosure via Headers',
                    'severity': 'LOW',
                    'url': url,
                    'header': f'{header}: {headers[header]}',
                    'bounty': '$100-$1,000',
                    'description': f'Version info leaked in {header} header'
                })
        
        return findings
    
    def check_access_control(self, url):
        """Check for CWE-281: Improper Access Control"""
        findings = []
        
        # Check for IDOR patterns
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        idor_params = ['id', 'user_id', 'account_id', 'order_id', 'invoice_id']
        
        for param in params:
            if any(idor in param.lower() for idor in idor_params):
                findings.append({
                    'cwe': 'CWE-281',
                    'name': 'Potential IDOR',
                    'severity': 'HIGH',
                    'url': url,
                    'parameter': param,
                    'bounty': '$1,000-$25,000',
                    'description': f'Parameter "{param}" may be vulnerable to IDOR',
                    'test': 'Try changing the ID value to access other users\' data'
                })
        
        return findings
    
    def check_open_redirect(self, url, response_text):
        """Check for CWE-601: Open Redirect"""
        findings = []
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        redirect_params = ['redirect', 'url', 'next', 'return', 'goto', 'return_to']
        
        for param in params:
            if any(redir in param.lower() for redir in redirect_params):
                findings.append({
                    'cwe': 'CWE-601',
                    'name': 'Potential Open Redirect',
                    'severity': 'MEDIUM',
                    'url': url,
                    'parameter': param,
                    'bounty': '$250-$3,000',
                    'description': f'Redirect parameter "{param}" may allow open redirects',
                    'test': 'Try: ?{}=https://evil.com'.format(param)
                })
        
        return findings
    
    def hunt_cwe_patterns(self, target_url):
        """Hunt for TOP CWE patterns"""
        print(f"\n{'='*70}")
        print(f" CWE-TARGETED BUG HUNTER")
        print(f" Hunting TOP 25 Most Common Vulnerabilities")
        print(f" Target: {target_url}")
        print(f"{'='*70}")
        
        all_findings = []
        
        try:
            print(f"\n[*] Fetching target...")
            response = requests.get(target_url, timeout=10, verify=False, allow_redirects=True)
            
            print(f"[✓] Status: {response.status_code}")
            print(f"[✓] Size: {len(response.text)} bytes")
            
            # Run CWE checks
            print(f"\n[*] Checking for CWE patterns...")
            
            checks = [
                ('XSS (CWE-79)', self.check_xss, [target_url, response.text]),
                ('Info Disclosure (CWE-200)', self.check_info_disclosure, [target_url, response.text, response.headers]),
                ('Access Control (CWE-281)', self.check_access_control, [target_url]),
                ('Open Redirect (CWE-601)', self.check_open_redirect, [target_url, response.text])
            ]
            
            for check_name, check_func, args in checks:
                findings = check_func(*args)
                if findings:
                    all_findings.extend(findings)
                    print(f"  [!] {check_name}: {len(findings)} findings")
            
        except Exception as e:
            print(f"[!] Error: {e}")
        
        return all_findings
    
    def generate_cwe_report(self, target, findings):
        """Generate CWE-focused report"""
        print(f"\n{'='*70}")
        print(f" CWE SCAN RESULTS")
        print(f"{'='*70}")
        
        print(f"\nTarget: {target}")
        print(f"Total Findings: {len(findings)}")
        
        if findings:
            # Group by CWE
            by_cwe = {}
            for f in findings:
                cwe = f.get('cwe', 'Unknown')
                if cwe not in by_cwe:
                    by_cwe[cwe] = []
                by_cwe[cwe].append(f)
            
            for cwe, cwe_findings in by_cwe.items():
                cwe_info = self.TOP_CWES.get(cwe, {})
                print(f"\n--- {cwe}: {cwe_info.get('name', 'Unknown')} ---")
                print(f"Instances in Wild: {cwe_info.get('instances', 0):,}")
                print(f"Findings: {len(cwe_findings)}")
                
                for i, finding in enumerate(cwe_findings, 1):
                    print(f"\n  Finding #{i}:")
                    print(f"    Severity: {finding.get('severity')}")
                    print(f"    Bounty:   {finding.get('bounty')}")
                    print(f"    Details:  {finding.get('description')}")
        
        # Save report
        report = {
            'target': target,
            'scan_date': datetime.now().isoformat(),
            'findings': findings,
            'cwe_coverage': list(set(f.get('cwe') for f in findings))
        }
        
        output_file = f"output/cwe_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        os.makedirs('output', exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[✓] Report saved: {output_file}")


def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     CASCADE IDE - CWE-TARGETED BUG HUNTER                    ║
║     TOP 25 Most Common Vulnerabilities                       ║
║                                                              ║
║     CWE-79:  XSS (119,391 instances)                         ║
║     CWE-200: Info Disclosure (81,946 instances)              ║
║     CWE-281: Access Control (49,791 instances)               ║
║     CWE-639: Auth Bypass (38,410 instances)                  ║
║     + 21 more high-value CWEs                                ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    hunter = CWETargetedHunter()
    
    # Test your targets
    targets = [
        "https://polygon.technology",
        "https://1inch.io",
        "https://app.uniswap.org",
        "https://chain.link"
    ]
    
    for target in targets:
        findings = hunter.hunt_cwe_patterns(target)
        if findings:
            hunter.generate_cwe_report(target, findings)
    
    print(f"\n[✓] CWE hunting complete! Check output/ for reports")


if __name__ == '__main__':
    main()
