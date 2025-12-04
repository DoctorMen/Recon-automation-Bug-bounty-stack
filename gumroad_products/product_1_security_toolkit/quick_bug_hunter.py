#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
CASCADE IDE™ - Quick Bug Hunter
Test all 9 accessible crypto bug bounty programs
Find vulnerabilities in minutes!
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'scripts'))

from crypto_vulnerability_scanner import CryptoVulnerabilityScanner
import requests
import json
from datetime import datetime

def test_target(program_name, program_info):
    """Test a single bug bounty target"""
    print(f"\n{'='*70}")
    print(f" Testing: {program_name.upper()}")
    print(f" Max Bounty: {program_info['max_reward']}")
    print(f" Platform: {program_info['platform']}")
    print(f"{'='*70}")
    
    findings = []
    
    # Test each domain
    for domain in program_info['domains'][:2]:  # Test first 2 domains
        if domain.startswith('*.'):
            # Test subdomain
            test_domain = f"api.{domain[2:]}"
        else:
            test_domain = domain
        
        # Test common endpoints
        endpoints = [
            f"https://{test_domain}",
            f"https://{test_domain}/api",
            f"https://{test_domain}/api/v1",
            f"https://{test_domain}/api/v2",
            f"https://{test_domain}/graphql",
        ]
        
        for url in endpoints:
            try:
                print(f"\n[*] Testing: {url}")
                response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
                
                print(f"    Status: {response.status_code}")
                
                if response.status_code == 200:
                    print(f"    [✓] Accessible!")
                    
                    # Create finding for scanners
                    finding = {
                        'matched-at': url,
                        'host': test_domain,
                        'response': response.text[:5000],  # First 5KB
                        'request': '',
                        'info': {
                            'name': f'{program_name} endpoint',
                            'description': f'Testing {url}'
                        }
                    }
                    
                    # Run crypto vulnerability scanner
                    print(f"    [*] Scanning for vulnerabilities...")
                    vulns = CryptoVulnerabilityScanner.scan_finding(finding)
                    
                    if vulns:
                        print(f"    [!] FOUND {len(vulns)} VULNERABILITIES!")
                        for v in vulns:
                            print(f"        - {v['type']}: {v['severity']} (${v.get('bounty_estimate', 'N/A')})")
                        findings.extend(vulns)
                    else:
                        print(f"    [✓] No obvious vulnerabilities")
                    
                    # Check for common issues
                    headers = response.headers
                    
                    # Check 1: Server header exposure
                    if 'Server' in headers:
                        print(f"    [!] Server header exposed: {headers['Server']}")
                        findings.append({
                            'type': 'information_disclosure',
                            'severity': 'low',
                            'description': f"Server header exposed: {headers['Server']}",
                            'url': url,
                            'bounty_estimate': '$100-$500'
                        })
                    
                    # Check 2: Missing security headers
                    security_headers = [
                        'Strict-Transport-Security',
                        'X-Frame-Options',
                        'X-Content-Type-Options',
                        'Content-Security-Policy'
                    ]
                    
                    missing = [h for h in security_headers if h not in headers]
                    if missing:
                        print(f"    [!] Missing security headers: {', '.join(missing)}")
                        findings.append({
                            'type': 'missing_security_headers',
                            'severity': 'low',
                            'description': f"Missing headers: {', '.join(missing)}",
                            'url': url,
                            'bounty_estimate': '$200-$1,000'
                        })
                    
                    # Check 3: HTTP instead of HTTPS
                    if url.startswith('http://'):
                        print(f"    [!] HTTP endpoint (no encryption)")
                        findings.append({
                            'type': 'no_encryption',
                            'severity': 'medium',
                            'description': 'HTTP endpoint without encryption',
                            'url': url,
                            'bounty_estimate': '$500-$2,000'
                        })
                    
                elif response.status_code == 401:
                    print(f"    [*] Requires authentication (good security)")
                elif response.status_code == 403:
                    print(f"    [*] Forbidden (possible WAF/protection)")
                elif response.status_code == 404:
                    print(f"    [-] Not found")
                else:
                    print(f"    [?] Status {response.status_code}")
                    
            except requests.exceptions.Timeout:
                print(f"    [!] Timeout")
            except requests.exceptions.SSLError:
                print(f"    [!] SSL Error - possible certificate issue")
                findings.append({
                    'type': 'ssl_issue',
                    'severity': 'medium',
                    'description': 'SSL/TLS certificate problem',
                    'url': url,
                    'bounty_estimate': '$500-$3,000'
                })
            except Exception as e:
                print(f"    [!] Error: {str(e)[:50]}")
    
    return findings


def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║         CASCADE IDE - QUICK BUG HUNTER                       ║
║         Testing 9 Crypto Bug Bounty Programs                 ║
║                                                              ║
║         Total Bounty Potential: $5,000,000+                  ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    programs = CryptoVulnerabilityScanner.CRYPTO_PROGRAM_SCOPES
    
    all_findings = {}
    total_vulns = 0
    
    # Test each program
    for program_name, program_info in programs.items():
        if program_info.get('beginner_friendly'):
            findings = test_target(program_name, program_info)
            
            if findings:
                all_findings[program_name] = findings
                total_vulns += len(findings)
    
    # Generate report
    print("\n" + "="*70)
    print(" QUICK SCAN RESULTS")
    print("="*70)
    
    print(f"\n[*] Programs Tested: {len(programs)}")
    print(f"[*] Total Vulnerabilities Found: {total_vulns}")
    
    if total_vulns > 0:
        print("\n" + "="*70)
        print(" VULNERABILITIES BY PROGRAM")
        print("="*70)
        
        for program, findings in all_findings.items():
            if findings:
                print(f"\n{program.upper()}: {len(findings)} findings")
                for i, finding in enumerate(findings, 1):
                    print(f"  #{i}: {finding['type']} - {finding['severity'].upper()}")
                    print(f"      Bounty: {finding.get('bounty_estimate', 'N/A')}")
                    print(f"      URL: {finding.get('url', 'N/A')}")
    
    # Save report
    report = {
        'scan_date': datetime.now().isoformat(),
        'programs_tested': len(programs),
        'total_vulnerabilities': total_vulns,
        'findings': all_findings
    }
    
    output_file = f"output/quick_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    os.makedirs('output', exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n[✓] Full report saved: {output_file}")
    
    print("\n" + "="*70)
    print(" NEXT STEPS")
    print("="*70)
    print("\n1. Review findings above")
    print("2. Verify each vulnerability manually")
    print("3. Prepare proof of concept")
    print("4. Submit to respective bug bounty program")
    print("\n[*] Good hunting! 🎯")


if __name__ == '__main__':
    main()
