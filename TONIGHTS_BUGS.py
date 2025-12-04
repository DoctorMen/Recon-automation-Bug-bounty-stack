#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.

TONIGHT'S BUGS - Quick Manual Bug Finding System
Legal, authorized, immediate results for bug bounty programs.
"""

import requests
import re
import json
from datetime import datetime
from pathlib import Path

class TonightsBugs:
    """Find real bugs tonight on authorized programs"""
    
    def __init__(self):
        self.base_path = Path(__file__).parent
        
        # Top targets with active programs
        self.targets = {
            'shopify.com': {
                'program': 'hackerone',
                'min_payout': 500,
                'scope': ['*.shopify.com', 'shopify.com'],
                'submission': 'https://hackerone.com/shopify/reports/new'
            },
            'mozilla.org': {
                'program': 'hackerone', 
                'min_payout': 500,
                'scope': ['*.mozilla.org', 'mozilla.org'],
                'submission': 'https://hackerone.com/mozilla/reports/new'
            },
            'atlassian.com': {
                'program': 'bugcrowd',
                'min_payout': 500,
                'scope': ['*.atlassian.com', 'atlassian.com'],
                'submission': 'https://bugcrowd.com/atlassian/report'
            }
        }
    
    def check_subdomain_takeover(self, domain):
        """Check for subdomain takeover vulnerabilities"""
        print(f"\n[*] Checking {domain} for subdomain takeover...")
        
        # Common CNAME patterns that indicate takeover
        takeover_signatures = [
            'github.io',
            'herokuapp.com', 
            's3.amazonaws.com',
            'cloudapp.net',
            'azurewebsites.net'
        ]
        
        try:
            # Try to resolve the domain
            import subprocess
            result = subprocess.run(['nslookup', domain], capture_output=True, text=True, timeout=10)
            
            for sig in takeover_signatures:
                if sig in result.stdout:
                    print(f"[+] Potential takeover found: {domain} -> {sig}")
                    
                    # Verify by checking response
                    try:
                        response = requests.get(f"https://{domain}", timeout=10)
                        if "NoSuchBucket" in response.text or "Repository not found" in response.text:
                            print(f"[!] CONFIRMED: Subdomain takeover possible on {domain}")
                            return {
                                'type': 'subdomain-takeover',
                                'url': f"https://{domain}",
                                'severity': 'high',
                                'payout': '500-2000',
                                'proof': f"Points to {sig} but returns 404/Not found"
                            }
                    except:
                        pass
                        
        except Exception as e:
            pass
            
        return None
    
    def check_open_redirect(self, domain):
        """Check for open redirect vulnerabilities"""
        print(f"\n[*] Checking {domain} for open redirects...")
        
        # Common redirect parameters
        redirect_params = ['url', 'redirect', 'return', 'return_to', 'goto', 'next']
        
        for param in redirect_params:
            test_url = f"https://{domain}/?{param}=https://evil.com"
            
            try:
                response = requests.get(test_url, timeout=10, allow_redirects=False)
                
                # Check if it redirects to evil.com
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if 'evil.com' in location:
                        print(f"[!] CONFIRMED: Open redirect on {domain}")
                        return {
                            'type': 'open-redirect',
                            'url': test_url,
                            'severity': 'medium',
                            'payout': '100-500',
                            'proof': f"Redirects to: {location}"
                        }
                        
            except Exception as e:
                pass
                
        return None
    
    def check_exposed_panel(self, domain):
        """Check for exposed admin/login panels"""
        print(f"\n[*] Checking {domain} for exposed panels...")
        
        common_paths = [
            '/admin',
            '/login',
            '/wp-admin',
            '/admin.php',
            '/administrator',
            '/panel',
            '/dashboard'
        ]
        
        for path in common_paths:
            url = f"https://{domain}{path}"
            
            try:
                response = requests.get(url, timeout=10)
                
                if response.status_code == 200:
                    # Check if it's actually a login/admin panel
                    if any(keyword in response.text.lower() for keyword in ['password', 'username', 'login', 'admin']):
                        print(f"[!] Potential exposed panel: {url}")
                        
                        # Check for default credentials
                        if 'admin' in response.text and 'password' in response.text:
                            return {
                                'type': 'exposed-panel',
                                'url': url,
                                'severity': 'medium',
                                'payout': '250-1000',
                                'proof': f"Accessible admin panel at {url}"
                            }
                            
            except Exception as e:
                pass
                
        return None
    
    def hunt_target(self, domain):
        """Hunt for bugs on a specific target"""
        print(f"\n{'='*60}")
        print(f"TARGET: {domain}")
        print(f"PROGRAM: {self.targets[domain]['program']}")
        print(f"MIN PAYOUT: ${self.targets[domain]['min_payout']}")
        print(f"{'='*60}")
        
        findings = []
        
        # Check different vulnerability types
        print("\n--- Subdomain Takeover Check ---")
        takeover = self.check_subdomain_takeover(f"api.{domain}")
        if takeover:
            findings.append(takeover)
            
        print("\n--- Open Redirect Check ---")
        redirect = self.check_open_redirect(domain)
        if redirect:
            findings.append(redirect)
            
        print("\n--- Exposed Panel Check ---")
        panel = self.check_exposed_panel(domain)
        if panel:
            findings.append(panel)
        
        return findings
    
    def generate_report(self, domain, finding):
        """Generate submission-ready report"""
        report = f"""
## Summary
{finding['type']} vulnerability found on {domain}

## Vulnerability Details
**Type:** {finding['type']}
**Severity:** {finding['severity']}
**Asset:** {finding['url']}

## Steps to Reproduce
1. Navigate to {finding['url']}
2. Observe the vulnerability

## Proof of Concept
URL: {finding['url']}
Evidence: {finding['proof']}

## Impact
This vulnerability could allow attackers to [describe impact based on type]

## Recommended Fix
[Provide brief fix recommendation]

## Discovery Date
{datetime.now().strftime('%YY%m-%d')}

---
Submitted via: Recon Automation Bug Bounty Stack
Copyright © 2025 DoctorMen. All Rights Reserved.
        """
        return report.strip()
    
    def run(self):
        """Execute tonight's bug hunt"""
        print("""
==================================================
              TONIGHT'S BUGS
         Quick Manual Bug Finding
         Legal & Authorized Only
==================================================
        """)
        
        all_findings = {}
        
        for domain in self.targets:
            findings = self.hunt_target(domain)
            if findings:
                all_findings[domain] = findings
                
        print("\n" + "="*70)
        print("HUNT COMPLETE - RESULTS SUMMARY")
        print("="*70)
        
        if all_findings:
            print(f"\nFound potential vulnerabilities on {len(all_findings)} targets:")
            
            for domain, findings in all_findings.items():
                print(f"\n{domain}:")
                for i, finding in enumerate(findings, 1):
                    print(f"  {i}. {finding['type']} - ${finding['payout']} - {finding['severity']}")
                    print(f"     URL: {finding['url']}")
                    
                    # Generate report
                    report = self.generate_report(domain, finding)
                    
                    # Save report
                    report_file = self.base_path / f"report_{domain}_{finding['type'].replace('-', '_')}.md"
                    with open(report_file, 'w') as f:
                        f.write(report)
                    
                    print(f"     Report saved: {report_file}")
                    print(f"     Submit at: {self.targets[domain]['submission']}")
                    
            print(f"\nExpected payout: ${sum([int(f['payout'].split('-')[0]) for findings in all_findings.values() for f in findings])}-${sum([int(f['payout'].split('-')[1]) for findings in all_findings.values() for f in findings])}")
            
        else:
            print("\nNo obvious vulnerabilities found.")
            print("Try manual testing:")
            print("1. Check API endpoints for authentication issues")
            print("2. Look for information disclosure")
            print("3. Test for CORS misconfiguration")
            print("4. Review JavaScript files for secrets")

def main():
    """Run tonight's bug hunt"""
    hunter = TonightsBugs()
    hunter.run()

if __name__ == '__main__':
    main()
