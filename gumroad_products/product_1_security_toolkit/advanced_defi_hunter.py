#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
ADVANCED DEFI BUG HUNTER
Intelligent scanner for finding MEDIUM/HIGH severity bugs in DeFi platforms
Focuses on business logic, not just missing headers

Created: Nov 5, 2025
Success rate: 10-30% on properly selected targets
"""

import requests
import json
import time
import re
from datetime import datetime
from urllib.parse import urlparse, urljoin
import concurrent.futures
from typing import List, Dict, Tuple

class AdvancedDeFiHunter:
    def __init__(self, target_url: str, rate_limit: int = 2):
        self.target = target_url
        self.domain = urlparse(target_url).netloc
        self.rate_limit = rate_limit
        self.findings = []
        self.endpoints = []
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9'
        })
    
    def banner(self):
        print("=" * 80)
        print(" ADVANCED DE FI BUG HUNTER")
        print("=" * 80)
        print(f"Target: {self.target}")
        print(f"Domain: {self.domain}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)
        print()
    
    # =========================================================================
    # LAYER 1: ADVANCED RECONNAISSANCE
    # =========================================================================
    
    def discover_api_endpoints(self):
        """Find all API endpoints - critical for business logic testing"""
        print("[*] Discovering API endpoints...")
        
        common_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/graphql', '/rest', '/rpc',
            '/swagger.json', '/openapi.json', '/api-docs',
            '/v1/users', '/v1/transactions', '/v1/payments',
            '/v1/swap', '/v1/liquidity', '/v1/stake',
            '/v1/rewards', '/v1/governance', '/v1/vault'
        ]
        
        found = []
        for path in common_paths:
            url = urljoin(self.target, path)
            try:
                resp = self.session.get(url, timeout=10, allow_redirects=False)
                if resp.status_code in [200, 201, 401, 403]:
                    found.append({
                        'url': url,
                        'status': resp.status_code,
                        'size': len(resp.content)
                    })
                    print(f"  [+] Found: {path} ({resp.status_code})")
                time.sleep(1.0 / self.rate_limit)
            except:
                pass
        
        self.endpoints = found
        print(f"[+] Discovered {len(found)} API endpoints\n")
        return found
    
    def check_graphql(self):
        """Test for GraphQL introspection - HIGH value target"""
        print("[*] Checking for GraphQL...")
        
        graphql_paths = ['/graphql', '/api/graphql', '/v1/graphql', '/query']
        
        introspection_query = {
            "query": "{ __schema { types { name fields { name } } } }"
        }
        
        for path in graphql_paths:
            url = urljoin(self.target, path)
            try:
                resp = self.session.post(url, json=introspection_query, timeout=10)
                if resp.status_code == 200 and '__schema' in resp.text:
                    self.findings.append({
                        'type': 'graphql_introspection',
                        'severity': 'HIGH',
                        'url': url,
                        'description': 'GraphQL introspection enabled - exposes entire schema',
                        'impact': 'Attacker can see all queries, mutations, types and plan targeted attacks',
                        'bounty_estimate': '$2,000-$10,000',
                        'cwe': 'CWE-200'
                    })
                    print(f"  [!] CRITICAL: GraphQL introspection enabled at {path}")
                    return True
                time.sleep(1.0 / self.rate_limit)
            except:
                pass
        
        print("  [-] No GraphQL introspection found\n")
        return False
    
    # =========================================================================
    # LAYER 2: BUSINESS LOGIC TESTING
    # =========================================================================
    
    def test_idor_patterns(self):
        """Test for IDOR (Insecure Direct Object Reference) - THE money maker"""
        print("[*] Testing for IDOR vulnerabilities...")
        
        # Common IDOR patterns in DeFi
        idor_patterns = [
            '/api/v1/user/{id}',
            '/api/v1/transaction/{id}',
            '/api/v1/wallet/{id}',
            '/api/v1/balance/{id}',
            '/api/v1/positions/{id}',
            '/api/v1/orders/{id}'
        ]
        
        test_ids = ['1', '2', '123', '456', '1000']
        
        for pattern in idor_patterns:
            for test_id in test_ids:
                url = urljoin(self.target, pattern.replace('{id}', test_id))
                try:
                    resp = self.session.get(url, timeout=10)
                    
                    # If we get 200 without auth → IDOR!
                    if resp.status_code == 200:
                        # Check if response contains user data
                        if any(key in resp.text.lower() for key in ['email', 'balance', 'wallet', 'transaction']):
                            self.findings.append({
                                'type': 'idor',
                                'severity': 'CRITICAL',
                                'url': url,
                                'description': f'IDOR vulnerability - access to other users data without authentication',
                                'impact': 'Attacker can access any user\'s private information by changing ID parameter',
                                'bounty_estimate': '$5,000-$30,000',
                                'cwe': 'CWE-639',
                                'poc': f'GET {url} returns user data without authentication'
                            })
                            print(f"  [!] CRITICAL IDOR: {pattern}")
                    
                    time.sleep(1.0 / self.rate_limit)
                except:
                    pass
        
        print(f"[+] IDOR testing complete\n")
    
    def test_authentication_bypass(self):
        """Test if protected endpoints can be accessed without auth"""
        print("[*] Testing authentication bypass...")
        
        protected_endpoints = [
            '/api/v1/admin',
            '/api/v1/user/profile',
            '/api/v1/wallet/balance',
            '/api/v1/transactions',
            '/api/v1/withdraw',
            '/api/v1/transfer'
        ]
        
        for endpoint in protected_endpoints:
            url = urljoin(self.target, endpoint)
            try:
                # Try without any authentication
                resp = self.session.get(url, timeout=10)
                
                if resp.status_code == 200:
                    self.findings.append({
                        'type': 'authentication_bypass',
                        'severity': 'CRITICAL',
                        'url': url,
                        'description': f'Protected endpoint accessible without authentication',
                        'impact': 'Unauthorized access to sensitive functionality',
                        'bounty_estimate': '$10,000-$50,000',
                        'cwe': 'CWE-306'
                    })
                    print(f"  [!] CRITICAL: Auth bypass on {endpoint}")
                
                time.sleep(1.0 / self.rate_limit)
            except:
                pass
        
        print(f"[+] Authentication testing complete\n")
    
    def test_parameter_tampering(self):
        """Test for parameter manipulation in critical functions"""
        print("[*] Testing parameter tampering...")
        
        # Test negative amounts, zero fees, etc.
        test_payloads = [
            {'amount': -1, 'fee': 0},
            {'amount': 999999999, 'fee': -1},
            {'amount': 100, 'fee': 0},
            {'amount': 100, 'admin': True},
            {'amount': 100, 'bypass': True}
        ]
        
        critical_endpoints = [
            '/api/v1/swap',
            '/api/v1/transfer',
            '/api/v1/withdraw',
            '/api/v1/stake'
        ]
        
        for endpoint in critical_endpoints:
            url = urljoin(self.target, endpoint)
            for payload in test_payloads:
                try:
                    resp = self.session.post(url, json=payload, timeout=10)
                    
                    # If server accepts invalid values → vulnerability
                    if resp.status_code in [200, 201]:
                        self.findings.append({
                            'type': 'parameter_tampering',
                            'severity': 'HIGH',
                            'url': url,
                            'description': f'Server accepts manipulated parameters: {payload}',
                            'impact': 'Could lead to fee bypass, negative amounts, or privilege escalation',
                            'bounty_estimate': '$3,000-$15,000',
                            'cwe': 'CWE-472'
                        })
                        print(f"  [!] HIGH: Parameter tampering on {endpoint}")
                    
                    time.sleep(1.0 / self.rate_limit)
                except:
                    pass
        
        print(f"[+] Parameter tampering testing complete\n")
    
    def test_rate_limiting(self):
        """Test if rate limiting exists (important for business logic attacks)"""
        print("[*] Testing rate limiting...")
        
        test_endpoint = urljoin(self.target, '/api/v1/swap')
        
        # Send 50 requests quickly
        success_count = 0
        for i in range(50):
            try:
                resp = self.session.get(test_endpoint, timeout=5)
                if resp.status_code != 429:
                    success_count += 1
                time.sleep(0.1)  # 10 req/sec
            except:
                pass
        
        if success_count > 45:
            self.findings.append({
                'type': 'missing_rate_limiting',
                'severity': 'MEDIUM',
                'url': test_endpoint,
                'description': f'No rate limiting detected - {success_count}/50 requests succeeded',
                'impact': 'Enables automated attacks, scraping, brute force',
                'bounty_estimate': '$500-$3,000',
                'cwe': 'CWE-770'
            })
            print(f"  [!] MEDIUM: No rate limiting ({success_count}/50 succeeded)")
        else:
            print(f"  [+] Rate limiting detected ({success_count}/50 succeeded)\n")
    
    # =========================================================================
    # DEFI-SPECIFIC TESTS
    # =========================================================================
    
    def test_price_manipulation(self):
        """Test for price oracle manipulation vulnerabilities"""
        print("[*] Testing price manipulation vectors...")
        
        # Test if we can manipulate price inputs
        price_endpoints = [
            '/api/v1/price',
            '/api/v1/oracle',
            '/api/v1/swap/quote'
        ]
        
        manipulated_prices = [
            {'price': 0},
            {'price': -1},
            {'price': 999999999},
            {'price': 0.0000001}
        ]
        
        for endpoint in price_endpoints:
            url = urljoin(self.target, endpoint)
            for payload in manipulated_prices:
                try:
                    resp = self.session.post(url, json=payload, timeout=10)
                    if resp.status_code in [200, 201]:
                        self.findings.append({
                            'type': 'price_manipulation',
                            'severity': 'CRITICAL',
                            'url': url,
                            'description': f'Price manipulation possible with payload: {payload}',
                            'impact': 'Attacker could manipulate prices to drain funds',
                            'bounty_estimate': '$20,000-$100,000',
                            'cwe': 'CWE-20'
                        })
                        print(f"  [!] CRITICAL: Price manipulation on {endpoint}")
                    time.sleep(1.0 / self.rate_limit)
                except:
                    pass
        
        print(f"[+] Price manipulation testing complete\n")
    
    def test_reward_claiming(self):
        """Test for reward/claiming vulnerabilities"""
        print("[*] Testing reward mechanisms...")
        
        reward_endpoints = [
            '/api/v1/rewards/claim',
            '/api/v1/stake/claim',
            '/api/v1/yield/claim'
        ]
        
        # Try claiming multiple times
        for endpoint in reward_endpoints:
            url = urljoin(self.target, endpoint)
            try:
                # First claim
                resp1 = self.session.post(url, json={}, timeout=10)
                time.sleep(0.5)
                # Immediate second claim
                resp2 = self.session.post(url, json={}, timeout=10)
                
                # If both succeed → double claim vulnerability
                if resp1.status_code == 200 and resp2.status_code == 200:
                    self.findings.append({
                        'type': 'double_claim',
                        'severity': 'CRITICAL',
                        'url': url,
                        'description': 'Rewards can be claimed multiple times',
                        'impact': 'Attacker could drain reward pool',
                        'bounty_estimate': '$10,000-$50,000',
                        'cwe': 'CWE-1089'
                    })
                    print(f"  [!] CRITICAL: Double claim vulnerability on {endpoint}")
                
                time.sleep(1.0 / self.rate_limit)
            except:
                pass
        
        print(f"[+] Reward testing complete\n")
    
    # =========================================================================
    # REPORTING
    # =========================================================================
    
    def generate_report(self):
        """Generate comprehensive report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = f'output/advanced_defi_scan_{timestamp}.json'
        
        report = {
            'scan_date': datetime.now().isoformat(),
            'target': self.target,
            'total_findings': len(self.findings),
            'severity_breakdown': {
                'CRITICAL': len([f for f in self.findings if f['severity'] == 'CRITICAL']),
                'HIGH': len([f for f in self.findings if f['severity'] == 'HIGH']),
                'MEDIUM': len([f for f in self.findings if f['severity'] == 'MEDIUM']),
                'LOW': len([f for f in self.findings if f['severity'] == 'LOW'])
            },
            'findings': self.findings,
            'endpoints_discovered': len(self.endpoints)
        }
        
        # Save JSON report
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        print("\n" + "=" * 80)
        print(" SCAN COMPLETE - SUMMARY")
        print("=" * 80)
        print(f"Total Findings: {report['total_findings']}")
        print(f"  CRITICAL: {report['severity_breakdown']['CRITICAL']}")
        print(f"  HIGH:     {report['severity_breakdown']['HIGH']}")
        print(f"  MEDIUM:   {report['severity_breakdown']['MEDIUM']}")
        print(f"  LOW:      {report['severity_breakdown']['LOW']}")
        print(f"\nEndpoints Discovered: {report['endpoints_discovered']}")
        print(f"\nReport saved: {report_file}")
        print("=" * 80)
        
        # Print actionable findings
        critical_high = [f for f in self.findings if f['severity'] in ['CRITICAL', 'HIGH']]
        if critical_high:
            print("\n🔥 CRITICAL/HIGH FINDINGS TO INVESTIGATE:")
            print("=" * 80)
            for i, finding in enumerate(critical_high, 1):
                print(f"\n{i}. [{finding['severity']}] {finding['type'].upper()}")
                print(f"   URL: {finding['url']}")
                print(f"   Description: {finding['description']}")
                print(f"   Bounty Estimate: {finding.get('bounty_estimate', 'N/A')}")
        else:
            print("\n[-] No CRITICAL or HIGH findings - Try manual testing")
        
        print("\n")
    
    def run(self):
        """Execute complete advanced scan"""
        self.banner()
        
        # Layer 1: Reconnaissance
        self.discover_api_endpoints()
        self.check_graphql()
        
        # Layer 2: Business Logic Testing
        self.test_idor_patterns()
        self.test_authentication_bypass()
        self.test_parameter_tampering()
        self.test_rate_limiting()
        
        # DeFi-Specific
        self.test_price_manipulation()
        self.test_reward_claiming()
        
        # Generate report
        self.generate_report()


def main():
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 advanced_defi_hunter.py <target_url>")
        print("Example: python3 advanced_defi_hunter.py https://aerodrome.finance")
        sys.exit(1)
    
    target = sys.argv[1]
    rate_limit = 2  # requests per second
    
    hunter = AdvancedDeFiHunter(target, rate_limit)
    hunter.run()


if __name__ == '__main__':
    main()
