#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
ADVANCED API FUZZER - For Business Logic Testing
Designed for mature programs like PayPal
Safe, intelligent, and effective

Usage:
    python3 advanced_api_fuzzer.py --target api.sandbox.paypal.com --endpoints endpoints.txt
"""

import requests
import json
import time
import sys
from urllib.parse import urljoin
import argparse
from datetime import datetime

class AdvancedAPIFuzzer:
    """
    Advanced API fuzzer focusing on business logic vulnerabilities
    that automated scanners miss
    """
    
    def __init__(self, base_url, rate_limit=2):
        self.base_url = base_url.rstrip('/')
        self.rate_limit = rate_limit  # Requests per second
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Security Research)',
            'Accept': 'application/json',
        })
    
    def test_idor(self, endpoint):
        """Test for Insecure Direct Object Reference"""
        print(f"[*] Testing IDOR on {endpoint}")
        
        # Common IDOR patterns
        test_cases = [
            {'id': '1'},
            {'user_id': '1'},
            {'account_id': '1'},
            {'payment_id': 'PAYMENT_12345'},
            {'transaction_id': 'TXN_12345'},
        ]
        
        for test in test_cases:
            try:
                url = urljoin(self.base_url, endpoint)
                resp = self.session.get(url, params=test, timeout=10)
                
                if resp.status_code == 200 and len(resp.content) > 100:
                    self.findings.append({
                        'type': 'IDOR',
                        'severity': 'HIGH',
                        'endpoint': endpoint,
                        'payload': test,
                        'response_code': resp.status_code,
                        'response_length': len(resp.content)
                    })
                    print(f"[!] POTENTIAL IDOR FOUND: {endpoint} with {test}")
                
                time.sleep(1 / self.rate_limit)
                
            except Exception as e:
                print(f"[-] Error testing {endpoint}: {e}")
    
    def test_parameter_tampering(self, endpoint):
        """Test for parameter manipulation vulnerabilities"""
        print(f"[*] Testing parameter tampering on {endpoint}")
        
        # Business logic tampering tests
        test_cases = [
            {'amount': '0.01'},
            {'amount': '-1'},
            {'quantity': '999999'},
            {'price': '0'},
            {'discount': '100'},
            {'admin': 'true'},
            {'role': 'admin'},
            {'is_verified': 'true'},
        ]
        
        for test in test_cases:
            try:
                url = urljoin(self.base_url, endpoint)
                resp = self.session.get(url, params=test, timeout=10)
                
                # Look for successful tampering
                if resp.status_code in [200, 201] and 'error' not in resp.text.lower():
                    self.findings.append({
                        'type': 'PARAMETER_TAMPERING',
                        'severity': 'MEDIUM',
                        'endpoint': endpoint,
                        'payload': test,
                        'response_code': resp.status_code
                    })
                    print(f"[!] POTENTIAL PARAMETER TAMPERING: {endpoint} with {test}")
                
                time.sleep(1 / self.rate_limit)
                
            except Exception as e:
                print(f"[-] Error testing {endpoint}: {e}")
    
    def test_authentication_bypass(self, endpoint):
        """Test for authentication bypass vulnerabilities"""
        print(f"[*] Testing auth bypass on {endpoint}")
        
        # Authentication bypass techniques
        headers_tests = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
            {'Authorization': 'Bearer FAKE_TOKEN'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
        ]
        
        for headers in headers_tests:
            try:
                url = urljoin(self.base_url, endpoint)
                resp = self.session.get(url, headers=headers, timeout=10)
                
                if resp.status_code in [200, 301, 302] and len(resp.content) > 100:
                    self.findings.append({
                        'type': 'AUTH_BYPASS',
                        'severity': 'CRITICAL',
                        'endpoint': endpoint,
                        'headers': headers,
                        'response_code': resp.status_code
                    })
                    print(f"[!] POTENTIAL AUTH BYPASS: {endpoint} with {headers}")
                
                time.sleep(1 / self.rate_limit)
                
            except Exception as e:
                print(f"[-] Error testing {endpoint}: {e}")
    
    def test_information_disclosure(self, endpoint):
        """Test for information disclosure"""
        print(f"[*] Testing information disclosure on {endpoint}")
        
        # Paths that might leak info
        info_paths = [
            '/debug', '/health', '/status', '/metrics',
            '/api-docs', '/swagger', '/swagger.json',
            '/.git/config', '/.env', '/config.json',
            '/admin', '/console', '/actuator'
        ]
        
        for path in info_paths:
            try:
                url = urljoin(self.base_url, path)
                resp = self.session.get(url, timeout=10)
                
                if resp.status_code == 200:
                    # Check for sensitive keywords
                    sensitive = ['password', 'secret', 'key', 'token', 'api_key', 'database']
                    if any(keyword in resp.text.lower() for keyword in sensitive):
                        self.findings.append({
                            'type': 'INFORMATION_DISCLOSURE',
                            'severity': 'HIGH',
                            'endpoint': path,
                            'response_code': resp.status_code,
                            'response_preview': resp.text[:200]
                        })
                        print(f"[!] INFORMATION DISCLOSURE: {path}")
                
                time.sleep(1 / self.rate_limit)
                
            except Exception as e:
                pass  # Expected for many paths
    
    def run_full_test(self, endpoints_file):
        """Run full test suite on all endpoints"""
        print(f"\n{'='*60}")
        print(f"ADVANCED API FUZZER - Starting Tests")
        print(f"Target: {self.base_url}")
        print(f"Rate Limit: {self.rate_limit} req/sec")
        print(f"{'='*60}\n")
        
        # Read endpoints
        try:
            with open(endpoints_file, 'r') as f:
                endpoints = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[-] Endpoints file not found: {endpoints_file}")
            sys.exit(1)
        
        # Test each endpoint
        for endpoint in endpoints:
            print(f"\n[*] Testing endpoint: {endpoint}")
            self.test_idor(endpoint)
            self.test_parameter_tampering(endpoint)
            self.test_authentication_bypass(endpoint)
        
        # Test for information disclosure
        self.test_information_disclosure('')
        
        # Save results
        self.save_results()
    
    def save_results(self):
        """Save findings to file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"../findings/advanced_fuzzer_results_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.findings, f, indent=2)
        
        print(f"\n{'='*60}")
        print(f"RESULTS SUMMARY")
        print(f"{'='*60}")
        print(f"Total Findings: {len(self.findings)}")
        
        # Count by severity
        critical = len([f for f in self.findings if f['severity'] == 'CRITICAL'])
        high = len([f for f in self.findings if f['severity'] == 'HIGH'])
        medium = len([f for f in self.findings if f['severity'] == 'MEDIUM'])
        
        print(f"Critical: {critical}")
        print(f"High: {high}")
        print(f"Medium: {medium}")
        print(f"\nResults saved to: {filename}")
        print(f"{'='*60}\n")

def main():
    parser = argparse.ArgumentParser(description='Advanced API Fuzzer for Business Logic Testing')
    parser.add_argument('--target', required=True, help='Target base URL (e.g., https://api.sandbox.paypal.com)')
    parser.add_argument('--endpoints', required=True, help='File containing API endpoints to test')
    parser.add_argument('--rate-limit', type=int, default=2, help='Requests per second (default: 2)')
    
    args = parser.parse_args()
    
    fuzzer = AdvancedAPIFuzzer(args.target, args.rate_limit)
    fuzzer.run_full_test(args.endpoints)

if __name__ == '__main__':
    main()
