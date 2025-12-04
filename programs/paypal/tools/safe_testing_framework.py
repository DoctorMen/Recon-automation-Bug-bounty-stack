#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
SAFE TESTING FRAMEWORK
Ensures all testing respects rate limits, legal boundaries, and ethical standards

Usage:
    python3 safe_testing_framework.py --mode gentle --target api.sandbox.paypal.com
"""

import time
import requests
import json
import sys
from datetime import datetime, timedelta
import argparse
from collections import defaultdict

class SafeTestingFramework:
    """
    Framework for safe, ethical, and legal security testing
    """
    
    # Testing modes with different aggressiveness
    MODES = {
        'gentle': {
            'requests_per_second': 1,
            'max_concurrent': 1,
            'timeout': 15,
            'description': 'Minimal impact - 1 req/sec'
        },
        'moderate': {
            'requests_per_second': 5,
            'max_concurrent': 2,
            'timeout': 10,
            'description': 'Balanced testing - 5 req/sec'
        },
        'aggressive': {
            'requests_per_second': 15,
            'max_concurrent': 5,
            'timeout': 5,
            'description': 'Fast testing - 15 req/sec (use with caution)'
        }
    }
    
    def __init__(self, target, mode='gentle'):
        self.target = target
        self.mode = mode
        self.config = self.MODES[mode]
        
        # Tracking
        self.request_log = []
        self.error_count = defaultdict(int)
        self.start_time = None
        self.total_requests = 0
        
        # Safety limits
        self.max_consecutive_errors = 10
        self.max_429_responses = 5  # Rate limit responses
        self.cooldown_on_429 = 60  # Wait 60 seconds if rate limited
        
        # Session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Security Research / Bug Bounty',
            'Accept': 'application/json, text/html',
        })
    
    def rate_limit(self):
        """Enforce rate limiting"""
        if self.request_log:
            last_request_time = self.request_log[-1]['timestamp']
            time_since_last = time.time() - last_request_time
            min_delay = 1.0 / self.config['requests_per_second']
            
            if time_since_last < min_delay:
                time.sleep(min_delay - time_since_last)
    
    def check_safety(self):
        """Check if it's safe to continue testing"""
        # Check consecutive errors
        recent_errors = [r for r in self.request_log[-10:] if r.get('error')]
        if len(recent_errors) >= self.max_consecutive_errors:
            print(f"\n[!] Too many consecutive errors. Stopping for safety.")
            print(f"[!] Target may be blocking or experiencing issues.")
            return False
        
        # Check rate limiting
        if self.error_count['429'] >= self.max_429_responses:
            print(f"\n[!] Received {self.error_count['429']} rate limit responses.")
            print(f"[!] Cooling down for {self.cooldown_on_429} seconds...")
            time.sleep(self.cooldown_on_429)
            self.error_count['429'] = 0  # Reset counter
        
        return True
    
    def safe_request(self, url, method='GET', **kwargs):
        """Make a safe, rate-limited request"""
        if not self.check_safety():
            return None
        
        self.rate_limit()
        
        try:
            self.total_requests += 1
            start = time.time()
            
            if method == 'GET':
                resp = self.session.get(url, timeout=self.config['timeout'], **kwargs)
            elif method == 'POST':
                resp = self.session.post(url, timeout=self.config['timeout'], **kwargs)
            else:
                resp = self.session.request(method, url, timeout=self.config['timeout'], **kwargs)
            
            duration = time.time() - start
            
            # Log request
            log_entry = {
                'timestamp': time.time(),
                'url': url,
                'method': method,
                'status_code': resp.status_code,
                'duration': duration,
                'error': None
            }
            
            # Handle rate limiting
            if resp.status_code == 429:
                self.error_count['429'] += 1
                log_entry['error'] = 'RATE_LIMITED'
                print(f"[!] Rate limited: {url}")
            
            self.request_log.append(log_entry)
            
            return resp
            
        except requests.exceptions.Timeout:
            log_entry = {
                'timestamp': time.time(),
                'url': url,
                'method': method,
                'status_code': None,
                'duration': self.config['timeout'],
                'error': 'TIMEOUT'
            }
            self.request_log.append(log_entry)
            return None
            
        except Exception as e:
            log_entry = {
                'timestamp': time.time(),
                'url': url,
                'method': method,
                'status_code': None,
                'duration': 0,
                'error': str(e)
            }
            self.request_log.append(log_entry)
            return None
    
    def test_endpoint(self, path, tests):
        """Test an endpoint with multiple test cases"""
        url = f"https://{self.target}{path}"
        results = []
        
        print(f"\n[*] Testing: {url}")
        print(f"[*] Mode: {self.mode} ({self.config['description']})")
        
        for test_name, test_config in tests.items():
            print(f"    - {test_name}...", end=' ')
            
            resp = self.safe_request(
                url,
                method=test_config.get('method', 'GET'),
                params=test_config.get('params'),
                headers=test_config.get('headers'),
                data=test_config.get('data')
            )
            
            if resp:
                result = {
                    'test': test_name,
                    'status_code': resp.status_code,
                    'vulnerable': self.check_vulnerable(resp, test_config),
                    'response_preview': resp.text[:200] if resp.text else None
                }
                results.append(result)
                
                if result['vulnerable']:
                    print(f"🔴 VULNERABLE")
                else:
                    print(f"🟢 OK")
            else:
                print(f"❌ FAILED")
        
        return results
    
    def check_vulnerable(self, response, test_config):
        """Check if response indicates a vulnerability"""
        # Define vulnerability indicators
        vulnerable_indicators = test_config.get('vulnerable_indicators', [])
        
        for indicator in vulnerable_indicators:
            if indicator.get('type') == 'status_code':
                if response.status_code == indicator.get('value'):
                    return True
            elif indicator.get('type') == 'content':
                if indicator.get('value').lower() in response.text.lower():
                    return True
        
        return False
    
    def generate_safety_report(self):
        """Generate report on testing safety and statistics"""
        duration = time.time() - self.start_time if self.start_time else 0
        
        print(f"\n{'='*80}")
        print(f"SAFE TESTING REPORT")
        print(f"{'='*80}\n")
        
        print(f"Target: {self.target}")
        print(f"Mode: {self.mode} ({self.config['description']})")
        print(f"Duration: {duration:.2f} seconds")
        print(f"Total Requests: {self.total_requests}")
        print(f"Avg Request Rate: {self.total_requests/duration:.2f} req/sec" if duration > 0 else "N/A")
        
        # Status code breakdown
        status_codes = defaultdict(int)
        for entry in self.request_log:
            if entry['status_code']:
                status_codes[entry['status_code']] += 1
        
        print(f"\nStatus Code Breakdown:")
        for code, count in sorted(status_codes.items()):
            print(f"  {code}: {count}")
        
        # Error summary
        errors = [e for e in self.request_log if e['error']]
        print(f"\nErrors: {len(errors)}")
        if errors:
            error_types = defaultdict(int)
            for e in errors:
                error_types[e['error']] += 1
            for error_type, count in error_types.items():
                print(f"  {error_type}: {count}")
        
        # Safety assessment
        print(f"\nSafety Assessment:")
        if len(errors) / len(self.request_log) > 0.3 if self.request_log else False:
            print(f"  ⚠️  HIGH ERROR RATE - Consider more gentle approach")
        elif self.error_count['429'] > 0:
            print(f"  ⚠️  RATE LIMITED - Slow down testing")
        else:
            print(f"  ✅ SAFE - No issues detected")
        
        print(f"\n{'='*80}\n")

def main():
    parser = argparse.ArgumentParser(description='Safe Testing Framework')
    parser.add_argument('--target', required=True, help='Target domain (e.g., api.sandbox.paypal.com)')
    parser.add_argument('--mode', choices=['gentle', 'moderate', 'aggressive'], default='gentle',
                       help='Testing mode (default: gentle)')
    parser.add_argument('--test-type', choices=['idor', 'xss', 'sqli', 'all'], default='all',
                       help='Type of tests to run')
    
    args = parser.parse_args()
    
    framework = SafeTestingFramework(args.target, args.mode)
    framework.start_time = time.time()
    
    print(f"\n{'='*80}")
    print(f"SAFE TESTING FRAMEWORK")
    print(f"{'='*80}\n")
    print(f"Target: {args.target}")
    print(f"Mode: {args.mode}")
    print(f"Rate Limit: {framework.config['requests_per_second']} req/sec")
    print(f"\n⚠️  REMEMBER: Only test authorized targets!")
    print(f"⚠️  Stop if you receive rate limit errors!")
    print(f"\n{'='*80}\n")
    
    # Example: Test common API endpoints
    test_endpoints = [
        '/api/v1/users',
        '/api/v1/payments',
        '/debug',
        '/.git/config',
    ]
    
    for endpoint in test_endpoints:
        # Example IDOR test
        tests = {
            'baseline': {
                'method': 'GET',
                'vulnerable_indicators': []
            },
            'idor_test': {
                'method': 'GET',
                'params': {'id': '1'},
                'vulnerable_indicators': [
                    {'type': 'status_code', 'value': 200}
                ]
            }
        }
        
        framework.test_endpoint(endpoint, tests)
    
    framework.generate_safety_report()

if __name__ == '__main__':
    main()
