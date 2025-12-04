import json
import os
import time
from datetime import datetime, timezone
from urllib.parse import urljoin

class SimulatedDvwaTester:
    def __init__(self, profile_path):
        self.profile = self.load_profile(profile_path)
        self.base_url = self.profile['target']
        self.results = {
            'start_time': datetime.now(timezone.utc).isoformat(),
            'target': self.base_url,
            'findings': [],
            'simulation': True
        }

    def load_profile(self, profile_path):
        with open(profile_path, 'r') as f:
            return json.load(f)

    def run_assessment(self):
        print(f"Starting SIMULATED assessment of {self.base_url}")
        print("Note: This is a simulation to demonstrate the framework")
        
        # Simulate login
        print("\n[*] Simulating login to DVWA...")
        time.sleep(1)
        print("[+] Successfully logged in (simulated)")
        
        # Set security level to low
        print("\n[*] Setting security level to LOW...")
        time.sleep(0.5)
        
        # Run vulnerability tests
        self.test_reflected_xss()
        self.test_sql_injection()
        self.test_command_injection()
        self.test_lfi()
        self.test_idor()
        
        # Save results
        self.save_results()

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
            time.sleep(0.2)
            # Simulate finding XSS in DVWA (it's vulnerable)
            if '<script>' in payload or 'onerror' in payload:
                self.record_finding(
                    type="xss",
                    url=test_url,
                    parameter="name",
                    payload=payload,
                    status="vulnerable"
                )
                print(f"[+] XSS found with payload: {payload}")

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
            time.sleep(0.2)
            # DVWA is vulnerable to SQLi on low security
            if "' OR" in payload or "UNION" in payload:
                self.record_finding(
                    type="sqli",
                    url=test_url,
                    parameter="id",
                    payload=payload,
                    status="vulnerable"
                )
                print(f"[+] SQL injection found with payload: {payload}")

    def test_command_injection(self):
        print("\n[*] Testing Command Injection...")
        test_url = urljoin(self.base_url, 'vulnerabilities/exec/')
        test_payloads = [
            "127.0.0.1; whoami",
            "127.0.0.1 | ls",
            "127.0.0.1 && echo test"
        ]

        for payload in test_payloads:
            time.sleep(0.2)
            # DVWA is vulnerable to command injection on low security
            if ';' in payload or '|' in payload or '&&' in payload:
                self.record_finding(
                    type="command_injection",
                    url=test_url,
                    parameter="ip",
                    payload=payload,
                    status="vulnerable"
                )
                print(f"[+] Command injection found with payload: {payload}")

    def test_lfi(self):
        print("\n[*] Testing Local File Inclusion...")
        test_url = urljoin(self.base_url, 'vulnerabilities/fi/')
        test_payloads = [
            "../../../../../etc/passwd",
            "..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "php://filter/read=convert.base64-encode/resource=config.php"
        ]

        for payload in test_payloads:
            time.sleep(0.2)
            # Simulate LFI vulnerability
            if "../" in payload or "php://" in payload:
                self.record_finding(
                    type="lfi",
                    url=test_url,
                    parameter="page",
                    payload=payload,
                    status="vulnerable"
                )
                print(f"[+] LFI found with payload: {payload}")

    def test_idor(self):
        print("\n[*] Testing Insecure Direct Object Reference...")
        test_url = urljoin(self.base_url, 'vulnerabilities/idor/')
        test_payloads = [
            "user_id=1",
            "user_id=2",
            "user_id=3"
        ]

        for payload in test_payloads:
            time.sleep(0.2)
            # Simulate IDOR vulnerability
            self.record_finding(
                type="idor",
                url=test_url,
                parameter="user_id",
                payload=payload,
                status="vulnerable"
            )
            print(f"[+] IDOR found with payload: {payload}")

    def record_finding(self, type, url, parameter, payload, status="potential"):
        self.results['findings'].append({
            'type': type,
            'url': url,
            'parameter': parameter,
            'payload': payload,
            'status': status,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })

    def save_results(self):
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        filename = f"dvwa_assessment_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\nAssessment complete. Results saved to {filename}")
        print(f"Total findings: {len(self.results['findings'])}")
        
        # Summary by type
        summary = {}
        for finding in self.results['findings']:
            vuln_type = finding['type']
            summary[vuln_type] = summary.get(vuln_type, 0) + 1
        
        print("\nFindings Summary:")
        for vuln_type, count in summary.items():
            print(f"  {vuln_type.upper()}: {count}")

if __name__ == "__main__":
    tester = SimulatedDvwaTester('dvwa_lab_config.json')
    tester.run_assessment()
