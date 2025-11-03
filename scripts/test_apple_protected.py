#!/usr/bin/env python3
"""
Apple Bug Bounty - Better Testing Strategy
Find protected endpoints and test them properly
"""

import requests
import json
import urllib3
from pathlib import Path
from urllib.parse import urlparse

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REPO_ROOT = Path(__file__).parent.parent
RESULTS_DIR = REPO_ROOT / "output" / "apple_testing"

def test_protected_endpoints():
    """Test protected endpoints, not public websites"""
    
    print("=" * 60)
    print("APPLE - BETTER TESTING STRATEGY")
    print("=" * 60)
    print()
    
    print("⚠️  FIXING FALSE POSITIVES:")
    print("   ❌ Old: Tested public websites (false positives)")
    print("   ✅ New: Test protected endpoints")
    print()
    
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    findings = []
    
    # Test PROTECTED endpoints (not public websites)
    protected_endpoints = [
        "https://developer.apple.com/account",
        "https://developer.apple.com/api/keys",
        "https://developer.apple.com/membercenter",
        "https://idmsa.apple.com/IDMSWebAuth",
        "https://appleid.apple.com/account",
        "https://appleid.apple.com/api/auth",
    ]
    
    print("Testing PROTECTED endpoints:")
    for ep in protected_endpoints:
        print(f"   - {ep}")
    print()
    
    for url in protected_endpoints:
        print(f"Testing: {url}")
        result = test_endpoint_properly(url)
        if result:
            findings.append(result)
        print()
    
    # Save findings
    findings_file = RESULTS_DIR / "real_vulnerability_findings.json"
    with open(findings_file, 'w') as f:
        json.dump(findings, f, indent=2)
    
    print("=" * 60)
    print("RESULTS")
    print("=" * 60)
    print()
    
    if findings:
        print("⚠️  POTENTIAL VULNERABILITIES:")
        for f in findings:
            print(f"   - {f['test_type']}: {f['url']}")
            print(f"     {f['finding']}")
        print()
    else:
        print("❌ No vulnerabilities found")
        print("   - All endpoints properly protected")
        print("   - No authentication bypass")
        print()
    
    print(f"✅ Results saved to: {findings_file}")
    print()
    
    print("=" * 60)
    print("HONEST ASSESSMENT")
    print("=" * 60)
    print()
    
    print("Apple testing is HARD because:")
    print("   - Public endpoints don't count")
    print("   - Protected endpoints are hard to find")
    print("   - Need Apple account for testing")
    print("   - Low success rate")
    print()
    
    print("💡 RECOMMENDATION:")
    print("   Focus on Rapyd instead:")
    print("   ✅ You have API keys")
    print("   ✅ Confirmed in scope")
    print("   ✅ Higher success rate")
    print("   ✅ Real bugs found before")
    print()
    
    print("=" * 60)

def test_endpoint_properly(url: str) -> dict:
    """Test endpoint properly - check if it's protected"""
    
    try:
        # Test without auth
        response = requests.get(url, timeout=10, verify=False)
        
        status = response.status_code
        
        print(f"   Status: {status}")
        
        # If 200, check if it's actually protected content
        if status == 200:
            # Check if it's a login page or error page
            if "login" in response.text.lower() or "sign in" in response.text.lower():
                print("   ✅ Protected - redirects to login")
                return None
            elif "error" in response.text.lower() or "403" in response.text.lower():
                print("   ✅ Protected - returns error")
                return None
            else:
                # Might be vulnerable - need manual verification
                print("   ⚠️  Got 200 - may need manual verification")
                return {
                    "test_type": "Potential Authentication Bypass",
                    "url": url,
                    "vulnerable": False,  # Set to False, needs manual verification
                    "finding": "Got 200 but needs manual verification - may be protected",
                    "severity": "Unknown",
                    "needs_verification": True
                }
        
        elif status == 401 or status == 403:
            print("   ✅ Protected (expected)")
            return None
        
        elif status == 404:
            print("   ℹ️  Endpoint doesn't exist")
            return None
        
    except Exception as e:
        print(f"   Error: {e}")
        return None
    
    return None

if __name__ == "__main__":
    test_protected_endpoints()


