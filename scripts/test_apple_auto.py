#!/usr/bin/env python3
"""
Quick Apple Endpoint Test & Capture
Automatically tests Apple endpoints and captures results
"""

import requests
import json
import urllib3
from pathlib import Path
from datetime import datetime

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REPO_ROOT = Path(__file__).parent.parent
ROI_OUTPUT_DIR = REPO_ROOT / "output" / "immediate_roi"
RESULTS_FILE = ROI_OUTPUT_DIR / "apple_manual_test_results.json"

def test_and_capture():
    """Test Apple endpoints and automatically capture results"""
    
    print("=" * 60)
    print("Quick Apple Endpoint Test & Capture")
    print("=" * 60)
    print()
    
    # Load Apple endpoints
    priority_file = ROI_OUTPUT_DIR / "priority_endpoints_by_program.json"
    
    if not priority_file.exists():
        print("❌ Priority endpoints file not found")
        print("Run: python3 scripts/prioritize_endpoints.py")
        return
    
    with open(priority_file, 'r') as f:
        data = json.load(f)
    
    apple_endpoints = data.get("apple", [])
    
    if not apple_endpoints:
        print("❌ No Apple endpoints found")
        return
    
    # Get first endpoint
    endpoint = apple_endpoints[0]
    url = endpoint.get("url", "")
    
    print(f"Testing: {url}")
    print()
    print("Running tests...")
    print()
    
    results = []
    
    # Test 1: Simple GET request
    print("[TEST 1] GET request (no auth)")
    try:
        response = requests.get(url, timeout=10, allow_redirects=False, verify=False)
        
        result = {
            "timestamp": datetime.now().isoformat(),
            "endpoint": url,
            "test_type": "GET request (no auth)",
            "status_code": str(response.status_code),
            "response_preview": response.text[:200] if len(response.text) < 1000 else response.text[:200] + "...",
            "headers": dict(response.headers),
            "content_length": len(response.content),
            "finding": "safe" if response.status_code >= 400 else "unknown"
        }
        
        results.append(result)
        
        print(f"   Status: {response.status_code}")
        print(f"   Server: {response.headers.get('Server', 'N/A')}")
        print(f"   Content-Type: {response.headers.get('Content-Type', 'N/A')}")
        print(f"   Content-Length: {len(response.content)}")
        
        if response.status_code == 200:
            print("   ⚠️  Got 200 - endpoint is accessible!")
        elif response.status_code == 403:
            print("   ✅ Got 403 - protected (expected)")
        elif response.status_code == 404:
            print("   ⚠️  Got 404 - endpoint not found")
        else:
            print(f"   Status: {response.status_code}")
        
        print()
        
    except requests.exceptions.SSLError as e:
        print(f"   ⚠️  SSL Error: {e}")
        result = {
            "timestamp": datetime.now().isoformat(),
            "endpoint": url,
            "test_type": "GET request (no auth)",
            "status_code": "SSL_ERROR",
            "response_preview": str(e),
            "finding": "error"
        }
        results.append(result)
        print()
    except Exception as e:
        print(f"   Error: {e}")
        result = {
            "timestamp": datetime.now().isoformat(),
            "endpoint": url,
            "test_type": "GET request (no auth)",
            "status_code": "ERROR",
            "response_preview": str(e),
            "finding": "error"
        }
        results.append(result)
        print()
    
    # Test 2: IDOR test (if we have user IDs)
    print("[TEST 2] IDOR test (with fake user ID)")
    try:
        # Try to access with different user ID in path
        test_url = url.replace("/api/checkout", "/api/users/12345")
        response = requests.get(test_url, timeout=10, allow_redirects=False, verify=False)
        
        result = {
            "timestamp": datetime.now().isoformat(),
            "endpoint": test_url,
            "test_type": "IDOR test (fake user ID)",
            "status_code": str(response.status_code),
            "response_preview": response.text[:200] if len(response.text) < 1000 else response.text[:200] + "...",
            "finding": "safe" if response.status_code >= 400 else "unknown"
        }
        
        results.append(result)
        
        print(f"   Status: {response.status_code}")
        if response.status_code == 200:
            print("   ⚠️  Got 200 - may be vulnerable to IDOR!")
        elif response.status_code == 403:
            print("   ✅ Got 403 - protected")
        elif response.status_code == 404:
            print("   ℹ️  Got 404 - endpoint doesn't exist")
        
        print()
        
    except Exception as e:
        print(f"   Error: {e}")
        print()
    
    # Save results
    ROI_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Load existing results
    if RESULTS_FILE.exists():
        with open(RESULTS_FILE, 'r') as f:
            existing_results = json.load(f)
    else:
        existing_results = []
    
    # Merge results
    all_results = existing_results + results
    
    with open(RESULTS_FILE, 'w') as f:
        json.dump(all_results, f, indent=2)
    
    print("=" * 60)
    print("Results Summary")
    print("=" * 60)
    print()
    
    for idx, r in enumerate(results, 1):
        print(f"Test {idx}:")
        print(f"   Endpoint: {r['endpoint']}")
        print(f"   Test: {r['test_type']}")
        print(f"   Status: {r['status_code']}")
        print(f"   Finding: {r['finding']}")
        print()
    
    print(f"✅ Results saved to: {RESULTS_FILE}")
    print()
    
    print("=" * 60)
    print("Analysis")
    print("=" * 60)
    print()
    
    # Check if CDN endpoint
    if "2b4a6b31ca2273bb" in url:
        print("⚠️  WARNING: This looks like a CDN subdomain!")
        print("   - Domain: 2b4a6b31ca2273bb.apple.com")
        print("   - Hash prefix suggests CDN/cache endpoint")
        print("   - Likely OUT OF SCOPE for bug bounty")
        print()
    
    # Check results
    vulnerable_tests = [r for r in results if r.get("status_code") == "200"]
    if vulnerable_tests:
        print("⚠️  Found accessible endpoints:")
        for r in vulnerable_tests:
            print(f"   - {r['endpoint']}")
        print()
    
    print("Next steps:")
    print("1. Review the results above")
    print("2. Check if endpoints are in Apple's bug bounty scope")
    print("3. If CDN endpoints, focus on real Apple domains instead")
    print("4. Test other programs: Mastercard, Atlassian, Kraken")
    print()
    
    print("=" * 60)

if __name__ == "__main__":
    test_and_capture()


