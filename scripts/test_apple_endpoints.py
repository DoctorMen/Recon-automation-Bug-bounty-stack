#!/usr/bin/env python3
"""
Test Apple Endpoints - Verify what they actually are
Check if they're real Apple APIs or just CDN subdomains
"""

import requests
import json
import urllib3
from pathlib import Path

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REPO_ROOT = Path(__file__).parent.parent
ROI_OUTPUT_DIR = REPO_ROOT / "output" / "immediate_roi"

def test_apple_endpoints():
    """Test Apple endpoints to see what they actually are"""
    
    print("=" * 60)
    print("Testing Apple Endpoints - Reality Check")
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
    
    print(f"Testing {len(apple_endpoints)} Apple endpoints...")
    print()
    print("⚠️  WARNING: These look like CDN subdomains!")
    print("   Domain: 2b4a6b31ca2273bb.apple.com")
    print("   The hash prefix suggests CDN/cache endpoints")
    print("   May NOT be in Apple's bug bounty scope")
    print()
    
    results = []
    
    # Test top 5 endpoints
    for idx, ep in enumerate(apple_endpoints[:5], 1):
        url = ep.get("url", "")
        if not url:
            continue
        
        print(f"[{idx}/5] Testing: {url}")
        
        try:
            # Test without auth
            response = requests.get(url, timeout=10, allow_redirects=False, verify=False)
            
            status = response.status_code
            headers = dict(response.headers)
            content_length = len(response.content)
            
            # Check if it's a real API or CDN
            server = headers.get("Server", "")
            content_type = headers.get("Content-Type", "")
            
            result = {
                "url": url,
                "status_code": status,
                "server": server,
                "content_type": content_type,
                "content_length": content_length,
                "is_cdn": "cloudfront" in server.lower() or "cloudflare" in server.lower() or "cdn" in server.lower(),
                "is_api": "application/json" in content_type.lower() or "api" in url.lower(),
                "response_preview": response.text[:200] if content_length < 1000 else "[Too large]"
            }
            
            results.append(result)
            
            print(f"   Status: {status}")
            print(f"   Server: {server}")
            print(f"   Content-Type: {content_type}")
            
            if result["is_cdn"]:
                print("   ⚠️  CDN endpoint detected")
            if result["is_api"]:
                print("   ✅ API endpoint detected")
            
            print()
            
        except requests.exceptions.SSLError:
            print("   ⚠️  SSL Error (may be invalid certificate)")
            results.append({
                "url": url,
                "error": "SSL Error"
            })
            print()
        except requests.exceptions.RequestException as e:
            print(f"   Error: {e}")
            results.append({
                "url": url,
                "error": str(e)
            })
            print()
    
    # Summary
    print("=" * 60)
    print("Test Results Summary")
    print("=" * 60)
    print()
    
    cdn_count = sum(1 for r in results if r.get("is_cdn"))
    api_count = sum(1 for r in results if r.get("is_api"))
    accessible = sum(1 for r in results if r.get("status_code", 0) < 500)
    
    print(f"Tested: {len(results)} endpoints")
    print(f"Accessible: {accessible}")
    print(f"CDN endpoints: {cdn_count}")
    print(f"API endpoints: {api_count}")
    print()
    
    if cdn_count > 0:
        print("⚠️  IMPORTANT FINDING:")
        print("   These are CDN subdomains, NOT Apple API endpoints!")
        print("   CDN subdomains are typically:")
        print("   - Out of scope for bug bounty programs")
        print("   - Just cache endpoints")
        print("   - Not exploitable")
        print()
    
    # Save results
    results_file = ROI_OUTPUT_DIR / "apple_endpoint_test_results.json"
    ROI_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"[*] Results saved to: {results_file}")
    print()
    
    print("=" * 60)
    print("Recommendation")
    print("=" * 60)
    print()
    
    if cdn_count > 0 or not results:
        print("❌ These are NOT valid Apple endpoints for bug bounty")
        print()
        print("✅ Better options:")
        print("1. Focus on REAL bug bounty programs:")
        print("   - Mastercard (check if you have endpoints)")
        print("   - Atlassian (check if you have endpoints)")
        print("   - Kraken (check if you have endpoints)")
        print()
        print("2. Check what endpoints you actually have:")
        print("   cat output/immediate_roi/priority_endpoints.json | grep -v paypal")
        print()
    else:
        print("✅ These appear to be real endpoints")
        print("   Continue manual testing")
    
    print("=" * 60)

if __name__ == "__main__":
    test_apple_endpoints()
