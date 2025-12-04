#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Follow Apple Endpoint Redirects
See where the 301 redirects are going
"""

import requests
import urllib3
from pathlib import Path

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def follow_redirects():
    """Follow redirects to see where they lead"""
    
    url = "http://2b4a6b31ca2273bb.apple.com/api/checkout"
    
    print("=" * 60)
    print("Following Apple Endpoint Redirects")
    print("=" * 60)
    print()
    print(f"Starting URL: {url}")
    print()
    
    try:
        # Follow redirects
        response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
        
        print(f"Final URL: {response.url}")
        print(f"Final Status: {response.status_code}")
        print(f"Final Server: {response.headers.get('Server', 'N/A')}")
        print(f"Final Content-Type: {response.headers.get('Content-Type', 'N/A')}")
        print(f"Content Length: {len(response.content)}")
        print()
        
        # Show redirect history
        if response.history:
            print("Redirect Chain:")
            for idx, hist in enumerate(response.history, 1):
                print(f"  {idx}. {hist.status_code} -> {hist.url}")
            print()
        
        # Show response preview
        if len(response.content) < 500:
            print("Response Preview:")
            print(response.text[:500])
        else:
            print("Response Preview (first 200 chars):")
            print(response.text[:200])
            print()
        
        # Analysis
        print("=" * 60)
        print("Analysis")
        print("=" * 60)
        print()
        
        if "https://" in response.url:
            print("✅ Redirected to HTTPS")
            print("   This is normal security practice")
        
        if "apple.com" in response.url:
            print("✅ Still on Apple domain")
        else:
            print("⚠️  Redirected to different domain")
            print(f"   New domain: {response.url}")
        
        if response.status_code == 200:
            print("⚠️  Got 200 - endpoint is accessible!")
            print("   Check if this is in Apple's bug bounty scope")
        elif response.status_code == 403:
            print("✅ Got 403 - protected (good security)")
        elif response.status_code == 404:
            print("ℹ️  Got 404 - endpoint not found")
        elif response.status_code >= 400:
            print(f"Status {response.status_code} - protected or error")
        
        print()
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    follow_redirects()






