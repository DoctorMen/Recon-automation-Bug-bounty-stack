#!/usr/bin/env python3
"""
Quick Test - Single Apple Endpoint
Fast test to see what one endpoint actually is
"""

import requests
import sys

if len(sys.argv) < 2:
    url = "http://2b4a6b31ca2273bb.apple.com/api/checkout"
else:
    url = sys.argv[1]

print(f"Testing: {url}")
print()

try:
    response = requests.get(url, timeout=10, allow_redirects=False, verify=False)
    
    print(f"Status: {response.status_code}")
    print(f"Server: {response.headers.get('Server', 'N/A')}")
    print(f"Content-Type: {response.headers.get('Content-Type', 'N/A')}")
    print(f"Content-Length: {len(response.content)}")
    print()
    
    if len(response.content) < 500:
        print("Response:")
        print(response.text[:500])
    else:
        print("Response too large, showing first 200 chars:")
        print(response.text[:200])
        
except Exception as e:
    print(f"Error: {e}")


