#!/usr/bin/env python3
"""
Simple Live Host Checker
Replacement for httpx -silent
"""

import requests
import sys
import concurrent.futures
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def check_url(url):
    # Ensure schema
    target = url if url.startswith("http") else f"https://{url}"
    try:
        r = requests.get(target, timeout=5, verify=False, allow_redirects=True)
        # If https fails, try http? No, usually https is fine for modern bug bounty, 
        # but strict checking would try both. For speed, we stick to https preference.
        return target
    except:
        # Try http fallback
        try:
            target_http = f"http://{url}"
            r = requests.get(target_http, timeout=5)
            return target_http
        except:
            return None

if __name__ == "__main__":
    # Read from stdin
    domains = [line.strip() for line in sys.stdin if line.strip()]
    
    print(f"[*] Checking {len(domains)} domains for liveness...", file=sys.stderr)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_url, d): d for d in domains}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                print(result)
