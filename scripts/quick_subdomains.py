#!/usr/bin/env python3
"""
Quick Subdomain Enum (crt.sh)
Fetches subdomains from Certificate Transparency logs.
Fallback when subfinder is not installed.
"""

import requests
import sys
import json
import re

def get_subdomains(domain):
    print(f"[*] Querying crt.sh for {domain}...")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=20)
        if r.status_code != 200:
            print("[-] Error contacting crt.sh")
            return []
            
        data = r.json()
        subs = set()
        for item in data:
            name = item.get('name_value', '')
            # Handle multi-line entries
            for sub in name.split('\n'):
                if '*' not in sub and sub.endswith(domain):
                    subs.add(sub.lower())
        return list(subs)
    except Exception as e:
        print(f"[-] Exception: {e}")
        return []

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 quick_subdomains.py <domain1> [domain2...]")
        sys.exit(1)
        
    all_subs = set()
    for d in sys.argv[1:]:
        results = get_subdomains(d)
        print(f"[*] Found {len(results)} subdomains for {d}")
        all_subs.update(results)
        
    # Print to stdout for piping
    for s in sorted(all_subs):
        print(s)
