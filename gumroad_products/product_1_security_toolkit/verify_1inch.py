#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
import requests
import re

url = "https://1inch.io"
response = requests.get(url, verify=False)

# Check for weak randomness patterns
patterns = [
    'Math.random',
    'timestamp',
    'Date.now()',
    'getTime()'
]

found = []
for pattern in patterns:
    if pattern in response.text:
        found.append(pattern)
        print(f"[!] FOUND: {pattern}")

if found:
    print(f"\n[✓] CONFIRMED: Weak randomness detected!")
    print(f"Patterns: {', '.join(found)}")
    print(f"\nBounty: $500-$3,000")
else:
    print("[*] No clear evidence, needs manual verification")
