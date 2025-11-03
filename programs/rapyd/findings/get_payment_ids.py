#!/usr/bin/env python3
"""
Get Payment IDs from Rapyd API
Lists payments from Account B to use for IDOR testing
"""

import sys
import json
import requests
import os
from pathlib import Path

def get_payments(token, limit=10):
    """Get list of payments from API"""
    print("=" * 60)
    print("Fetching Payments from Rapyd API")
    print("=" * 60)
    print()
    
    # Try different endpoints
    endpoints = [
        "https://sandboxapi.rapyd.net/v1/payments",
        "https://sandboxapi.rapyd.net/v1/data/payments",
        "https://sandboxapi.rapyd.net/v1/data/payments/list",
    ]
    
    headers = {
        'Authorization': f'Bearer {token}',
        'X-Bugcrowd': 'Bugcrowd-DoctorMen',
        'Content-Type': 'application/json'
    }
    
    for endpoint in endpoints:
        print(f"[*] Trying: {endpoint}")
        
        # Try GET first
        try:
            resp = requests.get(endpoint, headers=headers, timeout=30)
            print(f"    GET {endpoint}: {resp.status_code}")
            
            if resp.status_code == 200:
                data = resp.json()
                print(f"    ✓ Success!")
                return data
        except Exception as e:
            print(f"    ✗ Error: {e}")
        
        # Try POST with pagination
        try:
            payload = {"limit": limit}
            resp = requests.post(endpoint, headers=headers, json=payload, timeout=30)
            print(f"    POST {endpoint}: {resp.status_code}")
            
            if resp.status_code == 200:
                data = resp.json()
                print(f"    ✓ Success!")
                return data
        except Exception as e:
            print(f"    ✗ Error: {e}")
        
        print()
    
    return None

def extract_payment_ids(data):
    """Extract payment IDs from API response"""
    payment_ids = []
    
    if isinstance(data, dict):
        # Check common response structures
        if 'data' in data:
            items = data['data']
        elif 'result' in data:
            items = data['result']
        elif 'payments' in data:
            items = data['payments']
        else:
            items = [data]
    elif isinstance(data, list):
        items = data
    else:
        items = []
    
    for item in items:
        if isinstance(item, dict):
            # Check for payment ID in various formats
            payment_id = (
                item.get('id') or
                item.get('payment_id') or
                item.get('paymentId') or
                item.get('paymentID')
            )
            if payment_id:
                payment_ids.append(payment_id)
    
    return payment_ids

def main():
    # Try to get token from argument, env var, or credentials
    if len(sys.argv) > 1:
        token_b = sys.argv[1]
    else:
        token_b = os.environ.get('TOKEN_B', '')
        if not token_b:
            # Try RAPYD_SECRET_KEY as fallback
            token_b = os.environ.get('RAPYD_SECRET_KEY', '')
    
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    
    if not token_b:
        print("Error: TOKEN_B not provided")
        print()
        print("Options:")
        print("1. Set environment variable:")
        print("   export TOKEN_B='your_token'")
        print("   python3 get_payment_ids.py")
        print()
        print("2. Pass as argument:")
        print("   python3 get_payment_ids.py TOKEN_B 10")
        print()
        print("3. Load from credentials.sh:")
        print("   source ../credentials.sh")
        print("   python3 get_payment_ids.py $TOKEN_B")
        print()
        print("Note: TOKEN_B should be the API token from Account B")
        sys.exit(1)
    
    print(f"[*] Using token: {token_b[:20]}...")
    print(f"[*] Limit: {limit}")
    print()
    
    # Get payments
    data = get_payments(token_b, limit)
    
    if not data:
        print("=" * 60)
        print("❌ Could not fetch payments from API")
        print("=" * 60)
        print()
        print("Possible reasons:")
        print("1. Token might be invalid or expired")
        print("2. Account B might not have any payments")
        print("3. API endpoint structure might be different")
        print()
        print("Manual alternative:")
        print("1. Log into dashboard.rapyd.net with Account B")
        print("2. Navigate to Collect → Payments")
        print("3. Create a payment or find an existing one")
        print("4. Click on a payment to view details")
        print("5. Copy the payment ID from the URL or payment details")
        print()
        sys.exit(1)
    
    print()
    print("=" * 60)
    print("Raw API Response:")
    print("=" * 60)
    print(json.dumps(data, indent=2)[:1000])  # First 1000 chars
    print()
    
    # Extract payment IDs
    payment_ids = extract_payment_ids(data)
    
    print("=" * 60)
    if payment_ids:
        print(f"✅ Found {len(payment_ids)} Payment ID(s):")
        print("=" * 60)
        for i, pid in enumerate(payment_ids, 1):
            print(f"{i}. {pid}")
        print()
        print("Use one of these IDs for IDOR testing:")
        print(f"  python3 quick_api_test.py \"$TOKEN_A\" \"$TOKEN_B\" \"{payment_ids[0]}\"")
        print()
        
        # Save to file
        output_file = Path("payment_ids.txt")
        with open(output_file, 'w') as f:
            for pid in payment_ids:
                f.write(f"{pid}\n")
        print(f"✅ Saved to: {output_file}")
    else:
        print("⚠️  No payment IDs found in response")
        print("=" * 60)
        print()
        print("The API response structure might be different.")
        print("Try manual method:")
        print("1. Log into dashboard.rapyd.net")
        print("2. Navigate to Collect → Payments")
        print("3. Create or find a payment")
        print("4. Copy the payment ID")
    
    print()

if __name__ == '__main__':
    main()

