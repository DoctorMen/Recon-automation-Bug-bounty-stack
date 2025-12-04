#!/usr/bin/env python3
"""
AUTHORIZATION CREATOR - Create legal authorization files
Copyright © 2025 DoctorMen. All Rights Reserved.

Creates authorization files required before any security scanning.
"""

import argparse
from LEGAL_AUTHORIZATION_SYSTEM import LegalAuthorizationShield

def main():
    parser = argparse.ArgumentParser(
        description='Create authorization file for security assessment',
        epilog='Authorization is REQUIRED before any scanning. No exceptions.'
    )
    parser.add_argument('--target', required=True, help='Target domain or IP')
    parser.add_argument('--client', required=True, help='Client company name')
    parser.add_argument('--output', help='Output file path (optional)')
    
    args = parser.parse_args()
    
    print("\n" + "="*60)
    print("AUTHORIZATION FILE CREATOR")
    print("="*60)
    print(f"\nTarget: {args.target}")
    print(f"Client: {args.client}")
    
    shield = LegalAuthorizationShield()
    auth_file = shield.create_authorization_template(
        target=args.target,
        client_name=args.client,
        output_file=args.output
    )
    
    print(f"\n{'='*60}")
    print("NEXT STEPS - CRITICAL:")
    print("="*60)
    print(f"\n1. EDIT the file: {auth_file}")
    print(f"   - Replace ALL placeholder values")
    print(f"   - Add all in-scope targets to 'scope' array")
    print(f"   - Set correct start_date and end_date")
    print(f"   - Add client contact information")
    
    print(f"\n2. GET CLIENT SIGNATURE")
    print(f"   - Email to client for review")
    print(f"   - Get written confirmation (reply email minimum)")
    print(f"   - Add signature_date to file")
    
    print(f"\n3. SAVE ORIGINAL")
    print(f"   - Keep signed copy forever (legal protection)")
    print(f"   - Multiple backups")
    
    print(f"\n4. THEN SCAN")
    print(f"   python3 SENTINEL_AGENT.py {args.target} --tier basic")
    
    print(f"\n⚠️  WITHOUT SIGNED AUTHORIZATION = ILLEGAL SCANNING")
    print(f"{'='*60}\n")

if __name__ == '__main__':
    main()
