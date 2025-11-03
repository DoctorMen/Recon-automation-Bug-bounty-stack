#!/usr/bin/env python3
"""
License Check Module
Protects Bug Bounty Automation System from unauthorized use

Copyright (c) 2025 DoctorMen
Proprietary and Confidential
"""

import sys
import hashlib
from pathlib import Path

# System Identifier
SYSTEM_ID = "BB_RECON_2025_DOCTORMEN"

# Valid license hash (SHA256 of your secret key)
# Generated: 2025-11-02
VALID_LICENSE_HASH = "d49d9bf65891bfc7cc1be5b077b6c3a02f101c96fc1a8768ce70701fb2af13fc"

def check_license(silent=False):
    """
    Check if valid license file exists
    
    Args:
        silent (bool): If True, don't print error messages
        
    Returns:
        bool: True if license is valid, exits program otherwise
    """
    try:
        # Look for .license file in repo root
        script_dir = Path(__file__).parent
        license_file = script_dir / ".license"
        
        if not license_file.exists():
            if not silent:
                print("\n" + "="*70)
                print("❌ LICENSE FILE NOT FOUND")
                print("="*70)
                print("This system requires valid licensing to operate.")
                print(f"System ID: {SYSTEM_ID}")
                print("\nExpected license file: .license")
                print("\nIf you are the system owner:")
                print("  1. Ensure .license file exists in repository root")
                print("  2. File should contain your license key")
                print("  3. Run: chmod 600 .license")
                print("\nFor licensing inquiries: doctormen131@outlook.com")
                print("="*70)
            sys.exit(1)
        
        # Read and validate license key
        with open(license_file, 'r') as f:
            key = f.read().strip()
        
        # Compute hash of provided key
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        
        # Compare to valid hash
        if key_hash != VALID_LICENSE_HASH:
            if not silent:
                print("\n" + "="*70)
                print("❌ INVALID LICENSE KEY")
                print("="*70)
                print("The license key in .license file is not valid.")
                print(f"System ID: {SYSTEM_ID}")
                print("\nThis system is licensed and protected.")
                print("Unauthorized use is prohibited and may be tracked.")
                print("\nFor legitimate licensing: doctormen131@outlook.com")
                print("="*70)
            sys.exit(1)
        
        # License is valid
        return True
        
    except Exception as e:
        if not silent:
            print(f"\n❌ License validation error: {e}")
            print(f"System ID: {SYSTEM_ID}")
        sys.exit(1)

def generate_license_key():
    """
    Generate a new random license key
    Use this once to create your license key, then save it to .license
    
    Returns:
        str: A secure random license key
    """
    import secrets
    # Generate a 32-byte (256-bit) random key
    key = secrets.token_hex(32)
    return key

def display_license_hash(key):
    """
    Display the SHA256 hash of a license key
    Use this to get the hash to put in VALID_LICENSE_HASH
    
    Args:
        key (str): The license key to hash
    """
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    print("\n" + "="*70)
    print("LICENSE KEY HASH")
    print("="*70)
    print(f"Key: {key}")
    print(f"SHA256 Hash: {key_hash}")
    print("\nAdd this hash to license_check.py:")
    print(f'VALID_LICENSE_HASH = "{key_hash}"')
    print("="*70)

if __name__ == "__main__":
    """
    Run this directly to:
    1. Generate a new license key
    2. Get the hash for VALID_LICENSE_HASH
    3. Test license validation
    """
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "generate":
            # Generate new license key
            print("\n🔐 Generating new license key...")
            key = generate_license_key()
            display_license_hash(key)
            print("\nNext steps:")
            print(f"1. Save key to file: echo '{key}' > .license")
            print("2. Set permissions: chmod 600 .license")
            print("3. Update VALID_LICENSE_HASH in license_check.py")
            print("4. Add .license to .gitignore")
            
        elif sys.argv[1] == "test":
            # Test current license
            print("\n🧪 Testing license validation...")
            if check_license(silent=False):
                print("\n✅ License valid!")
                print(f"System ID: {SYSTEM_ID}")
                
        elif sys.argv[1] == "hash":
            # Get hash of provided key
            if len(sys.argv) > 2:
                key = sys.argv[2]
                display_license_hash(key)
            else:
                print("Usage: python3 license_check.py hash <your_key>")
        else:
            print("Usage:")
            print("  python3 license_check.py generate  - Generate new license key")
            print("  python3 license_check.py test      - Test current license")
            print("  python3 license_check.py hash <key> - Get hash of a key")
    else:
        # Default: test license
        print("\n🧪 Testing license validation...")
        if check_license(silent=False):
            print("\n✅ License valid!")
            print(f"System ID: {SYSTEM_ID}")

# System ID: BB_RECON_2025_DOCTORMEN
# Owner: DoctorMen
# Build Date: 2025-11-02

