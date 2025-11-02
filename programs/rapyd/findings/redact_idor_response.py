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

"""
IDOR Evidence Redaction Script
Redacts sensitive data from API responses while preserving evidence of IDOR vulnerability.

Usage:
    python3 redact_idor_response.py [input_file] [output_file]
    
Default:
    input_file:  evidence/idor_response_raw.json
    output_file: evidence/idor_response_redacted.json
"""

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

# Fields to always redact
SENSITIVE_FIELDS = [
    'email', 'phone', 'phone_number', 'cvv', 'ssn', 
    'card_number', 'name', 'full_name', 'last_name', 'first_name',
    'last4', 'expiration_month', 'expiration_year',
    'billing_address', 'shipping_address', 'street', 'city', 'zip',
    'address', 'address_line1', 'address_line2', 'postal_code',
    'account_number', 'bank_account', 'routing_number'
]

# Fields to preserve (evidence-related)
PRESERVE_FIELDS = [
    'id', 'payment_id', 'operation_id', 'status', 'status_code',
    'amount', 'currency', 'created_at', 'timestamp', 'date',
    'type', 'method', 'status', 'message'
]


def redact_email(value: str) -> str:
    """Redact email addresses"""
    if '@' in value and '.' in value:
        # Check if it's already redacted
        if value.startswith('[REDACTED'):
            return value
        # Redact email
        parts = value.split('@')
        if len(parts) == 2:
            domain = parts[1].split('.')[0]
            return f"[REDACTED_EMAIL@{domain}.com]"
    return value


def redact_phone(value: str) -> str:
    """Redact phone numbers"""
    # Remove common formatting
    cleaned = re.sub(r'[\s\-\(\)\+]', '', value)
    # Check if it's a phone number (10-15 digits)
    if re.match(r'^\d{10,15}$', cleaned):
        return "[REDACTED_PHONE]"
    return value


def redact_card_number(value: str) -> str:
    """Redact credit card numbers"""
    cleaned = re.sub(r'[\s\-]', '', str(value))
    # Check if it's a card number (13-19 digits)
    if re.match(r'^\d{13,19}$', cleaned):
        return "[REDACTED_CARD]"
    return value


def redact_value(obj: Any, path: str = '') -> Any:
    """Recursively redact sensitive values in strings"""
    if isinstance(obj, dict):
        return {k: redact_value(v, f"{path}.{k}" if path else k) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [redact_value(item, path) for item in obj]
    elif isinstance(obj, str):
        # Apply redaction functions
        result = redact_email(obj)
        result = redact_phone(result)
        result = redact_card_number(result)
        return result
    else:
        return obj


def deep_redact(obj: Any, path: str = '') -> Any:
    """Redact specific sensitive fields"""
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            field_path = f"{path}.{k}" if path else k
            key_lower = k.lower()
            
            # Check if this field should be redacted
            should_redact = False
            for sensitive_field in SENSITIVE_FIELDS:
                if sensitive_field in key_lower:
                    should_redact = True
                    break
            
            # Preserve evidence fields
            should_preserve = False
            for preserve_field in PRESERVE_FIELDS:
                if preserve_field in key_lower:
                    should_preserve = True
                    break
            
            if should_redact and not should_preserve:
                result[k] = "[REDACTED]"
            else:
                result[k] = deep_redact(v, field_path)
        return result
    elif isinstance(obj, list):
        return [deep_redact(item, path) for item in obj]
    else:
        return obj


def redact_json(input_file: Path, output_file: Path) -> bool:
    """Redact sensitive data from JSON file"""
    try:
        # Load raw response
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        print(f"✅ Loaded JSON from: {input_file}")
        
        # Apply redaction
        redacted = deep_redact(redact_value(data))
        
        # Save redacted version
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(redacted, f, indent=2)
        
        print(f"✅ Redacted JSON saved to: {output_file}")
        
        # Show statistics
        original_size = len(json.dumps(data))
        redacted_size = len(json.dumps(redacted))
        print(f"\n📊 Statistics:")
        print(f"   Original size: {original_size:,} bytes")
        print(f"   Redacted size: {redacted_size:,} bytes")
        print(f"   Reduction: {original_size - redacted_size:,} bytes")
        
        return True
        
    except FileNotFoundError:
        print(f"❌ Error: File not found: {input_file}")
        print(f"   Please ensure the file exists before running redaction.")
        return False
    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON in {input_file}")
        print(f"   {e}")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def main():
    """Main function"""
    # Default paths
    evidence_dir = Path(__file__).parent / "evidence"
    
    # Get input/output files from command line or use defaults
    if len(sys.argv) >= 2:
        input_file = Path(sys.argv[1])
    else:
        input_file = evidence_dir / "idor_response_raw.json"
    
    if len(sys.argv) >= 3:
        output_file = Path(sys.argv[2])
    else:
        output_file = evidence_dir / "idor_response_redacted.json"
    
    # Ensure evidence directory exists
    evidence_dir.mkdir(parents=True, exist_ok=True)
    
    print("="*70)
    print("IDOR Evidence Redaction Script")
    print("="*70)
    print(f"\nInput file:  {input_file}")
    print(f"Output file: {output_file}")
    print("\nRedacting sensitive data (emails, phone numbers, card numbers, etc.)")
    print("Preserving evidence fields (IDs, timestamps, amounts, etc.)")
    print("-"*70)
    
    success = redact_json(input_file, output_file)
    
    if success:
        print("\n✅ Redaction complete!")
        print("\n📋 Next steps:")
        print("   1. Review the redacted JSON file")
        print("   2. Verify all sensitive data is redacted")
        print("   3. Ensure evidence fields are preserved")
        print("   4. Use redacted JSON in bug bounty report")
    else:
        print("\n❌ Redaction failed. Please check errors above.")
        sys.exit(1)


if __name__ == "__main__":
    main()


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
