#!/usr/bin/env python3
"""
PROTECT_DATA - CLI tool for DATA FORTRESS™
Copyright © 2025 DoctorMen. All Rights Reserved.

Easy command-line interface for protecting your data
"""

import sys
import argparse
from pathlib import Path
from DATA_FORTRESS import DataFortress, SecurityException

def main():
    parser = argparse.ArgumentParser(
        description='DATA FORTRESS™ - Protect your data from unauthorized access',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Encrypt a single file
  python3 PROTECT_DATA.py encrypt output/report.json
  
  # Decrypt a file
  python3 PROTECT_DATA.py decrypt .data_fortress/encrypted/report.json.encrypted
  
  # Protect entire output directory
  python3 PROTECT_DATA.py protect-dir output/
  
  # Redact PII from a file
  python3 PROTECT_DATA.py redact-file output/scan_results.txt
  
  # Generate security report
  python3 PROTECT_DATA.py report
  
  # Quick protect (encrypt all sensitive data)
  python3 PROTECT_DATA.py quick-protect
        '''
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
    encrypt_parser.add_argument('file', help='File to encrypt')
    encrypt_parser.add_argument('--delete', action='store_true', 
                               help='Securely delete original after encryption')
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('file', help='Encrypted file to decrypt')
    decrypt_parser.add_argument('-o', '--output', help='Output path for decrypted file')
    
    # Protect directory command
    protect_parser = subparsers.add_parser('protect-dir', 
                                           help='Encrypt all sensitive files in directory')
    protect_parser.add_argument('directory', help='Directory to protect')
    protect_parser.add_argument('--extensions', nargs='+', 
                               help='File extensions to encrypt (default: all sensitive)')
    protect_parser.add_argument('--delete', action='store_true',
                               help='Securely delete originals after encryption')
    
    # Redact PII command
    redact_parser = subparsers.add_parser('redact-file', help='Redact PII from a text file')
    redact_parser.add_argument('file', help='File to redact PII from')
    redact_parser.add_argument('-o', '--output', help='Output path (default: overwrite)')
    
    # Report command
    subparsers.add_parser('report', help='Generate security report')
    
    # Quick protect command
    quick_parser = subparsers.add_parser('quick-protect', 
                                         help='Quickly protect all sensitive data')
    quick_parser.add_argument('--delete', action='store_true',
                             help='Securely delete originals')
    
    # Verify command
    verify_parser = subparsers.add_parser('verify', help='Verify file integrity')
    verify_parser.add_argument('file', help='File to verify')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        fortress = DataFortress()
        
        if args.command == 'encrypt':
            encrypted_path = fortress.encrypt_file(args.file, delete_original=args.delete)
            print(f"\n✅ SUCCESS: File encrypted to {encrypted_path}")
        
        elif args.command == 'decrypt':
            decrypted_path = fortress.decrypt_file(args.file, output_path=args.output)
            print(f"\n✅ SUCCESS: File decrypted to {decrypted_path}")
        
        elif args.command == 'protect-dir':
            fortress.protect_directory(args.directory, 
                                      extensions=args.extensions,
                                      delete_originals=args.delete)
            print(f"\n✅ SUCCESS: Directory protected")
        
        elif args.command == 'redact-file':
            with open(args.file, 'r') as f:
                text = f.read()
            
            redacted = fortress.redact_pii(text)
            
            output_path = args.output if args.output else args.file
            with open(output_path, 'w') as f:
                f.write(redacted)
            
            print(f"\n✅ SUCCESS: PII redacted in {output_path}")
        
        elif args.command == 'report':
            fortress.generate_report()
        
        elif args.command == 'quick-protect':
            print("\n🛡️  QUICK PROTECT - Securing all sensitive data...")
            
            # Protect common sensitive directories
            sensitive_dirs = [
                'output',
                'authorizations',
                'data',
                '.data_fortress'
            ]
            
            for dir_path in sensitive_dirs:
                if Path(dir_path).exists():
                    print(f"\nProtecting: {dir_path}")
                    fortress.protect_directory(dir_path, delete_originals=args.delete)
            
            print("\n✅ QUICK PROTECT COMPLETE")
            fortress.generate_report()
        
        elif args.command == 'verify':
            if fortress._verify_integrity(Path(args.file)):
                print(f"\n✅ INTEGRITY VERIFIED: {args.file}")
                print("   File has not been tampered with")
            else:
                print(f"\n🚨 INTEGRITY VIOLATION: {args.file}")
                print("   ⚠️  WARNING: File may have been tampered with!")
                sys.exit(1)
    
    except SecurityException as e:
        print(f"\n🚨 SECURITY ERROR: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
