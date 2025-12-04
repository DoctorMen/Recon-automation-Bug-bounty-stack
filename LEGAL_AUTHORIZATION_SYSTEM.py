#!/usr/bin/env python3
"""
LEGAL AUTHORIZATION SYSTEM - Idempotent Legal Shield
Copyright © 2025 DoctorMen. All Rights Reserved.

PREVENTS ANY SCAN WITHOUT PROPER AUTHORIZATION
Enforces legal compliance for all security tools
"""

import os
import json
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
import sys

class LegalAuthorizationShield:
    """
    Idempotent legal protection system.
    
    BLOCKS ALL SCANS unless:
    1. Written authorization file exists
    2. Target is in authorized scope
    3. Current time is within authorized window
    4. Authorization signature is valid
    
    NO EXCEPTIONS. NO BYPASSES.
    """
    
    def __init__(self, auth_dir='./authorizations'):
        self.auth_dir = Path(auth_dir)
        self.auth_dir.mkdir(parents=True, exist_ok=True)
        self.audit_log = self.auth_dir / 'audit_log.json'
        
    def check_authorization(self, target):
        """
        CRITICAL: Check if target is legally authorized
        
        Returns: (authorized: bool, reason: str, auth_data: dict)
        """
        print(f"\n{'='*60}")
        print(f"🛡️  LEGAL AUTHORIZATION CHECK")
        print(f"{'='*60}")
        print(f"Target: {target}")
        
        # Step 1: Check if authorization file exists
        auth_file = self.find_authorization_file(target)
        if not auth_file:
            reason = "NO AUTHORIZATION FILE FOUND - SCAN BLOCKED"
            self.log_blocked_attempt(target, reason)
            return False, reason, None
        
        # Step 2: Load and validate authorization
        auth_data = self.load_authorization(auth_file)
        if not auth_data:
            reason = "INVALID AUTHORIZATION FILE - SCAN BLOCKED"
            self.log_blocked_attempt(target, reason)
            return False, reason, None
        
        # Step 3: Check if target is in scope
        if not self.target_in_scope(target, auth_data):
            reason = f"TARGET OUT OF SCOPE - SCAN BLOCKED\nAuthorized: {auth_data.get('scope', [])}"
            self.log_blocked_attempt(target, reason)
            return False, reason, None
        
        # Step 4: Check time window
        if not self.within_time_window(auth_data):
            reason = f"OUTSIDE AUTHORIZED TIME WINDOW - SCAN BLOCKED\nWindow: {auth_data.get('start_date')} to {auth_data.get('end_date')}"
            self.log_blocked_attempt(target, reason)
            return False, reason, None
        
        # Step 5: Verify signature
        if not self.verify_signature(auth_data):
            reason = "INVALID AUTHORIZATION SIGNATURE - SCAN BLOCKED"
            self.log_blocked_attempt(target, reason)
            return False, reason, None
        
        # ALL CHECKS PASSED
        print(f"\n✅ AUTHORIZATION VALID")
        print(f"   Client: {auth_data.get('client_name', 'Unknown')}")
        print(f"   Authorized by: {auth_data.get('authorized_by', 'Unknown')}")
        print(f"   Valid until: {auth_data.get('end_date', 'Unknown')}")
        print(f"   Scope: {auth_data.get('scope', [])}")
        print(f"{'='*60}\n")
        
        self.log_authorized_scan(target, auth_data)
        return True, "AUTHORIZED", auth_data
    
    def find_authorization_file(self, target):
        """Find authorization file for target"""
        # Clean target name for filename
        clean_target = target.replace('https://', '').replace('http://', '').replace('/', '_').replace(':', '_')
        
        # Look for exact match
        auth_file = self.auth_dir / f"{clean_target}_authorization.json"
        if auth_file.exists():
            return auth_file
        
        # Look for any authorization file that includes this target
        for auth_file in self.auth_dir.glob('*_authorization.json'):
            auth_data = self.load_authorization(auth_file)
            if auth_data and self.target_in_scope(target, auth_data):
                return auth_file
        
        return None
    
    def load_authorization(self, auth_file):
        """Load and parse authorization file"""
        try:
            with open(auth_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"❌ Error loading authorization: {e}")
            return None
    
    def target_in_scope(self, target, auth_data):
        """Check if target is in authorized scope"""
        scope = auth_data.get('scope', [])
        
        # Clean target for comparison
        clean_target = target.replace('https://', '').replace('http://', '').replace('www.', '')
        
        for authorized in scope:
            clean_authorized = authorized.replace('https://', '').replace('http://', '').replace('www.', '')
            
            # Exact match
            if clean_target == clean_authorized:
                return True
            
            # Wildcard subdomain match (*.example.com)
            if clean_authorized.startswith('*.'):
                domain = clean_authorized[2:]
                if clean_target.endswith(domain) or clean_target == domain:
                    return True
            
            # Parent domain match
            if clean_target.endswith(clean_authorized):
                return True
        
        return False
    
    def within_time_window(self, auth_data):
        """Check if current time is within authorized window"""
        try:
            start_date = datetime.fromisoformat(auth_data['start_date'])
            end_date = datetime.fromisoformat(auth_data['end_date'])
            now = datetime.now()
            
            return start_date <= now <= end_date
        except Exception as e:
            print(f"❌ Error checking time window: {e}")
            return False
    
    def verify_signature(self, auth_data):
        """Verify authorization signature"""
        # For now, just check that required fields exist
        # In production, implement cryptographic signature verification
        required_fields = ['client_name', 'authorized_by', 'scope', 'start_date', 'end_date']
        return all(field in auth_data for field in required_fields)
    
    def log_blocked_attempt(self, target, reason):
        """Log blocked scan attempt"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'status': 'BLOCKED',
            'reason': reason,
            'user': os.environ.get('USER', 'unknown')
        }
        
        self.append_audit_log(log_entry)
        
        print(f"\n❌ SCAN BLOCKED")
        print(f"   Target: {target}")
        print(f"   Reason: {reason}")
        print(f"\n⚠️  TO AUTHORIZE THIS TARGET:")
        print(f"   1. Create authorization file: {self.auth_dir}/[target]_authorization.json")
        print(f"   2. Use template: ./CREATE_AUTHORIZATION.py")
        print(f"   3. Get client signature")
        print(f"   4. Try again")
        print(f"{'='*60}\n")
    
    def log_authorized_scan(self, target, auth_data):
        """Log authorized scan"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'status': 'AUTHORIZED',
            'client': auth_data.get('client_name'),
            'authorized_by': auth_data.get('authorized_by'),
            'user': os.environ.get('USER', 'unknown')
        }
        
        self.append_audit_log(log_entry)
    
    def append_audit_log(self, entry):
        """Append entry to audit log"""
        logs = []
        if self.audit_log.exists():
            with open(self.audit_log, 'r') as f:
                logs = json.load(f)
        
        logs.append(entry)
        
        with open(self.audit_log, 'w') as f:
            json.dump(logs, f, indent=2)
    
    def create_authorization_template(self, target, client_name, output_file=None):
        """Create authorization template for client signature"""
        if output_file is None:
            clean_target = target.replace('https://', '').replace('http://', '').replace('/', '_').replace(':', '_')
            output_file = self.auth_dir / f"{clean_target}_authorization.json"
        
        template = {
            "client_name": client_name,
            "target": target,
            "scope": [
                target,
                f"*.{target}",
                "# Add all authorized domains/IPs here"
            ],
            "start_date": datetime.now().isoformat(),
            "end_date": (datetime.now() + timedelta(days=30)).isoformat(),
            "authorized_by": "CLIENT_NAME_HERE",
            "authorized_by_email": "client@example.com",
            "authorized_by_title": "CEO/CTO/Authorized Representative",
            "contact_emergency": "phone_number_here",
            "testing_types_authorized": [
                "vulnerability_scanning",
                "port_scanning",
                "web_application_testing"
            ],
            "testing_types_forbidden": [
                "dos_testing",
                "social_engineering",
                "physical_access"
            ],
            "notes": "Replace all placeholder values before use",
            "signature_date": None,
            "signature_hash": None
        }
        
        with open(output_file, 'w') as f:
            json.dump(template, f, indent=2)
        
        print(f"\n✅ Authorization template created: {output_file}")
        print(f"\n⚠️  REQUIRED BEFORE USE:")
        print(f"   1. Fill in all placeholder values")
        print(f"   2. Get client signature (email confirmation minimum)")
        print(f"   3. Update signature_date and signature_hash")
        print(f"   4. Keep original signed copy forever (legal protection)")
        
        return output_file


def require_authorization(func):
    """
    Decorator to enforce authorization on any function
    
    Usage:
        @require_authorization
        def scan_target(target):
            # This will only run if authorized
            pass
    """
    def wrapper(target, *args, **kwargs):
        shield = LegalAuthorizationShield()
        authorized, reason, auth_data = shield.check_authorization(target)
        
        if not authorized:
            print(f"\n🚫 FUNCTION BLOCKED: {func.__name__}")
            print(f"   Reason: {reason}\n")
            sys.exit(1)
        
        # Authorization valid - proceed
        return func(target, *args, **kwargs)
    
    return wrapper


# Example usage
if __name__ == '__main__':
    shield = LegalAuthorizationShield()
    
    print("LEGAL AUTHORIZATION SHIELD - TEST MODE")
    print("\nAttempting to scan without authorization...")
    
    authorized, reason, auth_data = shield.check_authorization("example.com")
    
    if not authorized:
        print(f"\n✅ Shield working correctly - unauthorized scan blocked")
        print(f"\nCreating authorization template...")
        shield.create_authorization_template("example.com", "Example Corp")
    else:
        print(f"\n⚠️  Warning: Scan was authorized")
