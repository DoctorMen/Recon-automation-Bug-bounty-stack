#!/usr/bin/env python3
"""
🛡️ AUTHORIZATION CHECKER - LEGAL SAFEGUARD SYSTEM
Copyright © 2025. All Rights Reserved.

CRITICAL: This module ensures all security testing is AUTHORIZED and LEGAL.
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, List
import sys

class AuthorizationChecker:
    """
    Enforces legal and ethical requirements before any security testing.
    BLOCKS unauthorized or illegal operations.
    """
    
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.auth_dir = self.base_dir / "authorizations"
        self.auth_dir.mkdir(parents=True, exist_ok=True)
        
        self.auth_file = self.auth_dir / "authorized_targets.json"
        self.log_file = self.auth_dir / "authorization_log.json"
        
        # Load authorized targets
        self.authorized_targets = self.load_authorizations()
        
    def load_authorizations(self) -> Dict:
        """Load list of authorized targets"""
        if self.auth_file.exists():
            with open(self.auth_file, 'r') as f:
                return json.load(f)
        return {
            "targets": [],
            "last_updated": None
        }
    
    def save_authorizations(self):
        """Save authorized targets"""
        self.authorized_targets["last_updated"] = datetime.now().isoformat()
        with open(self.auth_file, 'w') as f:
            json.dump(self.authorized_targets, f, indent=2)
    
    def log_authorization_check(self, target: str, authorized: bool, reason: str):
        """Log all authorization checks for audit trail"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "authorized": authorized,
            "reason": reason
        }
        
        logs = []
        if self.log_file.exists():
            with open(self.log_file, 'r') as f:
                logs = json.load(f)
        
        logs.append(log_entry)
        
        with open(self.log_file, 'w') as f:
            json.dump(logs, f, indent=2)
    
    def check_authorization(self, target: str, operation: str = "scan") -> tuple[bool, str]:
        """
        Check if target is authorized for security testing.
        
        Returns: (authorized: bool, reason: str)
        """
        
        # Check if target is in authorized list
        for auth_target in self.authorized_targets.get("targets", []):
            if auth_target["target"] == target:
                # Check if authorization is still valid
                if self.is_authorization_valid(auth_target):
                    reason = f"✅ AUTHORIZED: {auth_target.get('authorization_type', 'Unknown')}"
                    self.log_authorization_check(target, True, reason)
                    return True, reason
                else:
                    reason = "❌ AUTHORIZATION EXPIRED"
                    self.log_authorization_check(target, False, reason)
                    return False, reason
        
        # Target not found in authorized list
        reason = "❌ NO AUTHORIZATION FOUND - Written permission required"
        self.log_authorization_check(target, False, reason)
        return False, reason
    
    def is_authorization_valid(self, auth_target: Dict) -> bool:
        """Check if authorization is still valid (not expired)"""
        if "expiry_date" not in auth_target:
            return True  # No expiry set
        
        expiry = datetime.fromisoformat(auth_target["expiry_date"])
        return datetime.now() < expiry
    
    def add_authorization(self, 
                         target: str,
                         authorization_type: str,
                         client_name: str,
                         contract_reference: str,
                         scope: List[str],
                         expiry_date: Optional[str] = None,
                         contact_email: Optional[str] = None,
                         notes: Optional[str] = None) -> bool:
        """
        Add a new authorized target with full documentation.
        
        Args:
            target: Domain or system to authorize
            authorization_type: "client_contract", "bug_bounty", "own_system"
            client_name: Name of authorizing party
            contract_reference: Contract number or reference
            scope: List of what's in scope
            expiry_date: When authorization expires (ISO format)
            contact_email: Emergency contact
            notes: Additional notes
        """
        
        auth_entry = {
            "target": target,
            "authorization_type": authorization_type,
            "client_name": client_name,
            "contract_reference": contract_reference,
            "scope": scope,
            "authorized_date": datetime.now().isoformat(),
            "expiry_date": expiry_date,
            "contact_email": contact_email,
            "notes": notes,
            "added_by": os.getenv("USER", "unknown")
        }
        
        # Check if target already exists
        for i, existing in enumerate(self.authorized_targets.get("targets", [])):
            if existing["target"] == target:
                # Update existing
                self.authorized_targets["targets"][i] = auth_entry
                self.save_authorizations()
                print(f"✅ Updated authorization for: {target}")
                return True
        
        # Add new
        if "targets" not in self.authorized_targets:
            self.authorized_targets["targets"] = []
        
        self.authorized_targets["targets"].append(auth_entry)
        self.save_authorizations()
        print(f"✅ Added authorization for: {target}")
        return True
    
    def remove_authorization(self, target: str) -> bool:
        """Remove authorization for a target"""
        original_count = len(self.authorized_targets.get("targets", []))
        
        self.authorized_targets["targets"] = [
            t for t in self.authorized_targets.get("targets", [])
            if t["target"] != target
        ]
        
        if len(self.authorized_targets["targets"]) < original_count:
            self.save_authorizations()
            print(f"✅ Removed authorization for: {target}")
            return True
        
        print(f"⚠️  No authorization found for: {target}")
        return False
    
    def list_authorizations(self):
        """List all current authorizations"""
        print("\n" + "="*80)
        print("📋 AUTHORIZED TARGETS")
        print("="*80)
        
        if not self.authorized_targets.get("targets"):
            print("⚠️  No authorized targets found.")
            print("\nYou must add authorization before scanning any target.")
            print("Use: add_authorization() method")
            return
        
        for i, target in enumerate(self.authorized_targets["targets"], 1):
            print(f"\n[{i}] {target['target']}")
            print(f"    Type: {target['authorization_type']}")
            print(f"    Client: {target['client_name']}")
            print(f"    Contract: {target['contract_reference']}")
            print(f"    Authorized: {target['authorized_date']}")
            
            if target.get('expiry_date'):
                expiry = datetime.fromisoformat(target['expiry_date'])
                if datetime.now() < expiry:
                    print(f"    Expires: {target['expiry_date']} ✅")
                else:
                    print(f"    Expires: {target['expiry_date']} ❌ EXPIRED")
            
            if target.get('scope'):
                print(f"    Scope: {', '.join(target['scope'])}")
            
            if target.get('contact_email'):
                print(f"    Contact: {target['contact_email']}")
        
        print("\n" + "="*80)
    
    def require_authorization(self, target: str, operation: str = "scan"):
        """
        Decorator/function to require authorization before proceeding.
        Raises exception if not authorized.
        """
        authorized, reason = self.check_authorization(target, operation)
        
        if not authorized:
            error_msg = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                         🚨 AUTHORIZATION REQUIRED 🚨                         ║
╚══════════════════════════════════════════════════════════════════════════════╝

Target: {target}
Operation: {operation}
Status: {reason}

⚠️  CRITICAL: You MUST have written authorization before scanning any system.

REQUIRED DOCUMENTATION:
  1. ✅ Written permission from system owner
  2. ✅ Signed contract or authorization letter
  3. ✅ Clear scope definition
  4. ✅ Legal agreement

TO ADD AUTHORIZATION:
  
  from authorization_checker import AuthorizationChecker
  
  checker = AuthorizationChecker()
  checker.add_authorization(
      target="{target}",
      authorization_type="client_contract",  # or "bug_bounty" or "own_system"
      client_name="Client Name",
      contract_reference="Contract #12345",
      scope=["web_scan", "api_test"],
      expiry_date="2025-12-31T23:59:59",
      contact_email="client@example.com",
      notes="Full penetration test authorized"
  )

LEGAL CONSEQUENCES OF UNAUTHORIZED ACCESS:
  - Criminal prosecution under CFAA
  - Civil lawsuits
  - Financial penalties
  - Imprisonment
  - Professional reputation damage

DO NOT PROCEED WITHOUT AUTHORIZATION.

For more information, see: LEGAL_SAFEGUARDS.md
            """
            
            print(error_msg)
            raise PermissionError(f"AUTHORIZATION REQUIRED: {reason}")
        
        print(f"✅ Authorization verified: {reason}")
        return True


# Convenience functions
def check_authorization(target: str) -> bool:
    """Quick check if target is authorized"""
    checker = AuthorizationChecker()
    authorized, reason = checker.check_authorization(target)
    print(f"{reason}")
    return authorized


def require_authorization(target: str):
    """Require authorization or raise exception"""
    checker = AuthorizationChecker()
    return checker.require_authorization(target)


def add_authorization(**kwargs):
    """Add new authorization"""
    checker = AuthorizationChecker()
    return checker.add_authorization(**kwargs)


def list_authorizations():
    """List all authorizations"""
    checker = AuthorizationChecker()
    checker.list_authorizations()


def interactive_add_authorization():
    """Interactive CLI for adding authorization"""
    print("\n" + "="*80)
    print("📝 ADD NEW AUTHORIZATION")
    print("="*80)
    
    target = input("\nTarget domain/system: ").strip()
    
    print("\nAuthorization Type:")
    print("  1. Client Contract")
    print("  2. Bug Bounty Program")
    print("  3. Own System")
    auth_type_choice = input("Select (1-3): ").strip()
    
    auth_types = {
        "1": "client_contract",
        "2": "bug_bounty",
        "3": "own_system"
    }
    auth_type = auth_types.get(auth_type_choice, "client_contract")
    
    client_name = input("\nClient/Program Name: ").strip()
    contract_ref = input("Contract/Reference Number: ").strip()
    
    scope_input = input("Scope (comma-separated): ").strip()
    scope = [s.strip() for s in scope_input.split(",")]
    
    expiry = input("Expiry Date (YYYY-MM-DD) or leave blank: ").strip()
    if expiry:
        expiry = f"{expiry}T23:59:59"
    else:
        expiry = None
    
    contact = input("Contact Email: ").strip()
    notes = input("Notes: ").strip()
    
    checker = AuthorizationChecker()
    checker.add_authorization(
        target=target,
        authorization_type=auth_type,
        client_name=client_name,
        contract_reference=contract_ref,
        scope=scope,
        expiry_date=expiry,
        contact_email=contact if contact else None,
        notes=notes if notes else None
    )
    
    print("\n✅ Authorization added successfully!")
    print("\nYou can now scan this target legally.")


if __name__ == "__main__":
    """CLI interface for authorization management"""
    
    if len(sys.argv) < 2:
        print("""
🛡️ AUTHORIZATION CHECKER - Legal Safeguard System

Usage:
  python authorization_checker.py list                    - List all authorizations
  python authorization_checker.py check <target>          - Check if target is authorized
  python authorization_checker.py add                     - Interactive add authorization
  python authorization_checker.py remove <target>         - Remove authorization

Examples:
  python authorization_checker.py list
  python authorization_checker.py check example.com
  python authorization_checker.py add
  python authorization_checker.py remove example.com

IMPORTANT: You MUST have written authorization before scanning any system.
        """)
        sys.exit(0)
    
    command = sys.argv[1].lower()
    checker = AuthorizationChecker()
    
    if command == "list":
        checker.list_authorizations()
    
    elif command == "check":
        if len(sys.argv) < 3:
            print("❌ Error: Target required")
            print("Usage: python authorization_checker.py check <target>")
            sys.exit(1)
        
        target = sys.argv[2]
        authorized, reason = checker.check_authorization(target)
        print(f"\nTarget: {target}")
        print(f"Status: {reason}")
        sys.exit(0 if authorized else 1)
    
    elif command == "add":
        interactive_add_authorization()
    
    elif command == "remove":
        if len(sys.argv) < 3:
            print("❌ Error: Target required")
            print("Usage: python authorization_checker.py remove <target>")
            sys.exit(1)
        
        target = sys.argv[2]
        checker.remove_authorization(target)
    
    else:
        print(f"❌ Unknown command: {command}")
        print("Use: list, check, add, or remove")
        sys.exit(1)
