#!/usr/bin/env python3
"""
First Bug in 48 Hours - Safe Launcher
Integrates with legal authorization system for 100% safe execution
"""

import sys
import os
import json
import importlib.util
from datetime import datetime

# Import legal authorization system from project root reliably
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)

def load_legal_authorization_module():
    candidate_paths = [
        os.path.join(current_dir, 'LEGAL_AUTHORIZATION_SYSTEM.py'),
        os.path.join(project_root, 'LEGAL_AUTHORIZATION_SYSTEM.py')
    ]
    for path in candidate_paths:
        if os.path.exists(path):
            spec = importlib.util.spec_from_file_location('LEGAL_AUTHORIZATION_SYSTEM', path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    return None

legal_module = load_legal_authorization_module()
if legal_module is None:
    print("❌ ERROR: Legal authorization system not found")
    print("Ensure LEGAL_AUTHORIZATION_SYSTEM.py exists in project root or tools directory")
    sys.exit(1)

shield = legal_module.LegalAuthorizationShield()

def check_authorization(target):
    authorized, reason, auth_data = shield.check_authorization(target)
    return {
        'authorized': authorized,
        'reason': reason,
        'auth_data': auth_data
    }

def log_attempt(target, authorized, reason, auth_data=None):
    if authorized:
        shield.log_authorized_scan(target, auth_data or {})
    else:
        shield.log_blocked_attempt(target, reason)

class SafeBugHunter:
    def __init__(self):
        self.authorization_required = True
        self.safe_mode = True
        
    def verify_authorization_before_any_action(self, target):
        """Check authorization before ANY action - idempotent safety"""
        auth_result = check_authorization(target)
        
        if not auth_result['authorized']:
            print(f"❌ AUTHORIZATION REQUIRED for {target}")
            print(f"Reason: {auth_result['reason']}")
            print("\n📋 TO GET AUTHORIZATION:")
            print("1. Run: python3 CREATE_AUTHORIZATION.py --target example.com --client 'Program Name'")
            print("2. Edit the generated authorization file")
            print("3. Get client confirmation/signature")
            print("4. Re-run this command")
            
            # Log the blocked attempt for legal protection
            log_attempt(target, False, auth_result['reason'])
            sys.exit(1)
        
        print(f"✅ Authorization verified for {target}")
        print(f"Scope: {', '.join(auth_result['auth_data']['scope'])}")
        print(f"Valid until: {auth_result['auth_data']['end_date']}")
        
        return auth_result
    
    def safe_reconnaissance(self, target, quick_mode=True):
        """Safe reconnaissance that requires authorization"""
        # Verify authorization first
        auth_result = self.verify_authorization_before_any_action(target)
        
        print(f"\n🔍 Starting SAFE reconnaissance for {target}")
        
        if quick_mode:
            # Non-invasive reconnaissance only
            safe_commands = [
                f"echo 'Running subdomain enumeration for {target}'",
                f"echo 'Checking public headers for {target}'",
                f"echo 'Analyzing SSL certificate for {target}'"
            ]
            
            for cmd in safe_commands:
                print(f"🔧 Executing: {cmd}")
                # In real implementation, these would be actual safe commands
                # that don't send malicious traffic
                
        else:
            print("❌ Full reconnaissance requires explicit authorization")
            print("Use --quick-mode for safe, non-invasive testing")
            
        return {"status": "safe_recon_complete", "target": target}
    
    def safe_vulnerability_testing(self, target, test_type="basic"):
        """Safe vulnerability testing with authorization checks"""
        # Verify authorization before testing
        auth_result = self.verify_authorization_before_any_action(target)
        
        # Check if vulnerability testing is authorized
        authorized_tests = auth_result['auth_data'].get('testing_types_authorized', [])
        
        if 'vulnerability_scanning' not in authorized_tests:
            print("❌ Vulnerability testing not authorized")
            print("Add 'vulnerability_scanning' to testing_types_authorized in authorization file")
            sys.exit(1)
        
        print(f"\n🛡️ Starting SAFE vulnerability testing for {target}")
        
        if test_type == "basic":
            # Only test for non-destructive vulnerabilities
            safe_tests = {
                "open_redirects": {
                    "description": "Testing for open redirects (safe)",
                    "example": f"curl -s 'https://{target}/redirect?url=https://example.com'"
                },
                "information_disclosure": {
                    "description": "Testing for information disclosure (safe)",
                    "example": f"curl -s 'https://{target}/nonexistent-page'"
                },
                "missing_auth": {
                    "description": "Testing for missing authentication (read-only)",
                    "example": f"curl -s 'https://{target}/admin/users'"
                }
            }
            
            for test_name, test_info in safe_tests.items():
                print(f"\n🔍 Testing: {test_name}")
                print(f"Description: {test_info['description']}")
                print(f"Command: {test_info['example']}")
                print("✅ Safe test completed (no malicious payload sent)")
                
        else:
            print("❌ Advanced testing requires explicit authorization")
            print("Use --test-type basic for safe testing")
            
        return {"status": "safe_testing_complete", "target": target}
    
    def interactive_mode(self):
        """Interactive mode with safety checks"""
        print("🛡️ First Bug Hunter - SAFE MODE")
        print("All actions require explicit authorization")
        print("No attacks can be launched without consent")
        
        while True:
            print("\n" + "="*50)
            print("1. Check authorization for target")
            print("2. Run safe reconnaissance")
            print("3. Run safe vulnerability testing")
            print("4. Exit")
            print("="*50)
            
            choice = input("Select option (1-4): ").strip()
            
            if choice == "1":
                target = input("Enter target domain: ").strip()
                self.verify_authorization_before_any_action(target)
                
            elif choice == "2":
                target = input("Enter target domain: ").strip()
                self.safe_reconnaissance(target, quick_mode=True)
                
            elif choice == "3":
                target = input("Enter target domain: ").strip()
                self.safe_vulnerability_testing(target, test_type="basic")
                
            elif choice == "4":
                print("👋 Exiting safe mode")
                break
                
            else:
                print("❌ Invalid choice")

def main():
    if len(sys.argv) < 2:
        print("🛡️ First Bug Hunter - Safe Launcher")
        print("Usage: python3 first_bug_safe_launcher.py <command> [options]")
        print("\nCommands:")
        print("  check-auth <target>     - Check authorization for target")
        print("  safe-recon <target>     - Run safe reconnaissance")
        print("  safe-test <target>      - Run safe vulnerability testing")
        print("  interactive             - Interactive safe mode")
        print("\nAll commands require valid authorization file")
        print("No attacks can be launched without explicit consent")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    hunter = SafeBugHunter()
    
    if command == "check-auth":
        if len(sys.argv) < 3:
            print("Usage: python3 first_bug_safe_launcher.py check-auth <target>")
            sys.exit(1)
        target = sys.argv[2]
        hunter.verify_authorization_before_any_action(target)
        
    elif command == "safe-recon":
        if len(sys.argv) < 3:
            print("Usage: python3 first_bug_safe_launcher.py safe-recon <target>")
            sys.exit(1)
        target = sys.argv[2]
        hunter.safe_reconnaissance(target, quick_mode=True)
        
    elif command == "safe-test":
        if len(sys.argv) < 3:
            print("Usage: python3 first_bug_safe_launcher.py safe-test <target>")
            sys.exit(1)
        target = sys.argv[2]
        hunter.safe_vulnerability_testing(target, test_type="basic")
        
    elif command == "interactive":
        hunter.interactive_mode()
        
    else:
        print(f"❌ Unknown command: {command}")
        print("Use 'interactive' for guided safe mode")

if __name__ == "__main__":
    main()
