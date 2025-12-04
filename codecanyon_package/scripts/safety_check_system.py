#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
🛡️ SAFETY CHECK SYSTEM - LEGAL PROTECTION LAYER
Prevents any tool from causing legal trouble
ALL security operations MUST pass through this system

© 2025 - Critical Legal Protection System
"""

import os
import sys
import json
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

class SafetyCheckSystem:
    """
    Multi-layered safety system that blocks unauthorized operations
    """
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.safety_db = self.project_root / "data" / "safety"
        self.safety_db.mkdir(parents=True, exist_ok=True)
        
        self.auth_db = self.safety_db / "authorizations.json"
        self.audit_log = self.safety_db / "audit_trail.json"
        self.blocked_ops = self.safety_db / "blocked_operations.json"
        self.insurance_db = self.safety_db / "insurance_status.json"
        
        self._init_databases()
    
    def _init_databases(self):
        """Initialize safety databases if they don't exist"""
        if not self.auth_db.exists():
            self._save_json(self.auth_db, {
                "authorizations": [],
                "templates": self._get_default_templates()
            })
        
        if not self.audit_log.exists():
            self._save_json(self.audit_log, {"entries": []})
        
        if not self.blocked_ops.exists():
            self._save_json(self.blocked_ops, {"blocked": []})
        
        if not self.insurance_db.exists():
            self._save_json(self.insurance_db, {
                "status": "NOT_CONFIGURED",
                "provider": "",
                "coverage_amount": 0,
                "expiry_date": "",
                "policy_number": ""
            })
    
    def _get_default_templates(self) -> Dict:
        """Get default authorization templates"""
        return {
            "client_authorization_template": {
                "client_name": "",
                "company": "",
                "contact_email": "",
                "contact_phone": "",
                "authorized_domains": [],
                "authorized_ips": [],
                "testing_period_start": "",
                "testing_period_end": "",
                "authorized_activities": [],
                "prohibited_activities": [],
                "emergency_contact": "",
                "signed_date": "",
                "authorization_hash": ""
            }
        }
    
    def verify_authorization(self, 
                           target: str, 
                           activity: str, 
                           client: Optional[str] = None) -> Tuple[bool, str]:
        """
        🚨 CRITICAL: Verify authorization before ANY security testing
        
        Args:
            target: Domain, IP, or system to test
            activity: Type of activity (reconnaissance, vulnerability_scan, exploit_verification)
            client: Client name (optional)
        
        Returns:
            (authorized: bool, message: str)
        """
        
        # RULE 1: Block all testing without authorization
        if not target:
            return False, "❌ BLOCKED: No target specified"
        
        # RULE 2: Load authorizations
        auth_data = self._load_json(self.auth_db)
        authorizations = auth_data.get("authorizations", [])
        
        if not authorizations:
            return False, (
                "❌ BLOCKED: No authorizations found\n"
                f"LEGAL REQUIREMENT: You MUST obtain written authorization before testing\n"
                f"Use: python3 scripts/add_authorization.py --client 'Client Name' --domain {target}"
            )
        
        # RULE 3: Check if target is authorized
        authorized = False
        auth_record = None
        
        for auth in authorizations:
            # Check if target matches authorized domains or IPs
            if target in auth.get("authorized_domains", []) or \
               target in auth.get("authorized_ips", []):
                
                # Check if authorization is still valid
                if self._is_authorization_valid(auth):
                    # Check if activity is permitted
                    if activity in auth.get("authorized_activities", []):
                        authorized = True
                        auth_record = auth
                        break
                    else:
                        return False, (
                            f"❌ BLOCKED: Activity '{activity}' not authorized\n"
                            f"Authorized activities: {', '.join(auth.get('authorized_activities', []))}\n"
                            f"Client: {auth.get('client_name', 'Unknown')}"
                        )
        
        if not authorized:
            self._log_blocked_operation(target, activity, "No valid authorization")
            return False, (
                f"❌ BLOCKED: Target '{target}' not authorized\n"
                f"LEGAL REQUIREMENT: Obtain written authorization first\n"
                f"Use: python3 scripts/add_authorization.py --client 'Client Name' --domain {target}"
            )
        
        # RULE 4: Log authorized access
        self._log_audit_entry(target, activity, auth_record, "AUTHORIZED")
        
        return True, f"✅ AUTHORIZED: {activity} on {target} for client {auth_record.get('client_name', 'Unknown')}"
    
    def _is_authorization_valid(self, auth: Dict) -> bool:
        """Check if authorization is still valid"""
        try:
            end_date = datetime.fromisoformat(auth.get("testing_period_end", ""))
            return datetime.now() <= end_date
        except:
            return False
    
    def check_destructive_operation(self, operation: str) -> Tuple[bool, str]:
        """
        🚨 CRITICAL: Block destructive operations
        
        These operations are NEVER allowed without explicit verification:
        - DoS/DDoS attacks
        - Data exfiltration
        - System modification
        - Privilege escalation (beyond PoC)
        """
        
        destructive_keywords = [
            "dos", "ddos", "flood", "exhaust",
            "delete", "drop", "truncate", "destroy",
            "exfiltrate", "dump", "extract_data",
            "modify_production", "alter_database",
            "shutdown", "reboot", "restart",
        ]
        
        operation_lower = operation.lower()
        
        for keyword in destructive_keywords:
            if keyword in operation_lower:
                self._log_blocked_operation("SYSTEM", operation, "Destructive operation blocked")
                return False, (
                    f"❌ BLOCKED: Destructive operation detected - '{operation}'\n"
                    f"Matched keyword: '{keyword}'\n"
                    f"LEGAL PROTECTION: These operations are prohibited without explicit client approval\n"
                    f"If you have approval, use: python3 scripts/approve_destructive_operation.py"
                )
        
        return True, "✅ Operation is non-destructive"
    
    def check_rate_limits(self, target: str, operation: str) -> Tuple[bool, str]:
        """
        Check rate limits to prevent accidental DoS
        """
        # Load rate limit tracking
        rate_file = self.safety_db / "rate_limits.json"
        
        if rate_file.exists():
            rate_data = self._load_json(rate_file)
        else:
            rate_data = {"targets": {}}
        
        # Get current rate for target
        target_key = f"{target}:{operation}"
        now = datetime.now()
        
        if target_key not in rate_data["targets"]:
            rate_data["targets"][target_key] = {
                "first_request": now.isoformat(),
                "request_count": 1,
                "last_request": now.isoformat()
            }
        else:
            target_info = rate_data["targets"][target_key]
            first_request = datetime.fromisoformat(target_info["first_request"])
            
            # Reset if more than 1 minute has passed
            if (now - first_request).total_seconds() > 60:
                target_info["first_request"] = now.isoformat()
                target_info["request_count"] = 1
            else:
                target_info["request_count"] += 1
            
            target_info["last_request"] = now.isoformat()
            
            # Check if rate limit exceeded (max 150 requests per minute)
            if target_info["request_count"] > 150:
                return False, (
                    f"❌ BLOCKED: Rate limit exceeded for {target}\n"
                    f"Current rate: {target_info['request_count']} requests/minute\n"
                    f"Maximum allowed: 150 requests/minute\n"
                    f"LEGAL PROTECTION: Preventing accidental DoS"
                )
        
        self._save_json(rate_file, rate_data)
        return True, "✅ Rate limit OK"
    
    def check_insurance_status(self) -> Tuple[bool, str]:
        """
        Check if professional liability insurance is active
        """
        insurance_data = self._load_json(self.insurance_db)
        
        status = insurance_data.get("status", "NOT_CONFIGURED")
        
        if status == "NOT_CONFIGURED":
            return False, (
                "⚠️  WARNING: Insurance not configured\n"
                "LEGAL REQUIREMENT: Maintain $1M-$2M liability insurance\n"
                "Configure: python3 scripts/setup_insurance_info.py\n"
                "This is a warning - operations will proceed but you are at legal risk"
            )
        
        if status == "EXPIRED":
            return False, (
                "❌ BLOCKED: Insurance policy EXPIRED\n"
                "LEGAL REQUIREMENT: Active insurance required for security testing\n"
                "Update: python3 scripts/setup_insurance_info.py"
            )
        
        # Check expiry date
        try:
            expiry = datetime.fromisoformat(insurance_data.get("expiry_date", ""))
            days_until_expiry = (expiry - datetime.now()).days
            
            if days_until_expiry < 0:
                insurance_data["status"] = "EXPIRED"
                self._save_json(self.insurance_db, insurance_data)
                return False, "❌ BLOCKED: Insurance expired"
            
            if days_until_expiry < 30:
                return True, f"⚠️  WARNING: Insurance expires in {days_until_expiry} days - renew soon"
        except:
            pass
        
        return True, "✅ Insurance active"
    
    def full_safety_check(self, 
                         target: str, 
                         activity: str, 
                         client: Optional[str] = None,
                         skip_insurance: bool = False) -> Tuple[bool, List[str]]:
        """
        🛡️ COMPREHENSIVE SAFETY CHECK - ALL LAYERS
        
        This is the MASTER safety check that all security tools MUST call
        
        Returns:
            (safe: bool, messages: List[str])
        """
        
        messages = []
        all_safe = True
        
        print("🛡️  SAFETY CHECK SYSTEM - Verifying legal compliance...\n")
        
        # CHECK 1: Authorization
        auth_ok, auth_msg = self.verify_authorization(target, activity, client)
        messages.append(auth_msg)
        if not auth_ok:
            all_safe = False
            print(f"❌ AUTHORIZATION: FAILED\n{auth_msg}\n")
            return False, messages
        else:
            print(f"✅ AUTHORIZATION: VERIFIED\n{auth_msg}\n")
        
        # CHECK 2: Destructive operations
        destructive_ok, destructive_msg = self.check_destructive_operation(activity)
        messages.append(destructive_msg)
        if not destructive_ok:
            all_safe = False
            print(f"❌ DESTRUCTIVE CHECK: FAILED\n{destructive_msg}\n")
            return False, messages
        else:
            print(f"✅ DESTRUCTIVE CHECK: PASSED\n")
        
        # CHECK 3: Rate limits
        rate_ok, rate_msg = self.check_rate_limits(target, activity)
        messages.append(rate_msg)
        if not rate_ok:
            all_safe = False
            print(f"❌ RATE LIMIT: EXCEEDED\n{rate_msg}\n")
            return False, messages
        else:
            print(f"✅ RATE LIMIT: OK\n")
        
        # CHECK 4: Insurance (warning only)
        if not skip_insurance:
            insurance_ok, insurance_msg = self.check_insurance_status()
            messages.append(insurance_msg)
            if not insurance_ok and "EXPIRED" in insurance_msg:
                all_safe = False
                print(f"❌ INSURANCE: EXPIRED\n{insurance_msg}\n")
                return False, messages
            else:
                print(f"✅ INSURANCE: {insurance_msg}\n")
        
        if all_safe:
            print("✅ ALL SAFETY CHECKS PASSED - Proceeding with authorized operation\n")
            print("=" * 70)
        
        return all_safe, messages
    
    def _log_audit_entry(self, target: str, activity: str, auth_record: Optional[Dict], status: str):
        """Log to audit trail"""
        audit_data = self._load_json(self.audit_log)
        
        entry = {
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "activity": activity,
            "status": status,
            "client": auth_record.get("client_name", "Unknown") if auth_record else "N/A",
            "authorization_hash": auth_record.get("authorization_hash", "") if auth_record else ""
        }
        
        audit_data["entries"].append(entry)
        
        # Keep last 10,000 entries
        if len(audit_data["entries"]) > 10000:
            audit_data["entries"] = audit_data["entries"][-10000:]
        
        self._save_json(self.audit_log, audit_data)
    
    def _log_blocked_operation(self, target: str, activity: str, reason: str):
        """Log blocked operation for security review"""
        blocked_data = self._load_json(self.blocked_ops)
        
        entry = {
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "activity": activity,
            "reason": reason,
            "blocked_by": "SafetyCheckSystem"
        }
        
        blocked_data["blocked"].append(entry)
        
        # Keep last 1,000 blocked operations
        if len(blocked_data["blocked"]) > 1000:
            blocked_data["blocked"] = blocked_data["blocked"][-1000:]
        
        self._save_json(self.blocked_ops, blocked_data)
    
    def _load_json(self, filepath: Path) -> Dict:
        """Load JSON file"""
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except:
            return {}
    
    def _save_json(self, filepath: Path, data: Dict):
        """Save JSON file"""
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)


def require_authorization(target: str, activity: str, client: Optional[str] = None) -> bool:
    """
    🚨 DECORATOR FUNCTION - Use this in all security scripts
    
    Example usage:
        from safety_check_system import require_authorization
        
        if not require_authorization(domain, "vulnerability_scan", client_name):
            sys.exit(1)
    """
    safety = SafetyCheckSystem()
    safe, messages = safety.full_safety_check(target, activity, client)
    
    if not safe:
        print("\n" + "=" * 70)
        print("🚨 SAFETY CHECK FAILED - OPERATION BLOCKED")
        print("=" * 70)
        for msg in messages:
            print(msg)
        print("=" * 70)
        return False
    
    return True


if __name__ == "__main__":
    print("🛡️  Safety Check System - Legal Protection Layer")
    print("=" * 70)
    
    # Example usage
    safety = SafetyCheckSystem()
    
    # Test safety check
    test_target = "example.com"
    test_activity = "vulnerability_scan"
    
    safe, messages = safety.full_safety_check(test_target, test_activity)
    
    if safe:
        print("\n✅ System would allow this operation")
    else:
        print("\n❌ System blocked this operation")

