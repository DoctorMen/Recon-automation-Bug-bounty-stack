#!/usr/bin/env python3
"""
🛡️ MASTER SAFETY SYSTEM - BULLETPROOF PROTECTION
Copyright © 2025 Khallid Nurse. All Rights Reserved.

THIS SYSTEM PREVENTS:
- Scanning unauthorized targets
- Going outside defined scope
- Accidental DoS attacks
- Legal violations
- Reputation damage

ALL SECURITY TOOLS MUST USE THIS SYSTEM
"""

import sys
import json
import re
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple, Optional
import ipaddress

# Import existing safety systems
try:
    from authorization_checker import AuthorizationChecker
except:
    print("⚠️  Warning: authorization_checker.py not found")
    AuthorizationChecker = None

try:
    sys.path.append(str(Path(__file__).parent / "scripts"))
    from safety_check_system import SafetyCheckSystem
except:
    print("⚠️  Warning: safety_check_system.py not found")
    SafetyCheckSystem = None


class MasterSafetySystem:
    """
    MASTER SAFETY SYSTEM
    
    Combines all safety checks into one bulletproof system.
    NO security tool runs without passing ALL checks.
    """
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.safety_dir = self.project_root / ".protection"
        self.safety_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize sub-systems
        self.auth_checker = AuthorizationChecker() if AuthorizationChecker else None
        self.safety_checker = SafetyCheckSystem() if SafetyCheckSystem else None
        
        # Safety databases
        self.scope_db = self.safety_dir / "scope_definitions.json"
        self.blocked_targets = self.safety_dir / "blocked_targets.json"
        self.rate_limits = self.safety_dir / "rate_tracking.json"
        self.emergency_stop = self.safety_dir / "EMERGENCY_STOP"
        
        self._init_databases()
    
    def _init_databases(self):
        """Initialize all safety databases"""
        if not self.scope_db.exists():
            self._save_json(self.scope_db, {
                "programs": {},
                "last_updated": datetime.now().isoformat()
            })
        
        if not self.blocked_targets.exists():
            self._save_json(self.blocked_targets, {
                "blocked": [],
                "reasons": {}
            })
        
        if not self.rate_limits.exists():
            self._save_json(self.rate_limits, {
                "targets": {},
                "global_limit": 100,  # Max requests per minute globally
                "per_target_limit": 20  # Max requests per target per minute
            })
    
    def verify_target_safe(self, target: str, operation: str = "scan") -> Tuple[bool, str]:
        """
        🚨 MASTER SAFETY CHECK
        
        ALL security operations MUST call this first.
        Returns (safe: bool, reason: str)
        """
        
        print(f"\n{'='*70}")
        print("🛡️  MASTER SAFETY SYSTEM - VERIFICATION STARTING")
        print(f"{'='*70}")
        print(f"Target: {target}")
        print(f"Operation: {operation}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}\n")
        
        # CHECK 1: Emergency Stop
        if self.emergency_stop.exists():
            return False, (
                "🚨 EMERGENCY STOP ACTIVE\n"
                f"ALL OPERATIONS BLOCKED\n"
                f"Remove file: {self.emergency_stop}\n"
                "To resume operations"
            )
        
        # CHECK 2: Blocked Targets List
        is_blocked, block_reason = self._check_blocked_list(target)
        if is_blocked:
            return False, f"❌ BLOCKED: {block_reason}"
        
        # CHECK 3: Target Format Validation
        valid_format, format_msg = self._validate_target_format(target)
        if not valid_format:
            return False, f"❌ INVALID FORMAT: {format_msg}"
        
        # CHECK 4: Dangerous Target Protection
        is_dangerous, danger_msg = self._check_dangerous_targets(target)
        if is_dangerous:
            return False, f"🚨 DANGEROUS TARGET: {danger_msg}"
        
        # CHECK 5: Authorization Check (existing system)
        if self.auth_checker:
            try:
                authorized, auth_msg = self.auth_checker.check_authorization(target, operation)
                if not authorized:
                    return False, f"❌ NOT AUTHORIZED: {auth_msg}"
                print(f"✅ Authorization Check: PASSED")
            except Exception as e:
                return False, f"❌ Authorization Check Failed: {str(e)}"
        
        # CHECK 6: Scope Verification
        in_scope, scope_msg = self._check_scope(target)
        if not in_scope:
            return False, f"❌ OUT OF SCOPE: {scope_msg}"
        
        # CHECK 7: Rate Limiting
        rate_ok, rate_msg = self._check_rate_limit(target)
        if not rate_ok:
            return False, f"❌ RATE LIMIT: {rate_msg}"
        
        # CHECK 8: Destructive Operation Check
        if self.safety_checker:
            try:
                destructive_ok, destructive_msg = self.safety_checker.check_destructive_operation(operation)
                if not destructive_ok:
                    return False, f"❌ DESTRUCTIVE OP: {destructive_msg}"
                print(f"✅ Destructive Check: PASSED")
            except Exception as e:
                print(f"⚠️  Warning: Destructive check failed: {e}")
        
        # ALL CHECKS PASSED
        self._log_safe_operation(target, operation)
        
        print(f"\n{'='*70}")
        print("✅ ALL SAFETY CHECKS PASSED")
        print(f"{'='*70}\n")
        
        return True, "✅ ALL SAFETY CHECKS PASSED - Operation authorized"
    
    def _check_blocked_list(self, target: str) -> Tuple[bool, str]:
        """Check if target is on blocked list"""
        blocked_data = self._load_json(self.blocked_targets)
        
        blocked_list = blocked_data.get("blocked", [])
        reasons = blocked_data.get("reasons", {})
        
        # Exact match
        if target in blocked_list:
            reason = reasons.get(target, "No reason specified")
            return True, f"Target explicitly blocked: {reason}"
        
        # Domain match
        for blocked in blocked_list:
            if target.endswith(blocked) or blocked in target:
                reason = reasons.get(blocked, "Parent domain blocked")
                return True, f"Matches blocked pattern '{blocked}': {reason}"
        
        return False, "Not blocked"
    
    def _validate_target_format(self, target: str) -> Tuple[bool, str]:
        """Validate target format (domain or IP)"""
        
        # Check for obviously invalid targets
        if not target or len(target) < 3:
            return False, "Target too short"
        
        if target.startswith("http://") or target.startswith("https://"):
            return False, "Remove http:// or https:// - use domain only"
        
        # Check if it's an IP address
        try:
            ipaddress.ip_address(target)
            return True, "Valid IP address"
        except:
            pass
        
        # Check if it's a valid domain
        domain_pattern = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
        if re.match(domain_pattern, target, re.IGNORECASE):
            return True, "Valid domain"
        
        # Allow wildcards for subdomain scanning
        wildcard_pattern = r'^\*\.([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
        if re.match(wildcard_pattern, target, re.IGNORECASE):
            return True, "Valid wildcard domain"
        
        return False, f"Invalid target format: '{target}'"
    
    def _check_dangerous_targets(self, target: str) -> Tuple[bool, str]:
        """
        Block obviously dangerous targets that should NEVER be scanned
        """
        
        # Government/Military (NEVER scan these)
        dangerous_domains = [
            '.gov', '.mil', '.edu',  # US government, military, education
            'whitehouse.gov', 'fbi.gov', 'cia.gov', 'nsa.gov',
            'defense.gov', 'army.mil', 'navy.mil', 'airforce.mil',
            'pentagon.', 'darpa.',
            # Critical Infrastructure
            'powerplant.', 'nuclear.', 'hospital.', 'emergency.',
            # Financial regulators
            'federalreserve.', 'sec.gov', 'treasury.gov',
        ]
        
        target_lower = target.lower()
        
        for dangerous in dangerous_domains:
            if dangerous in target_lower:
                return True, (
                    f"CRITICAL: Target matches dangerous pattern '{dangerous}'\n"
                    f"This target is PROHIBITED - legal consequences are severe\n"
                    f"If you have EXPLICIT written authorization, contact admin"
                )
        
        # localhost/private IPs (usually a mistake)
        if target in ['localhost', '127.0.0.1', '0.0.0.0']:
            return True, "Scanning localhost - use development environment instead"
        
        # Private IP ranges
        try:
            ip = ipaddress.ip_address(target)
            if ip.is_private:
                return False, "Warning: Private IP (allowed but verify authorization)"
        except:
            pass
        
        return False, "Target is not in dangerous category"
    
    def _check_scope(self, target: str) -> Tuple[bool, str]:
        """
        Verify target is within authorized scope
        """
        scope_data = self._load_json(self.scope_db)
        programs = scope_data.get("programs", {})
        
        # If no scope defined, require explicit authorization
        if not programs:
            return False, (
                "No scope defined\n"
                "Define scope with: python3 MASTER_SAFETY_SYSTEM.py add-scope"
            )
        
        # Check if target matches any defined scope
        for program_name, program_info in programs.items():
            in_scope_list = program_info.get("in_scope", [])
            out_of_scope_list = program_info.get("out_of_scope", [])
            
            # Check if explicitly out of scope
            for out_pattern in out_of_scope_list:
                if self._matches_pattern(target, out_pattern):
                    return False, f"Explicitly OUT OF SCOPE for {program_name}: {out_pattern}"
            
            # Check if in scope
            for in_pattern in in_scope_list:
                if self._matches_pattern(target, in_pattern):
                    print(f"✅ Scope Check: IN SCOPE for program '{program_name}'")
                    return True, f"In scope for {program_name}"
        
        return False, (
            f"Target '{target}' does not match any defined scope\n"
            "Add to scope or verify authorization"
        )
    
    def _matches_pattern(self, target: str, pattern: str) -> bool:
        """Check if target matches scope pattern"""
        
        # Exact match
        if target == pattern:
            return True
        
        # Wildcard match (*.example.com)
        if pattern.startswith('*.'):
            base_domain = pattern[2:]
            if target.endswith(base_domain) or target == base_domain:
                return True
        
        # Subdomain match
        if target.endswith('.' + pattern):
            return True
        
        return False
    
    def _check_rate_limit(self, target: str) -> Tuple[bool, str]:
        """
        Enforce rate limits to prevent accidental DoS
        """
        rate_data = self._load_json(self.rate_limits)
        
        now = datetime.now()
        targets = rate_data.get("targets", {})
        
        # Clean old entries (older than 1 minute)
        for t in list(targets.keys()):
            last_time = datetime.fromisoformat(targets[t]["last_request"])
            if (now - last_time).total_seconds() > 60:
                del targets[t]
        
        # Check per-target limit
        if target in targets:
            target_data = targets[target]
            request_count = target_data["request_count"]
            per_target_limit = rate_data.get("per_target_limit", 20)
            
            if request_count >= per_target_limit:
                return False, (
                    f"Rate limit exceeded for {target}\n"
                    f"Current: {request_count} requests/minute\n"
                    f"Limit: {per_target_limit} requests/minute\n"
                    "Wait 60 seconds before retrying"
                )
            
            # Increment count
            targets[target]["request_count"] += 1
            targets[target]["last_request"] = now.isoformat()
        else:
            # First request for this target
            targets[target] = {
                "first_request": now.isoformat(),
                "last_request": now.isoformat(),
                "request_count": 1
            }
        
        # Check global limit
        total_requests = sum(t["request_count"] for t in targets.values())
        global_limit = rate_data.get("global_limit", 100)
        
        if total_requests >= global_limit:
            return False, (
                f"Global rate limit exceeded\n"
                f"Total requests: {total_requests}/minute\n"
                f"Limit: {global_limit}/minute\n"
                "Slow down - this prevents accidental DoS"
            )
        
        # Save updated rate data
        rate_data["targets"] = targets
        self._save_json(self.rate_limits, rate_data)
        
        print(f"✅ Rate Limit: {targets[target]['request_count']}/{per_target_limit} requests")
        return True, "Rate limit OK"
    
    def _log_safe_operation(self, target: str, operation: str):
        """Log successful safety check"""
        log_file = self.safety_dir / "safe_operations.log"
        
        log_entry = f"{datetime.now().isoformat()} | {operation} | {target} | APPROVED\n"
        
        with open(log_file, 'a') as f:
            f.write(log_entry)
    
    def add_scope(self, program_name: str, in_scope: List[str], out_of_scope: List[str] = None):
        """
        Add scope definition for a bug bounty program or client
        
        Args:
            program_name: Name of program (e.g., "Shopify", "Client XYZ")
            in_scope: List of domains/patterns in scope (e.g., ["*.shopify.com", "shopify.dev"])
            out_of_scope: List explicitly out of scope (e.g., ["admin.shopify.com"])
        """
        scope_data = self._load_json(self.scope_db)
        
        if "programs" not in scope_data:
            scope_data["programs"] = {}
        
        scope_data["programs"][program_name] = {
            "in_scope": in_scope,
            "out_of_scope": out_of_scope or [],
            "added_date": datetime.now().isoformat()
        }
        
        scope_data["last_updated"] = datetime.now().isoformat()
        
        self._save_json(self.scope_db, scope_data)
        print(f"✅ Scope added for: {program_name}")
        print(f"   In scope: {', '.join(in_scope)}")
        if out_of_scope:
            print(f"   Out of scope: {', '.join(out_of_scope)}")
    
    def block_target(self, target: str, reason: str):
        """
        Add target to blocked list
        """
        blocked_data = self._load_json(self.blocked_targets)
        
        if target not in blocked_data.get("blocked", []):
            blocked_data.setdefault("blocked", []).append(target)
            blocked_data.setdefault("reasons", {})[target] = reason
            
            self._save_json(self.blocked_targets, blocked_data)
            print(f"✅ Blocked: {target}")
            print(f"   Reason: {reason}")
    
    def emergency_stop_all(self):
        """
        EMERGENCY STOP - Blocks ALL operations immediately
        """
        self.emergency_stop.touch()
        print("🚨 EMERGENCY STOP ACTIVATED")
        print("ALL SECURITY OPERATIONS BLOCKED")
        print(f"Remove file to resume: {self.emergency_stop}")
    
    def resume_operations(self):
        """
        Resume operations after emergency stop
        """
        if self.emergency_stop.exists():
            self.emergency_stop.unlink()
            print("✅ Operations resumed")
        else:
            print("No emergency stop active")
    
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


# CONVENIENCE FUNCTIONS FOR EASY INTEGRATION

def verify_safe(target: str, operation: str = "scan") -> bool:
    """
    🚨 USE THIS IN ALL SECURITY SCRIPTS
    
    Example:
        from MASTER_SAFETY_SYSTEM import verify_safe
        
        if not verify_safe("example.com", "scan"):
            print("Operation blocked by safety system")
            sys.exit(1)
        
        # Proceed with scan...
    """
    safety = MasterSafetySystem()
    safe, message = safety.verify_target_safe(target, operation)
    
    if not safe:
        print(f"\n{'='*70}")
        print("🚨 SAFETY SYSTEM BLOCKED OPERATION")
        print(f"{'='*70}")
        print(message)
        print(f"{'='*70}\n")
        return False
    
    return True


def add_program_scope(program: str, domains: List[str], excluded: List[str] = None):
    """Quick function to add scope"""
    safety = MasterSafetySystem()
    safety.add_scope(program, domains, excluded)


if __name__ == "__main__":
    print("🛡️  MASTER SAFETY SYSTEM")
    print(f"{'='*70}")
    
    if len(sys.argv) < 2:
        print("""
Usage:
  python3 MASTER_SAFETY_SYSTEM.py test <target>           - Test if target is safe
  python3 MASTER_SAFETY_SYSTEM.py add-scope                - Add scope definition
  python3 MASTER_SAFETY_SYSTEM.py block <target> <reason>  - Block a target
  python3 MASTER_SAFETY_SYSTEM.py emergency-stop           - Stop all operations
  python3 MASTER_SAFETY_SYSTEM.py resume                   - Resume operations

Examples:
  python3 MASTER_SAFETY_SYSTEM.py test shopify.com
  python3 MASTER_SAFETY_SYSTEM.py add-scope
  python3 MASTER_SAFETY_SYSTEM.py block malicious.com "Dangerous target"
  python3 MASTER_SAFETY_SYSTEM.py emergency-stop
        """)
        sys.exit(0)
    
    command = sys.argv[1].lower()
    safety = MasterSafetySystem()
    
    if command == "test":
        if len(sys.argv) < 3:
            print("Error: Target required")
            sys.exit(1)
        
        target = sys.argv[2]
        safe, message = safety.verify_target_safe(target, "scan")
        
        if safe:
            print("\n✅ Target is SAFE to scan")
            sys.exit(0)
        else:
            print(f"\n❌ Target is BLOCKED\n{message}")
            sys.exit(1)
    
    elif command == "add-scope":
        program_name = input("Program name (e.g., 'Shopify'): ").strip()
        in_scope = input("In-scope domains (comma-separated): ").strip().split(',')
        in_scope = [d.strip() for d in in_scope if d.strip()]
        
        out_input = input("Out-of-scope domains (comma-separated, or leave blank): ").strip()
        out_of_scope = [d.strip() for d in out_input.split(',') if d.strip()] if out_input else None
        
        safety.add_scope(program_name, in_scope, out_of_scope)
    
    elif command == "block":
        if len(sys.argv) < 4:
            print("Error: Target and reason required")
            print("Usage: python3 MASTER_SAFETY_SYSTEM.py block <target> <reason>")
            sys.exit(1)
        
        target = sys.argv[2]
        reason = ' '.join(sys.argv[3:])
        safety.block_target(target, reason)
    
    elif command == "emergency-stop":
        safety.emergency_stop_all()
    
    elif command == "resume":
        safety.resume_operations()
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)
