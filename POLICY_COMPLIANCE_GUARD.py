#!/usr/bin/env python3
"""
Policy Compliance Guard
Ensures all operations strictly adhere to program policies and legal authorization.
This is a CRITICAL component that protects your reputation.

PRINCIPLE: If there's any doubt about compliance, STOP and ask.

Usage:
- Integrated into all automation scripts
- Blocks any operation outside authorized scope
- Logs all compliance checks
"""

import json
import sys
import re
from pathlib import Path
from datetime import datetime
import hashlib

class PolicyComplianceGuard:
    def __init__(self):
        self.authorization_system = None
        self.compliance_log = []
        self.strict_mode = True  # Default to strictest compliance
        
    def load_authorization_system(self):
        """Load the legal authorization system."""
        try:
            from LEGAL_AUTHORIZATION_SYSTEM import check_authorization
            self.authorization_system = check_authorization
        except ImportError:
            print("[!] CRITICAL: LEGAL_AUTHORIZATION_SYSTEM.py not found")
            print("[!] All operations will be blocked until fixed")
            self.authorization_system = None
    
    def check_scope_compliance(self, target, program_policy=None):
        """
        Check if target is within authorized scope.
        Returns: (allowed: bool, reason: str, policy_details: dict)
        """
        # If we have legal authorization, check it first
        if self.authorization_system:
            try:
                authorized, reason, auth_data = self.authorization_system(target)
                if not authorized:
                    self._log_compliance_check(target, "BLOCKED", reason)
                    return False, f"Authorization failed: {reason}", {}
                # Authorization valid, proceed with policy check
                policy_details = auth_data.get("scope", {})
            except Exception as e:
                self._log_compliance_check(target, "ERROR", f"Authorization check failed: {e}")
                return False, f"Authorization system error: {e}", {}
        else:
            # No authorization system, require explicit policy
            policy_details = {}
        
        # Parse program policy if provided
        if program_policy:
            policy_details.update(self._parse_policy(program_policy))
        
        # Check if target matches any allowed patterns
        allowed_patterns = policy_details.get("allowed_patterns", [])
        blocked_patterns = policy_details.get("blocked_patterns", [])
        
        # Check blocked patterns first (deny list)
        for pattern in blocked_patterns:
            if self._matches_pattern(target, pattern):
                reason = f"Target matches blocked pattern: {pattern}"
                self._log_compliance_check(target, "BLOCKED", reason)
                return False, reason, policy_details
        
        # Check allowed patterns (allow list)
        if allowed_patterns:
            for pattern in allowed_patterns:
                if self._matches_pattern(target, pattern):
                    self._log_compliance_check(target, "ALLOWED", f"Matches allowed pattern: {pattern}")
                    return True, f"Allowed by pattern: {pattern}", policy_details
            
            # If we have allowed patterns but none matched
            reason = "Target does not match any allowed scope patterns"
            self._log_compliance_check(target, "BLOCKED", reason)
            return False, reason, policy_details
        
        # No explicit patterns - require manual approval
        if self.strict_mode:
            reason = "Strict mode: No explicit scope patterns found"
            self._log_compliance_check(target, "BLOCKED", reason)
            return False, reason, policy_details
        
        # Non-strict mode: allow with warning
        reason = "Allowed with warning: No explicit scope patterns"
        self._log_compliance_check(target, "ALLOWED_WITH_WARNING", reason)
        return True, reason, policy_details
    
    def _parse_policy(self, policy_text):
        """
        Parse policy text to extract scope rules.
        Looks for:
        - "in scope" patterns
        - "out of scope" patterns
        - "not allowed" actions
        """
        policy = {
            "allowed_patterns": [],
            "blocked_patterns": [],
            "forbidden_actions": [],
            "rate_limits": {},
            "special_rules": []
        }
        
        # Extract in-scope domains/patterns
        in_scope_patterns = re.findall(
            r'(?:in[-\s]*scope|include|allowed)[\s:]*([^\n]*(?:\.com|\.org|\.io|\.app|api\.|.*\..*\/))',
            policy_text,
            re.IGNORECASE
        )
        for pattern in in_scope_patterns:
            # Clean up the pattern
            clean_pattern = re.sub(r'[^a-zA-Z0-9\.\-\*\/]', '', pattern).strip()
            if clean_pattern:
                policy["allowed_patterns"].append(clean_pattern)
        
        # Extract out-of-scope patterns
        out_scope_patterns = re.findall(
            r'(?:out[-\s]*scope|exclude|not[-\s]*in[-\s]*scope|do[-\s]*not)[\s:]*([^\n]*(?:\.com|\.org|\.io|\.app|api\.|.*\..*\/))',
            policy_text,
            re.IGNORECASE
        )
        for pattern in out_scope_patterns:
            clean_pattern = re.sub(r'[^a-zA-Z0-9\.\-\*\/]', '', pattern).strip()
            if clean_pattern:
                policy["blocked_patterns"].append(clean_pattern)
        
        # Extract forbidden actions
        forbidden_actions = re.findall(
            r'(?:not[-\s]*allowed|forbidden|prohibited|do[-\s]*not)[\s:]*([^\n]*(?:test|scan|attack|exploit|ddos|dos|brute[-\s]*force))',
            policy_text,
            re.IGNORECASE
        )
        for action in forbidden_actions:
            clean_action = action.strip().lower()
            if clean_action:
                policy["forbidden_actions"].append(clean_action)
        
        # Extract rate limits
        rate_limits = re.findall(
            r'(?:rate[-\s]*limit|requests? per|limit)[\s:]*([^\n]*(?:second|minute|hour|day))',
            policy_text,
            re.IGNORECASE
        )
        for limit in rate_limits:
            policy["rate_limits"]["general"] = limit.strip()
        
        return policy
    
    def _matches_pattern(self, target, pattern):
        """Check if target matches a scope pattern."""
        # Convert wildcard patterns to regex
        if '*' in pattern:
            regex_pattern = pattern.replace('*', '.*').replace('.', r'\.')
            return re.match(f'^{regex_pattern}$', target, re.IGNORECASE) is not None
        else:
            # Exact match or subdomain match
            return target == pattern or target.endswith('.' + pattern)
    
    def check_action_compliance(self, action, policy_details):
        """
        Check if an action is allowed under the policy.
        Returns: (allowed: bool, reason: str)
        """
        forbidden_actions = policy_details.get("forbidden_actions", [])
        
        for forbidden in forbidden_actions:
            if forbidden in action.lower():
                reason = f"Action '{action}' matches forbidden pattern: {forbidden}"
                self._log_compliance_check(action, "ACTION_BLOCKED", reason)
                return False, reason
        
        self._log_compliance_check(action, "ACTION_ALLOWED", "No policy restrictions")
        return True, "Action allowed"
    
    def validate_payload(self, payload, target_type="web"):
        """
        Validate that payloads are safe and policy-compliant.
        Blocks anything that could cause damage or violate policies.
        """
        # Dangerous payload patterns
        dangerous_patterns = [
            r'rm\s+-rf',
            r'dd\s+if=',
            r'shutdown',
            r'reboot',
            r'format',
            r'del\s+/f',
            r'format\s+c:',
            r'wget.*\|.*sh',
            r'curl.*\|.*bash',
            r'eval\s*\(',
            r'exec\s*\(',
            r'system\s*\(',
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                reason = f"Payload contains dangerous pattern: {pattern}"
                self._log_compliance_check(payload, "PAYLOAD_BLOCKED", reason)
                return False, reason
        
        # Check for potential DoS payloads
        dos_patterns = [
            r'ping.*-f',
            r'hping3',
            r'syn\s+flood',
            r'udp\s+flood',
            r'while.*true',
        ]
        
        for pattern in dos_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                reason = f"Payload appears to be DoS: {pattern}"
                self._log_compliance_check(payload, "PAYLOAD_BLOCKED", reason)
                return False, reason
        
        self._log_compliance_check(payload, "PAYLOAD_ALLOWED", "Payload appears safe")
        return True, "Payload allowed"
    
    def _log_compliance_check(self, item, status, reason):
        """Log all compliance checks for audit trail."""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "item": item,
            "status": status,
            "reason": reason,
            "hash": hashlib.sha256(item.encode()).hexdigest()[:16]
        }
        self.compliance_log.append(log_entry)
        
        # Also write to file for persistent audit
        log_file = Path("compliance_audit.log")
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"{log_entry['timestamp']} [{status}] {item}: {reason}\n")
    
    def get_compliance_report(self):
        """Generate a compliance report for review."""
        if not self.compliance_log:
            return "No compliance checks performed yet."
        
        summary = {
            "total_checks": len(self.compliance_log),
            "allowed": len([e for e in self.compliance_log if "ALLOWED" in e["status"]]),
            "blocked": len([e for e in self.compliance_log if "BLOCKED" in e["status"]]),
            "warnings": len([e for e in self.compliance_log if "WARNING" in e["status"]])
        }
        
        report = f"""
=== Policy Compliance Report ===
Total Checks: {summary['total_checks']}
Allowed: {summary['allowed']}
Blocked: {summary['blocked']}
Warnings: {summary['warnings']}

Recent Entries:
"""
        for entry in self.compliance_log[-10:]:
            report += f"- {entry['timestamp']} [{entry['status']}] {entry['item']}\n"
        
        return report
    
    def save_compliance_log(self):
        """Save detailed compliance log to JSON."""
        log_file = Path("compliance_audit.json")
        with open(log_file, "w", encoding="utf-8") as f:
            json.dump(self.compliance_log, f, indent=2)
        print(f"[+] Compliance log saved to: {log_file}")

# Global compliance guard instance
COMPLIANCE_GUARD = PolicyComplianceGuard()

def check_target_compliance(target, program_policy=None):
    """
    Convenience function to check if a target is compliant.
    Returns: (allowed: bool, reason: str)
    """
    allowed, reason, policy_details = COMPLIANCE_GUARD.check_scope_compliance(target, program_policy)
    return allowed, reason

def check_action_compliance(action, policy_details):
    """
    Convenience function to check if an action is compliant.
    Returns: (allowed: bool, reason: str)
    """
    return COMPLIANCE_GUARD.check_action_compliance(action, policy_details)

def validate_payload_safety(payload, target_type="web"):
    """
    Convenience function to validate payload safety.
    Returns: (allowed: bool, reason: str)
    """
    return COMPLIANCE_GUARD.validate_payload(payload, target_type)

if __name__ == "__main__":
    # Test the compliance guard
    COMPLIANCE_GUARD.load_authorization_system()
    
    # Example checks
    test_cases = [
        ("example.com", "In scope: *.example.com"),
        ("test.example.org", "Out of scope: *.example.org"),
        ("malicious.com", "No authorization"),
    ]
    
    for target, policy in test_cases:
        allowed, reason = check_target_compliance(target, policy)
        print(f"Target: {target}")
        print(f"Allowed: {allowed}")
        print(f"Reason: {reason}")
        print()
    
    # Show compliance report
    print(COMPLIANCE_GUARD.get_compliance_report())
    COMPLIANCE_GUARD.save_compliance_log()
