#!/usr/bin/env python3
"""
🤖 MASTER SAFETY SYSTEM - AI SECURITY EXTENSION
Copyright © 2025 Khallid Nurse. All Rights Reserved.

Extends the Master Safety System to support AI security testing
following HackerOne's AI Systems Testing guidelines.

THIS PREVENTS:
- Testing unauthorized AI systems
- Exceeding rate limits on AI endpoints
- Prohibited testing types (model theft, data poisoning)
- Ethical violations in AI research
- Legal issues from AI security testing

INTEGRATES WITH:
- MASTER_SAFETY_SYSTEM.py (base system)
- AI_SECURITY_SCOPE_DEFINITIONS.json (scope rules)
"""

import json
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import Tuple, Dict, List, Optional
import re

# Import base safety system
try:
    from MASTER_SAFETY_SYSTEM import MasterSafetySystem
except ImportError:
    print("❌ Error: MASTER_SAFETY_SYSTEM.py required")
    sys.exit(1)


class AISafetyExtension:
    """
    Extension for AI security testing safety
    
    Adds AI-specific protections on top of base safety system
    """
    
    def __init__(self):
        self.base_safety = MasterSafetySystem()
        self.project_root = Path(__file__).parent
        
        # AI-specific safety files
        self.ai_scope_file = self.project_root / "AI_SECURITY_SCOPE_DEFINITIONS.json"
        self.ai_rate_limits = self.base_safety.safety_dir / "ai_rate_tracking.json"
        self.prompt_history = self.base_safety.safety_dir / "prompt_history.json"
        
        # Load AI scope definitions
        self.ai_scope = self._load_ai_scope()
    
    def _load_ai_scope(self) -> Dict:
        """Load AI security scope definitions"""
        if not self.ai_scope_file.exists():
            print("⚠️  Warning: AI_SECURITY_SCOPE_DEFINITIONS.json not found")
            return {}
        
        try:
            with open(self.ai_scope_file, 'r') as f:
                return json.load(f).get("ai_security_testing", {})
        except Exception as e:
            print(f"❌ Error loading AI scope: {e}")
            return {}
    
    def verify_ai_target_safe(self, 
                              target: str, 
                              test_type: str,
                              model: Optional[str] = None) -> Tuple[bool, str]:
        """
        🤖 AI-SPECIFIC SAFETY CHECK
        
        Verifies AI system is safe to test according to HackerOne guidelines
        
        Args:
            target: AI system domain (e.g., "api.openai.com")
            test_type: Type of test ("prompt_injection", "safety_bypass", etc.)
            model: AI model being tested (e.g., "gpt-4")
        
        Returns:
            (safe: bool, reason: str)
        """
        
        print(f"\n{'='*70}")
        print("🤖 AI SAFETY EXTENSION - Verification Starting")
        print(f"{'='*70}")
        print(f"Target: {target}")
        print(f"Test Type: {test_type}")
        print(f"Model: {model or 'Any'}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}\n")
        
        # CHECK 1: Base safety system (standard checks)
        print("Running base safety checks...")
        base_safe, base_msg = self.base_safety.verify_target_safe(target, "ai_security_test")
        if not base_safe:
            return False, f"Base safety check failed:\n{base_msg}"
        
        # CHECK 2: AI program authorization
        is_authorized, auth_msg = self._check_ai_program_authorization(target)
        if not is_authorized:
            return False, f"❌ AI PROGRAM NOT AUTHORIZED:\n{auth_msg}"
        print(f"✅ AI Program Authorization: VERIFIED")
        
        # CHECK 3: Test type allowed
        is_allowed, type_msg = self._check_test_type_allowed(target, test_type)
        if not is_allowed:
            return False, f"❌ TEST TYPE NOT ALLOWED:\n{type_msg}"
        print(f"✅ Test Type: ALLOWED")
        
        # CHECK 4: AI-specific rate limiting
        rate_ok, rate_msg = self._check_ai_rate_limit(target, test_type)
        if not rate_ok:
            return False, f"❌ AI RATE LIMIT EXCEEDED:\n{rate_msg}"
        print(f"✅ AI Rate Limit: OK")
        
        # CHECK 5: Ethical guidelines check
        ethical_ok, ethical_msg = self._check_ethical_guidelines(test_type)
        if not ethical_ok:
            return False, f"❌ ETHICAL VIOLATION:\n{ethical_msg}"
        print(f"✅ Ethical Guidelines: COMPLIANT")
        
        # CHECK 6: Model-specific restrictions
        if model:
            model_ok, model_msg = self._check_model_restrictions(target, model, test_type)
            if not model_ok:
                return False, f"❌ MODEL RESTRICTION:\n{model_msg}"
            print(f"✅ Model Restrictions: COMPLIANT")
        
        # ALL CHECKS PASSED
        self._log_ai_test(target, test_type, model, "AUTHORIZED")
        
        print(f"\n{'='*70}")
        print("✅ ALL AI SAFETY CHECKS PASSED")
        print(f"{'='*70}\n")
        
        return True, "✅ AI security testing authorized - proceed responsibly"
    
    def _check_ai_program_authorization(self, target: str) -> Tuple[bool, str]:
        """Check if AI program is in authorized list"""
        ai_programs = self.ai_scope.get("ai_programs_in_scope", {})
        
        # Check each program
        for program_name, program_info in ai_programs.items():
            domains = program_info.get("domains", [])
            
            # Check if target matches any authorized domain
            for domain in domains:
                if target == domain or target.endswith(domain):
                    bug_bounty_url = program_info.get("bug_bounty_url", "N/A")
                    payout_range = program_info.get("payout_range", "Unknown")
                    
                    return True, (
                        f"Authorized under: {program_name}\n"
                        f"Bug Bounty: {bug_bounty_url}\n"
                        f"Payout Range: {payout_range}"
                    )
        
        return False, (
            f"Target '{target}' not in authorized AI programs\n"
            f"Available programs: {', '.join(ai_programs.keys())}\n"
            f"Add program to AI_SECURITY_SCOPE_DEFINITIONS.json"
        )
    
    def _check_test_type_allowed(self, target: str, test_type: str) -> Tuple[bool, str]:
        """Check if test type is allowed for this target"""
        
        # Get authorized test types
        authorized_security = self.ai_scope.get("authorized_testing_types", {}).get("ai_security", [])
        authorized_safety = self.ai_scope.get("authorized_testing_types", {}).get("ai_safety", [])
        all_authorized = authorized_security + authorized_safety
        
        # Check if test type is authorized
        if test_type not in all_authorized:
            prohibited = self.ai_scope.get("prohibited_testing_types", [])
            
            if test_type in prohibited:
                return False, (
                    f"Test type '{test_type}' is PROHIBITED\n"
                    f"This type of testing is not allowed under any circumstances\n"
                    f"Reason: Ethical/legal violations"
                )
            
            return False, (
                f"Test type '{test_type}' not in authorized list\n"
                f"Authorized: {', '.join(all_authorized[:5])}...\n"
                f"See AI_SECURITY_SCOPE_DEFINITIONS.json"
            )
        
        # Check target-specific restrictions
        ai_programs = self.ai_scope.get("ai_programs_in_scope", {})
        for program_name, program_info in ai_programs.items():
            domains = program_info.get("domains", [])
            
            if any(target == d or target.endswith(d) for d in domains):
                # Found the program, check if test type allowed
                allowed_tests = program_info.get("testing_allowed", [])
                forbidden_tests = program_info.get("testing_forbidden", [])
                
                if test_type in forbidden_tests:
                    return False, (
                        f"Test type '{test_type}' forbidden for {program_name}\n"
                        f"Allowed: {', '.join(allowed_tests)}\n"
                        f"Forbidden: {', '.join(forbidden_tests)}"
                    )
                
                if test_type not in allowed_tests:
                    return False, (
                        f"Test type '{test_type}' not explicitly allowed for {program_name}\n"
                        f"Allowed: {', '.join(allowed_tests)}"
                    )
        
        return True, f"Test type '{test_type}' is authorized"
    
    def _check_ai_rate_limit(self, target: str, test_type: str) -> Tuple[bool, str]:
        """AI-specific rate limiting (stricter than base)"""
        
        # Load rate tracking
        if self.ai_rate_limits.exists():
            with open(self.ai_rate_limits, 'r') as f:
                rate_data = json.load(f)
        else:
            rate_data = {"targets": {}}
        
        # Get AI-specific limits
        guardrails = self.ai_scope.get("safety_guardrails", {}).get("rate_limiting", {})
        max_per_minute = guardrails.get("max_prompts_per_target_per_minute", 10)
        max_per_day = guardrails.get("max_prompts_per_target_per_day", 500)
        
        # Also check program-specific limits
        ai_programs = self.ai_scope.get("ai_programs_in_scope", {})
        for program_name, program_info in ai_programs.items():
            domains = program_info.get("domains", [])
            if any(target == d or target.endswith(d) for d in domains):
                program_limit = program_info.get("max_requests_per_minute", 10)
                max_per_minute = min(max_per_minute, program_limit)
        
        now = datetime.now()
        target_key = f"{target}:{test_type}"
        
        # Initialize or get target data
        if target_key not in rate_data["targets"]:
            rate_data["targets"][target_key] = {
                "first_request_minute": now.isoformat(),
                "first_request_day": now.isoformat(),
                "minute_count": 1,
                "day_count": 1,
                "last_request": now.isoformat()
            }
        else:
            target_info = rate_data["targets"][target_key]
            
            # Check minute window
            first_minute = datetime.fromisoformat(target_info["first_request_minute"])
            if (now - first_minute).total_seconds() > 60:
                # Reset minute counter
                target_info["first_request_minute"] = now.isoformat()
                target_info["minute_count"] = 1
            else:
                target_info["minute_count"] += 1
            
            # Check day window
            first_day = datetime.fromisoformat(target_info["first_request_day"])
            if (now - first_day).total_seconds() > 86400:  # 24 hours
                # Reset day counter
                target_info["first_request_day"] = now.isoformat()
                target_info["day_count"] = 1
            else:
                target_info["day_count"] += 1
            
            target_info["last_request"] = now.isoformat()
            
            # Check limits
            if target_info["minute_count"] > max_per_minute:
                return False, (
                    f"AI Rate limit exceeded for {target}\n"
                    f"Minute: {target_info['minute_count']}/{max_per_minute}\n"
                    f"AI systems are sensitive - wait 60 seconds"
                )
            
            if target_info["day_count"] > max_per_day:
                return False, (
                    f"Daily AI rate limit exceeded for {target}\n"
                    f"Today: {target_info['day_count']}/{max_per_day}\n"
                    f"Resume tomorrow to avoid abuse detection"
                )
        
        # Save updated rate data
        with open(self.ai_rate_limits, 'w') as f:
            json.dump(rate_data, f, indent=2)
        
        minute_remaining = max_per_minute - rate_data["targets"][target_key]["minute_count"]
        day_remaining = max_per_day - rate_data["targets"][target_key]["day_count"]
        
        return True, (
            f"Rate limit OK\n"
            f"Remaining today: {day_remaining}/{max_per_day}\n"
            f"Remaining this minute: {minute_remaining}/{max_per_minute}"
        )
    
    def _check_ethical_guidelines(self, test_type: str) -> Tuple[bool, str]:
        """Verify testing follows ethical guidelines"""
        
        # Prohibited patterns
        prohibited_types = self.ai_scope.get("prohibited_testing_types", [])
        
        if test_type in prohibited_types:
            return False, (
                f"Test type '{test_type}' violates ethical guidelines\n"
                f"Prohibited testing types are never allowed\n"
                f"These can cause actual harm or legal issues"
            )
        
        # Check if test_type contains dangerous patterns
        dangerous_patterns = [
            "actual_",  # actual_data_poisoning, actual_model_theft
            "mass_",    # mass_automated_abuse
            "dos_",     # dos_attacks
            "theft",    # model_theft
        ]
        
        for pattern in dangerous_patterns:
            if pattern in test_type.lower():
                return False, (
                    f"Test type '{test_type}' contains dangerous pattern: '{pattern}'\n"
                    f"Only PoC/detection allowed, not actual exploitation"
                )
        
        return True, "Ethical guidelines compliant"
    
    def _check_model_restrictions(self, 
                                  target: str, 
                                  model: str, 
                                  test_type: str) -> Tuple[bool, str]:
        """Check model-specific restrictions"""
        
        # Find the program
        ai_programs = self.ai_scope.get("ai_programs_in_scope", {})
        for program_name, program_info in ai_programs.items():
            domains = program_info.get("domains", [])
            
            if any(target == d or target.endswith(d) for d in domains):
                # Check if model is in scope
                models = program_info.get("models", [])
                if models and model not in models:
                    return False, (
                        f"Model '{model}' not in scope for {program_name}\n"
                        f"Allowed models: {', '.join(models)}"
                    )
                
                return True, f"Model '{model}' is in scope"
        
        return True, "Model OK (no restrictions found)"
    
    def _log_ai_test(self, target: str, test_type: str, model: Optional[str], status: str):
        """Log AI security test to history"""
        
        # Load history
        if self.prompt_history.exists():
            with open(self.prompt_history, 'r') as f:
                history = json.load(f)
        else:
            history = {"tests": []}
        
        # Add entry
        entry = {
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "test_type": test_type,
            "model": model,
            "status": status
        }
        
        history["tests"].append(entry)
        
        # Keep last 10,000 entries
        if len(history["tests"]) > 10000:
            history["tests"] = history["tests"][-10000:]
        
        # Save
        with open(self.prompt_history, 'w') as f:
            json.dump(history, f, indent=2)
    
    def log_prompt_test(self, 
                       target: str, 
                       prompt: str, 
                       response: str, 
                       severity: str):
        """
        Log a specific prompt test for documentation
        
        Use this to build evidence for bug reports
        """
        log_file = self.base_safety.safety_dir / "prompt_test_log.jsonl"
        
        entry = {
            "timestamp": datetime.now().isoformat(),
            "target": target,
            "prompt": prompt[:500],  # Truncate long prompts
            "response": response[:1000],  # Truncate long responses
            "severity": severity,
            "documented": True
        }
        
        # Append to JSONL file
        with open(log_file, 'a') as f:
            f.write(json.dumps(entry) + '\n')
        
        print(f"✅ Logged prompt test (severity: {severity})")


# CONVENIENCE FUNCTIONS

def verify_ai_safe(target: str, test_type: str, model: Optional[str] = None) -> bool:
    """
    🤖 USE THIS FOR AI SECURITY TESTING
    
    Example:
        from MASTER_SAFETY_SYSTEM_AI_EXTENSION import verify_ai_safe
        
        if not verify_ai_safe("api.openai.com", "prompt_injection", "gpt-4"):
            print("AI test blocked by safety system")
            sys.exit(1)
        
        # Proceed with AI security test...
    """
    ai_safety = AISafetyExtension()
    safe, message = ai_safety.verify_ai_target_safe(target, test_type, model)
    
    if not safe:
        print(f"\n{'='*70}")
        print("🚨 AI SAFETY SYSTEM BLOCKED OPERATION")
        print(f"{'='*70}")
        print(message)
        print(f"{'='*70}\n")
        return False
    
    return True


if __name__ == "__main__":
    print("🤖 AI SAFETY EXTENSION - Test Mode")
    print(f"{'='*70}\n")
    
    # Example tests
    ai_safety = AISafetyExtension()
    
    # Test 1: OpenAI prompt injection
    print("Test 1: OpenAI prompt injection")
    safe, msg = ai_safety.verify_ai_target_safe(
        "api.openai.com",
        "prompt_injection",
        "gpt-4"
    )
    print(f"Result: {'✅ SAFE' if safe else '❌ BLOCKED'}")
    print(f"Message: {msg}\n")
    
    # Test 2: Prohibited test type
    print("\nTest 2: Prohibited test (should block)")
    safe, msg = ai_safety.verify_ai_target_safe(
        "api.openai.com",
        "actual_model_theft",
        "gpt-4"
    )
    print(f"Result: {'✅ SAFE' if safe else '❌ BLOCKED'}")
    print(f"Message: {msg}\n")
    
    print(f"\n{'='*70}")
    print("AI Safety Extension Ready")
    print(f"{'='*70}")
