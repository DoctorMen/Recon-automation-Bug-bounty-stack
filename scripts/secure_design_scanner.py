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
Secure Design Vulnerability Scanner
Based on Designing Secure Software PDF methodology
Identifies vulnerabilities arising from poor security design decisions
"""

import json
import re
from typing import Dict, List, Any, Optional

class SecureDesignScanner:
    """
    Scans for vulnerabilities based on secure design principles
    Based on Designing Secure Software PDF methodology
    """
    
    # Secure design anti-patterns (what NOT to do)
    DESIGN_ANTI_PATTERNS = {
        "broken_authentication": {
            "indicators": [
                "session_id", "user_id", "admin", "role",
                "password", "token", "auth", "login"
            ],
            "design_flaws": [
                "predictable_session_ids",
                "client_side_authentication",
                "weak_token_generation",
                "missing_rate_limiting",
                "default_credentials"
            ],
            "severity": "high",
            "bounty_tier": "high"
        },
        "broken_authorization": {
            "indicators": [
                "user", "account", "payment", "order",
                "transaction", "resource", "object"
            ],
            "design_flaws": [
                "missing_access_control",
                "id_based_authorization",
                "client_side_authorization",
                "privilege_confusion"
            ],
            "severity": "high",
            "bounty_tier": "high"
        },
        "insecure_data_storage": {
            "indicators": [
                "password", "secret", "key", "token",
                "credential", "pii", "ssn", "credit"
            ],
            "design_flaws": [
                "plaintext_storage",
                "weak_encryption",
                "client_side_storage",
                "insufficient_hashing"
            ],
            "severity": "critical",
            "bounty_tier": "high"
        },
        "insecure_communication": {
            "indicators": [
                "http://", "api", "endpoint", "transfer"
            ],
            "design_flaws": [
                "missing_tls",
                "weak_cipher_suites",
                "certificate_pinning_bypass",
                "man_in_the_middle"
            ],
            "severity": "high",
            "bounty_tier": "medium"
        },
        "security_misconfiguration": {
            "indicators": [
                "config", "setting", "admin", "debug",
                "test", "staging", "dev"
            ],
            "design_flaws": [
                "default_configurations",
                "exposed_debug_endpoints",
                "verbose_error_messages",
                "unnecessary_features_enabled"
            ],
            "severity": "medium",
            "bounty_tier": "medium"
        },
        "insufficient_input_validation": {
            "indicators": [
                "input", "parameter", "form", "field",
                "upload", "file"
            ],
            "design_flaws": [
                "no_input_validation",
                "client_side_validation_only",
                "type_confusion",
                "injection_vectors"
            ],
            "severity": "critical",
            "bounty_tier": "high"
        },
        "broken_cryptography": {
            "indicators": [
                "crypto", "encrypt", "hash", "sign",
                "jwt", "token", "key"
            ],
            "design_flaws": [
                "weak_algorithms",
                "improper_key_management",
                "predictable_randomness",
                "timing_attacks"
            ],
            "severity": "high",
            "bounty_tier": "high"
        },
        "insecure_deserialization": {
            "indicators": [
                "json", "xml", "serialize", "deserialize",
                "yaml", "pickle"
            ],
            "design_flaws": [
                "unsafe_deserialization",
                "object_injection",
                "remote_code_execution"
            ],
            "severity": "critical",
            "bounty_tier": "high"
        },
        "missing_security_headers": {
            "indicators": [
                "header", "cors", "csp", "hsts",
                "x-frame", "x-content-type"
            ],
            "design_flaws": [
                "missing_csp",
                "missing_hsts",
                "permissive_cors",
                "clickjacking_vulnerable"
            ],
            "severity": "medium",
            "bounty_tier": "medium"
        },
        "insufficient_logging": {
            "indicators": [
                "log", "audit", "event", "activity"
            ],
            "design_flaws": [
                "no_audit_logging",
                "insufficient_logging",
                "log_injection",
                "log_sensitive_data"
            ],
            "severity": "low",
            "bounty_tier": "low"
        }
    }
    
    # Secure design principles (what SHOULD be done)
    SECURE_DESIGN_PRINCIPLES = {
        "defense_in_depth": {
            "description": "Multiple layers of security controls",
            "violations": [
                "single_point_of_failure",
                "no_redundancy",
                "client_side_only_security"
            ]
        },
        "least_privilege": {
            "description": "Users should have minimum necessary permissions",
            "violations": [
                "overprivileged_users",
                "admin_by_default",
                "excessive_permissions"
            ]
        },
        "fail_secure": {
            "description": "System should fail in secure state",
            "violations": [
                "fail_open",
                "default_allow",
                "error_exposes_info"
            ]
        },
        "secure_by_default": {
            "description": "Security should be default, not opt-in",
            "violations": [
                "insecure_defaults",
                "optional_security",
                "permissive_by_default"
            ]
        },
        "separation_of_concerns": {
            "description": "Security logic separated from business logic",
            "violations": [
                "mixed_responsibilities",
                "business_logic_in_security",
                "security_in_client"
            ]
        },
        "input_validation": {
            "description": "All input should be validated",
            "violations": [
                "no_validation",
                "client_side_only",
                "whitelist_failure"
            ]
        },
        "secure_communication": {
            "description": "All communication should be encrypted",
            "violations": [
                "http_only",
                "weak_tls",
                "no_certificate_validation"
            ]
        }
    }
    
    @staticmethod
    def analyze_design_vulnerability(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Analyze finding for secure design violations
        """
        url = finding.get("matched-at", "").lower()
        template_id = finding.get("template-id", "").lower()
        info = finding.get("info", {})
        name = info.get("name", "").lower()
        description = info.get("description", "").lower()
        
        # Check for design anti-patterns
        for pattern_name, pattern_data in SecureDesignScanner.DESIGN_ANTI_PATTERNS.items():
            for indicator in pattern_data["indicators"]:
                if indicator in url or indicator in template_id or indicator in name or indicator in description:
                    # Found potential design flaw
                    return {
                        "design_vulnerability": pattern_name,
                        "design_flaws": pattern_data["design_flaws"],
                        "severity": pattern_data["severity"],
                        "bounty_tier": pattern_data["bounty_tier"],
                        "principle_violated": SecureDesignScanner._identify_violated_principle(pattern_name),
                        "recommendation": SecureDesignScanner._get_design_recommendation(pattern_name)
                    }
        
        return None
    
    @staticmethod
    def _identify_violated_principle(pattern_name: str) -> str:
        """Identify which secure design principle was violated"""
        principle_map = {
            "broken_authentication": "secure_by_default",
            "broken_authorization": "least_privilege",
            "insecure_data_storage": "fail_secure",
            "insecure_communication": "secure_communication",
            "security_misconfiguration": "secure_by_default",
            "insufficient_input_validation": "input_validation",
            "broken_cryptography": "defense_in_depth",
            "insecure_deserialization": "input_validation",
            "missing_security_headers": "defense_in_depth",
            "insufficient_logging": "fail_secure"
        }
        return principle_map.get(pattern_name, "unknown")
    
    @staticmethod
    def _get_design_recommendation(pattern_name: str) -> str:
        """Get secure design recommendation"""
        recommendations = {
            "broken_authentication": "Implement strong authentication with secure session management, rate limiting, and multi-factor authentication",
            "broken_authorization": "Implement proper access control checks server-side, use role-based access control, and verify permissions for all resources",
            "insecure_data_storage": "Encrypt sensitive data at rest, use strong encryption algorithms, and implement proper key management",
            "insecure_communication": "Enforce TLS/HTTPS for all communications, use strong cipher suites, and implement certificate pinning",
            "security_misconfiguration": "Remove default configurations, disable debug/test endpoints in production, and implement secure defaults",
            "insufficient_input_validation": "Validate all input server-side, use whitelisting, and implement proper type checking",
            "broken_cryptography": "Use strong cryptographic algorithms, implement proper key management, and avoid predictable randomness",
            "insecure_deserialization": "Avoid deserializing untrusted data, use safe serialization formats, and implement input validation",
            "missing_security_headers": "Implement security headers (CSP, HSTS, X-Frame-Options), configure CORS properly, and enable security features",
            "insufficient_logging": "Implement comprehensive audit logging, log security events, and protect logs from tampering"
        }
        return recommendations.get(pattern_name, "Review security design and implement secure design principles")
    
    @staticmethod
    def enhance_finding_with_design_analysis(finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enhance finding with secure design analysis
        """
        enhanced = finding.copy()
        
        # Analyze for design vulnerabilities
        design_analysis = SecureDesignScanner.analyze_design_vulnerability(finding)
        
        if design_analysis:
            enhanced["secure_design_analysis"] = design_analysis
        
        return enhanced
    
    @staticmethod
    def generate_design_test_cases(finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate test cases based on secure design principles
        """
        test_cases = []
        
        design_analysis = finding.get("secure_design_analysis")
        if not design_analysis:
            return test_cases
        
        vulnerability_type = design_analysis.get("design_vulnerability")
        design_flaws = design_analysis.get("design_flaws", [])
        
        for flaw in design_flaws:
            test_case = {
                "test": f"Design Flaw: {flaw}",
                "principle": design_analysis.get("principle_violated"),
                "steps": SecureDesignScanner._get_test_steps(vulnerability_type, flaw),
                "expected": f"Violation of secure design principle: {design_analysis.get('principle_violated')}"
            }
            test_cases.append(test_case)
        
        return test_cases
    
    @staticmethod
    def _get_test_steps(vulnerability_type: str, flaw: str) -> List[str]:
        """Get test steps for design flaw"""
        step_map = {
            "broken_authentication": {
                "predictable_session_ids": [
                    "1. Analyze session ID generation",
                    "2. Test for predictable patterns",
                    "3. Attempt session hijacking",
                    "4. Verify session security"
                ],
                "client_side_authentication": [
                    "1. Check client-side auth logic",
                    "2. Attempt bypass client-side checks",
                    "3. Verify server-side validation",
                    "4. Test unauthorized access"
                ],
                "weak_token_generation": [
                    "1. Analyze token generation",
                    "2. Test for weak randomness",
                    "3. Attempt token prediction",
                    "4. Verify token security"
                ]
            },
            "broken_authorization": {
                "missing_access_control": [
                    "1. Identify protected resources",
                    "2. Test without authentication",
                    "3. Verify access control",
                    "4. Test unauthorized access"
                ],
                "id_based_authorization": [
                    "1. Identify resource IDs",
                    "2. Test IDOR vulnerabilities",
                    "3. Attempt access to other users' resources",
                    "4. Verify authorization checks"
                ]
            }
        }
        
        steps = step_map.get(vulnerability_type, {}).get(flaw)
        if steps:
            return steps
        
        # Default steps
        return [
            "1. Identify design flaw",
            "2. Test for vulnerability",
            "3. Verify impact",
            "4. Document findings"
        ]


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
