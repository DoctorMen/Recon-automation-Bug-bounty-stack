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
Duplicate Detection Module
Integrates with bug bounty knowledge stack and tools
Uses PDF knowledge to identify duplicate patterns and check platforms
"""

import json
import re
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
import requests
from urllib.parse import urlparse

class DuplicateDetector:
    """Advanced duplicate detection using bug bounty knowledge"""
    
    # Duplicate patterns from bug bounty experience
    COMMON_DUPLICATE_PATTERNS = {
        "xss_reflected": {
            "keywords": ["reflected xss", "xss", "cross-site scripting"],
            "duplicate_rate": 0.75,  # 75% duplicate rate
            "check_priority": "high"
        },
        "missing_csp": {
            "keywords": ["missing csp", "content security policy", "csp header"],
            "duplicate_rate": 0.80,
            "check_priority": "high"
        },
        "missing_security_headers": {
            "keywords": ["missing security headers", "x-frame-options", "x-content-type"],
            "duplicate_rate": 0.70,
            "check_priority": "medium"
        },
        "weak_tls": {
            "keywords": ["weak tls", "ssl", "tls version"],
            "duplicate_rate": 0.60,
            "check_priority": "medium"
        },
        "crypto_weak": {
            "keywords": ["weak encryption", "md5", "sha1", "weak cipher"],
            "duplicate_rate": 0.30,  # Crypto bugs less duplicated
            "check_priority": "low"
        },
        "jwt_vulnerability": {
            "keywords": ["jwt", "json web token", "alg=none", "token"],
            "duplicate_rate": 0.20,  # Crypto bugs less duplicated
            "check_priority": "low"
        },
        "idor": {
            "keywords": ["idor", "insecure direct object reference"],
            "duplicate_rate": 0.55,
            "check_priority": "medium"
        },
        "sql_injection": {
            "keywords": ["sql injection", "sqli", "sql"],
            "duplicate_rate": 0.65,
            "check_priority": "high"
        },
        "ssrf": {
            "keywords": ["ssrf", "server-side request forgery"],
            "duplicate_rate": 0.50,
            "check_priority": "medium"
        },
        "rce": {
            "keywords": ["rce", "remote code execution", "code execution"],
            "duplicate_rate": 0.45,  # Less common, lower duplicate rate
            "check_priority": "low"
        },
        "api_auth_bypass": {
            "keywords": ["api", "authentication bypass", "auth bypass"],
            "duplicate_rate": 0.40,
            "check_priority": "medium"
        },
        "timing_attack": {
            "keywords": ["timing attack", "timing", "side-channel"],
            "duplicate_rate": 0.15,  # Very low - crypto bugs
            "check_priority": "low"
        }
    }
    
    # Platform-specific duplicate indicators
    PLATFORM_PATTERNS = {
        "bugcrowd": {
            "api_base": "https://api.bugcrowd.com",
            "search_endpoint": "/programs/{program}/submissions",
            "requires_auth": True
        },
        "hackerone": {
            "api_base": "https://api.hackerone.com",
            "search_endpoint": "/v1/programs/{program}/reports",
            "requires_auth": True
        }
    }
    
    @staticmethod
    def calculate_duplicate_risk(finding: Dict[str, Any]) -> Tuple[float, str, Dict[str, Any]]:
        """
        Calculate duplicate risk score based on vulnerability type and patterns
        Returns: (risk_score 0-1, risk_level, details)
        """
        info = finding.get("info", {})
        name = info.get("name", "").lower()
        description = info.get("description", "").lower()
        template_id = finding.get("template-id", "").lower()
        
        text = f"{name} {description} {template_id}"
        
        # Check for crypto vulnerabilities (low duplicate risk)
        crypto_analysis = finding.get("crypto_analysis")
        if crypto_analysis:
            return (0.15, "low", {
                "reason": "Crypto vulnerability - low duplicate rate",
                "confidence": 0.85
            })
        
        # Check bug classification
        classification = finding.get("bug_classification", {})
        primary_category = classification.get("primary_category", "").lower()
        
        # Crypto category = low duplicate risk
        if "crypto" in primary_category:
            return (0.20, "low", {
                "reason": "Cryptographic vulnerability - typically unique",
                "confidence": 0.80
            })
        
        # Check against known duplicate patterns
        matched_patterns = []
        max_duplicate_rate = 0.0
        
        for pattern_name, pattern_info in DuplicateDetector.COMMON_DUPLICATE_PATTERNS.items():
            for keyword in pattern_info["keywords"]:
                if keyword in text:
                    matched_patterns.append({
                        "pattern": pattern_name,
                        "keyword": keyword,
                        "duplicate_rate": pattern_info["duplicate_rate"],
                        "priority": pattern_info["check_priority"]
                    })
                    max_duplicate_rate = max(max_duplicate_rate, pattern_info["duplicate_rate"])
                    break
        
        # Determine risk level
        if max_duplicate_rate >= 0.70:
            risk_level = "high"
        elif max_duplicate_rate >= 0.50:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        # Adjust based on exploitability
        exploitability = classification.get("exploitability_score", 5)
        if exploitability >= 8:
            # High exploitability = more likely to be found by others
            max_duplicate_rate = min(1.0, max_duplicate_rate * 1.1)
        elif exploitability <= 4:
            # Low exploitability = less likely to be duplicate
            max_duplicate_rate = max_duplicate_rate * 0.9
        
        # Adjust based on severity
        severity = info.get("severity", "medium").lower()
        if severity == "critical":
            # Critical bugs are more likely to be found quickly
            max_duplicate_rate = min(1.0, max_duplicate_rate * 1.05)
        elif severity == "low":
            # Low severity = less competition
            max_duplicate_rate = max_duplicate_rate * 0.85
        
        return (
            min(1.0, max_duplicate_rate),
            risk_level,
            {
                "matched_patterns": matched_patterns,
                "primary_category": primary_category,
                "exploitability": exploitability,
                "severity": severity,
                "confidence": 0.70
            }
        )
    
    @staticmethod
    def check_platform_duplicates(
        finding: Dict[str, Any],
        platform: str = "bugcrowd",
        program: Optional[str] = None,
        api_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Check bug bounty platform for similar bugs
        Note: Requires API access - may not be available for all programs
        """
        if not program or not api_key:
            return {
                "checked": False,
                "reason": "Platform API credentials not provided",
                "recommendation": "Manual check recommended"
            }
        
        info = finding.get("info", {})
        matched_at = finding.get("matched-at", "")
        name = info.get("name", "").lower()
        
        # Parse domain from URL
        try:
            parsed = urlparse(matched_at)
            domain = parsed.netloc
        except:
            domain = ""
        
        # Extract vulnerability type
        vuln_type = DuplicateDetector._extract_vulnerability_type(finding)
        
        # Build search query
        search_terms = [vuln_type, domain]
        
        # Platform-specific checking
        if platform == "bugcrowd":
            return DuplicateDetector._check_bugcrowd(
                program, search_terms, api_key
            )
        elif platform == "hackerone":
            return DuplicateDetector._check_hackerone(
                program, search_terms, api_key
            )
        else:
            return {
                "checked": False,
                "reason": f"Platform {platform} not supported",
                "recommendation": "Manual check recommended"
            }
    
    @staticmethod
    def _extract_vulnerability_type(finding: Dict[str, Any]) -> str:
        """Extract vulnerability type for search"""
        info = finding.get("info", {})
        name = info.get("name", "").lower()
        template_id = finding.get("template-id", "").lower()
        
        # Check classification
        classification = finding.get("bug_classification", {})
        primary_category = classification.get("primary_category", "")
        
        if primary_category:
            return primary_category.replace("_", " ")
        
        # Extract from template ID
        if "xss" in template_id or "xss" in name:
            return "xss"
        elif "sql" in template_id or "sql" in name:
            return "sql injection"
        elif "idor" in template_id or "idor" in name:
            return "idor"
        elif "jwt" in template_id or "jwt" in name:
            return "jwt"
        elif "crypto" in template_id or "crypto" in name:
            return "crypto"
        else:
            return template_id.split("-")[0] if "-" in template_id else "unknown"
    
    @staticmethod
    def _check_bugcrowd(program: str, search_terms: List[str], api_key: str) -> Dict[str, Any]:
        """Check Bugcrowd API for duplicates"""
        try:
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/vnd.bugcrowd+json"
            }
            
            # Build search query
            query = " ".join(search_terms)
            
            # Note: Bugcrowd API structure may vary
            # This is a template - actual implementation depends on API docs
            url = f"https://api.bugcrowd.com/programs/{program}/submissions"
            params = {"q": query, "limit": 10}
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                results = response.json()
                similar_count = len(results.get("data", []))
                
                return {
                    "checked": True,
                    "platform": "bugcrowd",
                    "similar_found": similar_count,
                    "recommendation": "check_manual" if similar_count > 0 else "likely_unique"
                }
            else:
                return {
                    "checked": False,
                    "reason": f"API returned status {response.status_code}",
                    "recommendation": "manual_check"
                }
        except Exception as e:
            return {
                "checked": False,
                "reason": str(e),
                "recommendation": "manual_check"
            }
    
    @staticmethod
    def _check_hackerone(program: str, search_terms: List[str], api_key: str) -> Dict[str, Any]:
        """Check HackerOne API for duplicates"""
        try:
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json"
            }
            
            query = " ".join(search_terms)
            url = f"https://api.hackerone.com/v1/programs/{program}/reports"
            params = {"filter[search]": query, "page[size]": 10}
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                results = response.json()
                similar_count = len(results.get("data", []))
                
                return {
                    "checked": True,
                    "platform": "hackerone",
                    "similar_found": similar_count,
                    "recommendation": "check_manual" if similar_count > 0 else "likely_unique"
                }
            else:
                return {
                    "checked": False,
                    "reason": f"API returned status {response.status_code}",
                    "recommendation": "manual_check"
                }
        except Exception as e:
            return {
                "checked": False,
                "reason": str(e),
                "recommendation": "manual_check"
            }
    
    @staticmethod
    def generate_duplicate_report(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive duplicate analysis report"""
        report = {
            "total_findings": len(findings),
            "risk_distribution": {"high": 0, "medium": 0, "low": 0},
            "recommendations": [],
            "findings_analysis": []
        }
        
        for finding in findings:
            risk_score, risk_level, details = DuplicateDetector.calculate_duplicate_risk(finding)
            report["risk_distribution"][risk_level] += 1
            
            finding_analysis = {
                "template_id": finding.get("template-id", ""),
                "name": finding.get("info", {}).get("name", ""),
                "risk_score": risk_score,
                "risk_level": risk_level,
                "details": details,
                "recommendation": DuplicateDetector._get_recommendation(risk_score, risk_level)
            }
            
            report["findings_analysis"].append(finding_analysis)
        
        # Generate recommendations
        high_risk_count = report["risk_distribution"]["high"]
        if high_risk_count > 0:
            report["recommendations"].append(
                f"⚠️ {high_risk_count} findings have HIGH duplicate risk. "
                "Consider manual verification before submission."
            )
        
        crypto_count = sum(1 for f in report["findings_analysis"] 
                          if f["risk_level"] == "low" and "crypto" in f["details"].get("reason", "").lower())
        if crypto_count > 0:
            report["recommendations"].append(
                f"✅ {crypto_count} crypto findings have LOW duplicate risk. "
                "These are recommended for submission."
            )
        
        return report
    
    @staticmethod
    def _get_recommendation(risk_score: float, risk_level: str) -> str:
        """Get recommendation based on risk"""
        if risk_level == "low":
            return "✅ LOW RISK - Likely unique, safe to submit"
        elif risk_level == "medium":
            return "⚠️ MEDIUM RISK - Check platform for similar bugs before submitting"
        else:
            return "🔴 HIGH RISK - High chance of duplicate. Manual verification strongly recommended"
    
    @staticmethod
    def filter_high_risk_duplicates(findings: List[Dict[str, Any]], threshold: float = 0.70) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Filter findings by duplicate risk threshold"""
        safe_findings = []
        risky_findings = []
        
        for finding in findings:
            risk_score, risk_level, _ = DuplicateDetector.calculate_duplicate_risk(finding)
            
            if risk_score < threshold:
                safe_findings.append(finding)
            else:
                risky_findings.append(finding)
        
        return safe_findings, risky_findings


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
