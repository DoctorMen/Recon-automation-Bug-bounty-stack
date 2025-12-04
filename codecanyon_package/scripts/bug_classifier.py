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
Advanced Bug Classifier for Bug Bounty
Incorporates methodologies from:
- Bug Bounty Bootcamp
- Ethical Hacking
- Hacking APIs
- Crypto Dictionary
- Cyberjutsu
- Industry bug bounty standards
"""

import re
from typing import Dict, Any, List, Tuple
from datetime import datetime


class BugClassifier:
    """Advanced bug classification system based on bug bounty methodology"""
    
    # Vulnerability type mappings based on bug bounty categorization
    VULN_CATEGORIES = {
        "authentication": {
            "keywords": ["auth", "login", "session", "token", "jwt", "oauth", "bearer", "authentication", "credential"],
            "severity_weight": 1.2,
            "bounty_tier": "high",
            "cwe_mappings": ["CWE-287", "CWE-306", "CWE-798", "CWE-307"]
        },
        "authorization": {
            "keywords": ["idor", "authorization", "privilege", "access control", "permission", "rbac", "acl"],
            "severity_weight": 1.3,
            "bounty_tier": "high",
            "cwe_mappings": ["CWE-639", "CWE-285", "CWE-284", "CWE-639"]
        },
        "injection": {
            "keywords": ["sqli", "sql injection", "nosql", "command injection", "ldap", "xpath", "template injection", "code injection"],
            "severity_weight": 1.4,
            "bounty_tier": "critical",
            "cwe_mappings": ["CWE-89", "CWE-78", "CWE-79", "CWE-94", "CWE-95"]
        },
        "crypto": {
            "keywords": [
                "crypto", "encryption", "ssl", "tls", "certificate", "weak cipher", "md5", "sha1", "bcrypt", 
                "password hash", "jwt", "token", "timing attack", "predictable", "weak randomness", "algorithm",
                "cipher", "des", "rc4", "3des", "hash", "hmac", "signature", "nonce", "iv", "key", "secret"
            ],
            "severity_weight": 1.3,  # Increased - crypto bugs are valuable
            "bounty_tier": "high",  # Upgraded to high
            "cwe_mappings": ["CWE-327", "CWE-326", "CWE-330", "CWE-311", "CWE-287", "CWE-208"]
        },
        "api_security": {
            "keywords": ["api", "graphql", "rest", "soap", "endpoint", "rate limit", "mass assignment", "broken object", "api key"],
            "severity_weight": 1.2,
            "bounty_tier": "high",
            "cwe_mappings": ["CWE-639", "CWE-434", "CWE-307"]
        },
        "secrets": {
            "keywords": ["secret", "key", "credential", "password", "token", "api key", "aws", "gcp", "azure", "github token"],
            "severity_weight": 1.5,
            "bounty_tier": "critical",
            "cwe_mappings": ["CWE-798", "CWE-200"]
        },
        "ssrf": {
            "keywords": ["ssrf", "server-side request forgery", "request forgery", "internal network"],
            "severity_weight": 1.4,
            "bounty_tier": "critical",
            "cwe_mappings": ["CWE-918"]
        },
        "xxe": {
            "keywords": ["xxe", "xml external entity", "xml injection", "xml parser"],
            "severity_weight": 1.3,
            "bounty_tier": "high",
            "cwe_mappings": ["CWE-611"]
        },
        "xss": {
            "keywords": ["xss", "cross-site scripting", "reflected", "stored", "dom"],
            "severity_weight": 1.0,
            "bounty_tier": "medium",
            "cwe_mappings": ["CWE-79"]
        },
        "rce": {
            "keywords": ["rce", "remote code execution", "code execution", "command execution", "eval", "deserialization"],
            "severity_weight": 1.5,
            "bounty_tier": "critical",
            "cwe_mappings": ["CWE-94", "CWE-502"]
        },
        "lfi_rfi": {
            "keywords": ["lfi", "rfi", "local file inclusion", "remote file inclusion", "file inclusion", "path traversal"],
            "severity_weight": 1.2,
            "bounty_tier": "high",
            "cwe_mappings": ["CWE-22", "CWE-23"]
        },
        "cors": {
            "keywords": ["cors", "cross-origin", "origin", "access-control"],
            "severity_weight": 0.9,
            "bounty_tier": "medium",
            "cwe_mappings": ["CWE-942"]
        },
        "csrf": {
            "keywords": ["csrf", "cross-site request forgery", "state changing"],
            "severity_weight": 0.8,
            "bounty_tier": "medium",
            "cwe_mappings": ["CWE-352"]
        },
        "information_disclosure": {
            "keywords": ["information disclosure", "information leak", "sensitive data", "exposed", "leak", "disclosure"],
            "severity_weight": 0.7,
            "bounty_tier": "low-medium",
            "cwe_mappings": ["CWE-200"]
        },
        "subdomain_takeover": {
            "keywords": ["subdomain takeover", "dns", "cname", "subdomain"],
            "severity_weight": 1.2,
            "bounty_tier": "high",
            "cwe_mappings": ["CWE-639"]
        },
        "business_logic": {
            "keywords": ["business logic", "race condition", "payment", "transaction", "workflow", "price manipulation"],
            "severity_weight": 1.3,
            "bounty_tier": "high",
            "cwe_mappings": ["CWE-840"]
        }
    }
    
    # Bug bounty payout tiers (based on industry standards)
    BOUNTY_TIERS = {
        "critical": {
            "typical_range": "$1000-$50000",
            "cvss_range": "9.0-10.0",
            "priority": 1
        },
        "high": {
            "typical_range": "$500-$5000",
            "cvss_range": "7.0-8.9",
            "priority": 2
        },
        "medium": {
            "typical_range": "$100-$1000",
            "cvss_range": "5.0-6.9",
            "priority": 3
        },
        "low": {
            "typical_range": "$25-$500",
            "cvss_range": "0.1-4.9",
            "priority": 4
        }
    }
    
    @staticmethod
    def classify_vulnerability(finding: Dict[str, Any]) -> Dict[str, Any]:
        """Classify vulnerability type and assign bug bounty metrics"""
        info = finding.get("info", {})
        template_id = finding.get("template-id", "").lower()
        name = info.get("name", "").lower()
        description = info.get("description", "").lower()
        tags = [tag.lower() for tag in info.get("tags", [])]
        
        # Combine all text for analysis
        text = f"{template_id} {name} {description} {' '.join(tags)}"
        
        # Detect vulnerability category
        detected_categories = []
        category_scores = {}
        
        for category, config in BugClassifier.VULN_CATEGORIES.items():
            score = 0
            matches = []
            
            # Check keywords
            for keyword in config["keywords"]:
                pattern = r'\b' + re.escape(keyword.lower()) + r'\b'
                if re.search(pattern, text):
                    matches.append(keyword)
                    score += 1
            
            # Check tags
            for tag in tags:
                if tag in config["keywords"]:
                    score += 2
            
            # Check template ID
            if any(keyword in template_id for keyword in config["keywords"]):
                score += 2
            
            if score > 0:
                detected_categories.append(category)
                category_scores[category] = {
                    "score": score,
                    "matches": matches,
                    "severity_weight": config["severity_weight"],
                    "bounty_tier": config["bounty_tier"],
                    "cwe_mappings": config["cwe_mappings"]
                }
        
        # Get primary category (highest score)
        primary_category = None
        if category_scores:
            primary_category = max(category_scores.items(), key=lambda x: x[1]["score"])[0]
        
        # Determine if it's API-specific
        is_api_vulnerability = any(
            keyword in text for keyword in ["api", "endpoint", "graphql", "rest", "soap", "/api/"]
        )
        
        # Determine if it's crypto-related
        is_crypto_vulnerability = any(
            keyword in text for keyword in [
                "crypto", "encryption", "ssl", "tls", "certificate", "hash", "cipher",
                "jwt", "token", "timing attack", "predictable", "weak randomness",
                "algorithm", "des", "rc4", "md5", "sha1", "hmac", "signature"
            ]
        ) or finding.get("crypto_analysis") is not None  # Check for crypto scanner findings
        
        # Determine if it's payment-related (high value)
        is_payment_related = any(
            keyword in text for keyword in ["payment", "transaction", "checkout", "billing", "wallet", "credit card"]
        )
        
        # Calculate exploitability score
        exploitability = BugClassifier._calculate_exploitability(
            finding, primary_category, category_scores, is_api_vulnerability, is_payment_related
        )
        
        # Estimate bug bounty value
        bounty_estimate = BugClassifier._estimate_bounty_value(
            finding, primary_category, category_scores, exploitability, is_payment_related
        )
        
        # Get severity from Nuclei
        base_severity = info.get("severity", "info").lower()
        
        # Adjust severity based on category
        adjusted_severity = BugClassifier._adjust_severity(
            base_severity, primary_category, category_scores, is_payment_related
        )
        
        return {
            "primary_category": primary_category,
            "categories": detected_categories,
            "category_scores": category_scores,
            "is_api_vulnerability": is_api_vulnerability,
            "is_crypto_vulnerability": is_crypto_vulnerability,
            "is_payment_related": is_payment_related,
            "exploitability_score": exploitability,
            "bounty_estimate": bounty_estimate,
            "base_severity": base_severity,
            "adjusted_severity": adjusted_severity,
            "cwe_ids": category_scores.get(primary_category, {}).get("cwe_mappings", []) if primary_category else [],
            "bounty_tier": category_scores.get(primary_category, {}).get("bounty_tier", "medium") if primary_category else "medium",
            "classification_confidence": min(100, max(0, sum(cs["score"] for cs in category_scores.values())) * 10)
        }
    
    @staticmethod
    def _calculate_exploitability(
        finding: Dict[str, Any],
        primary_category: str,
        category_scores: Dict[str, Dict],
        is_api: bool,
        is_payment: bool
    ) -> int:
        """Calculate exploitability score (1-10) based on multiple factors"""
        score = 0
        info = finding.get("info", {})
        
        # Base severity
        severity = info.get("severity", "info").lower()
        severity_base = {"critical": 5, "high": 4, "medium": 2, "low": 1, "info": 0}.get(severity, 1)
        score += severity_base
        
        # Category-based bonus
        if primary_category and primary_category in category_scores:
            weight = category_scores[primary_category]["severity_weight"]
            score = int(score * weight)
        
        # API vulnerabilities often easier to exploit
        if is_api:
            score += 1
        
        # Payment-related = higher value
        if is_payment:
            score += 2
        
        # Crypto vulnerabilities are valuable (often overlooked)
        if finding.get("crypto_analysis") or is_crypto_vulnerability:
            score += 2
        
        # Verified findings
        if info.get("verified", False):
            score += 2
        
        # CVE reference
        if info.get("cve-id"):
            score += 1
        
        # CWE reference
        if info.get("cwe-id"):
            score += 1
        
        # Cap at 10
        return min(10, score)
    
    @staticmethod
    def _estimate_bounty_value(
        finding: Dict[str, Any],
        primary_category: str,
        category_scores: Dict[str, Dict],
        exploitability: int,
        is_payment: bool
    ) -> Dict[str, Any]:
        """Estimate bug bounty payout range"""
        info = finding.get("info", {})
        severity = info.get("severity", "info").lower()
        
        # Base tier
        if severity == "critical":
            tier = "critical"
        elif severity == "high":
            tier = "high"
        elif severity == "medium":
            tier = "medium"
        else:
            tier = "low"
        
        # Category-based adjustment
        if primary_category and primary_category in category_scores:
            category_tier = category_scores[primary_category]["bounty_tier"]
            if category_tier == "critical":
                tier = "critical"
            elif category_tier == "high" and tier in ["medium", "low"]:
                tier = "high"
        
        # Payment-related bonus
        if is_payment and tier in ["medium", "low"]:
            tier = "high"
        
        # Exploitability bonus
        if exploitability >= 8:
            tier = "critical" if tier == "high" else tier
        elif exploitability >= 6:
            tier = "high" if tier == "medium" else tier
        
        # Get tier info
        tier_info = BugClassifier.BOUNTY_TIERS.get(tier, BugClassifier.BOUNTY_TIERS["medium"])
        
        # Calculate estimate range
        range_str = tier_info["typical_range"]
        
        return {
            "tier": tier,
            "estimated_range": range_str,
            "priority": tier_info["priority"],
            "confidence": "high" if exploitability >= 7 else "medium" if exploitability >= 4 else "low"
        }
    
    @staticmethod
    def _adjust_severity(
        base_severity: str,
        primary_category: str,
        category_scores: Dict[str, Dict],
        is_payment: bool
    ) -> str:
        """Adjust severity based on context"""
        severity_order = ["info", "low", "medium", "high", "critical"]
        
        try:
            current_idx = severity_order.index(base_severity)
        except ValueError:
            current_idx = 1
        
        # Category-based adjustment
        if primary_category and primary_category in category_scores:
            category_tier = category_scores[primary_category]["bounty_tier"]
            if category_tier == "critical" and current_idx < 4:
                current_idx = 4
            elif category_tier == "high" and current_idx < 3:
                current_idx = 3
        
        # Payment-related = higher severity
        if is_payment and current_idx < 3:
            current_idx = 3
        
        return severity_order[min(current_idx, len(severity_order) - 1)]
    
    @staticmethod
    def generate_classification_report(classifications: List[Dict[str, Any]]) -> str:
        """Generate classification summary report"""
        if not classifications:
            return "No classifications available."
        
        # Count by category
        category_counts = {}
        tier_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        api_count = 0
        crypto_count = 0
        payment_count = 0
        
        for cls in classifications:
            cat = cls.get("primary_category", "unknown")
            category_counts[cat] = category_counts.get(cat, 0) + 1
            
            tier = cls.get("bounty_tier", "medium")
            tier_counts[tier] = tier_counts.get(tier, 0) + 1
            
            if cls.get("is_api_vulnerability"):
                api_count += 1
            if cls.get("is_crypto_vulnerability"):
                crypto_count += 1
            if cls.get("is_payment_related"):
                payment_count += 1
        
        report = "# Bug Classification Summary\n\n"
        report += f"**Total Classified**: {len(classifications)}\n\n"
        
        report += "## By Category\n\n"
        for cat, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
            report += f"- **{cat.replace('_', ' ').title()}**: {count}\n"
        
        report += "\n## By Bounty Tier\n\n"
        for tier in ["critical", "high", "medium", "low"]:
            count = tier_counts.get(tier, 0)
            if count > 0:
                report += f"- **{tier.upper()}**: {count}\n"
        
        report += "\n## Special Classifications\n\n"
        report += f"- **API Vulnerabilities**: {api_count}\n"
        report += f"- **Crypto Vulnerabilities**: {crypto_count}\n"
        report += f"- **Payment-Related**: {payment_count}\n"
        
        return report


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
