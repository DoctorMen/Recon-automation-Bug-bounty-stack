#!/usr/bin/env python3
"""
OPSEC & Scope Validator
Ensures bug bounty scanning is safe and authorized
"""

import json
import re
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any
from urllib.parse import urlparse

class OPSECValidator:
    """
    Validates targets for OPSEC readiness and scope compliance
    """
    
    # Beginner-Accessible Crypto Bug Bounty Programs (NO Premium Required)
    CRYPTO_PROGRAMS = {
        # Immunefi Programs (Public Access)
        "polygon": {
            "domains": ["polygon.technology", "*.polygon.technology", "api.polygon.io"],
            "platform": "immunefi",
            "program_url": "https://immunefi.com/bug-bounty/polygon",
            "max_reward": "$2,000,000",
            "scope": ["api", "web", "smart_contracts"],
            "access_level": "public",
            "beginner_friendly": True
        },
        "avalanche": {
            "domains": ["avax.network", "*.avax.network", "api.avax.network"],
            "platform": "immunefi",
            "program_url": "https://immunefi.com/bug-bounty/avalanche",
            "max_reward": "$1,000,000",
            "scope": ["api", "web", "smart_contracts"],
            "access_level": "public",
            "beginner_friendly": True
        },
        "chainlink": {
            "domains": ["chain.link", "*.chain.link", "api.chain.link"],
            "platform": "immunefi",
            "program_url": "https://immunefi.com/bug-bounty/chainlink",
            "max_reward": "$2,000,000",
            "scope": ["api", "web", "smart_contracts"],
            "access_level": "public",
            "beginner_friendly": True
        },
        # HackenProof Programs (Public Access)
        "whitebit": {
            "domains": ["whitebit.com", "*.whitebit.com"],
            "platform": "hackenproof",
            "program_url": "https://hackenproof.com/whitebit",
            "max_reward": "$10,000",
            "scope": ["api", "web", "exchange"],
            "access_level": "public",
            "beginner_friendly": True
        },
        "nicehash": {
            "domains": ["nicehash.com", "*.nicehash.com"],
            "platform": "hackenproof",
            "program_url": "https://hackenproof.com/nicehash",
            "max_reward": "$22,500",
            "scope": ["api", "mining", "platform"],
            "access_level": "public",
            "beginner_friendly": True
        },
        "coinscope": {
            "domains": ["coinscope.com", "*.coinscope.com", "api.coinscope.com"],
            "platform": "hackenproof",
            "program_url": "https://hackenproof.com/coinscope",
            "max_reward": "$5,000",
            "scope": ["api", "web", "analytics"],
            "access_level": "public",
            "beginner_friendly": True
        },
        # Public DeFi Platforms
        "uniswap": {
            "domains": ["uniswap.org", "app.uniswap.org"],
            "platform": "public",
            "program_url": "https://immunefi.com",
            "max_reward": "varies",
            "scope": ["web", "api", "dapp"],
            "access_level": "public",
            "beginner_friendly": True
        },
        "1inch": {
            "domains": ["1inch.io", "api.1inch.io"],
            "platform": "public",
            "program_url": "https://immunefi.com",
            "max_reward": "varies",
            "scope": ["web", "api", "defi"],
            "access_level": "public",
            "beginner_friendly": True
        },
        "sushiswap": {
            "domains": ["sushiswap.com", "app.sushiswap.com"],
            "platform": "public",
            "program_url": "https://immunefi.com",
            "max_reward": "varies",
            "scope": ["web", "api", "dapp"],
            "access_level": "public",
            "beginner_friendly": True
        }
    }
    
    # Beginner-Accessible Bug Bounty Programs (NO Premium Required)
    AUTHORIZED_PROGRAMS = {
        # Immunefi Programs (Public Access)
        "immunefi": [
            "polygon.technology", "avax.network", "chain.link"
        ],
        # HackenProof Programs (Public Access)
        "hackenproof": [
            "whitebit.com", "nicehash.com", "coinscope.com"
        ],
        # Public DeFi Platforms
        "public_defi": [
            "uniswap.org", "1inch.io", "sushiswap.com"
        ],
        # Code4rena Programs (Competitive Audit Contests)
        "code4rena": [
            "blackhole-exchange.com",
            "app.blackhole-exchange.com",
            "api.blackhole-exchange.com"
        ]
    }
    
    # High-risk patterns that require caution
    HIGH_RISK_PATTERNS = {
        "government": [".gov", ".mil", ".edu"],
        "financial": ["bank", "financial", "credit", "mortgage"],
        "healthcare": ["health", "medical", "hospital", "pharma"],
        "critical_infrastructure": ["power", "energy", "utility", "infrastructure"]
    }
    
    # OPSEC best practices
    OPSEC_RULES = {
        "rate_limiting": {
            "enabled": True,
            "requests_per_second": 10,
            "burst_limit": 50,
            "cooldown": 60  # seconds
        },
        "user_agents": {
            "rotate": True,
            "default": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "custom": False  # Don't use custom UAs that identify scanners
        },
        "headers": {
            "remove_identifying": True,
            "remove": ["X-Scanner", "X-Tool", "User-Agent-Bug-Bounty"],
            "add": {}  # Don't add identifying headers
        },
        "scanning_behavior": {
            "randomize_delays": True,
            "avoid_patterns": True,
            "respect_robots_txt": True,
            "avoid_dos": True
        }
    }
    
    @staticmethod
    def validate_target(target: str) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validate a target for scope and OPSEC readiness
        Returns: (is_valid, reason, metadata)
        """
        target_lower = target.lower().strip()
        
        # Check if empty
        if not target_lower:
            return False, "Empty target", {}
        
        # Check for dangerous patterns
        for category, patterns in OPSECValidator.HIGH_RISK_PATTERNS.items():
            for pattern in patterns:
                if pattern in target_lower:
                    return False, f"High-risk target ({category}) - verify authorization", {
                        "category": category,
                        "risk": "high",
                        "requires_manual_review": True
                    }
        
        # Check for government domains
        if ".gov" in target_lower or ".mil" in target_lower:
            return False, "Government domain - requires explicit authorization", {
                "category": "government",
                "risk": "critical",
                "requires_manual_review": True
            }
        
        # Check for educational domains (often have strict policies)
        if ".edu" in target_lower:
            return False, "Educational domain - verify scope and authorization", {
                "category": "educational",
                "risk": "medium",
                "requires_manual_review": True
            }
        
        # Validate domain format
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', target_lower):
            return False, "Invalid domain format", {}
        
        # Check if it's a known authorized program
        is_authorized = False
        program_type = None
        for ptype, domains in OPSECValidator.AUTHORIZED_PROGRAMS.items():
            for domain in domains:
                if target_lower == domain or target_lower.endswith(f".{domain}"):
                    is_authorized = True
                    program_type = ptype
                    break
            if is_authorized:
                break
        
        if is_authorized:
            return True, "Authorized bug bounty program", {
                "authorized": True,
                "program_type": program_type,
                "risk": "low"
            }
        
        # Generic validation (assume OK but warn)
        return True, "Target validated - verify scope before scanning", {
            "authorized": False,
            "requires_scope_check": True,
            "risk": "medium"
        }
    
    @staticmethod
    def validate_targets_file(targets_file: Path) -> Tuple[List[str], List[str], List[Dict[str, Any]]]:
        """
        Validate all targets in targets.txt
        Returns: (valid_targets, invalid_targets, warnings)
        """
        if not targets_file.exists():
            return [], [], [{"target": "targets.txt", "issue": "File not found"}]
        
        valid_targets = []
        invalid_targets = []
        warnings = []
        
        with open(targets_file, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue
                
                # Validate target
                is_valid, reason, metadata = OPSECValidator.validate_target(line)
                
                if is_valid:
                    valid_targets.append(line)
                    if metadata.get("requires_scope_check"):
                        warnings.append({
                            "target": line,
                            "line": line_num,
                            "warning": reason,
                            "metadata": metadata
                        })
                else:
                    invalid_targets.append({
                        "target": line,
                        "line": line_num,
                        "reason": reason,
                        "metadata": metadata
                    })
        
        return valid_targets, invalid_targets, warnings
    
    @staticmethod
    def apply_opsec_config() -> Dict[str, Any]:
        """
        Generate OPSEC-safe configuration
        """
        return {
            "rate_limiting": {
                "httpx_rate_limit": OPSECValidator.OPSEC_RULES["rate_limiting"]["requests_per_second"],
                "nuclei_rate_limit": 30,  # Slower for Nuclei
                "threads": 50,  # Moderate thread count
                "timeout": 10,
                "retries": 2
            },
            "headers": {
                "user_agent": OPSECValidator.OPSEC_RULES["user_agents"]["default"],
                "remove_identifying": True
            },
            "scanning": {
                "avoid_dos": True,
                "respect_robots_txt": True,
                "randomize_delays": True
            },
            "exclusions": {
                "skip_health_checks": False,
                "skip_load_balancers": False,
                "skip_cdn": False
            }
        }
    
    @staticmethod
    def generate_opsec_report(targets_file: Path) -> Dict[str, Any]:
        """
        Generate OPSEC readiness report
        """
        valid_targets, invalid_targets, warnings = OPSECValidator.validate_targets_file(targets_file)
        opsec_config = OPSECValidator.apply_opsec_config()
        
        return {
            "opsec_ready": len(invalid_targets) == 0,
            "valid_targets": len(valid_targets),
            "invalid_targets": len(invalid_targets),
            "warnings": len(warnings),
            "targets": {
                "valid": valid_targets,
                "invalid": invalid_targets,
                "warnings": warnings
            },
            "opsec_config": opsec_config,
            "recommendations": OPSECValidator._get_recommendations(invalid_targets, warnings)
        }
    
    @staticmethod
    def _get_recommendations(invalid_targets: List[Dict], warnings: List[Dict]) -> List[str]:
        """Get OPSEC recommendations"""
        recommendations = []
        
        if invalid_targets:
            recommendations.append("⚠️ REMOVE unauthorized targets before scanning")
            recommendations.append("⚠️ Verify scope for all targets at bug bounty platform")
        
        if warnings:
            recommendations.append("⚠️ Review warnings - some targets require scope verification")
        
        recommendations.append("✅ Use rate limiting to avoid detection")
        recommendations.append("✅ Rotate user agents (enabled)")
        recommendations.append("✅ Remove identifying headers (enabled)")
        recommendations.append("✅ Respect robots.txt (enabled)")
        recommendations.append("✅ Avoid aggressive scanning patterns")
        
        return recommendations

