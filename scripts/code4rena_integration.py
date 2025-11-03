#!/usr/bin/env python3
"""
Code4rena Bug Bounty Integration
For competitive audit contests on Code4rena platform
"""

import json
import re
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from urllib.parse import urlparse

class Code4renaIntegration:
    """
    Code4rena platform integration for bug bounty automation
    Handles Code4rena-specific submission format and scope validation
    """
    
    # Code4rena programs
    CODE4RENA_PROGRAMS = {
        "blackhole": {
            "name": "Blackhole",
            "platform": "code4rena",
            "program_url": "https://code4rena.com/bounties/blackhole",
            "max_bounty": "$100,000 in $BLACK",
            "type": "DEX",
            "chain": "Avalanche",
            "description": "Largest DEX on Avalanche by daily trading volume",
            "github_repo": "https://github.com/BlackHoleDEX/Contracts",
            "scope": {
                "smart_contracts": True,
                "web_frontend": True,
                "api_endpoints": True,
                "trading_logic": True,
                "liquidity_pools": True,
                "governance": False  # Out of scope
            },
            "in_scope_contracts": {
                "amm_pools": [
                    "Pair.sol",
                    "PairFees.sol",
                    "PairFactory.sol",
                    "PairGenerator.sol",
                    "RouterV2.sol",
                    "RouterHelper.sol",
                    "TokenHandler.sol"
                ],
                "ve33": [
                    "GaugeManager.sol",
                    "GaugeFactory.sol",
                    "GaugeFactoryCL.sol",
                    "GaugeExtraRewarder.sol",
                    "GaugeOwner.sol",
                    "GaugeV2.sol",
                    "GaugeCL.sol"
                ],
                "genesis_pool": [
                    "GenesisPool.sol",
                    "GenesisPoolFactory.sol",
                    "GenesisPoolManager.sol",
                    "Interfaces"
                ],
                "api_helpers": [
                    "AlgebraPoolApiStorage.sol",
                    "AlgebraPoolApi.sol",
                    "BlackHolePairApiV2.sol",
                    "GenesisPoolApi.sol",
                    "RewardApi.sol",
                    "TokenApi.sol",
                    "VNFTAPIV1.sol"
                ],
                "avm": [
                    "AutoVotingEscrowManager.sol",
                    "AutoVotingEscrow.sol",
                    "SetterTopNPoolStrategy.sol",
                    "SetterVoterWeightStrategy.sol",
                    "FoxedAuction.sol"
                ],
                "others": [
                    "PermissionRegistry.sol",
                    "BlackClaim.sol",
                    "AuctionFactory.sol",
                    "BlackTimeLibrary.sol",
                    "VoterFactoryLib.sol"
                ]
            },
            "out_of_scope": [
                "VNFTApi.sol",
                "ChainLink contracts",
                "Governance contracts",
                "BlackGovernor.sol",
                "TradeHelper.sol",
                "CustomToken.sol",
                "GlobalRouter.sol",
                "Waves.sol"
            ],
            "known_issues": [
                "getNFTPoolVotes() function (unused variable - timestamp before first lock returns wrong value)",
                "VotingEscrow::delegateBySig::DOMAIN_TYPEHASH variable is wrong (doesn't consider version)",
                "GaugeCL.sol: getReward(uint256 tokenId, bool isBonusReward) - inherent flaw with msg.sender",
                "GaugeFactoryCL.sol: createGauge() - transferring 10^-8 black (not exploitable due to require statement)",
                "GenesisPoolManager.depositNativeToken - can be called from whitelisted address when previous pool not in not_qualified state",
                "GenesisPool DoS attack before calling GenesisPoolManager.approveGenesisPool",
                "GenesisPool token ratio manipulation - tokens deposited directly into Pair address after GenesisPoolApproval",
                "All vulnerabilities from previous audits at https://docs.blackhole.xyz/security"
            ],
            "previous_audits": "https://docs.blackhole.xyz/security",
            "severity_criteria": {
                "critical": "Loss of user funds",
                "severe": "Temporary denial of service, incorrect calculations"
            },
            "payout_based_on_tvl": True,
            "tvl_payout_ratios": {
                "below_50m": "50% of category bounty",
                "50m_to_125m": "75% of category bounty",
                "above_125m": "100% of category bounty"
            },
            "focus_areas": [
                "Reentrancy attacks",
                "Flash loan vulnerabilities",
                "Price manipulation",
                "Liquidity pool exploits",
                "Access control issues",
                "Integer overflow/underflow",
                "Front-running vulnerabilities",
                "MEV exploitation",
                "Token approval issues",
                "Router vulnerabilities"
            ],
            "submission_format": "code4rena",
            "submission_url": "https://code4rena.com/bounties/blackhole/make-submission"
        }
    }
    
    # DEX-specific vulnerability patterns
    DEX_VULNERABILITY_PATTERNS = {
        "reentrancy": {
            "severity": "critical",
            "methodology": "Reentrancy attacks in swap functions",
            "tests": [
                "Check external calls before state changes",
                "Test recursive calls in swap functions",
                "Verify nonReentrant modifiers"
            ]
        },
        "flash_loan_attack": {
            "severity": "critical",
            "methodology": "Flash loan price manipulation",
            "tests": [
                "Test flash loan price manipulation",
                "Verify oracle price validation",
                "Check minimum liquidity requirements"
            ]
        },
        "price_manipulation": {
            "severity": "high",
            "methodology": "Price oracle manipulation",
            "tests": [
                "Test oracle price manipulation",
                "Verify price calculation logic",
                "Check TWAP (Time-Weighted Average Price) validation"
            ]
        },
        "access_control": {
            "severity": "high",
            "methodology": "Unauthorized access to critical functions",
            "tests": [
                "Test onlyOwner/onlyAdmin modifiers",
                "Verify role-based access control",
                "Check function visibility"
            ]
        },
        "integer_overflow": {
            "severity": "high",
            "methodology": "Integer overflow/underflow in calculations",
            "tests": [
                "Test overflow in swap calculations",
                "Verify SafeMath usage",
                "Check maximum value handling"
            ]
        },
        "front_running": {
            "severity": "medium",
            "methodology": "Front-running vulnerabilities",
            "tests": [
                "Test MEV exploitation",
                "Verify transaction ordering",
                "Check slippage protection"
            ]
        },
        "token_approval": {
            "severity": "high",
            "methodology": "Unlimited token approval vulnerabilities",
            "tests": [
                "Test unlimited approval risks",
                "Verify approval amounts",
                "Check approval revocation"
            ]
        },
        "liquidity_pool_exploit": {
            "severity": "critical",
            "methodology": "Liquidity pool manipulation",
            "tests": [
                "Test liquidity pool drainage",
                "Verify pool balance validation",
                "Check emergency withdrawal functions"
            ]
        },
        "router_vulnerability": {
            "severity": "high",
            "methodology": "Router contract vulnerabilities",
            "tests": [
                "Test swap path validation",
                "Verify router security",
                "Check multi-hop swap logic"
            ]
        }
    }
    
    @staticmethod
    def get_program_info(program_name: str) -> Optional[Dict[str, Any]]:
        """Get Code4rena program information"""
        return Code4renaIntegration.CODE4RENA_PROGRAMS.get(program_name.lower())
    
    @staticmethod
    def validate_scope(url: str, program_name: str) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validate if URL is within Code4rena program scope
        """
        program = Code4renaIntegration.get_program_info(program_name)
        if not program:
            return False, f"Program {program_name} not found", {}
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Check if domain matches program scope
        scope = program.get("scope", {})
        
        # Smart contracts are typically tested via GitHub repo, not URL
        if scope.get("smart_contracts"):
            # Web frontend and API endpoints can be tested via URL
            if scope.get("web_frontend") or scope.get("api_endpoints"):
                # Accept any domain/subdomain for web/API testing
                return True, program_name, program
        
        return False, "Not in scope", {}
    
    @staticmethod
    def generate_code4rena_submission(finding: Dict[str, Any], program_name: str) -> Dict[str, Any]:
        """
        Generate Code4rena submission format
        Code4rena uses a specific format for submissions
        """
        program = Code4renaIntegration.get_program_info(program_name)
        if not program:
            return {}
        
        submission = {
            "title": finding.get("title", finding.get("type", "Vulnerability")),
            "severity": finding.get("severity", "medium"),
            "impact": finding.get("impact", finding.get("description", "")),
            "description": finding.get("description", ""),
            "steps_to_reproduce": finding.get("steps", []),
            "proof_of_concept": finding.get("proof", ""),
            "recommended_fix": finding.get("recommendation", ""),
            "contract_address": finding.get("contract_address", ""),
            "vulnerability_type": finding.get("type", ""),
            "methodology": finding.get("methodology", ""),
            "platform": "code4rena",
            "program": program_name,
            "submission_url": program.get("submission_url", "")
        }
        
        return submission
    
    @staticmethod
    def get_dex_test_cases() -> List[Dict[str, Any]]:
        """
        Generate DEX-specific test cases for Blackhole
        Based on DeFi security best practices
        """
        test_cases = []
        
        for vuln_type, vuln_info in Code4renaIntegration.DEX_VULNERABILITY_PATTERNS.items():
            test_cases.append({
                "type": vuln_type,
                "severity": vuln_info["severity"],
                "methodology": vuln_info["methodology"],
                "tests": vuln_info["tests"],
                "description": f"{vuln_type.replace('_', ' ').title()} vulnerability testing",
                "focus": "DEX-specific vulnerability"
            })
        
        return test_cases
    
    @staticmethod
    def filter_known_issues(finding: Dict[str, Any], program_name: str = "blackhole") -> bool:
        """
        Filter out findings that match known issues
        Returns True if finding should be kept (not a known issue)
        """
        program = Code4renaIntegration.get_program_info(program_name)
        if not program:
            return True
        
        known_issues = program.get("known_issues", [])
        finding_description = finding.get("description", "").lower()
        finding_title = finding.get("title", "").lower()
        finding_type = finding.get("type", "").lower()
        
        for known_issue in known_issues:
            known_issue_lower = known_issue.lower()
            if (known_issue_lower in finding_description or 
                known_issue_lower in finding_title or 
                known_issue_lower in finding_type):
                return False
        
        return True
    
    @staticmethod
    def is_contract_in_scope(contract_name: str, program_name: str = "blackhole") -> bool:
        """Check if contract is in scope"""
        program = Code4renaIntegration.get_program_info(program_name)
        if not program:
            return False
        
        in_scope = program.get("in_scope_contracts", {})
        out_of_scope = program.get("out_of_scope", [])
        
        # Check if contract is explicitly out of scope
        for out_contract in out_of_scope:
            if out_contract.lower() in contract_name.lower():
                return False
        
        # Check if contract is in scope
        for category, contracts in in_scope.items():
            for contract in contracts:
                if contract.lower() == contract_name.lower():
                    return True
        
        return False
    
    @staticmethod
    def calculate_severity_tvl_impact(finding: Dict[str, Any], tvl: float) -> Dict[str, Any]:
        """
        Calculate severity and payout based on TVL impact
        Based on Code4rena payout ratios
        """
        severity = finding.get("severity", "medium")
        base_severity = severity
        
        payout_multiplier = 1.0
        
        if tvl < 50_000_000:
            payout_multiplier = 0.5
        elif tvl <= 125_000_000:
            payout_multiplier = 0.75
        else:
            payout_multiplier = 1.0
        
        return {
            "original_severity": base_severity,
            "tvl_at_risk": tvl,
            "payout_multiplier": payout_multiplier,
            "estimated_payout_percentage": f"{payout_multiplier * 100}%"
        }
    
    @staticmethod
    def format_finding_for_code4rena(finding: Dict[str, Any], program_name: str = "blackhole") -> str:
        """
        Format finding in Code4rena submission format
        Code4rena typically uses markdown format
        """
        program = Code4renaIntegration.get_program_info(program_name)
        if not program:
            return ""
        
        submission = f"""# {finding.get('title', finding.get('type', 'Vulnerability'))}

## Severity
**{finding.get('severity', 'Medium').upper()}**

## Impact
{finding.get('impact', finding.get('description', ''))}

## Description
{finding.get('description', '')}

## Proof of Concept
```
{finding.get('proof', finding.get('proof_of_concept', ''))}
```

## Steps to Reproduce
{chr(10).join([f"{i+1}. {step}" for i, step in enumerate(finding.get('steps', []))])}

## Recommended Fix
{finding.get('recommendation', finding.get('recommended_fix', ''))}

## Methodology
{finding.get('methodology', 'Automated testing using methodology-driven approach')}

## Contract Address (if applicable)
{finding.get('contract_address', 'N/A')}

---
**Program**: {program.get('name', program_name)}
**Platform**: Code4rena
**Submission URL**: {program.get('submission_url', '')}
"""
        return submission

