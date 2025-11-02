#!/usr/bin/env python3
"""
Blackhole Bug Verification & Valuation
Verifies findings against actual contract code and calculates payout values
"""

import json
import sys
import subprocess
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime

SCRIPT_DIR = Path(__file__).parent
REPO_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

from code4rena_integration import Code4renaIntegration

BLACKHOLE_OUTPUT_DIR = REPO_ROOT / "output" / "blackhole_code4rena"
REPORTS_DIR = BLACKHOLE_OUTPUT_DIR / "reports"
GITHUB_REPO = "https://github.com/BlackHoleDEX/Contracts"

# Code4rena payout structure (based on typical Code4rena contests)
PAYOUT_STRUCTURE = {
    "critical": {
        "base": 10000,  # $10,000 base for critical
        "tvl_multiplier": {
            "below_50m": 0.5,   # 50% = $5,000
            "50m_to_125m": 0.75, # 75% = $7,500
            "above_125m": 1.0    # 100% = $10,000
        }
    },
    "high": {
        "base": 5000,   # $5,000 base for high
        "tvl_multiplier": {
            "below_50m": 0.5,   # 50% = $2,500
            "50m_to_125m": 0.75, # 75% = $3,750
            "above_125m": 1.0    # 100% = $5,000
        }
    },
    "medium": {
        "base": 1000,   # $1,000 base for medium
        "tvl_multiplier": {
            "below_50m": 0.5,   # 50% = $500
            "50m_to_125m": 0.75, # 75% = $750
            "above_125m": 1.0    # 100% = $1,000
        }
    }
}

def verify_contract_vulnerability(finding: Dict[str, Any], contract_name: str) -> Tuple[bool, str]:
    """
    Verify if a vulnerability exists in actual contract code
    Returns: (is_verified, verification_details)
    """
    # Check if contract is in scope
    if not Code4renaIntegration.is_contract_in_scope(contract_name, "blackhole"):
        return False, f"Contract {contract_name} is OUT OF SCOPE"
    
    # Check if it's a known issue
    if not Code4renaIntegration.filter_known_issues(finding, "blackhole"):
        return False, f"Known issue - already reported"
    
    finding_type = finding.get("type", "").lower()
    
    # For smart contract vulnerabilities, we need to check actual code
    if finding_type in ["reentrancy", "flash_loan_attack", "liquidity_pool_exploit", 
                        "price_manipulation", "access_control", "integer_overflow", 
                        "token_approval", "router_vulnerability"]:
        # These require actual contract code analysis
        # For now, mark as "needs manual verification"
        return None, "Requires manual contract code review from GitHub"
    
    # For API vulnerabilities, check if endpoints are actually exploitable
    if finding_type.startswith("api_"):
        # API vulnerabilities need actual exploitation proof
        return None, "Requires manual API testing and exploitation proof"
    
    return None, "Unknown vulnerability type"

def calculate_payout_value(finding: Dict[str, Any], tvl_range: str = "below_50m") -> Dict[str, Any]:
    """
    Calculate payout value based on severity and TVL
    """
    severity = finding.get("severity", "medium").lower()
    
    if severity not in PAYOUT_STRUCTURE:
        severity = "medium"
    
    base_value = PAYOUT_STRUCTURE[severity]["base"]
    multiplier = PAYOUT_STRUCTURE[severity]["tvl_multiplier"].get(tvl_range, 0.5)
    
    payout_value = base_value * multiplier
    
    # Apply confidence/verification penalty
    verification_status = finding.get("verification_status", "unverified")
    if verification_status == "verified":
        confidence_multiplier = 1.0
    elif verification_status == "needs_manual_review":
        confidence_multiplier = 0.5  # 50% chance of acceptance
    else:
        confidence_multiplier = 0.1  # 10% chance of acceptance
    
    estimated_payout = payout_value * confidence_multiplier
    
    return {
        "severity": severity,
        "base_value": base_value,
        "tvl_multiplier": multiplier,
        "tvl_range": tvl_range,
        "payout_before_confidence": payout_value,
        "confidence_multiplier": confidence_multiplier,
        "estimated_payout": estimated_payout,
        "verification_status": verification_status
    }

def verify_all_findings():
    """Verify all findings and calculate values"""
    print("=" * 80)
    print("BLACKHOLE BUG VERIFICATION & VALUATION")
    print("=" * 80)
    print()
    
    # Load all reports
    reports = []
    if not REPORTS_DIR.exists():
        print(f"ERROR: Reports directory not found: {REPORTS_DIR}")
        return
    
    for report_file in REPORTS_DIR.glob("finding_*.md"):
        with open(report_file) as f:
            content = f.read()
        
        # Extract finding data
        finding = {
            "file": report_file.name,
            "severity": "medium",
            "type": "unknown"
        }
        
        # Extract severity
        if "**CRITICAL**" in content:
            finding["severity"] = "critical"
        elif "**HIGH**" in content or "High" in content:
            finding["severity"] = "high"
        elif "**MEDIUM**" in content or "Medium" in content:
            finding["severity"] = "medium"
        
        # Extract type from filename
        type_part = report_file.stem.replace("finding_", "").split("_")[1:]
        finding["type"] = "_".join(type_part) if type_part else "unknown"
        
        reports.append(finding)
    
    print(f"Found {len(reports)} reports to verify")
    print()
    
    # Group by severity
    critical = [f for f in reports if f["severity"] == "critical"]
    high = [f for f in reports if f["severity"] == "high"]
    medium = [f for f in reports if f["severity"] == "medium"]
    
    print("=" * 80)
    print("VERIFICATION STATUS")
    print("=" * 80)
    print()
    print(f"Critical: {len(critical)} findings")
    print(f"High: {len(high)} findings")
    print(f"Medium: {len(medium)} findings")
    print()
    
    # Verify each finding
    verified_findings = []
    unverified_findings = []
    
    print("=" * 80)
    print("VERIFICATION RESULTS")
    print("=" * 80)
    print()
    
    for finding in reports:
        finding_type = finding["type"]
        severity = finding["severity"]
        
        # Check if it's a known issue
        if not Code4renaIntegration.filter_known_issues(finding, "blackhole"):
            finding["verification_status"] = "known_issue"
            finding["verification_details"] = "Already reported - known issue"
            unverified_findings.append(finding)
            print(f"[FILTERED] {finding_type} ({severity}) - Known issue")
            continue
        
        # Check contract scope
        if finding_type in ["reentrancy", "flash_loan_attack", "liquidity_pool_exploit"]:
            # These are smart contract vulnerabilities - need manual verification
            finding["verification_status"] = "needs_manual_review"
            finding["verification_details"] = "Requires manual contract code review from GitHub"
            finding["requires"] = "Contract code analysis from https://github.com/BlackHoleDEX/Contracts"
            unverified_findings.append(finding)
            print(f"[NEEDS REVIEW] {finding_type} ({severity}) - Requires contract code analysis")
        elif finding_type.startswith("api_"):
            # API vulnerabilities - need actual exploitation proof
            finding["verification_status"] = "needs_manual_review"
            finding["verification_details"] = "Requires manual API testing and exploitation proof"
            finding["requires"] = "Manual API testing with actual exploitation proof"
            unverified_findings.append(finding)
            print(f"[NEEDS REVIEW] {finding_type} ({severity}) - Requires API exploitation proof")
        else:
            finding["verification_status"] = "needs_manual_review"
            finding["verification_details"] = "Requires manual verification"
            unverified_findings.append(finding)
            print(f"[NEEDS REVIEW] {finding_type} ({severity}) - Requires manual verification")
    
    print()
    print(f"Total findings: {len(reports)}")
    print(f"Needs manual review: {len(unverified_findings)}")
    print()
    
    # Calculate payout values
    print("=" * 80)
    print("PAYOUT VALUATION")
    print("=" * 80)
    print()
    print("Based on Code4rena TVL-based payout structure:")
    print("- Below $50M TVL: 50% of category bounty")
    print("- $50M-$125M TVL: 75% of category bounty")
    print("- Above $125M TVL: 100% of category bounty")
    print()
    print("NOTE: All findings currently require manual verification.")
    print("Payout values assume 50% acceptance rate (needs manual review).")
    print()
    
    # Calculate for different TVL ranges
    tvl_ranges = ["below_50m", "50m_to_125m", "above_125m"]
    
    valuation_results = {}
    
    for tvl_range in tvl_ranges:
        print(f"\n--- TVL Range: {tvl_range.replace('_', ' ').upper()} ---")
        
        total_payout = 0
        critical_payout = 0
        high_payout = 0
        medium_payout = 0
        
        for finding in reports:
            if finding.get("verification_status") == "known_issue":
                continue
            
            payout_info = calculate_payout_value(finding, tvl_range)
            estimated = payout_info["estimated_payout"]
            
            total_payout += estimated
            
            if finding["severity"] == "critical":
                critical_payout += estimated
            elif finding["severity"] == "high":
                high_payout += estimated
            else:
                medium_payout += estimated
        
        valuation_results[tvl_range] = {
            "total_estimated": total_payout,
            "critical": critical_payout,
            "high": high_payout,
            "medium": medium_payout
        }
        
        print(f"Critical ({len(critical)} findings): ${critical_payout:,.2f}")
        print(f"High ({len(high)} findings): ${high_payout:,.2f}")
        print(f"Medium ({len(medium)} findings): ${medium_payout:,.2f}")
        print(f"TOTAL ESTIMATED: ${total_payout:,.2f}")
    
    # Save results
    results_file = BLACKHOLE_OUTPUT_DIR / "verification_and_valuation.json"
    with open(results_file, "w") as f:
        json.dump({
            "verification_date": datetime.now().isoformat(),
            "total_findings": len(reports),
            "critical_count": len(critical),
            "high_count": len(high),
            "medium_count": len(medium),
            "verification_status": {
                "needs_manual_review": len(unverified_findings),
                "known_issues": len([f for f in reports if f.get("verification_status") == "known_issue"])
            },
            "findings": reports,
            "valuation": valuation_results,
            "payout_structure": PAYOUT_STRUCTURE,
            "note": "All findings require manual verification against actual contract code from GitHub"
        }, f, indent=2)
    
    print()
    print("=" * 80)
    print("VERIFICATION SUMMARY")
    print("=" * 80)
    print()
    print("⚠️ IMPORTANT: All findings require manual verification!")
    print()
    print("To verify findings:")
    print("1. Clone repository: git clone https://github.com/BlackHoleDEX/Contracts")
    print("2. Review contract code for each finding")
    print("3. Test actual exploitation")
    print("4. Provide proof of concept")
    print()
    print("Current findings are TEST CASES, not verified vulnerabilities.")
    print("Actual payout depends on:")
    print("- Verification against contract code")
    print("- Proof of exploitation")
    print("- TVL at time of submission")
    print("- Code4rena judge evaluation")
    print()
    print(f"Results saved to: {results_file}")
    print("=" * 80)

if __name__ == "__main__":
    verify_all_findings()

