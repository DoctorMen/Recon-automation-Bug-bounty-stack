#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Blackhole Critical Findings Verifier
Verifies critical findings against actual contract code
"""

import json
import sys
import subprocess
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
import requests

# Paths
SCRIPT_DIR = Path(__file__).parent
REPO_ROOT = SCRIPT_DIR.parent
OUTPUT_DIR = REPO_ROOT / "output"
BLACKHOLE_OUTPUT_DIR = OUTPUT_DIR / "blackhole_code4rena"
REPORTS_DIR = BLACKHOLE_OUTPUT_DIR / "reports"
VERIFICATION_DIR = BLACKHOLE_OUTPUT_DIR / "verification"
VERIFICATION_DIR.mkdir(parents=True, exist_ok=True)

# Critical contracts to check (with full paths)
CRITICAL_CONTRACTS = {
    "reentrancy": [
        "contracts/Pair.sol",
        "contracts/RouterV2.sol",
        "contracts/factories/PairFactory.sol",
        "contracts/TokenHandler.sol"
    ],
    "flash_loan_attack": [
        "contracts/Pair.sol",
        "contracts/RouterV2.sol",
        "contracts/RouterHelper.sol"
    ],
    "liquidity_pool_exploit": [
        "contracts/Pair.sol",
        "contracts/factories/PairFactory.sol",
        "contracts/GaugeV2.sol",
        "contracts/AlgebraCLVe33/GaugeCL.sol"
    ]
}

LOCAL_REPO_PATH = Path("/tmp/blackhole_contracts")

def log(message: str, level: str = "INFO"):
    """Log message"""
    timestamp = subprocess.check_output(["date", "+%Y-%m-%d %H:%M:%S"]).decode().strip()
    print(f"[{timestamp}] [{level}] {message}")

def get_contract_file(file_path: str) -> Optional[str]:
    """Get contract file from local repo or download from GitHub"""
    # Try local repo first
    local_path = LOCAL_REPO_PATH / file_path
    if local_path.exists():
        try:
            return local_path.read_text()
        except Exception as e:
            log(f"Error reading local file {file_path}: {e}", "WARNING")
    
    # Fallback to GitHub
    try:
        repo = "BlackHoleDEX/Contracts"
        url = f"https://raw.githubusercontent.com/{repo}/main/{file_path}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.text
        else:
            # Try other branches
            for branch in ["master", "develop"]:
                url = f"https://raw.githubusercontent.com/{repo}/{branch}/{file_path}"
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    return response.text
    except Exception as e:
        log(f"Error downloading {file_path}: {e}", "WARNING")
    return None

def check_reentrancy(contract_code: str, contract_name: str) -> List[Dict[str, Any]]:
    """Check for reentrancy vulnerabilities"""
    findings = []
    
    # Check for external calls before state changes
    # Pattern: external call without reentrancy guard
    external_call_patterns = [
        r'\.transfer\(',
        r'\.send\(',
        r'\.call\(',
        r'\.delegatecall\(',
        r'\.callcode\(',
        r'\.transferFrom\(',
        r'\.safeTransfer\(',
        r'\.safeTransferFrom\('
    ]
    
    # Check for reentrancy guards
    reentrancy_guards = [
        r'nonReentrant',
        r'reentrancyGuard',
        r'ReentrancyGuard',
        r'lock'
    ]
    
    lines = contract_code.split('\n')
    has_guard = False
    
    # Check if contract uses reentrancy guard
    for line in lines:
        if any(re.search(pattern, line, re.IGNORECASE) for pattern in reentrancy_guards):
            has_guard = True
            break
    
    # Find external calls
    for i, line in enumerate(lines, 1):
        for pattern in external_call_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                # Check if there's a state change after this call
                next_lines = lines[i:i+10]
                state_change_patterns = [
                    r'=',
                    r'\+=',
                    r'-=',
                    r'\+\+',
                    r'--',
                    r'balanceOf',
                    r'totalSupply'
                ]
                
                has_state_change = False
                for next_line in next_lines:
                    if any(re.search(p, next_line) for p in state_change_patterns):
                        has_state_change = True
                        break
                
                if has_state_change and not has_guard:
                    findings.append({
                        "type": "reentrancy",
                        "contract": contract_name,
                        "line": i,
                        "code": line.strip(),
                        "severity": "critical",
                        "description": f"Potential reentrancy vulnerability: External call followed by state change without reentrancy guard",
                        "recommendation": "Add nonReentrant modifier or use Checks-Effects-Interactions pattern"
                    })
    
    return findings

def check_flash_loan_attack(contract_code: str, contract_name: str) -> List[Dict[str, Any]]:
    """Check for flash loan attack vulnerabilities"""
    findings = []
    
    # Check for price manipulation patterns
    price_patterns = [
        r'getAmountOut',
        r'getAmountIn',
        r'quote',
        r'getReserves',
        r'balanceOf'
    ]
    
    # Check for oracle usage
    oracle_patterns = [
        r'oracle',
        r'Chainlink',
        r'priceFeed'
    ]
    
    # Check for minimum liquidity checks
    min_liquidity_patterns = [
        r'MINIMUM_LIQUIDITY',
        r'minimumLiquidity',
        r'require.*liquidity'
    ]
    
    lines = contract_code.split('\n')
    has_price_check = False
    has_min_liquidity = False
    
    # Check if contract has price validation
    for line in lines:
        if any(re.search(pattern, line, re.IGNORECASE) for pattern in price_patterns):
            has_price_check = True
        if any(re.search(pattern, line, re.IGNORECASE) for pattern in min_liquidity_patterns):
            has_min_liquidity = True
    
    # Find swap functions
    for i, line in enumerate(lines, 1):
        if 'function' in line.lower() and ('swap' in line.lower() or 'exchange' in line.lower()):
            # Check next 50 lines for flash loan vulnerability indicators
            function_lines = lines[i:i+50]
            function_code = '\n'.join(function_lines)
            
            # Check if function uses price without validation
            uses_price = any(re.search(pattern, function_code, re.IGNORECASE) for pattern in price_patterns)
            uses_oracle = any(re.search(pattern, function_code, re.IGNORECASE) for pattern in oracle_patterns)
            
            if uses_price and not uses_oracle and not has_min_liquidity:
                findings.append({
                    "type": "flash_loan_attack",
                    "contract": contract_name,
                    "line": i,
                    "function": line.strip(),
                    "severity": "critical",
                    "description": f"Potential flash loan attack vulnerability: Price calculation without oracle validation or minimum liquidity check",
                    "recommendation": "Add oracle price validation or minimum liquidity requirements to prevent price manipulation"
                })
    
    return findings

def check_liquidity_pool_exploit(contract_code: str, contract_name: str) -> List[Dict[str, Any]]:
    """Check for liquidity pool exploit vulnerabilities"""
    findings = []
    
    # Check for emergency withdrawal functions
    emergency_patterns = [
        r'emergency',
        r'withdraw',
        r'rescue',
        r'recover'
    ]
    
    # Check for access control
    access_control_patterns = [
        r'onlyOwner',
        r'onlyAdmin',
        r'require.*owner',
        r'require.*admin'
    ]
    
    lines = contract_code.split('\n')
    has_access_control = False
    
    # Check if contract has access control
    for line in lines:
        if any(re.search(pattern, line, re.IGNORECASE) for pattern in access_control_patterns):
            has_access_control = True
            break
    
    # Find withdrawal functions
    for i, line in enumerate(lines, 1):
        if 'function' in line.lower():
            function_lower = line.lower()
            if any(pattern in function_lower for pattern in emergency_patterns):
                # Check if function has access control
                function_lines = lines[i:i+20]
                function_code = '\n'.join(function_lines)
                
                if not has_access_control and not any(re.search(pattern, function_code, re.IGNORECASE) for pattern in access_control_patterns):
                    findings.append({
                        "type": "liquidity_pool_exploit",
                        "contract": contract_name,
                        "line": i,
                        "function": line.strip(),
                        "severity": "critical",
                        "description": f"Potential liquidity pool exploit: Withdrawal function without access control",
                        "recommendation": "Add access control modifiers (onlyOwner, onlyAdmin) to prevent unauthorized withdrawals"
                    })
    
    # Check for balance manipulation
    balance_patterns = [
        r'balanceOf\[',
        r'balanceOf\(',
        r'totalSupply',
        r'_mint',
        r'_burn'
    ]
    
    for i, line in enumerate(lines, 1):
        if any(re.search(pattern, line, re.IGNORECASE) for pattern in balance_patterns):
            # Check if there's validation before balance changes
            prev_lines = lines[max(0, i-10):i]
            prev_code = '\n'.join(prev_lines)
            
            validation_patterns = [
                r'require',
                r'assert',
                r'if.*revert',
                r'check'
            ]
            
            has_validation = any(re.search(pattern, prev_code, re.IGNORECASE) for pattern in validation_patterns)
            
            if not has_validation and 'balance' in line.lower():
                findings.append({
                    "type": "liquidity_pool_exploit",
                    "contract": contract_name,
                    "line": i,
                    "code": line.strip(),
                    "severity": "critical",
                    "description": f"Potential liquidity pool exploit: Balance manipulation without validation",
                    "recommendation": "Add validation checks before balance modifications"
                })
    
    return findings

def verify_critical_findings():
    """Verify critical findings against contract code"""
    log("=" * 60)
    log("VERIFYING CRITICAL FINDINGS AGAINST CONTRACT CODE")
    log("=" * 60)
    
    verified_findings = []
    
    # Verify reentrancy
    log("Checking reentrancy vulnerabilities...")
    for contract in CRITICAL_CONTRACTS["reentrancy"]:
        log(f"  Checking {contract}...")
        contract_code = get_contract_file(contract)
        if contract_code:
            findings = check_reentrancy(contract_code, contract)
            verified_findings.extend(findings)
            log(f"    Found {len(findings)} potential reentrancy issues")
        else:
            log(f"    Could not download {contract}", "WARNING")
    
    # Verify flash loan attacks
    log("Checking flash loan attack vulnerabilities...")
    for contract in CRITICAL_CONTRACTS["flash_loan_attack"]:
        log(f"  Checking {contract}...")
        contract_code = get_contract_file(contract)
        if contract_code:
            findings = check_flash_loan_attack(contract_code, contract)
            verified_findings.extend(findings)
            log(f"    Found {len(findings)} potential flash loan issues")
        else:
            log(f"    Could not download {contract}", "WARNING")
    
    # Verify liquidity pool exploits
    log("Checking liquidity pool exploit vulnerabilities...")
    for contract in CRITICAL_CONTRACTS["liquidity_pool_exploit"]:
        log(f"  Checking {contract}...")
        contract_code = get_contract_file(contract)
        if contract_code:
            findings = check_liquidity_pool_exploit(contract_code, contract)
            verified_findings.extend(findings)
            log(f"    Found {len(findings)} potential liquidity pool issues")
        else:
            log(f"    Could not download {contract}", "WARNING")
    
    # Save verified findings
    findings_file = VERIFICATION_DIR / "verified_critical_findings.json"
    with open(findings_file, "w") as f:
        json.dump(verified_findings, f, indent=2)
    
    # Generate summary
    summary = {
        "total_verified": len(verified_findings),
        "reentrancy": len([f for f in verified_findings if f["type"] == "reentrancy"]),
        "flash_loan_attack": len([f for f in verified_findings if f["type"] == "flash_loan_attack"]),
        "liquidity_pool_exploit": len([f for f in verified_findings if f["type"] == "liquidity_pool_exploit"]),
        "findings": verified_findings
    }
    
    summary_file = VERIFICATION_DIR / "verification_summary.json"
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2)
    
    log("=" * 60)
    log("VERIFICATION COMPLETE")
    log("=" * 60)
    log(f"Total verified findings: {len(verified_findings)}")
    log(f"  - Reentrancy: {summary['reentrancy']}")
    log(f"  - Flash Loan Attack: {summary['flash_loan_attack']}")
    log(f"  - Liquidity Pool Exploit: {summary['liquidity_pool_exploit']}")
    log(f"Saved to: {VERIFICATION_DIR}")
    log("=" * 60)
    
    return verified_findings

if __name__ == "__main__":
    verify_critical_findings()

