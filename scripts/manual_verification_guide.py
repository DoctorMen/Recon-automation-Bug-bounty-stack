#!/usr/bin/env python3
"""
Blackhole Manual Verification Guide
Safe, in-scope methods for verifying vulnerabilities
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
import requests

SCRIPT_DIR = Path(__file__).parent
REPO_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

from code4rena_integration import Code4renaIntegration

BLACKHOLE_OUTPUT_DIR = REPO_ROOT / "output" / "blackhole_code4rena"
REPORTS_DIR = BLACKHOLE_OUTPUT_DIR / "reports"
GITHUB_REPO = "https://github.com/BlackHoleDEX/Contracts"

def print_section(title: str):
    """Print section header"""
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80 + "\n")

def verify_smart_contract_findings():
    """Guide for verifying smart contract findings"""
    print_section("SMART CONTRACT VERIFICATION (IN-SCOPE)")
    
    print("✅ SAFE METHODS (100% IN SCOPE):")
    print("=" * 80)
    print()
    print("1. STATIC CODE ANALYSIS (Recommended)")
    print("   - Review contract code without executing")
    print("   - Identify vulnerabilities in code logic")
    print("   - Check for common patterns")
    print("   - ✅ 100% safe - no code execution")
    print()
    print("2. LOCAL TESTING WITH FORK")
    print("   - Fork mainnet blockchain locally")
    print("   - Deploy contracts on fork")
    print("   - Test exploits on local fork")
    print("   - ✅ Safe - no interaction with live contracts")
    print()
    print("❌ OUT OF SCOPE:")
    print("   - Exploiting live contracts on mainnet")
    print("   - Interacting with production contracts")
    print("   - Any action that could cause real damage")
    print()
    
    print("STEP-BY-STEP VERIFICATION PROCESS:")
    print("-" * 80)
    print()
    print("Step 1: Clone Repository")
    print("  git clone https://github.com/BlackHoleDEX/Contracts")
    print("  cd Contracts")
    print()
    
    print("Step 2: Review Contract Code")
    print("  Focus on in-scope contracts:")
    in_scope = Code4renaIntegration.CODE4RENA_PROGRAMS["blackhole"]["in_scope_contracts"]
    for category, contracts in in_scope.items():
        print(f"  {category}:")
        for contract in contracts[:3]:  # Show first 3
            print(f"    - {contract}")
        if len(contracts) > 3:
            print(f"    ... and {len(contracts) - 3} more")
    print()
    
    print("Step 3: Static Analysis Checklist")
    print("  For each finding, check:")
    print("  □ Code pattern matches vulnerability type")
    print("  □ Vulnerability is exploitable")
    print("  □ Impact is real (not theoretical)")
    print("  □ Not a known issue")
    print("  □ Not out of scope")
    print()
    
    print("Step 4: Create Proof of Concept")
    print("  - Write exploit code (for local testing)")
    print("  - Document attack vector")
    print("  - Calculate potential impact")
    print()

def verify_api_findings():
    """Guide for verifying API findings"""
    print_section("API VERIFICATION (IN-SCOPE)")
    
    print("✅ SAFE METHODS (100% IN SCOPE):")
    print("=" * 80)
    print()
    print("1. PASSIVE RECONNAISSANCE")
    print("   - Check API documentation")
    print("   - Review API endpoints")
    print("   - Analyze response headers")
    print("   - ✅ Safe - read-only operations")
    print()
    print("2. READ-ONLY TESTING")
    print("   - GET requests only")
    print("   - No data modification")
    print("   - No authentication bypass attempts")
    print("   - ✅ Safe - no write operations")
    print()
    print("3. CONTROLLED TESTING")
    print("   - Use your own test accounts")
    print("   - Test on non-production endpoints")
    print("   - Document all requests/responses")
    print("   - ✅ Safe - controlled environment")
    print()
    
    print("❌ OUT OF SCOPE:")
    print("   - Attempting to exploit live systems")
    print("   - Modifying user data")
    print("   - Accessing other users' accounts")
    print("   - Any destructive actions")
    print()
    
    print("STEP-BY-STEP API VERIFICATION:")
    print("-" * 80)
    print()
    print("Step 1: Identify Target Endpoints")
    print("  - Check discovered_endpoints.json")
    print("  - Filter for in-scope domains")
    print("  - Identify API endpoints")
    print()
    
    print("Step 2: Passive Information Gathering")
    print("  - Check for API documentation")
    print("  - Review OpenAPI/Swagger specs")
    print("  - Analyze response headers")
    print("  - Check for information disclosure")
    print()
    
    print("Step 3: Safe Testing Methods")
    print("  For Rate Limit Bypass:")
    print("    - Make multiple requests")
    print("    - Check rate limit headers")
    print("    - Document response codes")
    print("    - ✅ No actual bypass needed for report")
    print()
    print("  For IDOR:")
    print("    - Test with your own account")
    print("    - Check if IDs are predictable")
    print("    - Document findings")
    print("    - ✅ No unauthorized access needed")
    print()
    
    print("Step 4: Create Report")
    print("  - Document vulnerability type")
    print("  - Show proof of concept")
    print("  - Explain potential impact")
    print("  - Provide remediation")
    print()

def setup_local_testing_environment():
    """Guide for setting up local testing"""
    print_section("LOCAL TESTING SETUP (RECOMMENDED)")
    
    print("This allows you to test exploits safely without touching live contracts.")
    print()
    
    print("OPTION 1: Foundry (Recommended for Solidity)")
    print("-" * 80)
    print()
    print("Install:")
    print("  curl -L https://foundry.paradigm.xyz | bash")
    print("  foundryup")
    print()
    print("Setup:")
    print("  mkdir blackhole-testing")
    print("  cd blackhole-testing")
    print("  forge init")
    print()
    print("Clone contracts:")
    print("  git clone https://github.com/BlackHoleDEX/Contracts contracts")
    print()
    print("Create test:")
    print("  forge test --fork-url https://api.avax.network/ext/bc/C/rpc")
    print()
    
    print("OPTION 2: Hardhat")
    print("-" * 80)
    print()
    print("Install:")
    print("  npm install --save-dev hardhat")
    print("  npm install @nomicfoundation/hardhat-toolbox")
    print()
    print("Setup:")
    print("  npx hardhat init")
    print()
    print("Configure fork:")
    print("  networks: {")
    print("    hardhat: {")
    print("      forking: {")
    print("        url: 'https://api.avax.network/ext/bc/C/rpc'")
    print("      }")
    print("    }")
    print("  }")
    print()
    
    print("OPTION 3: Manual Code Review")
    print("-" * 80)
    print()
    print("Tools:")
    print("  - VS Code with Solidity extension")
    print("  - Slither (static analysis)")
    print("  - Mythril (security analysis)")
    print()
    print("Install Slither:")
    print("  pip install slither-analyzer")
    print("  slither Contracts/")
    print()

def verify_critical_findings():
    """Specific verification for critical findings"""
    print_section("CRITICAL FINDINGS VERIFICATION GUIDE")
    
    critical_findings = [
        {
            "name": "Reentrancy",
            "contracts": ["Pair.sol", "RouterV2.sol", "RouterHelper.sol"],
            "check": [
                "Look for external calls before state updates",
                "Check for reentrancy guards",
                "Verify use of Checks-Effects-Interactions pattern",
                "Check for payable functions with external calls"
            ]
        },
        {
            "name": "Flash Loan Attack",
            "contracts": ["Pair.sol", "PairFactory.sol"],
            "check": [
                "Check for flash loan checks in swap functions",
                "Verify price oracle usage",
                "Check for MEV protection",
                "Look for price manipulation vectors"
            ]
        },
        {
            "name": "Liquidity Pool Exploit",
            "contracts": ["Pair.sol", "GenesisPool.sol"],
            "check": [
                "Check access control on pool functions",
                "Verify liquidity manipulation protection",
                "Check for improper access control",
                "Look for pool draining vectors"
            ]
        }
    ]
    
    for finding in critical_findings:
        print(f"\n{finding['name']} Verification:")
        print("-" * 80)
        print(f"Target Contracts: {', '.join(finding['contracts'])}")
        print()
        print("What to Check:")
        for i, check in enumerate(finding['check'], 1):
            print(f"  {i}. {check}")
        print()
        print("How to Verify:")
        print("  1. Open contract file in GitHub")
        print("  2. Search for vulnerable patterns")
        print("  3. Check if guards/protections exist")
        print("  4. Create proof of concept (local test)")
        print()

def create_verification_checklist():
    """Create verification checklist"""
    print_section("VERIFICATION CHECKLIST")
    
    checklist = {
        "Pre-Verification": [
            "✓ Finding is in scope (contract in in_scope_contracts)",
            "✓ Finding is not a known issue",
            "✓ Finding is not from previous audits",
            "✓ Finding matches vulnerability type"
        ],
        "Code Review": [
            "□ Contract code reviewed",
            "□ Vulnerability pattern identified",
            "□ Impact assessed",
            "□ Exploitability confirmed"
        ],
        "Testing": [
            "□ Local test environment setup",
            "□ Exploit code written",
            "□ Proof of concept created",
            "□ Impact calculated"
        ],
        "Documentation": [
            "□ Report written",
            "□ Proof of concept included",
            "□ Impact documented",
            "□ Remediation provided"
        ],
        "Submission": [
            "□ Verified against actual code",
            "□ Proof of concept tested",
            "□ All details verified",
            "□ Ready for submission"
        ]
    }
    
    for category, items in checklist.items():
        print(f"\n{category}:")
        for item in items:
            print(f"  {item}")
    
    print()

def main():
    """Main verification guide"""
    print("=" * 80)
    print("BLACKHOLE MANUAL VERIFICATION GUIDE")
    print("=" * 80)
    print()
    print("This guide shows you how to verify bugs SAFELY and WITHIN SCOPE.")
    print("All methods are read-only or use local testing environments.")
    print()
    
    verify_smart_contract_findings()
    verify_api_findings()
    setup_local_testing_environment()
    verify_critical_findings()
    create_verification_checklist()
    
    print_section("SUMMARY")
    print("✅ ALL VERIFICATION METHODS ARE IN SCOPE")
    print()
    print("Safe Methods:")
    print("  1. Static code analysis (read-only)")
    print("  2. Local testing with fork (no live interaction)")
    print("  3. Passive API reconnaissance (read-only)")
    print("  4. Controlled testing (your own accounts)")
    print()
    print("Next Steps:")
    print("  1. Clone contract repository")
    print("  2. Review critical findings first")
    print("  3. Set up local testing environment")
    print("  4. Verify each finding")
    print("  5. Create proof of concept")
    print("  6. Submit verified findings")
    print()
    print("=" * 80)

if __name__ == "__main__":
    main()

