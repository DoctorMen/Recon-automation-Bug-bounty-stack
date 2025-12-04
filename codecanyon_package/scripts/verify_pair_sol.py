#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Pair.sol Verification Script
Analyzes Pair.sol for critical vulnerabilities using grep and pattern matching
"""

import subprocess
import sys
from pathlib import Path

CONTRACT_FILE = Path("~/Recon-automation-Bug-bounty-stack/blackhole_verification/Contracts/contracts/Pair.sol").expanduser()

def run_grep(pattern, description):
    """Run grep and show results"""
    print(f"\n[*] {description}:")
    print("-" * 80)
    try:
        result = subprocess.run(
            ["grep", "-n", pattern, str(CONTRACT_FILE)],
            capture_output=True,
            text=True
        )
        if result.stdout:
            lines = result.stdout.strip().split('\n')
            for line in lines[:10]:  # Show first 10 matches
                print(f"  {line}")
            if len(lines) > 10:
                print(f"  ... and {len(lines) - 10} more matches")
        else:
            print("  No matches found")
    except Exception as e:
        print(f"  Error: {e}")

def main():
    """Main verification function"""
    print("=" * 80)
    print("PAIR.SOL VULNERABILITY VERIFICATION")
    print("=" * 80)
    print()
    print(f"Contract: {CONTRACT_FILE}")
    print(f"Size: 588 lines, ~26KB")
    print()
    
    # Check for reentrancy patterns
    print("\n" + "=" * 80)
    print("1. REENTRANCY CHECKS")
    print("=" * 80)
    
    run_grep("function.*swap", "Finding swap functions")
    run_grep("function.*mint", "Finding mint functions")
    run_grep("function.*burn", "Finding burn functions")
    run_grep("\\.transfer\\|\\call\\|\\.send", "Finding external calls")
    run_grep("balanceOf\\[\\|totalSupply\\s*=\\|totalSupply\\s*-", "Finding state updates")
    run_grep("nonReentrant\\|ReentrancyGuard", "Checking for reentrancy guards")
    
    # Check for flash loan protection
    print("\n" + "=" * 80)
    print("2. FLASH LOAN ATTACK CHECKS")
    print("=" * 80)
    
    run_grep("flash\\|loan", "Checking for flash loan protection")
    run_grep("getAmount\\|getPrice\\|calculate", "Finding price calculation functions")
    run_grep("oracle\\|price", "Checking for oracle usage")
    
    # Check for access control
    print("\n" + "=" * 80)
    print("3. ACCESS CONTROL CHECKS")
    print("=" * 80)
    
    run_grep("onlyOwner\\|onlyAdmin\\|require.*owner", "Checking for access modifiers")
    run_grep("function.*public\\|function.*external", "Finding public/external functions")
    
    # Summary
    print("\n" + "=" * 80)
    print("VERIFICATION SUMMARY")
    print("=" * 80)
    print()
    print("Next steps:")
    print("1. Review the grep results above")
    print("2. Open Pair.sol and check each flagged function")
    print("3. Verify if patterns match vulnerability types")
    print("4. Document line numbers and code snippets")
    print()
    print("To view full contract:")
    print(f"  cat {CONTRACT_FILE} | less")
    print("  # or")
    print(f"  vim {CONTRACT_FILE}")
    print()

if __name__ == "__main__":
    main()

