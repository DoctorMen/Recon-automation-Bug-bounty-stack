#!/usr/bin/env python3
"""
Clone Blackhole Contracts for Verification
Quick script to clone and setup contract code for manual verification
"""

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
BLACKHOLE_DIR = REPO_ROOT / "blackhole_verification"
CONTRACTS_DIR = BLACKHOLE_DIR / "Contracts"
GITHUB_REPO = "https://github.com/BlackHoleDEX/Contracts"

def print_header(text):
    """Print formatted header"""
    print("\n" + "=" * 80)
    print(text)
    print("=" * 80 + "\n")

def run_command(cmd, description, check=True):
    """Run command with error handling"""
    print(f"[*] {description}...")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)
        if result.returncode == 0:
            print(f"[✓] {description} completed successfully")
            return True
        else:
            print(f"[✗] {description} failed")
            if result.stderr:
                print(f"    Error: {result.stderr}")
            return False
    except Exception as e:
        print(f"[✗] {description} failed: {e}")
        return False

def clone_contracts():
    """Clone Blackhole contracts repository"""
    print_header("CLONING BLACKHOLE CONTRACTS")
    
    # Create directory
    BLACKHOLE_DIR.mkdir(exist_ok=True)
    print(f"[*] Created directory: {BLACKHOLE_DIR}")
    
    # Check if already cloned
    if CONTRACTS_DIR.exists() and (CONTRACTS_DIR / ".git").exists():
        print(f"[✓] Contracts already cloned at: {CONTRACTS_DIR}")
        print(f"[*] To update: cd {CONTRACTS_DIR} && git pull")
        return True
    
    # Clone repository
    print(f"\n[*] Cloning from: {GITHUB_REPO}")
    print(f"[*] Destination: {CONTRACTS_DIR}")
    print()
    
    cmd = f"cd {BLACKHOLE_DIR} && git clone {GITHUB_REPO} Contracts"
    if run_command(cmd, "Cloning contracts repository"):
        print(f"\n[✓] Contracts cloned successfully!")
        print(f"[*] Location: {CONTRACTS_DIR}")
        return True
    else:
        print("\n[✗] Failed to clone contracts")
        print("\nManual clone instructions:")
        print(f"  1. cd {BLACKHOLE_DIR}")
        print(f"  2. git clone {GITHUB_REPO} Contracts")
        return False

def show_contract_structure():
    """Show contract structure"""
    print_header("CONTRACT STRUCTURE")
    
    if not CONTRACTS_DIR.exists():
        print("[✗] Contracts directory not found")
        return
    
    contracts_dir = CONTRACTS_DIR / "contracts"
    if not contracts_dir.exists():
        print("[*] Checking for contract files...")
        # List all .sol files
        sol_files = list(CONTRACTS_DIR.rglob("*.sol"))
        if sol_files:
            print(f"[✓] Found {len(sol_files)} Solidity files")
            print("\n[*] Key contract files:")
            for f in sol_files[:10]:
                rel_path = f.relative_to(CONTRACTS_DIR)
                print(f"  - {rel_path}")
            if len(sol_files) > 10:
                print(f"  ... and {len(sol_files) - 10} more")
        else:
            print("[!] No .sol files found yet")
        return
    
    print(f"[*] Contract files location: {contracts_dir}")
    
    # List in-scope contracts
    in_scope_contracts = {
        "AMM Pools": ["Pair.sol", "PairFees.sol", "PairFactory.sol", "PairGenerator.sol", 
                      "RouterV2.sol", "RouterHelper.sol", "TokenHandler.sol"],
        "VE(3,3)": ["GaugeManager.sol", "GaugeFactory.sol", "GaugeFactoryCL.sol", 
                    "GaugeExtraRewarder.sol", "GaugeOwner.sol", "GaugeV2.sol", "GaugeCL.sol"],
        "Genesis Pool": ["GenesisPool.sol", "GenesisPoolFactory.sol", "GenesisPoolManager.sol"]
    }
    
    print("\n[*] In-scope contracts to verify:")
    found_count = 0
    for category, contracts in in_scope_contracts.items():
        print(f"\n  {category}:")
        for contract in contracts:
            contract_path = contracts_dir / contract
            if contract_path.exists():
                print(f"    ✓ {contract}")
                found_count += 1
            else:
                # Try case-insensitive search
                matching = list(contracts_dir.glob(f"*{contract.lower()}"))
                if matching:
                    print(f"    ✓ {matching[0].name}")
                    found_count += 1
                else:
                    print(f"    ✗ {contract} (not found)")
    
    print(f"\n[✓] Found {found_count} in-scope contracts")

def show_verification_guide():
    """Show how to verify findings"""
    print_header("HOW TO VERIFY FINDINGS")
    
    print("Step 1: Navigate to contracts")
    print(f"  cd {CONTRACTS_DIR}")
    print()
    
    print("Step 2: Review critical contracts")
    print("  For Reentrancy:")
    print("    - contracts/Pair.sol")
    print("    - contracts/RouterV2.sol")
    print("    - contracts/RouterHelper.sol")
    print()
    print("  For Flash Loan Attack:")
    print("    - contracts/Pair.sol")
    print("    - contracts/PairFactory.sol")
    print()
    print("  For Liquidity Pool Exploit:")
    print("    - contracts/Pair.sol")
    print("    - contracts/GenesisPool.sol")
    print()
    
    print("Step 3: Use static analysis tools")
    print("  Install Slither:")
    print("    pip install slither-analyzer")
    print()
    print("  Run analysis:")
    print(f"    cd {CONTRACTS_DIR}")
    print("    slither . --detect reentrancy,access-control")
    print()
    
    print("Step 4: Review code manually")
    print("  - Open contract files in VS Code")
    print("  - Search for vulnerability patterns")
    print("  - Check for protections/guards")
    print("  - Document findings")
    print()
    
    print("Step 5: Create proof of concept")
    print("  - Write exploit code (for local testing)")
    print("  - Document attack vector")
    print("  - Calculate impact")
    print()

def main():
    """Main function"""
    print_header("BLACKHOLE CONTRACT CLONING & VERIFICATION SETUP")
    
    print("Repository:", GITHUB_REPO)
    print("Destination:", CONTRACTS_DIR)
    print()
    
    # Clone contracts
    if clone_contracts():
        # Show structure
        show_contract_structure()
        
        # Show verification guide
        show_verification_guide()
        
        print_header("SETUP COMPLETE")
        print(f"[✓] Contracts ready at: {CONTRACTS_DIR}")
        print("\nNext steps:")
        print(f"  1. cd {CONTRACTS_DIR}")
        print("  2. Review contract files")
        print("  3. Run: python3 ../scripts/manual_verification_guide.py")
        print("  4. Start verifying findings!")
    else:
        print_header("MANUAL CLONE REQUIRED")
        print("Please run manually:")
        print(f"  cd {REPO_ROOT}")
        print(f"  mkdir -p blackhole_verification")
        print(f"  cd blackhole_verification")
        print(f"  git clone {GITHUB_REPO} Contracts")
        print()

if __name__ == "__main__":
    main()

