#!/usr/bin/env python3
"""
Setup Slither for Contract Analysis
Creates virtual environment and installs Slither safely
"""

import subprocess
import sys
from pathlib import Path

CONTRACTS_DIR = Path(__file__).parent.parent / "blackhole_verification" / "Contracts"
VENV_DIR = CONTRACTS_DIR / "venv"

def run_command(cmd, description, check=True):
    """Run command with error handling"""
    print(f"[*] {description}...")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)
        if result.returncode == 0:
            print(f"[✓] {description} completed")
            if result.stdout:
                print(result.stdout)
            return True
        else:
            print(f"[✗] {description} failed")
            if result.stderr:
                print(f"    Error: {result.stderr}")
            return False
    except Exception as e:
        print(f"[✗] {description} failed: {e}")
        return False

def setup_slither():
    """Setup Slither in virtual environment"""
    print("=" * 80)
    print("SETTING UP SLITHER FOR CONTRACT ANALYSIS")
    print("=" * 80)
    print()
    
    # Create virtual environment
    if not VENV_DIR.exists():
        print("[*] Creating virtual environment...")
        cmd = f"cd {CONTRACTS_DIR} && python3 -m venv venv"
        if not run_command(cmd, "Creating venv"):
            return False
    else:
        print("[✓] Virtual environment already exists")
    
    # Install Slither
    print("\n[*] Installing Slither...")
    pip_cmd = f"{VENV_DIR}/bin/pip install slither-analyzer"
    if run_command(pip_cmd, "Installing Slither"):
        print("\n[✓] Slither installed successfully!")
        return True
    else:
        print("\n[✗] Failed to install Slither")
        return False

def show_usage():
    """Show how to use Slither"""
    print("\n" + "=" * 80)
    print("HOW TO USE SLITHER")
    print("=" * 80)
    print()
    print("Activate virtual environment:")
    print(f"  cd {CONTRACTS_DIR}")
    print("  source venv/bin/activate")
    print()
    print("Run Slither analysis:")
    print("  slither . --detect reentrancy")
    print("  slither . --detect reentrancy,access-control,unchecked-transfer")
    print("  slither . --detect all")
    print()
    print("Analyze specific contract:")
    print("  slither contracts/Pair.sol --detect reentrancy")
    print()
    print("Get detailed report:")
    print("  slither . --detect reentrancy --json report.json")
    print()
    print("Deactivate when done:")
    print("  deactivate")
    print()

def main():
    """Main function"""
    if setup_slither():
        show_usage()
        
        print("\n" + "=" * 80)
        print("QUICK START")
        print("=" * 80)
        print()
        print("Run these commands:")
        print(f"  cd {CONTRACTS_DIR}")
        print("  source venv/bin/activate")
        print("  slither . --detect reentrancy")
        print()
    else:
        print("\n" + "=" * 80)
        print("ALTERNATIVE: USE PIPX")
        print("=" * 80)
        print()
        print("If virtual environment fails, try pipx:")
        print("  sudo apt install pipx")
        print("  pipx install slither-analyzer")
        print("  slither . --detect reentrancy")
        print()

if __name__ == "__main__":
    main()

