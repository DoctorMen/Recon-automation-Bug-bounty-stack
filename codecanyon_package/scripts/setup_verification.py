#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Quick Start Script for Manual Verification
Automates the setup process for safe verification
"""

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
BLACKHOLE_DIR = REPO_ROOT / "blackhole_verification"

def run_command(cmd: list, description: str):
    """Run command with error handling"""
    print(f"\n[*] {description}...")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"[✓] {description} completed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[✗] {description} failed: {e}")
        return False
    except FileNotFoundError:
        print(f"[✗] Command not found. Install required tools first.")
        return False

def setup_verification_environment():
    """Set up verification environment"""
    print("=" * 80)
    print("SETTING UP MANUAL VERIFICATION ENVIRONMENT")
    print("=" * 80)
    print()
    
    # Create verification directory
    BLACKHOLE_DIR.mkdir(exist_ok=True)
    print(f"[*] Created directory: {BLACKHOLE_DIR}")
    
    # Clone contracts
    contracts_dir = BLACKHOLE_DIR / "Contracts"
    if not contracts_dir.exists():
        print("\n[*] Cloning Blackhole contracts...")
        if run_command(
            ["git", "clone", "https://github.com/BlackHoleDEX/Contracts", str(contracts_dir)],
            "Cloning contracts"
        ):
            print("[✓] Contracts cloned successfully")
        else:
            print("[✗] Failed to clone contracts")
            print("    You can clone manually:")
            print(f"    cd {BLACKHOLE_DIR}")
            print("    git clone https://github.com/BlackHoleDEX/Contracts")
    else:
        print("[✓] Contracts already cloned")
    
    # Check for required tools
    print("\n[*] Checking for required tools...")
    
    tools = {
        "git": ["git", "--version"],
        "python3": ["python3", "--version"],
        "node": ["node", "--version"],
        "npm": ["npm", "--version"]
    }
    
    available_tools = []
    missing_tools = []
    
    for tool, cmd in tools.items():
        if run_command(cmd[:2], f"Checking {tool}"):
            available_tools.append(tool)
        else:
            missing_tools.append(tool)
    
    print("\n[*] Tool Status:")
    print(f"  Available: {', '.join(available_tools)}")
    if missing_tools:
        print(f"  Missing: {', '.join(missing_tools)}")
    
    # Create verification script
    verification_script = BLACKHOLE_DIR / "verify_findings.py"
    if not verification_script.exists():
        script_content = '''#!/usr/bin/env python3
"""
Manual Verification Script
Run this to verify findings against actual contract code
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from manual_verification_guide import *

if __name__ == "__main__":
    main()
'''
        with open(verification_script, "w") as f:
            f.write(script_content)
        verification_script.chmod(0o755)
        print(f"\n[✓] Created verification script: {verification_script}")
    
    print("\n" + "=" * 80)
    print("SETUP COMPLETE")
    print("=" * 80)
    print()
    print("Next Steps:")
    print(f"  1. cd {BLACKHOLE_DIR}")
    print("  2. Review contracts: cd Contracts")
    print("  3. Run verification guide:")
    print(f"     python3 {REPO_ROOT}/scripts/manual_verification_guide.py")
    print()
    print("For critical findings:")
    print("  1. Open contracts in VS Code")
    print("  2. Review Pair.sol, RouterV2.sol, etc.")
    print("  3. Check for vulnerability patterns")
    print("  4. Document findings")
    print()
    print("=" * 80)

if __name__ == "__main__":
    setup_verification_environment()

