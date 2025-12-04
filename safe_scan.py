#!/usr/bin/env python3
"""
🛡️ SAFE SCAN WRAPPER
Copyright © 2025 Khallid Nurse. All Rights Reserved.

USE THIS INSTEAD OF DIRECT TOOL CALLS
This wraps all scanning tools with safety checks

NEVER bypass this system
"""

import sys
import subprocess
from pathlib import Path

# Import master safety system
try:
    from MASTER_SAFETY_SYSTEM import verify_safe
except ImportError:
    print("❌ Error: MASTER_SAFETY_SYSTEM.py not found")
    print("Run from project root directory")
    sys.exit(1)


def safe_scan(target: str, scan_type: str = "full"):
    """
    Run scan with safety checks
    
    Args:
        target: Domain to scan
        scan_type: "full", "recon", "nuclei", "httpx"
    """
    
    print(f"\n{'='*70}")
    print("🛡️  SAFE SCAN - Starting with protection")
    print(f"{'='*70}\n")
    
    # SAFETY CHECK
    if not verify_safe(target, scan_type):
        print("\n❌ SCAN BLOCKED BY SAFETY SYSTEM")
        print("Fix the issues above before scanning")
        return False
    
    # Safety passed - proceed with scan
    print(f"\n✅ Safety checks passed - starting {scan_type} scan of {target}")
    print(f"{'='*70}\n")
    
    project_root = Path(__file__).parent
    
    # Add target to targets.txt
    targets_file = project_root / "targets.txt"
    current_targets = []
    
    if targets_file.exists():
        with open(targets_file, 'r') as f:
            current_targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    if target not in current_targets:
        with open(targets_file, 'a') as f:
            f.write(f"\n{target}  # Added by safe_scan.py on {import datetime; datetime.datetime.now().isoformat()}\n")
        print(f"✅ Added {target} to targets.txt")
    
    # Run appropriate scan
    if scan_type == "full":
        print("Running full pipeline...")
        result = subprocess.run([sys.executable, str(project_root / "run_pipeline.py")],
                              cwd=str(project_root))
        return result.returncode == 0
    
    elif scan_type == "recon":
        print("Running reconnaissance only...")
        result = subprocess.run([sys.executable, str(project_root / "run_recon.py")],
                              cwd=str(project_root))
        return result.returncode == 0
    
    elif scan_type == "nuclei":
        print("Running Nuclei scan...")
        result = subprocess.run([sys.executable, str(project_root / "run_nuclei.py")],
                              cwd=str(project_root))
        return result.returncode == 0
    
    elif scan_type == "httpx":
        print("Running HTTP probing...")
        result = subprocess.run([sys.executable, str(project_root / "run_httpx.py")],
                              cwd=str(project_root))
        return result.returncode == 0
    
    else:
        print(f"❌ Unknown scan type: {scan_type}")
        print("Use: full, recon, nuclei, httpx")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("""
🛡️  SAFE SCAN - Protected Scanning Wrapper

Usage:
  python3 safe_scan.py <target> [scan_type]

Scan Types:
  full    - Full pipeline (recon + httpx + nuclei)
  recon   - Reconnaissance only (subdomain enum)
  nuclei  - Vulnerability scanning
  httpx   - HTTP probing

Examples:
  python3 safe_scan.py shopify.com full
  python3 safe_scan.py github.com recon
  python3 safe_scan.py example.com nuclei

IMPORTANT:
  - Target must be authorized (add with authorization_checker.py)
  - Target must be in scope (add with MASTER_SAFETY_SYSTEM.py)
  - All safety checks run automatically
        """)
        sys.exit(0)
    
    target = sys.argv[1]
    scan_type = sys.argv[2] if len(sys.argv) > 2 else "full"
    
    success = safe_scan(target, scan_type)
    
    if success:
        print(f"\n✅ Scan completed successfully")
        print(f"Check output/ directory for results")
        sys.exit(0)
    else:
        print(f"\n❌ Scan failed or was blocked")
        sys.exit(1)
