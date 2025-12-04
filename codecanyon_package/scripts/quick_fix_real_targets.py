#!/usr/bin/env python3
"""
Copyright (c) 2025 YOUR_NAME_HERE
Proprietary and Confidential
All Rights Reserved

This software is proprietary and confidential.
Unauthorized copying, modification, or distribution is prohibited.

System ID: BB_20251102_5946
Owner: YOUR_NAME_HERE
"""

"""
Quick Fix: Clear Old Results and Restart with Real Targets
"""

import subprocess
from pathlib import Path

def quick_fix():
    repo_root = Path(__file__).parent.parent
    output_dir = repo_root / "output"
    roi_dir = output_dir / "immediate_roi"
    
    print("=" * 70)
    print("🔧 QUICK FIX: Restarting with Real Bug Bounty Targets")
    print("=" * 70)
    print()
    
    # Check what's in targets.txt
    targets_file = repo_root / "targets.txt"
    if targets_file.exists():
        with open(targets_file, "r") as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        print(f"✅ Found {len(targets)} real targets in targets.txt:")
        for target in targets[:10]:
            print(f"   - {target}")
        if len(targets) > 10:
            print(f"   ... and {len(targets) - 10} more")
    else:
        print("❌ targets.txt not found!")
        return
    
    print()
    print("⚠️  ISSUE: Old example.com subdomains found")
    print("   Clearing old results to restart with real targets...")
    print()
    
    # Clear old subdomains (they're example.com)
    subs_file = output_dir / "subs.txt"
    if subs_file.exists():
        subs_file.unlink()
        print("✅ Cleared old subs.txt")
    
    # Clear old http.json
    http_file = output_dir / "http.json"
    if http_file.exists():
        http_file.unlink()
        print("✅ Cleared old http.json")
    
    # Clear status file
    status_file = roi_dir / ".status"
    if status_file.exists():
        status_file.unlink()
        print("✅ Cleared status file")
    
    print()
    print("=" * 70)
    print("🚀 READY TO RESTART")
    print("=" * 70)
    print()
    print("Run this command to start fresh scan:")
    print()
    print("  python3 scripts/immediate_roi_hunter.py")
    print()
    print("This will:")
    print("  ✅ Scan REAL bug bounty targets (not example.com)")
    print("  ✅ Apply PDF methodology (crypto detection)")
    print("  ✅ Generate real bug reports")
    print()

if __name__ == "__main__":
    quick_fix()


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
