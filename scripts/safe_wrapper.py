#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
🛡️ SAFE WRAPPER - Integrates safety checks into all security operations
Wraps existing security tools with legal protection layer

Use this wrapper to execute any security command safely
"""

import os
import sys
import subprocess
from pathlib import Path

# Add parent directory to path to import safety check system
sys.path.insert(0, str(Path(__file__).parent))

from safety_check_system import SafetyCheckSystem


def safe_scan(target: str, scan_type: str, client: Optional[str] = None, extra_args: List[str] = None):
    """
    Execute scan with safety checks
    
    Args:
        target: Domain or IP to scan
        scan_type: Type of scan (recon, httpx, nuclei)
        client: Client name
        extra_args: Additional arguments to pass to scan tool
    """
    
    # Map scan types to activities
    activity_map = {
        "recon": "reconnaissance",
        "httpx": "reconnaissance",
        "subfinder": "reconnaissance",
        "assetfinder": "reconnaissance",
        "amass": "reconnaissance",
        "nuclei": "vulnerability_scan",
        "nmap": "vulnerability_scan",
        "exploit": "exploit_verification"
    }
    
    activity = activity_map.get(scan_type.lower(), "vulnerability_scan")
    
    # Initialize safety system
    safety = SafetyCheckSystem()
    
    # Run comprehensive safety check
    safe, messages = safety.full_safety_check(target, activity, client)
    
    if not safe:
        print("\n" + "="*70)
        print("🚨 SCAN BLOCKED BY SAFETY SYSTEM")
        print("="*70)
        for msg in messages:
            print(msg)
        print("="*70)
        print("\nREQUIRED ACTIONS:")
        print("1. Obtain written authorization from client")
        print("2. Add authorization: python3 scripts/add_authorization.py --client 'Name' --domain", target)
        print("3. Retry scan after authorization added")
        print("="*70 + "\n")
        return False
    
    # Safety checks passed - proceed with scan
    print("✅ Safety checks passed - executing scan\n")
    
    return True


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Safe wrapper for security scans")
    parser.add_argument("--target", required=True, help="Target domain or IP")
    parser.add_argument("--scan-type", required=True, help="Type of scan (recon, nuclei, etc)")
    parser.add_argument("--client", help="Client name")
    parser.add_argument("--extra-args", nargs="*", help="Extra arguments")
    
    args = parser.parse_args()
    
    result = safe_scan(
        target=args.target,
        scan_type=args.scan_type,
        client=args.client,
        extra_args=args.extra_args
    )
    
    if result:
        print("✅ Scan authorized and can proceed")
        sys.exit(0)
    else:
        print("❌ Scan blocked by safety system")
        sys.exit(1)


if __name__ == "__main__":
    from typing import Optional, List
    main()

