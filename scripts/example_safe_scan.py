#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
🛡️ EXAMPLE: Security Scan with Safety Checks
This demonstrates how to integrate safety checks into existing security scripts

CRITICAL: All security scripts should follow this pattern
"""

import sys
import subprocess
from pathlib import Path

# Import safety check system
sys.path.insert(0, str(Path(__file__).parent))
from safety_check_system import require_authorization

def safe_security_scan(target: str, client: str, scan_type: str = "vulnerability_scan"):
    """
    Execute security scan with safety checks
    
    Args:
        target: Domain or IP to scan
        client: Client name (must match authorization)
        scan_type: Type of scan (reconnaissance, vulnerability_scan, exploit_verification)
    """
    
    print(f"🔍 Initiating {scan_type} on {target} for {client}")
    print("="*70)
    
    # 🛡️ CRITICAL: Safety check FIRST (before any security operations)
    if not require_authorization(target, scan_type, client):
        print("\n❌ SCAN BLOCKED BY SAFETY SYSTEM")
        print("\nREQUIRED ACTION:")
        print(f"Add authorization: python3 scripts/add_authorization.py --client '{client}' --domain {target}")
        return False
    
    # Safety checks passed - safe to proceed
    print("\n✅ All safety checks passed - proceeding with scan\n")
    
    # Execute actual scan (example with subfinder)
    try:
        if scan_type == "reconnaissance":
            print(f"Running reconnaissance on {target}...")
            # Example: subprocess.run(["subfinder", "-d", target])
            print("✅ Reconnaissance completed")
        
        elif scan_type == "vulnerability_scan":
            print(f"Running vulnerability scan on {target}...")
            # Example: subprocess.run(["nuclei", "-u", target])
            print("✅ Vulnerability scan completed")
        
        elif scan_type == "exploit_verification":
            print(f"Running exploitability verification on {target}...")
            # Example: subprocess.run(["nuclei", "-u", target, "-severity", "critical"])
            print("✅ Exploitability verification completed")
        
        else:
            print(f"❌ Unknown scan type: {scan_type}")
            return False
        
        print("\n✅ Scan completed successfully")
        return True
        
    except Exception as e:
        print(f"\n❌ Scan failed: {e}")
        print("\n🚨 Consider using emergency stop if issues persist:")
        print(f"   python3 scripts/emergency_stop.py --stop-all --reason 'Scan failure on {target}'")
        return False


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Example safe security scan")
    parser.add_argument("--target", required=True, help="Target domain or IP")
    parser.add_argument("--client", required=True, help="Client name")
    parser.add_argument("--scan-type", default="vulnerability_scan",
                       choices=["reconnaissance", "vulnerability_scan", "exploit_verification"],
                       help="Type of scan to perform")
    
    args = parser.parse_args()
    
    success = safe_security_scan(args.target, args.client, args.scan_type)
    
    if success:
        print("\n🎉 Operation completed successfully")
        sys.exit(0)
    else:
        print("\n❌ Operation failed or blocked")
        sys.exit(1)


if __name__ == "__main__":
    main()


# INTEGRATION NOTES:
# ===================
#
# To integrate safety checks into YOUR existing scripts:
#
# 1. Add this import at the top:
#    from safety_check_system import require_authorization
#
# 2. Before ANY security operation, add:
#    if not require_authorization(target, activity_type, client):
#        sys.exit(1)
#
# 3. Activity types: "reconnaissance", "vulnerability_scan", "exploit_verification"
#
# 4. Test that blocking works:
#    - Run script without authorization → Should be blocked
#    - Add authorization → Should pass
#
# 5. Emergency stop available:
#    python3 scripts/emergency_stop.py --stop-all --reason "Description"

