#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Quick Universal Bug Bounty Scanner
Scans ALL programs in targets.txt, prioritizing quick wins
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

# Import the main scanner
from immediate_roi_hunter import main as roi_main

if __name__ == "__main__":
    print("=" * 60)
    print("Universal Bug Bounty Scanner")
    print("=" * 60)
    print()
    print("Scanning ALL targets in targets.txt")
    print("Not just Rapyd - ALL legal bug bounty programs!")
    print()
    
    # Import argparse to modify arguments
    import argparse
    
    # Parse arguments but force universal scan
    sys.argv = [sys.argv[0], "--resume"]  # Force resume mode
    
    roi_main()

