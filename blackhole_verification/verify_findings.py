#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
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
