#!/usr/bin/env python3
"""
Add Protection to Bug Bounty System
- Adds watermarks
- Adds copyright notices
- Creates licensing file
- Protects your ROI
"""

import os
import sys
from pathlib import Path
from datetime import datetime

# ⚠️ CHANGE THIS TO YOUR BUG BOUNTY HANDLE/PSEUDONYM! ⚠️
# RECOMMENDED: Use your bug bounty handle (NOT your real name for OPSEC)
# Examples: "DoctorMen", "SecurityResearcher", "YourHandle", etc.
SYSTEM_OWNER = "YOUR_NAME_HERE"  # <-- CHANGE THIS LINE!

# Alternative: Use environment variable if set
if os.environ.get("SYSTEM_OWNER"):
    SYSTEM_OWNER = os.environ.get("SYSTEM_OWNER")

SYSTEM_ID = f"BB_{datetime.now().strftime('%Y%m%d')}_{hash(SYSTEM_OWNER) % 10000}"
COPYRIGHT_YEAR = datetime.now().year

# Copyright notice template - ALL RIGHTS WILL BE TO SYSTEM_OWNER (YOU)
COPYRIGHT_NOTICE = f'''"""
Copyright (c) {COPYRIGHT_YEAR} {SYSTEM_OWNER}
Proprietary and Confidential
All Rights Reserved

This software is proprietary and confidential.
Unauthorized copying, modification, or distribution is prohibited.

System ID: {SYSTEM_ID}
Owner: {SYSTEM_OWNER}
"""

'''

# Watermark to add
WATERMARK = f"\n# System ID: {SYSTEM_ID}\n# Owner: {SYSTEM_OWNER}\n# Build Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"

def add_protection_to_file(file_path: Path):
    """Add copyright and watermark to a Python file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check if already protected
        if "System ID:" in content or "Proprietary" in content:
            print(f"⚠️  {file_path.name} already protected")
            return False
        
        # Add copyright at top
        if content.startswith('#!/'):
            # Has shebang - add after shebang
            lines = content.split('\n')
            new_content = lines[0] + '\n' + COPYRIGHT_NOTICE + '\n'.join(lines[1:])
        else:
            # No shebang - add at start
            new_content = COPYRIGHT_NOTICE + content
        
        # Add watermark at end
        new_content += WATERMARK
        
        # Write back
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        print(f"✅ Protected: {file_path.name}")
        return True
        
    except Exception as e:
        print(f"❌ Error protecting {file_path.name}: {e}")
        return False

def create_license_file(repo_root: Path):
    """Create proprietary license file"""
    license_content = f'''PROPRIETARY SOFTWARE LICENSE

Copyright (c) {COPYRIGHT_YEAR} {SYSTEM_OWNER}
All Rights Reserved

This software and associated documentation files (the "Software") are
proprietary and confidential. Unauthorized copying, modification, distribution,
or use of this Software, via any medium, is strictly prohibited.

TERMS AND CONDITIONS:

1. This Software is proprietary and confidential.
2. You may not copy, modify, distribute, or use this Software without
   explicit written permission from the copyright owner.
3. This Software is provided "AS IS" without warranty of any kind.
4. Unauthorized use may result in legal action.

System ID: {SYSTEM_ID}
License Date: {datetime.now().strftime('%Y-%m-%d')}

For licensing inquiries, contact: {SYSTEM_OWNER}
'''
    
    license_file = repo_root / "LICENSE_PROPRIETARY.txt"
    with open(license_file, 'w') as f:
        f.write(license_content)
    
    print(f"✅ Created license file: {license_file.name}")

def main():
    """Add protection to all Python files"""
    print("=" * 70)
    print("🔒 ADDING PROTECTION TO BUG BOUNTY SYSTEM")
    print("=" * 70)
    print()
    
    # Check if owner is set
    if SYSTEM_OWNER == "YOUR_NAME_HERE":
        print("⚠️  WARNING: SYSTEM_OWNER is still 'YOUR_NAME_HERE'")
        print("⚠️  Please edit this script and change SYSTEM_OWNER to your name!")
        print()
        print("Or set it via environment variable:")
        print("  export SYSTEM_OWNER='Your Name'")
        print("  python3 scripts/add_protection.py")
        print()
        response = input("Continue anyway? (y/n): ")
        if response.lower() != 'y':
            print("❌ Aborted. Please set SYSTEM_OWNER first.")
            return
    
    # Get repo root
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent
    
    print(f"System Owner: {SYSTEM_OWNER}")
    print(f"System ID: {SYSTEM_ID}")
    print(f"Repository: {repo_root}")
    print()
    
    # Find all Python files
    python_files = list(repo_root.rglob("*.py"))
    
    print(f"Found {len(python_files)} Python files")
    print()
    
    # Protect each file
    protected_count = 0
    for py_file in python_files:
        # Skip this script itself
        if py_file.name == "add_protection.py":
            continue
        
        # Skip if in venv or __pycache__
        if "venv" in str(py_file) or "__pycache__" in str(py_file):
            continue
        
        if add_protection_to_file(py_file):
            protected_count += 1
    
    # Create license file
    create_license_file(repo_root)
    
    print()
    print("=" * 70)
    print("✅ PROTECTION COMPLETE")
    print("=" * 70)
    print(f"Protected files: {protected_count}/{len(python_files)}")
    print(f"System ID: {SYSTEM_ID}")
    print(f"Copyright Owner: {SYSTEM_OWNER}")
    print()
    print("⚠️  IMPORTANT:")
    print("   1. Keep code private/confidential")
    print("   2. Don't share publicly")
    print("   3. Review LICENSE_PROPRIETARY.txt")
    print("=" * 70)

if __name__ == "__main__":
    main()
