#!/usr/bin/env python3
"""
Copyright © 2025 Khallid H Nurse. All Rights Reserved.

This script adds copyright notices to source files.
"""

import os
import sys
from pathlib import Path

COPYRIGHT_NOTICE = """"
"""
PROPRIETARY AND CONFIDENTIAL

Copyright © 2025 Khallid H Nurse. All Rights Reserved.

This file contains proprietary and confidential information of Khallid H Nurse.
No part of this file may be used, copied, modified, or distributed except
in compliance with the license terms and conditions set forth in the
accompanying LICENSE file.
"""
"""

def add_copyright_to_file(file_path):
    """Add copyright notice to a file if it doesn't already have one."""
    try:
        with open(file_path, 'r+', encoding='utf-8') as f:
            content = f.read()
            
            # Skip if already has copyright
            if "Copyright © 2025 Khallid H Nurse" in content:
                print(f"Skipping (already has copyright): {file_path}")
                return False
                
            # Add copyright notice after shebang if present
            lines = content.splitlines(keepends=True)
            new_content = []
            
            # Keep shebang if present
            if lines and lines[0].startswith('#!'):
                new_content.append(lines[0])
                new_content.append(COPYRIGHT_NOTICE)
                new_content.extend(lines[1:])
            else:
                new_content.append(COPYRIGHT_NOTICE)
                new_content.extend(lines)
            
            # Write back to file
            f.seek(0)
            f.writelines(new_content)
            f.truncate()
            return True
            
    except Exception as e:
        print(f"Error processing {file_path}: {str(e)}")
        return False

def main():
    """Main function to process all Python files."""
    root_dir = Path(__file__).parent.parent
    processed = 0
    
    for py_file in root_dir.rglob('*.py'):
        if add_copyright_to_file(py_file):
            print(f"Added copyright to: {py_file.relative_to(root_dir)}")
            processed += 1
    
    print(f"\nProcessed {processed} files.")

if __name__ == "__main__":
    main()
