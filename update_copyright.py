#!/usr/bin/env python3
"""
GHOST IP Management System
Copyright (c) 2025 Khallid Hakeem Nurse - All Rights Reserved
"""

import os
import re
from datetime import datetime

# Configuration
COPYRIGHT_OWNER = "Khallid Hakeem Nurse"
CURRENT_YEAR = "2025"
FILE_TYPES = ['.py', '.js', '.html', '.css', '.md', '.java', '.c', '.cpp', '.h', '.hpp']
EXCLUDE_DIRS = ['node_modules', '.git', '__pycache__', 'venv', 'dist', 'build']

# Standard copyright notice template
COPYRIGHT_TEMPLATE = """"""
{file_type} {file_name}
Copyright (c) {year} {owner} - All Rights Reserved
Proprietary and Confidential

{description}
Owner: {owner}
System: {system_name}
Date: {date}
""""""

def get_file_description(file_path):
    """Generate a description based on file type and path."""
    if file_path.endswith('.py'):
        if 'api' in file_path.lower():
            return "API endpoints and business logic"
        elif 'models' in file_path.lower():
            return "Data models and database schemas"
        return "Python module"
    elif file_path.endswith('.js'):
        return "Frontend JavaScript functionality"
    elif file_path.endswith('.html'):
        return "Web interface templates"
    return "Source code file"

def get_system_name(file_path):
    """Determine the system name from file path."""
    path_parts = file_path.split(os.sep)
    if 'ghost' in path_parts[-1].lower():
        return path_parts[-1].split('.')[0].upper()
    for part in reversed(path_parts):
        if 'ghost' in part.lower():
            return part.upper()
    return "GHOST SECURITY SYSTEM"

def update_file_copyright(file_path):
    """Update or add copyright notice to a file."""
    try:
        with open(file_path, 'r+', encoding='utf-8') as f:
            content = f.read()
            
            # Skip if already has current copyright
            if f"Copyright (c) {CURRENT_YEAR} {COPYRIGHT_OWNER}" in content:
                return False
                
            # Remove old copyright if exists
            content = re.sub(
                r'#.*Copyright.*\n(?:#.*\n)*',
                '',
                content,
                flags=re.MULTILINE,
                count=1
            )
            
            # Prepare new copyright
            file_ext = os.path.splitext(file_path)[1]
            comment_char = '#' if file_ext in ['.py', '.sh'] else '//' if file_ext in ['.js', '.java', '.c', '.cpp', '.h', '.hpp'] else '<!--' if file_ext == '.html' else '#'
            
            description = get_file_description(file_path)
            system_name = get_system_name(file_path)
            
            new_copyright = COPYRIGHT_TEMPLATE.format(
                file_type=file_ext.upper().lstrip('.') if file_ext else 'SOURCE',
                file_name=os.path.basename(file_path),
                year=CURRENT_YEAR,
                owner=COPYRIGHT_OWNER,
                description=description,
                system_name=system_name,
                date=datetime.now().strftime("%B %d, %Y")
            )
            
            # Format with comment characters
            lines = new_copyright.strip().split('\n')
            commented_lines = [f"{comment_char} {line}" if line.strip() else comment_char for line in lines]
            new_copyright = '\n'.join(commented_lines) + '\n\n'
            # Write new content
            f.seek(0, 0)
            f.write(new_copyright + content)
            return True
            
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
    return False

def scan_directory(root_dir):
    """Recursively scan directory for files to update."""
    updated_files = 0
    for root, dirs, files in os.walk(root_dir):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        
        for file in files:
            if any(file.endswith(ext) for ext in FILE_TYPES):
                file_path = os.path.join(root, file)
                if update_file_copyright(file_path):
                    print(f"Updated: {file_path}")
                    updated_files += 1
    return updated_files

def main():
    """Main function to update copyright notices."""
    print(f"GHOST IP Management System - Copyright © {CURRENT_YEAR} {COPYRIGHT_OWNER}\n")
    
    root_dir = os.path.dirname(os.path.abspath(__file__))
    print(f"Scanning directory: {root_dir}")
    
    updated = scan_directory(root_dir)
    print(f"\nUpdate complete. {updated} files were updated with current copyright information.")
    print("\nPlease review the changes before committing to version control.")

if __name__ == "__main__":
    main()
