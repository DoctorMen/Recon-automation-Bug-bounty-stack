#!/usr/bin/env python3
"""
AUTO COPYRIGHT GUARDIAN - Automated 10-Minute Copyright Protection
Copyright © 2025 DoctorMen. All Rights Reserved.

Monitors repository changes and automatically updates copyright notices.
Runs every 10 minutes to ensure copyright stays current.

IDEMPOTENT: Safe to run multiple times, only updates when needed.
"""

import os
import sys
import json
import hashlib
import subprocess
from datetime import datetime
from pathlib import Path
import time
import re

class AutoCopyrightGuardian:
    """
    Automated copyright protection system.
    Checks every 10 minutes and updates copyright in modified files.
    """
    
    def __init__(self, repo_path='.'):
        self.repo_path = Path(repo_path).resolve()
        self.state_file = self.repo_path / '.auto_copyright_state.json'
        self.log_file = self.repo_path / '.auto_copyright_log.txt'
        self.copyright_text = "Copyright © 2025 DoctorMen. All Rights Reserved."
        self.current_year = datetime.now().year
        
        # File extensions to protect
        self.protected_extensions = {
            '.py', '.js', '.html', '.css', '.md', '.sh', '.bat',
            '.json', '.yml', '.yaml', '.xml', '.txt', '.sql'
        }
        
        # Directories to skip
        self.skip_dirs = {
            '.git', '__pycache__', 'node_modules', '.cursor', 
            '.vscode', 'dist', 'build', 'env', '.env', 
            'venv', '.venv', 'output', 'logs'
        }
        
        self.state = self.load_state()
        
    def load_state(self):
        """Load previous state or create new"""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                pass
        
        return {
            'last_check': None,
            'files_tracked': {},
            'total_updates': 0,
            'last_update_time': None
        }
    
    def save_state(self):
        """Save current state"""
        with open(self.state_file, 'w', encoding='utf-8') as f:
            json.dump(self.state, f, indent=2)
    
    def log(self, message):
        """Log activity"""
        timestamp = datetime.now().isoformat()
        log_entry = f"[{timestamp}] {message}\n"
        
        # Print to console (handle encoding issues)
        try:
            print(log_entry.strip())
        except UnicodeEncodeError:
            # Fallback: remove emojis for console
            clean_message = message.encode('ascii', 'ignore').decode('ascii')
            print(f"[{timestamp}] {clean_message}")
        
        # Append to log file (UTF-8 always works here)
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(log_entry)
    
    def get_file_hash(self, file_path):
        """Get MD5 hash of file content"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except:
            return None
    
    def should_skip_file(self, file_path):
        """Check if file should be skipped"""
        path = Path(file_path)
        
        # Skip if in excluded directory
        for part in path.parts:
            if part in self.skip_dirs:
                return True
        
        # Skip if not protected extension
        if path.suffix not in self.protected_extensions:
            return True
        
        # Skip state/log files
        if path.name in ['.auto_copyright_state.json', '.auto_copyright_log.txt']:
            return True
        
        return False
    
    def get_copyright_pattern(self, file_extension):
        """Get copyright pattern for file type"""
        patterns = {
            '.py': (
                '#!/usr/bin/env python3\n"""',
                f'Copyright © {self.current_year} DoctorMen. All Rights Reserved.',
                '"""'
            ),
            '.sh': (
                '#!/bin/bash',
                f'# Copyright © {self.current_year} DoctorMen. All Rights Reserved.',
                ''
            ),
            '.bat': (
                '@echo off',
                f'REM Copyright © {self.current_year} DoctorMen. All Rights Reserved.',
                ''
            ),
            '.js': (
                '/**',
                f' * Copyright © {self.current_year} DoctorMen. All Rights Reserved.',
                ' */'
            ),
            '.html': (
                '<!--',
                f'Copyright © {self.current_year} DoctorMen. All Rights Reserved.',
                '-->'
            ),
            '.css': (
                '/**',
                f' * Copyright © {self.current_year} DoctorMen. All Rights Reserved.',
                ' */'
            ),
            '.md': (
                '<!--',
                f'Copyright © {self.current_year} DoctorMen. All Rights Reserved.',
                '-->'
            )
        }
        
        return patterns.get(file_extension, None)
    
    def has_copyright(self, content, file_extension):
        """Check if file has copyright notice"""
        # Look for copyright in first 20 lines
        lines = content.split('\n')[:20]
        first_lines = '\n'.join(lines)
        
        # Check for any copyright notice
        copyright_patterns = [
            r'Copyright.*DoctorMen',
            r'©.*DoctorMen',
            r'All Rights Reserved'
        ]
        
        for pattern in copyright_patterns:
            if re.search(pattern, first_lines, re.IGNORECASE):
                return True
        
        return False
    
    def add_copyright_header(self, file_path):
        """Add copyright header to file"""
        path = Path(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except UnicodeDecodeError:
            # Binary file, skip
            return False
        except Exception as e:
            self.log(f"❌ Error reading {file_path}: {e}")
            return False
        
        # Check if already has copyright
        if self.has_copyright(content, path.suffix):
            return False
        
        # Get copyright pattern
        pattern = self.get_copyright_pattern(path.suffix)
        if not pattern:
            return False
        
        prefix, copyright_line, suffix = pattern
        
        # Build header
        header_lines = []
        if prefix:
            header_lines.append(prefix)
        header_lines.append(copyright_line)
        if suffix:
            header_lines.append(suffix)
        header_lines.append('')  # Empty line after header
        
        # Check if file starts with shebang
        lines = content.split('\n')
        if lines and lines[0].startswith('#!'):
            # Insert after shebang
            new_content = lines[0] + '\n' + '\n'.join(header_lines) + '\n'.join(lines[1:])
        else:
            # Insert at beginning
            new_content = '\n'.join(header_lines) + content
        
        # Write updated content
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            
            self.log(f"✅ Added copyright to: {file_path}")
            return True
        except Exception as e:
            self.log(f"❌ Error writing {file_path}: {e}")
            return False
    
    def update_copyright_year(self, file_path):
        """Update copyright year if outdated"""
        path = Path(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except:
            return False
        
        # Look for outdated copyright years
        old_year_pattern = r'Copyright © (\d{4}) DoctorMen'
        matches = re.finditer(old_year_pattern, content[:1000])  # Check first 1000 chars
        
        updated = False
        for match in matches:
            old_year = int(match.group(1))
            if old_year < self.current_year:
                # Update year
                old_text = f"Copyright © {old_year} DoctorMen"
                new_text = f"Copyright © {self.current_year} DoctorMen"
                content = content.replace(old_text, new_text)
                updated = True
        
        if updated:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.log(f"✅ Updated copyright year in: {file_path}")
                return True
            except Exception as e:
                self.log(f"❌ Error updating {file_path}: {e}")
        
        return False
    
    def scan_repository(self):
        """Scan entire repository for changes"""
        self.log("🔍 Starting copyright scan...")
        
        files_checked = 0
        files_updated = 0
        files_new = 0
        
        # Walk through repository
        for root, dirs, files in os.walk(self.repo_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self.skip_dirs]
            
            for filename in files:
                file_path = Path(root) / filename
                
                # Skip if should skip
                if self.should_skip_file(file_path):
                    continue
                
                files_checked += 1
                
                # Get current hash
                current_hash = self.get_file_hash(file_path)
                if not current_hash:
                    continue
                
                # Check if file is new or modified
                file_key = str(file_path.relative_to(self.repo_path))
                previous_hash = self.state['files_tracked'].get(file_key)
                
                if previous_hash is None:
                    # New file - add copyright
                    if self.add_copyright_header(file_path):
                        files_new += 1
                        files_updated += 1
                    # Update hash after adding copyright
                    current_hash = self.get_file_hash(file_path)
                
                elif previous_hash != current_hash:
                    # Modified file - update copyright year if needed
                    if self.update_copyright_year(file_path):
                        files_updated += 1
                    # Update hash
                    current_hash = self.get_file_hash(file_path)
                
                # Update tracking
                self.state['files_tracked'][file_key] = current_hash
        
        # Update state
        self.state['last_check'] = datetime.now().isoformat()
        if files_updated > 0:
            self.state['total_updates'] += files_updated
            self.state['last_update_time'] = datetime.now().isoformat()
        
        self.save_state()
        
        self.log(f"✅ Scan complete: {files_checked} files checked, {files_new} new, {files_updated} updated")
        return files_checked, files_new, files_updated
    
    def run_daemon(self, interval_minutes=10):
        """Run as daemon, checking every N minutes"""
        self.log(f"🚀 AUTO COPYRIGHT GUARDIAN started (checking every {interval_minutes} minutes)")
        self.log(f"📁 Repository: {self.repo_path}")
        self.log(f"📝 Log file: {self.log_file}")
        
        try:
            while True:
                # Run scan
                files_checked, files_new, files_updated = self.scan_repository()
                
                # Wait for next interval
                self.log(f"⏳ Next check in {interval_minutes} minutes...")
                time.sleep(interval_minutes * 60)
        
        except KeyboardInterrupt:
            self.log("🛑 Guardian stopped by user")
            sys.exit(0)
        except Exception as e:
            self.log(f"❌ Fatal error: {e}")
            sys.exit(1)
    
    def run_once(self):
        """Run single scan and exit"""
        self.log("🔍 Running single copyright scan...")
        files_checked, files_new, files_updated = self.scan_repository()
        
        if files_updated > 0:
            self.log(f"✅ COPYRIGHT PROTECTION ACTIVE: {files_updated} files updated")
        else:
            self.log("✅ All files protected, no updates needed")
        
        return files_checked, files_new, files_updated

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Automated copyright protection - checks every 10 minutes'
    )
    parser.add_argument(
        '--daemon',
        action='store_true',
        help='Run as background daemon (default: single scan)'
    )
    parser.add_argument(
        '--interval',
        type=int,
        default=10,
        help='Check interval in minutes (default: 10)'
    )
    parser.add_argument(
        '--repo',
        type=str,
        default='.',
        help='Repository path (default: current directory)'
    )
    
    args = parser.parse_args()
    
    # Create guardian
    guardian = AutoCopyrightGuardian(repo_path=args.repo)
    
    if args.daemon:
        # Run as daemon
        guardian.run_daemon(interval_minutes=args.interval)
    else:
        # Run once
        guardian.run_once()

if __name__ == '__main__':
    main()
