#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
BACKUP ALL REPOSITORIES - Complete System Backup
Creates dual backups for EVERY repository you have
"""

import os
import sys
from pathlib import Path
from datetime import datetime
import subprocess

# Color codes
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
BOLD = '\033[1m'
RESET = '\033[0m'

def find_all_repositories(base_path: Path):
    """Find all directories that look like repositories"""
    
    repositories = []
    
    # Check direct subdirectories
    for item in base_path.iterdir():
        if not item.is_dir():
            continue
        
        # Skip backup directories
        if 'BACKUP' in item.name.upper():
            continue
        
        # Check if it's a git repo or has substantial content
        is_git_repo = (item / '.git').exists()
        has_python = len(list(item.glob('*.py'))) > 0
        has_docs = len(list(item.glob('*.md'))) > 0
        has_scripts = (item / 'scripts').exists()
        
        if is_git_repo or has_python or has_docs or has_scripts:
            repositories.append(item)
    
    return repositories

def backup_repository(repo_path: Path):
    """Backup a single repository using dual_backup_system.py"""
    
    dual_backup_script = repo_path / "scripts" / "dual_backup_system.py"
    
    if not dual_backup_script.exists():
        # Copy the script to this repo
        source_script = Path(__file__).parent / "dual_backup_system.py"
        if source_script.exists():
            scripts_dir = repo_path / "scripts"
            scripts_dir.mkdir(exist_ok=True)
            
            import shutil
            shutil.copy2(source_script, dual_backup_script)
            dual_backup_script.chmod(0o755)
    
    # Run backup
    try:
        result = subprocess.run(
            ["python3", str(dual_backup_script), "backup"],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout
        )
        
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Backup timed out (>10 minutes)"
    except Exception as e:
        return False, "", str(e)

def main():
    """Main entry point"""
    
    print(f"\n{MAGENTA}{BOLD}{'='*70}{RESET}")
    print(f"{MAGENTA}{BOLD}🔄 BACKUP ALL REPOSITORIES - COMPLETE SYSTEM BACKUP{RESET}")
    print(f"{MAGENTA}{BOLD}{'='*70}{RESET}\n")
    
    # Find all repositories
    base_path = Path.home() / "Recon-automation-Bug-bounty-stack"
    if not base_path.exists():
        base_path = Path(__file__).parent.parent.parent
    
    print(f"{CYAN}🔍 Scanning for repositories...{RESET}")
    print(f"{CYAN}   Base path: {base_path}{RESET}\n")
    
    repositories = find_all_repositories(base_path)
    
    if not repositories:
        print(f"{YELLOW}No repositories found!{RESET}\n")
        sys.exit(1)
    
    print(f"{GREEN}✅ Found {len(repositories)} repositories:{RESET}")
    for repo in repositories:
        print(f"   • {repo.name}")
    print()
    
    # Ask for confirmation
    if len(sys.argv) < 2 or sys.argv[1] != "--yes":
        response = input(f"{YELLOW}Backup all {len(repositories)} repositories? (y/n): {RESET}")
        if response.lower() not in ['y', 'yes']:
            print(f"{RED}Backup cancelled.{RESET}\n")
            sys.exit(0)
    
    print()
    
    # Backup each repository
    success_count = 0
    fail_count = 0
    
    for i, repo in enumerate(repositories, 1):
        print(f"{MAGENTA}{BOLD}{'='*70}{RESET}")
        print(f"{MAGENTA}{BOLD}Repository {i}/{len(repositories)}: {repo.name}{RESET}")
        print(f"{MAGENTA}{BOLD}{'='*70}{RESET}\n")
        
        success, stdout, stderr = backup_repository(repo)
        
        if success:
            print(stdout)
            print(f"{GREEN}✅ {repo.name} backed up successfully{RESET}\n")
            success_count += 1
        else:
            print(f"{RED}❌ Failed to backup {repo.name}{RESET}")
            if stderr:
                print(f"{RED}Error: {stderr}{RESET}")
            print()
            fail_count += 1
    
    # Summary
    print(f"{MAGENTA}{BOLD}{'='*70}{RESET}")
    print(f"{MAGENTA}{BOLD}📊 BACKUP SUMMARY{RESET}")
    print(f"{MAGENTA}{BOLD}{'='*70}{RESET}\n")
    
    print(f"{GREEN}✅ Successful: {success_count} repositories{RESET}")
    if fail_count > 0:
        print(f"{RED}❌ Failed: {fail_count} repositories{RESET}")
    
    print(f"\n{CYAN}Backup locations:{RESET}")
    print(f"  Primary: {base_path.parent / 'BACKUP_PRIMARY'}")
    print(f"  Secondary: {base_path.parent / 'BACKUP_SECONDARY'}")
    
    print(f"\n{GREEN}{BOLD}✅ COMPLETE SYSTEM BACKUP FINISHED{RESET}\n")
    
    if fail_count == 0:
        print(f"{GREEN}💡 All your repositories now have TWO independent backups!{RESET}\n")
    else:
        print(f"{YELLOW}⚠️  Some backups failed. Review errors above.{RESET}\n")


if __name__ == "__main__":
    main()
