#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
DUAL BACKUP SYSTEM - Two Independent Repository Backups
Creates two separate backup paths for complete redundancy
"""

import os
import sys
import json
import shutil
import hashlib
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

class DualBackupSystem:
    """Creates two independent backup paths for all repositories"""
    
    def __init__(self, repo_root=None):
        if repo_root:
            self.repo_root = Path(repo_root)
        else:
            self.repo_root = Path(__file__).parent.parent
        
        # Two separate backup locations
        self.backup_path_1 = self.repo_root.parent / "BACKUP_PRIMARY"
        self.backup_path_2 = self.repo_root.parent / "BACKUP_SECONDARY"
        
        # Backup metadata
        self.backup_log = self.repo_root / "BACKUP_LOG.json"
        
        # Exclusions (don't backup these)
        self.exclude_patterns = [
            '.git',
            '__pycache__',
            '*.pyc',
            '.DS_Store',
            'node_modules',
            '.venv',
            'venv',
            '*.log',
            '.vault_state.json',
            'BACKUP_PRIMARY',
            'BACKUP_SECONDARY',
            '*.encrypted',
        ]
    
    def calculate_dir_hash(self, directory: Path) -> str:
        """Calculate hash of entire directory contents"""
        hash_md5 = hashlib.md5()
        
        for root, dirs, files in os.walk(directory):
            # Sort for consistent hashing
            dirs.sort()
            files.sort()
            
            for filename in files:
                filepath = Path(root) / filename
                try:
                    with open(filepath, 'rb') as f:
                        for chunk in iter(lambda: f.read(4096), b""):
                            hash_md5.update(chunk)
                except Exception:
                    pass  # Skip files that can't be read
        
        return hash_md5.hexdigest()
    
    def get_repository_size(self, directory: Path) -> int:
        """Calculate total size of repository in bytes"""
        total_size = 0
        
        for root, dirs, files in os.walk(directory):
            for filename in files:
                filepath = Path(root) / filename
                try:
                    total_size += filepath.stat().st_size
                except Exception:
                    pass
        
        return total_size
    
    def should_exclude(self, path: Path) -> bool:
        """Check if path should be excluded from backup"""
        for pattern in self.exclude_patterns:
            if pattern.startswith('*'):
                # File extension pattern
                if path.suffix == pattern[1:]:
                    return True
            elif pattern in path.parts:
                return True
        return False
    
    def copy_with_exclusions(self, src: Path, dst: Path):
        """Copy directory tree with exclusions"""
        dst.mkdir(parents=True, exist_ok=True)
        
        copied_files = 0
        skipped_files = 0
        total_size = 0
        
        for root, dirs, files in os.walk(src):
            root_path = Path(root)
            
            # Filter directories
            dirs[:] = [d for d in dirs if not self.should_exclude(root_path / d)]
            
            # Calculate relative path
            rel_path = root_path.relative_to(src)
            dst_dir = dst / rel_path
            dst_dir.mkdir(parents=True, exist_ok=True)
            
            # Copy files
            for filename in files:
                src_file = root_path / filename
                
                if self.should_exclude(src_file):
                    skipped_files += 1
                    continue
                
                dst_file = dst_dir / filename
                
                try:
                    shutil.copy2(src_file, dst_file)
                    copied_files += 1
                    total_size += src_file.stat().st_size
                except Exception as e:
                    print(f"{YELLOW}⚠️  Skip: {src_file.name} ({e}){RESET}")
                    skipped_files += 1
        
        return copied_files, skipped_files, total_size
    
    def create_backup(self, backup_path: Path, backup_name: str):
        """Create a single backup at specified path"""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = backup_path / f"{self.repo_root.name}_{timestamp}"
        
        print(f"{CYAN}📦 Creating {backup_name}...{RESET}")
        print(f"{CYAN}   Source: {self.repo_root}{RESET}")
        print(f"{CYAN}   Destination: {backup_dir}{RESET}\n")
        
        # Create backup
        start_time = datetime.now()
        copied, skipped, size = self.copy_with_exclusions(self.repo_root, backup_dir)
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Calculate hash
        print(f"{CYAN}🔐 Calculating integrity hash...{RESET}")
        backup_hash = self.calculate_dir_hash(backup_dir)
        
        # Create metadata file
        metadata = {
            "backup_name": backup_name,
            "timestamp": timestamp,
            "source": str(self.repo_root),
            "destination": str(backup_dir),
            "files_copied": copied,
            "files_skipped": skipped,
            "total_size_bytes": size,
            "total_size_mb": round(size / (1024 * 1024), 2),
            "duration_seconds": round(duration, 2),
            "integrity_hash": backup_hash,
            "created_at": datetime.now().isoformat()
        }
        
        metadata_file = backup_dir / "BACKUP_METADATA.json"
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Create README
        readme = backup_dir / "BACKUP_README.txt"
        with open(readme, 'w') as f:
            f.write(f"""
REPOSITORY BACKUP - {backup_name}
{'='*60}

Backup Information:
- Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- Source: {self.repo_root}
- Files: {copied:,} files backed up
- Size: {metadata['total_size_mb']:,.2f} MB
- Duration: {duration:.2f} seconds
- Integrity Hash: {backup_hash}

Restoration:
To restore this backup, copy the contents of this directory
back to: {self.repo_root}

Verification:
Run dual_backup_system.py verify to check integrity.

{'='*60}
""")
        
        print(f"{GREEN}✅ {backup_name} complete!{RESET}")
        print(f"{GREEN}   Files: {copied:,} copied, {skipped:,} skipped{RESET}")
        print(f"{GREEN}   Size: {metadata['total_size_mb']:,.2f} MB{RESET}")
        print(f"{GREEN}   Duration: {duration:.2f} seconds{RESET}")
        print(f"{GREEN}   Hash: {backup_hash[:16]}...{RESET}\n")
        
        return metadata
    
    def create_dual_backup(self):
        """Create both primary and secondary backups"""
        
        print(f"\n{MAGENTA}{BOLD}{'='*60}{RESET}")
        print(f"{MAGENTA}{BOLD}🔄 DUAL BACKUP SYSTEM{RESET}")
        print(f"{MAGENTA}{BOLD}{'='*60}{RESET}\n")
        
        print(f"{CYAN}Repository: {self.repo_root.name}{RESET}")
        print(f"{CYAN}Location: {self.repo_root}{RESET}\n")
        
        # Calculate source size
        print(f"{CYAN}📊 Analyzing repository...{RESET}")
        source_size = self.get_repository_size(self.repo_root)
        print(f"{CYAN}   Total size: {source_size / (1024 * 1024):.2f} MB{RESET}\n")
        
        # Create primary backup
        print(f"{MAGENTA}{BOLD}PATH 1: PRIMARY BACKUP{RESET}")
        print(f"{MAGENTA}{'='*60}{RESET}")
        metadata_1 = self.create_backup(self.backup_path_1, "PRIMARY BACKUP")
        
        # Create secondary backup
        print(f"{MAGENTA}{BOLD}PATH 2: SECONDARY BACKUP{RESET}")
        print(f"{MAGENTA}{'='*60}{RESET}")
        metadata_2 = self.create_backup(self.backup_path_2, "SECONDARY BACKUP")
        
        # Save backup log
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "repository": str(self.repo_root),
            "primary_backup": metadata_1,
            "secondary_backup": metadata_2,
            "status": "success"
        }
        
        # Load existing log
        if self.backup_log.exists():
            with open(self.backup_log, 'r') as f:
                log_data = json.load(f)
        else:
            log_data = {"backups": []}
        
        log_data["backups"].append(log_entry)
        log_data["last_backup"] = datetime.now().isoformat()
        
        with open(self.backup_log, 'w') as f:
            json.dump(log_data, f, indent=2)
        
        # Summary
        print(f"{MAGENTA}{BOLD}{'='*60}{RESET}")
        print(f"{GREEN}{BOLD}✅ DUAL BACKUP COMPLETE{RESET}\n")
        
        print(f"{CYAN}Summary:{RESET}")
        print(f"  {GREEN}✅ Primary Backup:{RESET} {metadata_1['destination']}")
        print(f"     Files: {metadata_1['files_copied']:,} | Size: {metadata_1['total_size_mb']:.2f} MB")
        print(f"     Hash: {metadata_1['integrity_hash'][:32]}...")
        print()
        print(f"  {GREEN}✅ Secondary Backup:{RESET} {metadata_2['destination']}")
        print(f"     Files: {metadata_2['files_copied']:,} | Size: {metadata_2['total_size_mb']:.2f} MB")
        print(f"     Hash: {metadata_2['integrity_hash'][:32]}...")
        print()
        
        # Verify they're different (independent)
        if metadata_1['integrity_hash'] == metadata_2['integrity_hash']:
            print(f"{GREEN}✅ Integrity verified: Both backups identical{RESET}")
        else:
            print(f"{YELLOW}⚠️  Warning: Backup hashes differ (this is unusual){RESET}")
        
        print(f"\n{CYAN}Backup locations:{RESET}")
        print(f"  Path 1: {self.backup_path_1}")
        print(f"  Path 2: {self.backup_path_2}")
        print(f"\n{CYAN}Backup log: {self.backup_log}{RESET}")
        
        print(f"\n{MAGENTA}{BOLD}{'='*60}{RESET}\n")
        
        print(f"{GREEN}💡 Your repository now has TWO independent backups!{RESET}")
        print(f"{GREEN}   If anything happens, you can restore from either path.{RESET}\n")
        
        return True
    
    def list_backups(self):
        """List all existing backups"""
        
        print(f"\n{CYAN}{BOLD}📋 BACKUP INVENTORY{RESET}")
        print(f"{CYAN}{'='*60}{RESET}\n")
        
        # Check primary path
        if self.backup_path_1.exists():
            backups_1 = sorted(self.backup_path_1.glob(f"{self.repo_root.name}_*"))
            print(f"{MAGENTA}PRIMARY BACKUP PATH:{RESET} {self.backup_path_1}")
            if backups_1:
                for backup in backups_1:
                    size = self.get_repository_size(backup)
                    print(f"  {GREEN}✅{RESET} {backup.name}")
                    print(f"     Size: {size / (1024 * 1024):.2f} MB")
                    
                    metadata_file = backup / "BACKUP_METADATA.json"
                    if metadata_file.exists():
                        with open(metadata_file, 'r') as f:
                            meta = json.load(f)
                        print(f"     Created: {meta.get('created_at', 'unknown')}")
                        print(f"     Files: {meta.get('files_copied', 'unknown'):,}")
                    print()
            else:
                print(f"  {YELLOW}No backups found{RESET}\n")
        else:
            print(f"{YELLOW}Primary backup path does not exist yet{RESET}\n")
        
        # Check secondary path
        if self.backup_path_2.exists():
            backups_2 = sorted(self.backup_path_2.glob(f"{self.repo_root.name}_*"))
            print(f"{MAGENTA}SECONDARY BACKUP PATH:{RESET} {self.backup_path_2}")
            if backups_2:
                for backup in backups_2:
                    size = self.get_repository_size(backup)
                    print(f"  {GREEN}✅{RESET} {backup.name}")
                    print(f"     Size: {size / (1024 * 1024):.2f} MB")
                    
                    metadata_file = backup / "BACKUP_METADATA.json"
                    if metadata_file.exists():
                        with open(metadata_file, 'r') as f:
                            meta = json.load(f)
                        print(f"     Created: {meta.get('created_at', 'unknown')}")
                        print(f"     Files: {meta.get('files_copied', 'unknown'):,}")
                    print()
            else:
                print(f"  {YELLOW}No backups found{RESET}\n")
        else:
            print(f"{YELLOW}Secondary backup path does not exist yet{RESET}\n")
        
        print(f"{CYAN}{'='*60}{RESET}\n")
    
    def verify_backup(self, backup_path: Path):
        """Verify backup integrity"""
        
        metadata_file = backup_path / "BACKUP_METADATA.json"
        if not metadata_file.exists():
            print(f"{RED}❌ No metadata found for {backup_path.name}{RESET}")
            return False
        
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
        
        print(f"{CYAN}🔍 Verifying: {backup_path.name}{RESET}")
        print(f"{CYAN}   Calculating hash...{RESET}")
        
        current_hash = self.calculate_dir_hash(backup_path)
        original_hash = metadata.get('integrity_hash', '')
        
        if current_hash == original_hash:
            print(f"{GREEN}✅ Integrity verified: Backup is intact{RESET}")
            return True
        else:
            print(f"{RED}❌ Integrity check FAILED: Backup may be corrupted{RESET}")
            print(f"{YELLOW}   Original hash: {original_hash}{RESET}")
            print(f"{YELLOW}   Current hash:  {current_hash}{RESET}")
            return False
    
    def verify_all_backups(self):
        """Verify all backups"""
        
        print(f"\n{CYAN}{BOLD}🔍 VERIFYING ALL BACKUPS{RESET}")
        print(f"{CYAN}{'='*60}{RESET}\n")
        
        verified = 0
        failed = 0
        
        # Verify primary backups
        if self.backup_path_1.exists():
            print(f"{MAGENTA}Primary Backups:{RESET}")
            for backup in sorted(self.backup_path_1.glob(f"{self.repo_root.name}_*")):
                if self.verify_backup(backup):
                    verified += 1
                else:
                    failed += 1
                print()
        
        # Verify secondary backups
        if self.backup_path_2.exists():
            print(f"{MAGENTA}Secondary Backups:{RESET}")
            for backup in sorted(self.backup_path_2.glob(f"{self.repo_root.name}_*")):
                if self.verify_backup(backup):
                    verified += 1
                else:
                    failed += 1
                print()
        
        print(f"{CYAN}{'='*60}{RESET}")
        print(f"{GREEN}✅ Verified: {verified} backups{RESET}")
        if failed > 0:
            print(f"{RED}❌ Failed: {failed} backups{RESET}")
        print()


def main():
    """Main entry point"""
    
    if len(sys.argv) < 2:
        print(f"\n{CYAN}{BOLD}DUAL BACKUP SYSTEM{RESET}")
        print(f"{CYAN}{'='*60}{RESET}\n")
        print("Usage:")
        print(f"  {sys.argv[0]} backup    - Create dual backups")
        print(f"  {sys.argv[0]} list      - List all backups")
        print(f"  {sys.argv[0]} verify    - Verify backup integrity")
        print()
        print("Features:")
        print("  • Two independent backup paths")
        print("  • Automatic integrity hashing")
        print("  • Metadata tracking")
        print("  • Smart exclusions (.git, __pycache__, etc.)")
        print("  • Verification system")
        print()
        print("Backup Locations:")
        print("  • Primary: ../BACKUP_PRIMARY/")
        print("  • Secondary: ../BACKUP_SECONDARY/")
        print()
        sys.exit(1)
    
    system = DualBackupSystem()
    command = sys.argv[1].lower()
    
    if command == "backup":
        system.create_dual_backup()
    elif command == "list":
        system.list_backups()
    elif command == "verify":
        system.verify_all_backups()
    else:
        print(f"{RED}Unknown command: {command}{RESET}")
        print(f"Use: backup, list, or verify")
        sys.exit(1)


if __name__ == "__main__":
    main()
