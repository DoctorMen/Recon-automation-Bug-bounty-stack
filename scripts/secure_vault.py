#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
SECURE VAULT - SHA-256 Based File Encryption System
Locks down bleeding edge monetization assets with military-grade encryption
"""

import os
import sys
import json
import hashlib
from pathlib import Path
from datetime import datetime
from getpass import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Color codes for terminal output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
BOLD = '\033[1m'
RESET = '\033[0m'

class SecureVault:
    """Military-grade file encryption system"""
    
    def __init__(self, vault_dir=None):
        if vault_dir:
            self.vault_dir = Path(vault_dir)
        else:
            self.vault_dir = Path(__file__).parent.parent
        
        self.vault_state = self.vault_dir / ".vault_state.json"
        self.backup_dir = self.vault_dir / "VAULT_BACKUPS"
        
        # Files to protect (bleeding edge assets)
        self.protected_files = [
            # Monetization projects (HIGH VALUE)
            "MONETIZATION_PROJECTS/1_CONSULTING/consulting_landing_page.html",
            "MONETIZATION_PROJECTS/1_CONSULTING/service_packages.md",
            "MONETIZATION_PROJECTS/2_SAAS/product_spec.md",
            "MONETIZATION_PROJECTS/3_COURSE/course_outline.md",
            "MONETIZATION_PROJECTS/4_IMPLEMENTATION/service_offering.md",
            "MONETIZATION_PROJECTS/MARKETING/email_templates.md",
            "MONETIZATION_PROJECTS/MARKETING/social_media_content.md",
            "MONETIZATION_PROJECTS/MASTER_LAUNCH_PLAN.md",
            "MONETIZATION_PROJECTS/EXECUTION_COMPLETE.md",
            "MONETIZATION_COMPLETE_OVERVIEW.md",
            "START_HERE_MONETIZATION.md",
            
            # Agentic system (PROPRIETARY)
            "agentic_core.py",
            "agentic_recon_agents.py",
            "agentic_coordinator.py",
            "agentic_learning.py",
            "agentic_monitoring.py",
            "agentic_distributed.py",
            "agentic_integration.py",
            "run_agentic_system.py",
            
            # Business systems (REVENUE GENERATING)
            "scripts/monetization_finder.py",
            "MONETIZATION_FROM_LEARNING.md",
            "EXAMPLE_MONETIZATION_OUTPUT.md",
            
            # Other bleeding edge assets
            "NEXUS_ENGINE.html",
            "NEXUS_AGENTS_SYSTEM.js",
            "VIBE_COMMAND_SYSTEM.py",
        ]
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using SHA-256 PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for AES-256
            salt=salt,
            iterations=100000,  # High iteration count for security
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def encrypt_file(self, file_path: Path, password: str) -> bool:
        """Encrypt a single file using AES-256-CBC"""
        try:
            # Read original file
            with open(file_path, 'rb') as f:
                plaintext = f.read()
            
            # Generate random salt and IV
            salt = os.urandom(16)
            iv = os.urandom(16)
            
            # Derive key from password
            key = self.derive_key(password, salt)
            
            # Encrypt using AES-256-CBC
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Add PKCS7 padding
            padding_length = 16 - (len(plaintext) % 16)
            padded_plaintext = plaintext + bytes([padding_length] * padding_length)
            
            # Encrypt
            ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
            
            # Write encrypted file (salt + iv + ciphertext)
            encrypted_path = file_path.with_suffix(file_path.suffix + '.encrypted')
            with open(encrypted_path, 'wb') as f:
                f.write(salt + iv + ciphertext)
            
            # Calculate SHA-256 hash of original file (for integrity verification)
            file_hash = hashlib.sha256(plaintext).hexdigest()
            
            return True, file_hash
            
        except Exception as e:
            print(f"{RED}Error encrypting {file_path}: {e}{RESET}")
            return False, None
    
    def decrypt_file(self, encrypted_path: Path, password: str, expected_hash: str = None) -> bool:
        """Decrypt a single file using AES-256-CBC"""
        try:
            # Read encrypted file
            with open(encrypted_path, 'rb') as f:
                data = f.read()
            
            # Extract salt, IV, and ciphertext
            salt = data[:16]
            iv = data[16:32]
            ciphertext = data[32:]
            
            # Derive key from password
            key = self.derive_key(password, salt)
            
            # Decrypt using AES-256-CBC
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove PKCS7 padding
            padding_length = padded_plaintext[-1]
            plaintext = padded_plaintext[:-padding_length]
            
            # Verify integrity if hash provided
            if expected_hash:
                actual_hash = hashlib.sha256(plaintext).hexdigest()
                if actual_hash != expected_hash:
                    print(f"{RED}Integrity check failed! File may be corrupted.{RESET}")
                    return False
            
            # Write decrypted file (remove .encrypted extension)
            original_path = encrypted_path.with_suffix('')
            if original_path.suffix == encrypted_path.suffix:
                # Handle double extension
                original_path = Path(str(encrypted_path).replace('.encrypted', ''))
            
            with open(original_path, 'wb') as f:
                f.write(plaintext)
            
            return True
            
        except Exception as e:
            print(f"{RED}Error decrypting {encrypted_path}: {e}{RESET}")
            print(f"{YELLOW}Possible wrong password or corrupted file.{RESET}")
            return False
    
    def create_backup(self, file_path: Path):
        """Create backup of file before encryption"""
        self.backup_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{file_path.name}.backup_{timestamp}"
        backup_path = self.backup_dir / backup_name
        
        try:
            import shutil
            shutil.copy2(file_path, backup_path)
            return True
        except Exception as e:
            print(f"{RED}Backup failed for {file_path}: {e}{RESET}")
            return False
    
    def load_vault_state(self) -> dict:
        """Load vault state (which files are encrypted)"""
        if self.vault_state.exists():
            with open(self.vault_state, 'r') as f:
                return json.load(f)
        return {"encrypted_files": {}, "created": datetime.now().isoformat()}
    
    def save_vault_state(self, state: dict):
        """Save vault state"""
        state["last_modified"] = datetime.now().isoformat()
        with open(self.vault_state, 'w') as f:
            json.dump(state, f, indent=2)
    
    def lock_vault(self, password: str = None):
        """Encrypt all protected files"""
        print(f"\n{CYAN}{BOLD}🔒 SECURE VAULT - LOCK MODE{RESET}")
        print(f"{CYAN}{'='*60}{RESET}\n")
        
        # Get password
        if not password:
            password = getpass(f"{YELLOW}Enter encryption password: {RESET}")
            confirm = getpass(f"{YELLOW}Confirm password: {RESET}")
            
            if password != confirm:
                print(f"{RED}Passwords don't match!{RESET}")
                return False
        
        # Load state
        state = self.load_vault_state()
        encrypted_files = state.get("encrypted_files", {})
        
        # Encrypt each file
        success_count = 0
        skip_count = 0
        fail_count = 0
        
        for rel_path in self.protected_files:
            file_path = self.vault_dir / rel_path
            
            if not file_path.exists():
                print(f"{YELLOW}⚠️  Skip: {rel_path} (not found){RESET}")
                skip_count += 1
                continue
            
            # Check if already encrypted
            encrypted_path = file_path.with_suffix(file_path.suffix + '.encrypted')
            if encrypted_path.exists():
                print(f"{YELLOW}⏭️  Skip: {rel_path} (already encrypted){RESET}")
                skip_count += 1
                continue
            
            # Create backup
            print(f"{CYAN}📦 Backing up: {rel_path}{RESET}")
            if not self.create_backup(file_path):
                print(f"{RED}❌ Backup failed, skipping encryption{RESET}")
                fail_count += 1
                continue
            
            # Encrypt
            print(f"{CYAN}🔐 Encrypting: {rel_path}{RESET}")
            success, file_hash = self.encrypt_file(file_path, password)
            
            if success:
                # Store metadata
                encrypted_files[rel_path] = {
                    "encrypted_at": datetime.now().isoformat(),
                    "sha256_hash": file_hash,
                    "original_size": file_path.stat().st_size
                }
                
                # Delete original (keep only encrypted)
                file_path.unlink()
                
                print(f"{GREEN}✅ Locked: {rel_path}{RESET}")
                success_count += 1
            else:
                fail_count += 1
        
        # Save state
        state["encrypted_files"] = encrypted_files
        self.save_vault_state(state)
        
        # Summary
        print(f"\n{CYAN}{'='*60}{RESET}")
        print(f"{GREEN}{BOLD}🔒 VAULT LOCKED{RESET}")
        print(f"{GREEN}✅ Encrypted: {success_count} files{RESET}")
        print(f"{YELLOW}⏭️  Skipped: {skip_count} files{RESET}")
        if fail_count > 0:
            print(f"{RED}❌ Failed: {fail_count} files{RESET}")
        print(f"{CYAN}{'='*60}{RESET}\n")
        
        print(f"{YELLOW}💡 Your files are now encrypted with AES-256.{RESET}")
        print(f"{YELLOW}   Keep your password safe - it cannot be recovered!{RESET}")
        print(f"{YELLOW}   Backups stored in: {self.backup_dir}{RESET}\n")
        
        return True
    
    def unlock_vault(self, password: str = None):
        """Decrypt all protected files"""
        print(f"\n{CYAN}{BOLD}🔓 SECURE VAULT - UNLOCK MODE{RESET}")
        print(f"{CYAN}{'='*60}{RESET}\n")
        
        # Get password
        if not password:
            password = getpass(f"{YELLOW}Enter decryption password: {RESET}")
        
        # Load state
        state = self.load_vault_state()
        encrypted_files = state.get("encrypted_files", {})
        
        if not encrypted_files:
            print(f"{YELLOW}No encrypted files found in vault.{RESET}")
            return False
        
        # Decrypt each file
        success_count = 0
        fail_count = 0
        
        for rel_path, metadata in encrypted_files.items():
            encrypted_path = self.vault_dir / (rel_path + '.encrypted')
            
            if not encrypted_path.exists():
                print(f"{YELLOW}⚠️  Skip: {rel_path} (encrypted file not found){RESET}")
                fail_count += 1
                continue
            
            # Decrypt
            print(f"{CYAN}🔓 Decrypting: {rel_path}{RESET}")
            expected_hash = metadata.get("sha256_hash")
            success = self.decrypt_file(encrypted_path, password, expected_hash)
            
            if success:
                # Delete encrypted file
                encrypted_path.unlink()
                
                print(f"{GREEN}✅ Unlocked: {rel_path}{RESET}")
                success_count += 1
            else:
                fail_count += 1
        
        # Clear state if all successful
        if fail_count == 0:
            state["encrypted_files"] = {}
            self.save_vault_state(state)
        
        # Summary
        print(f"\n{CYAN}{'='*60}{RESET}")
        if fail_count == 0:
            print(f"{GREEN}{BOLD}🔓 VAULT UNLOCKED{RESET}")
            print(f"{GREEN}✅ Decrypted: {success_count} files{RESET}")
        else:
            print(f"{RED}{BOLD}⚠️  PARTIAL UNLOCK{RESET}")
            print(f"{GREEN}✅ Decrypted: {success_count} files{RESET}")
            print(f"{RED}❌ Failed: {fail_count} files{RESET}")
            print(f"{YELLOW}   Check password and try again{RESET}")
        print(f"{CYAN}{'='*60}{RESET}\n")
        
        return fail_count == 0
    
    def vault_status(self):
        """Show vault status"""
        print(f"\n{CYAN}{BOLD}📊 SECURE VAULT STATUS{RESET}")
        print(f"{CYAN}{'='*60}{RESET}\n")
        
        state = self.load_vault_state()
        encrypted_files = state.get("encrypted_files", {})
        
        if encrypted_files:
            print(f"{RED}{BOLD}🔒 VAULT IS LOCKED{RESET}")
            print(f"{RED}   {len(encrypted_files)} files encrypted{RESET}\n")
            
            print(f"{CYAN}Encrypted Files:{RESET}")
            for rel_path, metadata in encrypted_files.items():
                encrypted_at = metadata.get("encrypted_at", "unknown")
                size = metadata.get("original_size", 0)
                print(f"  {YELLOW}🔐{RESET} {rel_path}")
                print(f"     Locked: {encrypted_at}")
                print(f"     Size: {size:,} bytes\n")
        else:
            print(f"{GREEN}{BOLD}🔓 VAULT IS UNLOCKED{RESET}")
            print(f"{GREEN}   All files accessible{RESET}\n")
            
            # Check which protected files exist
            existing = []
            missing = []
            for rel_path in self.protected_files:
                file_path = self.vault_dir / rel_path
                if file_path.exists():
                    existing.append(rel_path)
                else:
                    missing.append(rel_path)
            
            print(f"{CYAN}Protected Files:{RESET}")
            print(f"  {GREEN}✅ Available: {len(existing)} files{RESET}")
            if missing:
                print(f"  {YELLOW}⚠️  Missing: {len(missing)} files{RESET}")
        
        print(f"{CYAN}{'='*60}{RESET}\n")
        
        if self.backup_dir.exists():
            backups = list(self.backup_dir.glob("*.backup_*"))
            print(f"{CYAN}Backups: {len(backups)} files in {self.backup_dir}{RESET}\n")


def main():
    """Main entry point"""
    
    if len(sys.argv) < 2:
        print(f"\n{CYAN}{BOLD}SECURE VAULT - SHA-256 File Encryption{RESET}")
        print(f"{CYAN}{'='*60}{RESET}\n")
        print("Usage:")
        print(f"  {sys.argv[0]} lock     - Encrypt all protected files")
        print(f"  {sys.argv[0]} unlock   - Decrypt all protected files")
        print(f"  {sys.argv[0]} status   - Show vault status")
        print()
        print("Protected Assets:")
        print("  • Monetization projects ($300k-600k value)")
        print("  • Agentic system (proprietary code)")
        print("  • Business systems (revenue generating)")
        print("  • Bleeding edge UI files")
        print()
        print("Security:")
        print("  • AES-256-CBC encryption")
        print("  • SHA-256 key derivation (PBKDF2)")
        print("  • 100,000 iterations")
        print("  • Integrity verification")
        print("  • Automatic backups")
        print()
        sys.exit(1)
    
    vault = SecureVault()
    command = sys.argv[1].lower()
    
    if command == "lock":
        vault.lock_vault()
    elif command == "unlock":
        vault.unlock_vault()
    elif command == "status":
        vault.vault_status()
    else:
        print(f"{RED}Unknown command: {command}{RESET}")
        print(f"Use: lock, unlock, or status")
        sys.exit(1)


if __name__ == "__main__":
    main()
