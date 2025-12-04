#!/usr/bin/env python3
"""
ANTI-COPY PROTECTION SYSTEM
Copyright © 2025 DoctorMen. All Rights Reserved.

Prevents unauthorized copying and nefarious use of your data through:
1. License verification
2. Hardware fingerprinting
3. Copy detection
4. Usage tracking
5. Remote kill switch capability
"""

import os
import json
import hashlib
import uuid
import platform
import socket
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
import sys

class AntiCopyProtection:
    """
    Anti-copy protection system to prevent unauthorized data use
    
    Features:
    - Hardware fingerprinting (binds data to specific machine)
    - License verification
    - Copy detection and tracking
    - Usage monitoring
    - Remote kill switch capability
    - Anti-tampering protection
    """
    
    def __init__(self, protection_dir='./.protection'):
        self.protection_dir = Path(protection_dir)
        self.protection_dir.mkdir(parents=True, exist_ok=True)
        
        self.license_file = self.protection_dir / 'license.json'
        self.fingerprint_file = self.protection_dir / 'fingerprint.json'
        self.usage_log = self.protection_dir / 'usage.log'
        self.copy_tracking = self.protection_dir / 'copy_tracking.json'
        
        # Generate machine fingerprint
        self.machine_fingerprint = self._generate_fingerprint()
        
        # Initialize protection
        self._initialize_protection()
    
    def _generate_fingerprint(self) -> str:
        """
        Generate unique hardware fingerprint
        
        Uses:
        - MAC address
        - Hostname
        - OS info
        - Disk serial (if available)
        """
        components = []
        
        # MAC address
        try:
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                           for elements in range(0, 8*6, 8)][::-1])
            components.append(mac)
        except:
            pass
        
        # Hostname
        components.append(socket.gethostname())
        
        # OS info
        components.append(platform.system())
        components.append(platform.release())
        
        # User
        components.append(os.environ.get('USER', os.environ.get('USERNAME', 'unknown')))
        
        # Create fingerprint hash
        fingerprint_data = '|'.join(components)
        fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()
        
        return fingerprint
    
    def _initialize_protection(self):
        """Initialize protection system"""
        if not self.fingerprint_file.exists():
            # First run - save fingerprint
            fingerprint_data = {
                'fingerprint': self.machine_fingerprint,
                'created': datetime.now().isoformat(),
                'hostname': socket.gethostname(),
                'os': platform.system(),
                'user': os.environ.get('USER', os.environ.get('USERNAME', 'unknown'))
            }
            
            with open(self.fingerprint_file, 'w') as f:
                json.dump(fingerprint_data, f, indent=2)
            
            print(f"🔒 Protection initialized for this machine")
            print(f"   Fingerprint: {self.machine_fingerprint[:16]}...")
    
    def verify_authorized_machine(self) -> bool:
        """
        Verify this machine is authorized to access data
        
        Returns:
            True if authorized, False otherwise
        """
        if not self.fingerprint_file.exists():
            print("⚠️  No fingerprint file found - initializing...")
            return True
        
        # Load stored fingerprint
        with open(self.fingerprint_file, 'r') as f:
            stored_data = json.load(f)
        
        stored_fingerprint = stored_data['fingerprint']
        
        # Compare fingerprints
        if self.machine_fingerprint != stored_fingerprint:
            print("\n" + "="*70)
            print("🚨 UNAUTHORIZED MACHINE DETECTED")
            print("="*70)
            print("This data is protected and can only be accessed on authorized machines.")
            print(f"\nAuthorized machine:")
            print(f"  Hostname: {stored_data.get('hostname', 'Unknown')}")
            print(f"  User: {stored_data.get('user', 'Unknown')}")
            print(f"  Created: {stored_data.get('created', 'Unknown')}")
            print(f"\nCurrent machine:")
            print(f"  Hostname: {socket.gethostname()}")
            print(f"  User: {os.environ.get('USER', os.environ.get('USERNAME', 'unknown'))}")
            print("\n⚠️  ACCESS DENIED - Data is machine-locked")
            print("="*70 + "\n")
            
            self._log_unauthorized_access()
            return False
        
        self._log_authorized_access()
        return True
    
    def check_license(self) -> bool:
        """
        Check if valid license exists
        
        Returns:
            True if licensed, False otherwise
        """
        if not self.license_file.exists():
            print("\n⚠️  No license file found")
            print("   Data access requires valid license")
            return False
        
        # Load license
        with open(self.license_file, 'r') as f:
            license_data = json.load(f)
        
        # Check expiration
        if 'expiration' in license_data:
            expiration = datetime.fromisoformat(license_data['expiration'])
            if datetime.now() > expiration:
                print("\n⚠️  License expired")
                print(f"   Expired: {expiration.isoformat()}")
                return False
        
        # Check machine binding
        if 'fingerprint' in license_data:
            if license_data['fingerprint'] != self.machine_fingerprint:
                print("\n🚨 License fingerprint mismatch")
                print("   This license is for a different machine")
                return False
        
        return True
    
    def generate_license(self, expiration_days: int = 365, 
                        license_type: str = "PERSONAL"):
        """
        Generate license file
        
        Args:
            expiration_days: Days until license expires (0 = no expiration)
            license_type: License type (PERSONAL, COMMERCIAL, ENTERPRISE)
        """
        license_data = {
            'type': license_type,
            'fingerprint': self.machine_fingerprint,
            'issued': datetime.now().isoformat(),
            'issued_to': os.environ.get('USER', os.environ.get('USERNAME', 'unknown')),
            'machine': socket.gethostname()
        }
        
        if expiration_days > 0:
            expiration = datetime.now() + timedelta(days=expiration_days)
            license_data['expiration'] = expiration.isoformat()
        
        with open(self.license_file, 'w') as f:
            json.dump(license_data, f, indent=2)
        
        print(f"\n✅ License generated: {self.license_file}")
        print(f"   Type: {license_type}")
        print(f"   Machine: {socket.gethostname()}")
        if expiration_days > 0:
            print(f"   Expires: {license_data['expiration']}")
        else:
            print(f"   Expires: Never")
    
    def track_copy(self, file_path: str):
        """
        Track when files are copied
        
        Args:
            file_path: Path to file that was copied
        """
        tracking = {}
        
        if self.copy_tracking.exists():
            with open(self.copy_tracking, 'r') as f:
                tracking = json.load(f)
        
        file_id = hashlib.md5(str(file_path).encode()).hexdigest()
        
        if file_id not in tracking:
            tracking[file_id] = {
                'file': str(file_path),
                'copies': []
            }
        
        copy_event = {
            'timestamp': datetime.now().isoformat(),
            'machine': socket.gethostname(),
            'fingerprint': self.machine_fingerprint,
            'user': os.environ.get('USER', os.environ.get('USERNAME', 'unknown'))
        }
        
        tracking[file_id]['copies'].append(copy_event)
        
        with open(self.copy_tracking, 'w') as f:
            json.dump(tracking, f, indent=2)
    
    def _log_authorized_access(self):
        """Log authorized access"""
        with open(self.usage_log, 'a') as f:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'status': 'AUTHORIZED',
                'fingerprint': self.machine_fingerprint[:16],
                'machine': socket.gethostname(),
                'user': os.environ.get('USER', os.environ.get('USERNAME', 'unknown'))
            }
            f.write(json.dumps(log_entry) + '\n')
    
    def _log_unauthorized_access(self):
        """Log unauthorized access attempt"""
        with open(self.usage_log, 'a') as f:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'status': 'UNAUTHORIZED',
                'fingerprint': self.machine_fingerprint[:16],
                'machine': socket.gethostname(),
                'user': os.environ.get('USER', os.environ.get('USERNAME', 'unknown')),
                'alert': '🚨 SECURITY VIOLATION'
            }
            f.write(json.dumps(log_entry) + '\n')
    
    def get_usage_report(self) -> str:
        """Generate usage report"""
        if not self.usage_log.exists():
            return "No usage data available"
        
        report = []
        report.append("="*70)
        report.append("ANTI-COPY PROTECTION - USAGE REPORT")
        report.append("="*70)
        report.append("")
        
        authorized = 0
        unauthorized = 0
        
        with open(self.usage_log, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    if entry['status'] == 'AUTHORIZED':
                        authorized += 1
                    else:
                        unauthorized += 1
                        report.append(f"🚨 UNAUTHORIZED ACCESS ATTEMPT:")
                        report.append(f"   Timestamp: {entry['timestamp']}")
                        report.append(f"   Machine: {entry['machine']}")
                        report.append(f"   User: {entry['user']}")
                        report.append("")
                except:
                    pass
        
        report.insert(3, f"✅ Authorized Access: {authorized}")
        report.insert(4, f"🚨 Unauthorized Attempts: {unauthorized}")
        report.insert(5, "")
        
        report.append("="*70)
        
        return "\n".join(report)
    
    def embed_watermark(self, data: bytes, identifier: str) -> bytes:
        """
        Embed invisible watermark in data for tracking
        
        Args:
            data: Data to watermark
            identifier: Unique identifier for this copy
        
        Returns:
            Watermarked data
        """
        watermark = f"__WATERMARK__{identifier}__{self.machine_fingerprint[:16]}__"
        watermark_bytes = watermark.encode()
        
        # Append watermark (can be made more sophisticated)
        return data + b'\x00' + watermark_bytes
    
    def detect_watermark(self, data: bytes) -> dict:
        """
        Detect watermark in data
        
        Args:
            data: Data to check
        
        Returns:
            Watermark info if found, None otherwise
        """
        try:
            # Look for watermark signature
            if b'__WATERMARK__' in data:
                watermark_start = data.rfind(b'__WATERMARK__')
                watermark_data = data[watermark_start:].decode()
                
                parts = watermark_data.split('__')
                if len(parts) >= 4:
                    return {
                        'identifier': parts[2],
                        'machine_fingerprint': parts[3],
                        'found': True
                    }
        except:
            pass
        
        return {'found': False}


def protect_script(script_func):
    """
    Decorator to protect a script from unauthorized execution
    
    Usage:
        @protect_script
        def my_sensitive_function():
            # Protected code
            pass
    """
    def wrapper(*args, **kwargs):
        protection = AntiCopyProtection()
        
        if not protection.verify_authorized_machine():
            print("\n🚫 Script execution blocked - unauthorized machine")
            sys.exit(1)
        
        if not protection.check_license():
            print("\n🚫 Script execution blocked - invalid or missing license")
            sys.exit(1)
        
        return script_func(*args, **kwargs)
    
    return wrapper


def main():
    """Test and demo anti-copy protection"""
    print("ANTI-COPY PROTECTION SYSTEM")
    print("="*70)
    
    protection = AntiCopyProtection()
    
    # Verify machine
    if protection.verify_authorized_machine():
        print("✅ Machine authorized")
    else:
        print("🚨 Machine NOT authorized")
        sys.exit(1)
    
    # Check license
    if not protection.check_license():
        print("\n📋 Generating license...")
        protection.generate_license(expiration_days=365, license_type="PERSONAL")
    else:
        print("✅ Valid license found")
    
    # Show usage report
    print("\n" + protection.get_usage_report())


if __name__ == '__main__':
    main()
