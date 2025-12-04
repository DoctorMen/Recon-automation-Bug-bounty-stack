"""
IP Guardian - Embedded Intellectual Property Protection System

Copyright © 2025 Khallid H Nurse. All Rights Reserved.

This module provides embedded intellectual property protection that travels with your code.
"""
import hashlib
import inspect
import os
import platform
import socket
import sys
from datetime import datetime
from pathlib import Path

class IPGuardian:
    """
    Embedded IP Protection System that travels with your code.
    
    This class provides multiple layers of protection:
    1. Code fingerprinting
    2. Environment validation
    3. Dynamic watermarking
    4. License validation
    """
    
    def __init__(self, app_name="ReconAutomation"):
        self.app_name = app_name
        self.owner = "Khallid H Nurse"
        self.copyright_year = 2025
        self.license_key = None
        self.fingerprint = self._generate_fingerprint()
        
    def _generate_fingerprint(self):
        """Generate a unique fingerprint for this installation."""
        system_info = {
            'node': platform.node(),
            'system': platform.system(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'hostname': socket.gethostname(),
            'username': os.getenv('USER', os.getenv('USERNAME', 'unknown')),
            'cwd': os.getcwd(),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        fingerprint_data = "".join(f"{k}:{v}" for k, v in system_info.items())
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()
    
    def embed_watermark(self, content):
        """Embed an invisible watermark in the output."""
        watermark = f"\n"
        watermark += f"""
<!-- 
PROPRIETARY AND CONFIDENTIAL
Copyright © {self.copyright_year} {self.owner}
Fingerprint: {self.fingerprint[:16]}...
Generated: {datetime.utcnow().isoformat()}
-->
"""
        if isinstance(content, str):
            return content + watermark
        elif isinstance(content, bytes):
            return content + watermark.encode()
        return content
    
    def validate_environment(self):
        """Check if the execution environment is authorized."""
        # Basic environment checks
        if not os.environ.get('AUTHORIZED_ENV'):
            print("WARNING: Running in unauthorized environment", file=sys.stderr)
            
        # Check for common debugging tools
        debuggers = ['pydevd', 'pydev', 'pdb', 'ipdb', 'pudb']
        for module in sys.modules:
            if any(debugger in module.lower() for debugger in debuggers):
                print(f"WARNING: Debugger detected: {module}", file=sys.stderr)
    
    def get_copyright_notice(self):
        """Generate a dynamic copyright notice."""
        return f"""
"""
PROPRIETARY AND CONFIDENTIAL

{self.app_name} - Copyright © {self.copyright_year} {self.owner}

This software contains confidential and proprietary information of {self.owner}
and is protected by copyright and other intellectual property laws. Unauthorized
use, disclosure, reproduction, or distribution is strictly prohibited.

Fingerprint: {self.fingerprint}
Generated: {datetime.utcnow().isoformat()}
"""
"""
    
    @classmethod
    def protect_function(cls, func):
        """Decorator to protect functions with IP validation."""
        def wrapper(*args, **kwargs):
            self = cls()
            self.validate_environment()
            return func(*args, **kwargs)
        return wrapper

# Singleton instance for easy import
ip_guardian = IPGuardian()

# Self-protection: Add copyright notice to this file
with open(__file__, 'r+', encoding='utf-8') as f:
    content = f.read()
    if "Copyright ©" not in content:
        f.seek(0, 0)
        f.write(ip_guardian.get_copyright_notice().strip() + "\n\n" + content)
