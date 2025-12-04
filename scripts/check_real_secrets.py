#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Check for ACTUAL secrets in discovery files
Looks for API keys, tokens, passwords, credentials
"""

import re
import json
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
OUTPUT_DIR = REPO_ROOT / "output"

# Patterns for actual secrets
SECRET_PATTERNS = [
    r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'(?i)(secret[_-]?key|secretkey)\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'(?i)(token|bearer)\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'(?i)(password|pwd)\s*[=:]\s*["\']?([^\s"\'<>]{8,})["\']?',
    r'(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[=:]\s*["\']?([A-Z0-9]{20})["\']?',
    r'(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
    r'(?i)(github[_-]?token|gh[_-]?token)\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
    r'(?i)(private[_-]?key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40,})["\']?',
    r'(?i)(mongodb[_-]?uri|connection[_-]?string)\s*[=:]\s*["\']?(mongodb[^\s"\'<>]+)["\']?',
    r'(?i)(rsk_[a-zA-Z0-9]{50,})',  # Rapyd secret key format
    r'(?i)(access[_-]?key[_-]?id)\s*[=:]\s*["\']?([A-Z0-9]{20})["\']?',
]

def check_secrets():
    """Check for actual secrets in files"""
    
    print("=" * 60)
    print("Checking for ACTUAL Secrets")
    print("=" * 60)
    print()
    
    files_to_check = [
        OUTPUT_DIR / "potential-secrets.txt",
        OUTPUT_DIR / "functions.txt",
        OUTPUT_DIR / "endpoints.txt",
    ]
    
    # Also check JSON files
    json_files = [
        OUTPUT_DIR / "http.json",
        OUTPUT_DIR / "immediate_roi" / "api_endpoints.json",
    ]
    
    found_secrets = []
    
    print("[*] Checking text files...")
    for file_path in files_to_check:
        if not file_path.exists():
            continue
        
        print(f"[*] Checking: {file_path.name}")
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                for pattern in SECRET_PATTERNS:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        secret_type = match.group(1) if match.groups() else "Unknown"
                        secret_value = match.group(2) if len(match.groups()) > 1 else match.group(0)
                        
                        # Mask secret value
                        if len(secret_value) > 20:
                            masked = secret_value[:10] + "..." + secret_value[-5:]
                        else:
                            masked = secret_value[:5] + "..."
                        
                        found_secrets.append({
                            "file": file_path.name,
                            "type": secret_type,
                            "value": masked,
                            "line": content[:match.start()].count('\n') + 1
                        })
        except Exception as e:
            print(f"  Warning: {e}")
    
    print()
    print("[*] Checking JSON files...")
    for file_path in json_files:
        if not file_path.exists():
            continue
        
        print(f"[*] Checking: {file_path.name}")
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
                # Try NDJSON
                for line_num, line in enumerate(content.split('\n'), 1):
                    if not line.strip():
                        continue
                    
                    for pattern in SECRET_PATTERNS:
                        matches = re.finditer(pattern, line)
                        for match in matches:
                            secret_type = match.group(1) if match.groups() else "Unknown"
                            secret_value = match.group(2) if len(match.groups()) > 1 else match.group(0)
                            
                            if len(secret_value) > 20:
                                masked = secret_value[:10] + "..." + secret_value[-5:]
                            else:
                                masked = secret_value[:5] + "..."
                            
                            found_secrets.append({
                                "file": file_path.name,
                                "type": secret_type,
                                "value": masked,
                                "line": line_num
                            })
        except Exception as e:
            print(f"  Warning: {e}")
    
    print()
    print("=" * 60)
    
    if found_secrets:
        print(f"⚠️  Found {len(found_secrets)} potential secrets!")
        print()
        print("Top findings:")
        for idx, secret in enumerate(found_secrets[:10], 1):
            print(f"{idx}. Type: {secret['type']}")
            print(f"   File: {secret['file']} (line {secret['line']})")
            print(f"   Value: {secret['value']}")
            print()
        
        print("=" * 60)
        print("⚠️  IMPORTANT: Verify these are REAL secrets before submitting")
        print("   Many false positives can occur")
        print("   Only submit if you can verify the secret is exposed")
        print("=" * 60)
    else:
        print("✅ No obvious secrets found")
        print()
        print("This is normal - most sites don't expose secrets")
        print()
        print("=" * 60)
        print("RECOMMENDATION: Focus on Manual Testing")
        print("=" * 60)
        print()
        print("Since no secrets found, focus on:")
        print("1. Rapyd IDOR testing (highest value)")
        print("2. Authentication bypass")
        print("3. Business logic flaws")
        print()
        print("Run: python3 scripts/generate_rapyd_endpoints.py")
        print("=" * 60)
    
    return found_secrets

if __name__ == "__main__":
    check_secrets()








