#!/usr/bin/env python3
"""
Security Checks Script
Runs daily security and compliance checks for the recon automation system
"""

import os
import sys
import json
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

# Colors for terminal output
class Colors:
    GREEN = '\033[0;32m'
    RED = '\033[0;31m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color

def log(message, color=Colors.GREEN):
    """Print colored log message"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"{color}[{timestamp}]{Colors.NC} {message}")

def check_authorization_files():
    """Check for expired or expiring authorization files"""
    log("Checking authorization files...", Colors.BLUE)
    
    auth_dir = Path("authorizations")
    if not auth_dir.exists():
        log("No authorizations directory found", Colors.YELLOW)
        return
    
    expired = []
    expiring_soon = []
    valid = []
    
    for auth_file in auth_dir.glob("*.json"):
        try:
            with open(auth_file, 'r') as f:
                auth_data = json.load(f)
            
            end_date_str = auth_data.get('end_date', '')
            if end_date_str:
                end_date = datetime.fromisoformat(end_date_str.replace('Z', '+00:00'))
                now = datetime.now(end_date.tzinfo) if end_date.tzinfo else datetime.now()
                
                if end_date < now:
                    expired.append(auth_file.name)
                elif end_date < now + timedelta(days=7):
                    expiring_soon.append((auth_file.name, end_date))
                else:
                    valid.append(auth_file.name)
        except Exception as e:
            log(f"Error reading {auth_file.name}: {e}", Colors.RED)
    
    if expired:
        log(f"⚠️  EXPIRED authorizations: {len(expired)}", Colors.RED)
        for auth in expired:
            log(f"  - {auth}", Colors.RED)
    
    if expiring_soon:
        log(f"⚠️  Expiring soon (< 7 days): {len(expiring_soon)}", Colors.YELLOW)
        for auth, end_date in expiring_soon:
            days_left = (end_date - datetime.now(end_date.tzinfo)).days
            log(f"  - {auth} ({days_left} days left)", Colors.YELLOW)
    
    log(f"✓ Valid authorizations: {len(valid)}", Colors.GREEN)

def check_file_permissions():
    """Check for sensitive files with incorrect permissions"""
    log("Checking file permissions...", Colors.BLUE)
    
    sensitive_files = [
        "config/upwork_config.json",
        "authorizations/",
        ".env",
        "config/"
    ]
    
    issues = []
    
    for file_path in sensitive_files:
        path = Path(file_path)
        if path.exists():
            stat_info = path.stat()
            mode = oct(stat_info.st_mode)[-3:]
            
            # Check if file is world-readable (last digit > 0)
            if int(mode[-1]) > 0:
                issues.append(f"{file_path} is world-readable (mode: {mode})")
    
    if issues:
        log(f"⚠️  Permission issues found:", Colors.YELLOW)
        for issue in issues:
            log(f"  - {issue}", Colors.YELLOW)
    else:
        log("✓ File permissions OK", Colors.GREEN)

def check_git_secrets():
    """Check for potential secrets in Git history"""
    log("Checking for exposed secrets...", Colors.BLUE)
    
    # Patterns that might indicate secrets
    secret_patterns = [
        "password",
        "api_key",
        "secret",
        "token",
        "private_key"
    ]
    
    try:
        # Check staged files
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True,
            text=True,
            check=False
        )
        
        if result.returncode == 0 and result.stdout.strip():
            staged_files = result.stdout.strip().split('\n')
            
            for file in staged_files:
                if any(pattern in file.lower() for pattern in secret_patterns):
                    log(f"⚠️  Potential secret in staged file: {file}", Colors.YELLOW)
        
        log("✓ No obvious secrets detected", Colors.GREEN)
    except Exception as e:
        log(f"Could not check Git secrets: {e}", Colors.YELLOW)

def check_disk_space():
    """Check available disk space"""
    log("Checking disk space...", Colors.BLUE)
    
    try:
        result = subprocess.run(
            ["df", "-h", "/"],
            capture_output=True,
            text=True,
            check=True
        )
        
        lines = result.stdout.strip().split('\n')
        if len(lines) > 1:
            parts = lines[1].split()
            usage = parts[4].replace('%', '')
            
            if int(usage) > 90:
                log(f"⚠️  Disk usage critical: {usage}%", Colors.RED)
            elif int(usage) > 80:
                log(f"⚠️  Disk usage high: {usage}%", Colors.YELLOW)
            else:
                log(f"✓ Disk usage OK: {usage}%", Colors.GREEN)
    except Exception as e:
        log(f"Could not check disk space: {e}", Colors.YELLOW)

def check_output_directory():
    """Check output directory for old files"""
    log("Checking output directory...", Colors.BLUE)
    
    output_dir = Path("output")
    if not output_dir.exists():
        log("No output directory found", Colors.YELLOW)
        return
    
    # Count files older than 90 days
    old_threshold = datetime.now() - timedelta(days=90)
    old_files = []
    
    for file in output_dir.rglob("*"):
        if file.is_file():
            mtime = datetime.fromtimestamp(file.stat().st_mtime)
            if mtime < old_threshold:
                old_files.append(file)
    
    if old_files:
        total_size = sum(f.stat().st_size for f in old_files) / (1024 * 1024)  # MB
        log(f"ℹ️  Found {len(old_files)} files older than 90 days ({total_size:.2f} MB)", Colors.BLUE)
        log(f"   Consider running cleanup: find output/ -mtime +90 -delete", Colors.BLUE)
    else:
        log("✓ No old files in output directory", Colors.GREEN)

def check_python_dependencies():
    """Check for known vulnerabilities in Python dependencies"""
    log("Checking Python dependencies...", Colors.BLUE)
    
    try:
        # Check if pip-audit is installed
        result = subprocess.run(
            ["pip", "show", "pip-audit"],
            capture_output=True,
            check=False
        )
        
        if result.returncode != 0:
            log("ℹ️  Install pip-audit for vulnerability scanning: pip install pip-audit", Colors.BLUE)
        else:
            # Run pip-audit
            result = subprocess.run(
                ["pip-audit", "--format", "json"],
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode == 0:
                log("✓ No known vulnerabilities in dependencies", Colors.GREEN)
            else:
                log("⚠️  Vulnerabilities found in dependencies", Colors.YELLOW)
                log("   Run: pip-audit for details", Colors.YELLOW)
    except Exception as e:
        log(f"Could not check dependencies: {e}", Colors.YELLOW)

def check_tool_versions():
    """Check if security tools are up to date"""
    log("Checking tool versions...", Colors.BLUE)
    
    tools = {
        "subfinder": ["subfinder", "-version"],
        "nuclei": ["nuclei", "-version"],
        "httpx": ["httpx", "-version"],
    }
    
    for tool_name, cmd in tools.items():
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=5
            )
            
            if result.returncode == 0:
                version = result.stdout.strip().split('\n')[0]
                log(f"  {tool_name}: {version}", Colors.GREEN)
            else:
                log(f"  {tool_name}: Not installed", Colors.YELLOW)
        except Exception as e:
            log(f"  {tool_name}: Error checking version", Colors.YELLOW)

def main():
    """Run all security checks"""
    print(f"\n{Colors.BLUE}{'='*60}{Colors.NC}")
    print(f"{Colors.BLUE}Security Checks - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.NC}")
    print(f"{Colors.BLUE}{'='*60}{Colors.NC}\n")
    
    # Change to project directory
    project_dir = Path(__file__).parent.parent
    os.chdir(project_dir)
    
    # Run all checks
    check_authorization_files()
    print()
    
    check_file_permissions()
    print()
    
    check_git_secrets()
    print()
    
    check_disk_space()
    print()
    
    check_output_directory()
    print()
    
    check_python_dependencies()
    print()
    
    check_tool_versions()
    print()
    
    print(f"{Colors.GREEN}{'='*60}{Colors.NC}")
    print(f"{Colors.GREEN}Security checks completed{Colors.NC}")
    print(f"{Colors.GREEN}{'='*60}{Colors.NC}\n")

if __name__ == "__main__":
    main()
