#!/usr/bin/env python3
"""
Copyright (c) 2025 YOUR_NAME_HERE
Proprietary and Confidential
All Rights Reserved

This software is proprietary and confidential.
Unauthorized copying, modification, or distribution is prohibited.

System ID: BB_20251102_5946
Owner: YOUR_NAME_HERE
"""

"""
Nuclei Templates Updater Agent
Updates Nuclei templates while tools download
Ensures we have the latest vulnerability detection templates
"""

import sys
import subprocess
import os
from pathlib import Path
from datetime import datetime

REPO_ROOT = Path(__file__).parent.parent
NUCLEI_TEMPLATES_DIR = REPO_ROOT / "nuclei-templates"
OUTPUT_DIR = REPO_ROOT / "output"

def log(message: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def check_nuclei_installed():
    """Check if nuclei is available (may not be yet)"""
    try:
        result = subprocess.run(
            ["which", "nuclei"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except:
        return False

def check_local_nuclei():
    """Check if local nuclei binary exists"""
    local_nuclei = REPO_ROOT / "tools" / "bin" / "nuclei"
    return local_nuclei.exists() and os.access(local_nuclei, os.X_OK)

def update_templates_via_nuclei(nuclei_path: str):
    """Update templates using nuclei command"""
    try:
        log(f"Updating templates using: {nuclei_path}")
        result = subprocess.run(
            [nuclei_path, "-update-templates", "-silent"],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode == 0:
            log("✓ Templates updated successfully")
            return True
        else:
            log(f"⚠️  Template update returned code {result.returncode}")
            if result.stderr:
                log(f"   Error: {result.stderr[:200]}")
            return False
    except subprocess.TimeoutExpired:
        log("⚠️  Template update timed out")
        return False
    except Exception as e:
        log(f"⚠️  Template update failed: {e}")
        return False

def clone_templates_repo():
    """Clone nuclei-templates repository as fallback"""
    try:
        if NUCLEI_TEMPLATES_DIR.exists():
            log("Nuclei templates directory exists, updating...")
            result = subprocess.run(
                ["git", "pull"],
                cwd=str(NUCLEI_TEMPLATES_DIR),
                capture_output=True,
                text=True,
                timeout=300
            )
            if result.returncode == 0:
                log("✓ Templates repository updated")
                return True
        else:
            log("Cloning nuclei-templates repository...")
            result = subprocess.run(
                ["git", "clone", "--depth", "1", 
                 "https://github.com/projectdiscovery/nuclei-templates.git",
                 str(NUCLEI_TEMPLATES_DIR)],
                capture_output=True,
                text=True,
                timeout=600
            )
            if result.returncode == 0:
                log("✓ Templates repository cloned")
                return True
    except subprocess.TimeoutExpired:
        log("⚠️  Git operation timed out")
        return False
    except FileNotFoundError:
        log("⚠️  Git not found, skipping repository clone")
        return False
    except Exception as e:
        log(f"⚠️  Git operation failed: {e}")
        return False
    
    return False

def count_templates():
    """Count available templates"""
    if not NUCLEI_TEMPLATES_DIR.exists():
        return 0
    
    yaml_files = list(NUCLEI_TEMPLATES_DIR.rglob("*.yaml")) + \
                 list(NUCLEI_TEMPLATES_DIR.rglob("*.yml"))
    return len(yaml_files)

def main():
    """Main update function"""
    log("=== Nuclei Templates Updater Agent Starting ===")
    log("Updating templates while tools download...")
    log("")
    
    # Check for nuclei binary
    nuclei_path = None
    
    if check_local_nuclei():
        nuclei_path = str(REPO_ROOT / "tools" / "bin" / "nuclei")
        log("✓ Found local nuclei binary")
    elif check_nuclei_installed():
        nuclei_path = "nuclei"
        log("✓ Found nuclei in PATH")
    else:
        log("⚠️  Nuclei not found yet (still downloading)")
        log("   Will clone templates repository as fallback")
        nuclei_path = None
    
    log("")
    
    # Try updating via nuclei if available
    if nuclei_path:
        log("Attempting to update via nuclei command...")
        if update_templates_via_nuclei(nuclei_path):
            template_count = count_templates()
            log(f"✓ {template_count} templates available")
            log("=== Templates Update Complete ===")
            return
    
    # Fallback: Clone/update repository
    log("")
    log("Updating templates repository...")
    if clone_templates_repo():
        template_count = count_templates()
        log(f"✓ {template_count} templates available")
    else:
        log("⚠️  Could not update templates")
        log("   Templates will be updated when nuclei is ready")
    
    log("")
    log("=== Templates Update Complete ===")
    log("Note: Templates will be auto-updated when nuclei scan runs")

if __name__ == "__main__":
    main()


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
