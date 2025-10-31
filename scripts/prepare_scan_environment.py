#!/usr/bin/env python3
"""
Prepare Scan Environment Agent
Sets up environment and validates everything is ready for scanning
Runs while tools download to prepare the environment
"""

import sys
import os
from pathlib import Path
from datetime import datetime
import json

REPO_ROOT = Path(__file__).parent.parent
OUTPUT_DIR = REPO_ROOT / "output"
TARGETS_FILE = REPO_ROOT / "targets.txt"
TOOLS_BIN_DIR = REPO_ROOT / "tools" / "bin"

def log(message: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def check_directory(path: Path, description: str) -> bool:
    """Check and create directory if needed"""
    if not path.exists():
        path.mkdir(parents=True, exist_ok=True)
        log(f"✓ Created {description}: {path}")
        return True
    else:
        log(f"✓ {description} exists: {path}")
        return True

def check_targets_file() -> bool:
    """Check targets.txt"""
    if not TARGETS_FILE.exists():
        log(f"✗ targets.txt not found at {TARGETS_FILE}")
        return False
    
    with open(TARGETS_FILE, "r", encoding="utf-8") as f:
        targets = [line.strip() for line in f 
                  if line.strip() and not line.strip().startswith("#")]
    
    if not targets:
        log("✗ No valid targets in targets.txt")
        return False
    
    log(f"✓ Found {len(targets)} target(s) in targets.txt")
    return True

def check_tools_installation() -> Dict:
    """Check which tools are installed"""
    tools_status = {}
    required_tools = ["httpx", "nuclei", "subfinder", "amass", "dnsx"]
    
    log("Checking tools installation...")
    for tool in required_tools:
        # Check local tools
        local_tool = TOOLS_BIN_DIR / tool
        local_tool_exe = TOOLS_BIN_DIR / f"{tool}.exe"
        
        if local_tool.exists() or local_tool_exe.exists():
            tools_status[tool] = "local"
            log(f"  ✓ {tool}: Found in tools/bin/")
        else:
            # Check system PATH
            import shutil
            if shutil.which(tool):
                tools_status[tool] = "system"
                log(f"  ✓ {tool}: Found in system PATH")
            else:
                tools_status[tool] = "missing"
                log(f"  ✗ {tool}: Not found")
    
    return tools_status

def create_scan_config():
    """Create scan configuration file"""
    config = {
        "scan_started": datetime.now().isoformat(),
        "severity_filter": "medium,high,critical",
        "triage_min_severity": "medium",
        "rate_limits": {
            "nuclei": 50,
            "httpx": 100
        },
        "timeouts": {
            "nuclei_scan": 7200,
            "recon": 1800
        }
    }
    
    config_file = OUTPUT_DIR / "scan-config.json"
    with open(config_file, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    log(f"✓ Created scan configuration: {config_file}")

def main():
    """Main preparation function"""
    log("=== Scan Environment Preparation ===")
    log("Preparing environment while tools download...")
    log("")
    
    # Create directories
    log("Creating directories...")
    check_directory(OUTPUT_DIR, "Output directory")
    check_directory(OUTPUT_DIR / "reports", "Reports directory")
    check_directory(TOOLS_BIN_DIR, "Tools binary directory")
    log("")
    
    # Check targets
    log("Checking targets...")
    if not check_targets_file():
        log("⚠️  WARNING: No valid targets found!")
        log("   Add domains to targets.txt")
    log("")
    
    # Check tools
    tools_status = check_tools_installation()
    missing_tools = [tool for tool, status in tools_status.items() if status == "missing"]
    
    if missing_tools:
        log(f"⚠️  WARNING: {len(missing_tools)} tool(s) not installed: {', '.join(missing_tools)}")
        log("   Run: python3 setup_tools.py")
    else:
        log("✓ All tools are installed")
    log("")
    
    # Create config
    create_scan_config()
    log("")
    
    # Summary
    log("=== Environment Preparation Summary ===")
    log(f"Output directory: {OUTPUT_DIR}")
    log(f"Tools directory: {TOOLS_BIN_DIR}")
    
    ready_tools = sum(1 for status in tools_status.values() if status != "missing")
    log(f"Tools ready: {ready_tools}/{len(tools_status)}")
    
    if ready_tools == len(tools_status):
        log("")
        log("✓ Environment is ready for scanning!")
        log("   Run: python3 start_scan.py")
    else:
        log("")
        log("⚠️  Waiting for tools to finish downloading...")
        log("   Run this script again after tools are installed")
    
    log("")

if __name__ == "__main__":
    main()

