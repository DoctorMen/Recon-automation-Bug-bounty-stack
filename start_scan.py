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
Start Medium-to-High Severity Bug Bounty Scan
Runs the full pipeline with focus on medium+ severity findings
"""

import subprocess
import sys
import os
from pathlib import Path

# Set environment for medium+ severity focus
os.environ["NUCLEI_SEVERITY"] = "medium,high,critical"
os.environ["TRIAGE_MIN_SEVERITY"] = "medium"
os.environ["NUCLEI_RATE_LIMIT"] = "50"
os.environ["NUCLEI_SCAN_TIMEOUT"] = "7200"  # 2 hours

REPO_ROOT = Path(__file__).parent
TARGETS_FILE = REPO_ROOT / "targets.txt"
OUTPUT_DIR = REPO_ROOT / "output"

def log(message):
    print(f"[*] {message}")

def check_targets():
    """Check if targets.txt has valid targets"""
    if not TARGETS_FILE.exists():
        log("ERROR: targets.txt not found")
        return False
    
    with open(TARGETS_FILE, "r", encoding="utf-8") as f:
        targets = [line.strip() for line in f 
                  if line.strip() and not line.strip().startswith("#")]
    
    if not targets:
        log("ERROR: No valid targets found in targets.txt")
        log("Please add authorized domains to targets.txt")
        return False
    
    log(f"✓ Found {len(targets)} target(s): {', '.join(targets[:5])}" + 
        (f" ... and {len(targets)-5} more" if len(targets) > 5 else ""))
    return True

def run_script(script_name, description):
    """Run a Python script"""
    script_path = REPO_ROOT / script_name
    if not script_path.exists():
        log(f"WARNING: {script_name} not found, skipping {description}")
        return False
    
    log(f">>> Running {description}...")
    try:
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(REPO_ROOT),
            check=False,
            capture_output=False
        )
        if result.returncode == 0:
            log(f"✓ {description} completed")
            return True
        else:
            log(f"WARNING: {description} returned exit code {result.returncode}")
            return False
    except Exception as e:
        log(f"WARNING: {description} failed: {e}")
        return False

def main():
    print("=" * 60)
    print("Starting Bug Bounty Scan - Medium+ Severity Focus")
    print("=" * 60)
    print("")
    
    # Check targets
    if not check_targets():
        sys.exit(1)
    
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Step 1: Recon (if subs.txt doesn't exist or is empty)
    subs_file = OUTPUT_DIR / "subs.txt"
    if not subs_file.exists() or subs_file.stat().st_size == 0:
        log(">>> Step 1/5: Running Recon Scanner...")
        run_script("run_recon.py", "Recon Scanner")
        print("")
    else:
        log("✓ subs.txt exists, skipping recon")
        print("")
    
    # Step 2: HTTP Mapping (if http.json doesn't exist)
    http_file = OUTPUT_DIR / "http.json"
    if not http_file.exists() or http_file.stat().st_size == 0:
        log(">>> Step 2/5: Running Web Mapper (httpx)...")
        run_script("run_httpx.py", "Web Mapper")
        print("")
    else:
        log("✓ http.json exists, skipping httpx")
        print("")
    
    # Step 3: Vulnerability Scanning (Nuclei - Medium+ Only)
    log(">>> Step 3/5: Running Vulnerability Hunter (Nuclei - Medium+ Only)...")
    log("   Focus: medium, high, critical severity findings only")
    run_script("run_nuclei.py", "Vulnerability Hunter")
    print("")
    
    # Step 4: Triage
    log(">>> Step 4/5: Running Triage (Filtering Medium+ Findings)...")
    run_script("scripts/triage.py", "Triage")
    print("")
    
    # Step 5: Reports
    log(">>> Step 5/5: Generating Reports...")
    run_script("scripts/generate_report.py", "Report Generation")
    print("")
    
    print("=" * 60)
    print("Scan Complete!")
    print("=" * 60)
    print("")
    print("Results:")
    print(f"  - Findings: {OUTPUT_DIR / 'nuclei-findings.json'}")
    print(f"  - Triaged: {OUTPUT_DIR / 'triage.json'}")
    print(f"  - Reports: {OUTPUT_DIR / 'reports'}")
    print("")
    
    # Show summary if available
    summary_file = OUTPUT_DIR / "reports" / "summary.md"
    if summary_file.exists():
        print(f"View summary: {summary_file}")
        print("")

if __name__ == "__main__":
    main()


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
