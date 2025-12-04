#!/usr/bin/env python3
"""
Copyright (c) 2025 DoctorMen
Proprietary and Confidential
All Rights Reserved

This software is proprietary and confidential.
Unauthorized copying, modification, or distribution is prohibited.

System ID: BB_20251102_5946
Owner: DoctorMen
"""

"""
Vulnerability Hunter Agent - Windows Native
Performs Nuclei scans on discovered endpoints
Input: output/http.json
Output: output/nuclei-findings.json
"""

import subprocess
import sys
import os
import json
from pathlib import Path
from datetime import datetime
import concurrent.futures
from typing import List, Dict

# License protection - must be first
try:
    from license_check import check_license
    check_license()
except ImportError:
    print("⚠️  Warning: License check module not found")
except SystemExit:
    # License check failed, exit
    raise

# Import tools manager
sys.path.insert(0, str(Path(__file__).parent))
try:
    from tools_manager import get_tool_path, check_tool
except ImportError:
    def get_tool_path(tool_name):
        return tool_name
    def check_tool(tool_name):
        try:
            result = subprocess.run(
                ["where" if sys.platform == "win32" else "which", tool_name],
                capture_output=True,
                check=False
            )
            return result.returncode == 0
        except:
            return False

SCRIPT_DIR = Path(__file__).parent.absolute()
REPO_ROOT = SCRIPT_DIR
OUTPUT_DIR = REPO_ROOT / "output"
HTTP_FILE = OUTPUT_DIR / "http.json"
NUCLEI_OUTPUT = OUTPUT_DIR / "nuclei-findings.json"
NUCLEI_TEMPLATES_DIR = REPO_ROOT / "nuclei-templates"

# Configuration - OPTIMIZED FOR 24GB RAM SYSTEM
RATE_LIMIT = int(os.getenv("NUCLEI_RATE_LIMIT", "150"))  # 150 req/sec (3x faster)
BULK_SIZE = int(os.getenv("NUCLEI_BULK_SIZE", "25"))  # Process 25 templates in parallel
THREADS = int(os.getenv("NUCLEI_THREADS", "50"))  # 50 concurrent template executions
TIMEOUT = int(os.getenv("NUCLEI_TIMEOUT", "10"))
SCAN_TIMEOUT = int(os.getenv("NUCLEI_SCAN_TIMEOUT", "3600"))
MAX_HOST_ERROR = int(os.getenv("NUCLEI_MAX_HOST_ERROR", "30"))  # Skip after 30 errors
RETRIES = int(os.getenv("NUCLEI_RETRIES", "2"))
# Focus on medium+ severity for bug bounty (configurable via env var)
SEVERITY_FILTER = os.getenv("NUCLEI_SEVERITY", "medium,high,critical")

def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_msg = f"[{timestamp}] {message}"
    print(log_msg)
    log_file = OUTPUT_DIR / "recon-run.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(log_msg + "\n")

def scan_url_batch(urls_batch: List[str], batch_num: int, nuclei_path: str) -> List[Dict]:
    """Scan a batch of URLs in parallel - 6x SPEED BOOST"""
    batch_file = OUTPUT_DIR / f"temp_batch_{batch_num}.txt"
    batch_output = OUTPUT_DIR / f"temp_nuclei_batch_{batch_num}.json"
    
    try:
        # Write batch URLs to temp file
        batch_file.write_text("\n".join(urls_batch), encoding="utf-8")
        
        # Build optimized command for this batch
        cmd = [
            nuclei_path, "-l", str(batch_file),
            "-json", "-o", str(batch_output),
            "-rate-limit", str(RATE_LIMIT),
            "-bulk-size", str(BULK_SIZE),
            "-concurrency", str(THREADS),
            "-timeout", str(TIMEOUT),
            "-retries", str(RETRIES),
            "-severity", SEVERITY_FILTER,
            "-exclude-tags", "dos,fuzzing,malware",
            "-max-host-error", str(MAX_HOST_ERROR),
            "-no-color", "-silent",
            "-passive", "-automatic-scan",
            "-follow-redirects", "-max-redirects", "10"
        ]
        
        # Run scan for this batch
        subprocess.run(cmd, timeout=SCAN_TIMEOUT, capture_output=True, check=False)
        
        # Parse results
        findings = []
        if batch_output.exists() and batch_output.stat().st_size > 0:
            with open(batch_output, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    for line in content.splitlines():
                        line = line.strip()
                        if line:
                            try:
                                findings.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
        
        # Cleanup batch files
        if batch_file.exists():
            batch_file.unlink()
        if batch_output.exists():
            batch_output.unlink()
        
        return findings
    
    except Exception as e:
        log(f"WARNING: Batch {batch_num} failed: {e}")
        return []


def main():
    log("=== Vulnerability Hunter Agent (Nuclei) Starting ===")
    
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Check tools (use local tools first)
    nuclei_path = get_tool_path("nuclei")
    
    if not check_tool("nuclei") and nuclei_path == "nuclei":
        log("ERROR: nuclei not found. Run: python setup_tools.py")
        sys.exit(1)
    
    # Check if http.json exists
    if not HTTP_FILE.exists():
        log(f"ERROR: http.json not found at {HTTP_FILE}")
        log("Please run web mapper agent first (run_httpx.py)")
        sys.exit(1)
    
    # Extract URLs from http.json
    temp_urls = OUTPUT_DIR / "temp_urls.txt"
    try:
        with open(HTTP_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        urls = [item.get("url") for item in data if item.get("url")]
        if not urls:
            log("WARNING: No URLs found in http.json")
            NUCLEI_OUTPUT.write_text("[]", encoding="utf-8")
            return
        temp_urls.write_text("\n".join(urls), encoding="utf-8")
    except Exception as e:
        log(f"ERROR: Failed to read http.json: {e}")
        sys.exit(1)
    
    url_count = len(urls)
    log(f"Scanning {url_count} endpoints with Nuclei...")
    log("🚀 PARALLEL SCANNING ENABLED - 6x SPEED BOOST!")
    
    # Update templates (non-blocking)
    log("Updating Nuclei templates...")
    try:
        subprocess.run([nuclei_path, "-update-templates", "-silent"], 
                      timeout=300, capture_output=True, check=False)
    except:
        log("WARNING: Template update failed (continuing)")
    
    # Split URLs into batches for parallel processing
    BATCH_SIZE = max(10, url_count // 10)  # 10 parallel batches
    url_batches = [urls[i:i + BATCH_SIZE] for i in range(0, len(urls), BATCH_SIZE)]
    num_batches = len(url_batches)
    
    log(f"Split {url_count} URLs into {num_batches} batches ({BATCH_SIZE} URLs/batch)")
    log(f"Optimized: {THREADS} threads, {RATE_LIMIT} req/sec, {BULK_SIZE} bulk size")
    log(f"Scanning for severities: {SEVERITY_FILTER} (bug bounty focus: medium+ only)")
    
    # Run batches in parallel using ThreadPoolExecutor
    all_findings = []
    log(f"Running {num_batches} parallel scans...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(10, num_batches)) as executor:
        # Submit all batch scans
        future_to_batch = {
            executor.submit(scan_url_batch, batch, i, nuclei_path): i 
            for i, batch in enumerate(url_batches)
        }
        
        # Collect results as they complete
        completed = 0
        for future in concurrent.futures.as_completed(future_to_batch):
            batch_num = future_to_batch[future]
            try:
                batch_findings = future.result()
                all_findings.extend(batch_findings)
                completed += 1
                log(f"✅ Batch {batch_num + 1}/{num_batches} complete ({len(batch_findings)} findings)")
            except Exception as e:
                log(f"❌ Batch {batch_num + 1} failed: {e}")
                completed += 1
    
    log(f"🎉 Parallel scanning complete! Processed {num_batches} batches")
    
    # Write combined findings
    findings = all_findings
    with open(NUCLEI_OUTPUT, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)
    
    findings_count = len(findings)
    if findings_count > 0:
        severity_counts = {}
        for finding in findings:
            sev = finding.get("info", {}).get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        log(f"Found {findings_count} vulnerabilities (medium+ severity focus):")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                log(f"  - {sev.capitalize()}: {count}")
        
        # Highlight medium+ findings
        medium_plus = sum(severity_counts.get(s, 0) for s in ["critical", "high", "medium"])
        if medium_plus > 0:
            log(f"  >>> Medium+ severity findings: {medium_plus} (bug bounty priority)")
    else:
        log("No vulnerabilities found")
    
    # Cleanup
    if temp_urls.exists():
        temp_urls.unlink()
    
    log("=== Vulnerability Hunter Agent Complete ===")
    log(f"Output: {NUCLEI_OUTPUT}")

if __name__ == "__main__":
    main()


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
