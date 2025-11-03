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
Web Mapper Agent - Windows Native
Uses httpx to probe alive hosts and fingerprint technologies
Input: output/subs.txt
Output: output/http.json
"""

import subprocess
import sys
import os
import json
from pathlib import Path
from datetime import datetime

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
SUBS_FILE = OUTPUT_DIR / "subs.txt"
HTTP_OUTPUT = OUTPUT_DIR / "http.json"
HTTP_TEMP = OUTPUT_DIR / "temp_httpx.json"

# Configuration
RATE_LIMIT = int(os.getenv("HTTPX_RATE_LIMIT", "100"))
TIMEOUT = int(os.getenv("HTTPX_TIMEOUT", "10"))
THREADS = int(os.getenv("HTTPX_THREADS", "50"))

def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_msg = f"[{timestamp}] {message}"
    print(log_msg)
    log_file = OUTPUT_DIR / "recon-run.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(log_msg + "\n")


def main():
    log("=== Web Mapper Agent Starting ===")
    
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Check tools (use local tools first)
    httpx_path = get_tool_path("httpx")
    
    if not check_tool("httpx") and httpx_path == "httpx":
        log("ERROR: httpx not found. Run: python setup_tools.py")
        sys.exit(1)
    
    # Check if subs.txt exists
    if not SUBS_FILE.exists():
        log(f"ERROR: subs.txt not found at {SUBS_FILE}")
        log("Please run recon scanner agent first (run_recon.py)")
        sys.exit(1)
    
    # Check if subs.txt has content
    if not SUBS_FILE.stat().st_size:
        log("WARNING: subs.txt is empty. No subdomains to probe.")
        HTTP_OUTPUT.write_text("[]", encoding="utf-8")
        return
    
    sub_count = len(SUBS_FILE.read_text(encoding="utf-8").strip().splitlines())
    log(f"Probing {sub_count} subdomains with httpx...")
    
    # Run httpx
    log(f"Running httpx (rate-limit: {RATE_LIMIT}, threads: {THREADS})...")
    try:
        result = subprocess.run(
            [
                httpx_path, "-l", str(SUBS_FILE),
                "-probe", "-tech-detect", "-status-code", "-title", "-json",
                "-silent", "-rate-limit", str(RATE_LIMIT),
                "-threads", str(THREADS), "-timeout", str(TIMEOUT),
                "-retries", "2", "-o", str(HTTP_TEMP)
            ],
            capture_output=True,
            text=True,
            check=False
        )
    except Exception as e:
        log(f"WARNING: httpx encountered errors: {e}")
    
    # Convert NDJSON to JSON array
    if not HTTP_TEMP.exists() or not HTTP_TEMP.stat().st_size:
        log("No results from httpx")
        HTTP_OUTPUT.write_text("[]", encoding="utf-8")
    else:
        # Read NDJSON and convert to array
        findings = []
        with open(HTTP_TEMP, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        
        # Write as JSON array
        with open(HTTP_OUTPUT, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2, ensure_ascii=False)
        
        if HTTP_TEMP.exists():
            HTTP_TEMP.unlink()
    
    # Count results and extract statistics
    if HTTP_OUTPUT.exists():
        try:
            with open(HTTP_OUTPUT, "r", encoding="utf-8") as f:
                data = json.load(f)
            http_count = len(data)
            if http_count > 0:
                https_count = sum(1 for item in data if item.get("url", "").startswith("https://"))
                status_200 = sum(1 for item in data if item.get("status-code") == 200)
                log(f"Found {http_count} alive HTTP/HTTPS endpoints")
                log(f"  - HTTPS: {https_count}")
                log(f"  - Status 200: {status_200}")
            else:
                log("No alive endpoints found")
        except:
            log("No valid results found")
    
    log("=== Web Mapper Agent Complete ===")
    log(f"Output: {HTTP_OUTPUT}")

if __name__ == "__main__":
    main()


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
