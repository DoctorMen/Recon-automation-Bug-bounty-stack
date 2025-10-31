#!/usr/bin/env python3
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

# Configuration
RATE_LIMIT = int(os.getenv("NUCLEI_RATE_LIMIT", "50"))
BULK_SIZE = int(os.getenv("NUCLEI_BULK_SIZE", "25"))
TIMEOUT = int(os.getenv("NUCLEI_TIMEOUT", "10"))
SCAN_TIMEOUT = int(os.getenv("NUCLEI_SCAN_TIMEOUT", "3600"))
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
    
    # Update templates (non-blocking)
    log("Updating Nuclei templates...")
    try:
        subprocess.run([nuclei_path, "-update-templates", "-silent"], 
                      timeout=300, capture_output=True, check=False)
    except:
        log("WARNING: Template update failed (continuing)")
    
    # Build command
    cmd = [
        nuclei_path, "-l", str(temp_urls),
        "-json", "-o", str(NUCLEI_OUTPUT),
        "-rate-limit", str(RATE_LIMIT),
        "-bulk-size", str(BULK_SIZE),
        "-timeout", str(TIMEOUT),
        "-retries", "1",
        "-severity", SEVERITY_FILTER,
        "-exclude-tags", "dos,fuzzing,malware",
        "-no-color", "-silent"
    ]
    
    log(f"Scanning for severities: {SEVERITY_FILTER} (bug bounty focus: medium+ only)")
    
    # Add custom templates if available
    if NUCLEI_TEMPLATES_DIR.exists():
        template_files = list(NUCLEI_TEMPLATES_DIR.glob("*.yaml")) + \
                        list(NUCLEI_TEMPLATES_DIR.glob("*.yml"))
        if template_files:
            template_count = len(template_files)
            log(f"Including {template_count} custom templates")
            cmd.extend(["-t", str(NUCLEI_TEMPLATES_DIR)])
    
    # Run nuclei
    log(f"Running Nuclei scan (this may take a while, timeout: {SCAN_TIMEOUT}s)...")
    try:
        result = subprocess.run(
            cmd,
            timeout=SCAN_TIMEOUT,
            capture_output=True,
            text=True,
            check=False
        )
    except subprocess.TimeoutExpired:
        log(f"WARNING: Nuclei scan timed out after {SCAN_TIMEOUT}s (checking for partial output)")
    except Exception as e:
        log(f"WARNING: Nuclei encountered errors: {e}")
    
    # Process output (convert NDJSON to array)
    nuclei_temp = OUTPUT_DIR / "temp_nuclei.json"
    if not NUCLEI_OUTPUT.exists() or not NUCLEI_OUTPUT.stat().st_size:
        log("No findings generated by Nuclei")
        NUCLEI_OUTPUT.write_text("[]", encoding="utf-8")
    else:
        log("Processing Nuclei output (NDJSON to JSON array)...")
        findings = []
        try:
            with open(NUCLEI_OUTPUT, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    # Try as array first
                    try:
                        data = json.loads(content)
                        if isinstance(data, list):
                            findings = data
                        else:
                            findings = [data]
                    except json.JSONDecodeError:
                        # Parse as NDJSON
                        for line in content.splitlines():
                            line = line.strip()
                            if line:
                                try:
                                    findings.append(json.loads(line))
                                except json.JSONDecodeError:
                                    continue
        except Exception as e:
            log(f"WARNING: Failed to parse Nuclei output: {e}")
            findings = []
        
        # Write as JSON array
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
    if nuclei_temp.exists():
        nuclei_temp.unlink()
    
    log("=== Vulnerability Hunter Agent Complete ===")
    log(f"Output: {NUCLEI_OUTPUT}")

if __name__ == "__main__":
    main()

