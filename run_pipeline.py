#!/usr/bin/env python3
"""
Main Pipeline Orchestrator - Windows Native
Runs all agents in sequence: Recon → Mapper → Hunter → Triage → Report
"""

import sys
import os
import json
from pathlib import Path
from datetime import datetime

REPO_ROOT = Path(__file__).parent
OUTPUT_DIR = REPO_ROOT / "output"
STATUS_FILE = OUTPUT_DIR / ".pipeline_status"
RESUME = os.getenv("RESUME", "false").lower() == "true"

def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_msg = f"[{timestamp}] {message}"
    print(log_msg)
    log_file = OUTPUT_DIR / "recon-run.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(log_msg + "\n")

def mark_stage_complete(stage):
    STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATUS_FILE, "a", encoding="utf-8") as f:
        f.write(f"{stage}\n")

def is_stage_complete(stage):
    if not STATUS_FILE.exists():
        return False
    with open(STATUS_FILE, "r", encoding="utf-8") as f:
        return stage in [line.strip() for line in f]

def run_agent(script_name, stage_name):
    script_path = REPO_ROOT / script_name
    if not script_path.exists():
        log(f"ERROR: {script_name} not found")
        return False
    
    import subprocess
    try:
        result = subprocess.run(
            [sys.executable, str(script_path)],
            check=True,
            capture_output=False
        )
        return True
    except subprocess.CalledProcessError as e:
        log(f"ERROR: {stage_name} failed with exit code {e.returncode}")
        return False
    except Exception as e:
        log(f"ERROR: {stage_name} failed: {e}")
        return False

def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    log("=" * 60)
    log("Recon Stack Pipeline - Full Run")
    log("=" * 60)
    start_time = datetime.now()
    
    # Check targets.txt
    targets_file = REPO_ROOT / "targets.txt"
    if not targets_file.exists():
        log("ERROR: targets.txt not found")
        log("Please create targets.txt with authorized domains (one per line)")
        sys.exit(1)
    
    # Verify targets.txt has content
    with open(targets_file, "r", encoding="utf-8") as f:
        targets = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    
    if not targets:
        log("ERROR: No valid targets found in targets.txt")
        sys.exit(1)
    
    # Agent 1: Recon Scanner
    log("")
    log(">>> Starting Agent 1: Recon Scanner")
    if RESUME and is_stage_complete("recon"):
        log("Skipping recon (already complete, use RESUME=false to rerun)")
    else:
        if run_agent("run_recon.py", "Recon Scanner"):
            mark_stage_complete("recon")
        else:
            log("ERROR: Recon scanner failed")
            sys.exit(1)
    
    # Agent 2: Web Mapper
    log("")
    log(">>> Starting Agent 2: Web Mapper")
    if RESUME and is_stage_complete("httpx"):
        log("Skipping httpx (already complete)")
    else:
        if run_agent("run_httpx.py", "Web Mapper"):
            mark_stage_complete("httpx")
        else:
            log("WARNING: Web mapper failed (continuing)")
    
    # Agent 3: Vulnerability Hunter
    log("")
    log(">>> Starting Agent 3: Vulnerability Hunter")
    if RESUME and is_stage_complete("nuclei"):
        log("Skipping nuclei (already complete)")
    else:
        if run_agent("run_nuclei.py", "Vulnerability Hunter"):
            mark_stage_complete("nuclei")
        else:
            log("WARNING: Vulnerability hunter failed (continuing)")
    
    # Agent 4: Triage
    log("")
    log(">>> Starting Agent 4: Triage")
    if RESUME and is_stage_complete("triage"):
        log("Skipping triage (already complete)")
    else:
        if run_agent("scripts/triage.py", "Triage"):
            mark_stage_complete("triage")
        else:
            log("WARNING: Triage failed (continuing)")
    
    # Agent 5: Report Writer
    log("")
    log(">>> Starting Agent 5: Report Writer")
    if RESUME and is_stage_complete("reports"):
        log("Skipping reports (already complete)")
    else:
        if run_agent("scripts/generate_report.py", "Report Writer"):
            mark_stage_complete("reports")
        else:
            log("WARNING: Report generation failed (continuing)")
    
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    minutes = int(duration // 60)
    seconds = int(duration % 60)
    
    log("")
    log("=" * 60)
    log("Pipeline Complete!")
    log("=" * 60)
    log(f"Execution Time: {minutes}m {seconds}s")
    log("")
    
    # Generate statistics
    log("=== Statistics ===")
    if (OUTPUT_DIR / "subs.txt").exists():
        sub_count = len((OUTPUT_DIR / "subs.txt").read_text(encoding="utf-8").strip().splitlines())
        log(f"Subdomains Discovered: {sub_count}")
    
    if (OUTPUT_DIR / "http.json").exists():
        try:
            with open(OUTPUT_DIR / "http.json", "r", encoding="utf-8") as f:
                data = json.load(f)
            log(f"HTTP Endpoints: {len(data)}")
        except:
            pass
    
    if (OUTPUT_DIR / "nuclei-findings.json").exists():
        try:
            with open(OUTPUT_DIR / "nuclei-findings.json", "r", encoding="utf-8") as f:
                data = json.load(f)
            log(f"Raw Findings: {len(data)}")
        except:
            pass
    
    if (OUTPUT_DIR / "triage.json").exists():
        try:
            with open(OUTPUT_DIR / "triage.json", "r", encoding="utf-8") as f:
                data = json.load(f)
            triage_count = len(data)
            critical = sum(1 for f in data if f.get("info", {}).get("severity") == "critical")
            high = sum(1 for f in data if f.get("info", {}).get("severity") == "high")
            log(f"Triaged Findings: {triage_count}")
            log(f"  - Critical: {critical}")
            log(f"  - High: {high}")
        except:
            pass
    
    if (OUTPUT_DIR / "reports").exists():
        report_files = list((OUTPUT_DIR / "reports").glob("*.md"))
        log(f"Reports Generated: {len(report_files)}")
    
    log("")
    log("=== Output Files ===")
    log(f"  - Subdomains: {OUTPUT_DIR / 'subs.txt'}")
    log(f"  - HTTP Endpoints: {OUTPUT_DIR / 'http.json'}")
    log(f"  - Nuclei Findings: {OUTPUT_DIR / 'nuclei-findings.json'}")
    log(f"  - Triaged Findings: {OUTPUT_DIR / 'triage.json'}")
    log(f"  - Reports: {OUTPUT_DIR / 'reports'}")
    log("")
    log(f"View summary report: {OUTPUT_DIR / 'reports' / 'summary.md'}")
    log("")
    log("To rerun from start: RESUME=false python run_pipeline.py")
    log("")

if __name__ == "__main__":
    main()

