#!/usr/bin/env python3
"""
Performance Loop Updater
Updates programs.json with recent activity and dup rates after each batch.
Feeds results back into the target scorer to continuously optimize EV.

Usage:
1. After each batch of testing, create batch_results.json with findings.
2. Run: python3 performance_loop_updater.py
3. programs.json will be updated with latest activity and dup rates.
"""

import json
import sys
from pathlib import Path
from datetime import datetime, timedelta

def load_programs(path):
    """Load programs from JSON."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[!] Error loading programs.json: {e}")
        sys.exit(1)

def load_batch_results(path):
    """Load batch results from JSON."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[!] Error loading batch_results.json: {e}")
        sys.exit(1)

def update_program_activity(programs, batch_results):
    """
    Update program entries with recent activity and dup rates.
    Expected batch_results format:
    {
        "program": "Program Name",
        "reports_submitted": 3,
        "valid_reports": 1,
        "duplicate_reports": 2,
        "not_applicable": 0,
        "bounties_paid": [
            {"amount": 500, "paid_date": "2025-11-10"},
            {"amount": 800, "paid_date": "2025-11-05"}
        ],
        "notes": "Optional notes about this batch"
    }
    """
    prog_name = batch_results.get("program")
    if not prog_name:
        print("[!] No program name in batch_results.json")
        return

    # Find the program in programs list
    prog_entry = None
    for p in programs:
        if p.get("name") == prog_name:
            prog_entry = p
            break

    if not prog_entry:
        print(f"[!] Program '{prog_name}' not found in programs.json")
        return

    # Update recent bounties
    new_bounties = batch_results.get("bounties_paid", [])
    if "bounties" not in prog_entry:
        prog_entry["bounties"] = []
    prog_entry["bounties"].extend(new_bounties)

    # Calculate recent activity (last 30 days)
    last_30 = datetime.now() - timedelta(days=30)
    recent_bounties = [
        b for b in prog_entry["bounties"]
        if datetime.fromisoformat(b["paid_date"].replace("Z", "+00:00")) >= last_30
    ]
    prog_entry["recent_bounties_30d"] = len(recent_bounties)

    # Update dup rate
    total_reports = batch_results.get("reports_submitted", 0)
    dup_reports = batch_results.get("duplicate_reports", 0)
    if total_reports > 0:
        dup_rate = dup_reports / total_reports
    else:
        dup_rate = 0.0
    prog_entry["latest_dup_rate"] = dup_rate

    # Update recent reports count (last 30 days)
    if "recent_reports_30d" not in prog_entry:
        prog_entry["recent_reports_30d"] = 0
    prog_entry["recent_reports_30d"] += batch_results.get("reports_submitted", 0)

    # Add batch timestamp
    prog_entry["last_updated"] = datetime.utcnow().isoformat() + "Z"

    print(f"[+] Updated program '{prog_name}':")
    print(f"    Recent bounties (30d): {prog_entry['recent_bounties_30d']}")
    print(f"    Latest dup rate: {prog_entry['latest_dup_rate']:.2%}")
    print(f"    Recent reports (30d): {prog_entry['recent_reports_30d']}")

def save_programs(programs, path):
    """Save updated programs to JSON."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(programs, f, indent=2)
    print(f"[+] Saved updated programs to: {path}")

def main():
    programs_file = Path("programs.json")
    results_file = Path("batch_results.json")
    if not programs_file.is_file():
        print("[!] programs.json not found. Please create it first.")
        return
    if not results_file.is_file():
        print("[!] batch_results.json not found. Creating stub.")
        stub = {
            "program": "Example Program",
            "reports_submitted": 3,
            "valid_reports": 1,
            "duplicate_reports": 2,
            "not_applicable": 0,
            "bounties_paid": [
                {"amount": 500, "paid_date": "2025-11-10"},
                {"amount": 800, "paid_date": "2025-11-05"}
            ],
            "notes": "Example batch"
        }
        with open(results_file, "w", encoding="utf-8") as f:
            json.dump(stub, f, indent=2)
        print(f"[+] Stub batch_results.json created at {results_file}")
        print("[!] Edit it with real batch results and re-run.")
        return

    programs = load_programs(programs_file)
    batch_results = load_batch_results(results_file)
    update_program_activity(programs, batch_results)
    save_programs(programs, programs_file)

if __name__ == "__main__":
    main()
