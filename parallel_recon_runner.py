#!/usr/bin/env python3
"""
Parallel Recon Runner
Populates recon.json for multiple programs at once using your existing recon stack.

Usage:
1. Edit programs.json (same format as the scorer) with program names and domains.
2. Run: python3 parallel_recon_runner.py
3. Review combined recon output in combined_recon.json
"""

import json
import subprocess
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

def load_programs(path):
    """Load programs from JSON."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[!] Error loading programs.json: {e}")
        sys.exit(1)

def run_recon_for_program(program):
    """
    Run recon for a single program using your existing stack.
    Returns a recon structure for this program.
    """
    name = program.get("name", "unknown")
    domains = program.get("domains", [])
    if not domains:
        print(f"[!] No domains for program {name}, skipping.")
        return None

    print(f"[*] Starting recon for {name} ({len(domains)} domains)...")
    # Assume you have a script that outputs JSON for a list of domains.
    # For this example, we'll simulate with a placeholder subprocess call.
    # Replace the command below with your actual recon pipeline.
    # Example: python3 run_pipeline.py --targets targets.txt --output recon_{name}.json
    try:
        # Write temporary targets file
        targets_file = Path(f"targets_{name}.txt")
        with open(targets_file, "w", encoding="utf-8") as tf:
            for d in domains:
                tf.write(f"{d}\n")
        # Run your recon pipeline (adjust command as needed)
        result = subprocess.run(
            ["python3", "run_pipeline.py", "--targets", str(targets_file), "--output", f"recon_{name}.json"],
            capture_output=True, text=True, timeout=1800  # 30 min timeout
        )
        if result.returncode != 0:
            print(f"[!] Recon failed for {name}: {result.stderr}")
            return None
        # Load the generated recon file
        recon_file = Path(f"recon_{name}.json")
        if recon_file.is_file():
            with open(recon_file, "r", encoding="utf-8") as rf:
                recon_data = json.load(rf)
            print(f"[+] Recon completed for {name}")
            return {"program": name, "recon": recon_data}
        else:
            print(f"[!] Recon output not found for {name}")
            return None
    except subprocess.TimeoutExpired:
        print(f"[!] Recon timed out for {name}")
        return None
    except Exception as e:
        print(f"[!] Unexpected error for {name}: {e}")
        return None

def combine_recon(recon_results):
    """
    Combine individual program recon into a single structure.
    Expected output format:
    {
        "programs": [
            {"name": "...", "assets": [...], "endpoints": [...], ...},
            ...
        ]
    }
    """
    combined = {"programs": []}
    for entry in recon_results:
        if not entry:
            continue
        prog_name = entry["program"]
        recon = entry["recon"]
        # Normalize: ensure top-level keys exist
        assets = recon.get("assets", [])
        # Optionally add program metadata
        program_entry = {
            "name": prog_name,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "assets": assets,
            "summary": {
                "total_assets": len(assets),
                "total_endpoints": sum(len(a.get("endpoints", [])) for a in assets)
            }
        }
        combined["programs"].append(program_entry)
    return combined

def save_combined_recon(combined, path):
    """Save combined recon to JSON."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2, default=str)
    print(f"[+] Saved combined recon to: {path}")

def print_summary(combined):
    """Print a quick summary of combined recon."""
    print("\n--- Combined Recon Summary ---")
    for prog in combined.get("programs", []):
        name = prog["name"]
        total_assets = prog["summary"]["total_assets"]
        total_endpoints = prog["summary"]["total_endpoints"]
        print(f"- {name}: {total_assets} assets, {total_endpoints} endpoints")
    print()

def main():
    programs_file = Path("programs.json")
    combined_file = Path("combined_recon.json")
    if not programs_file.is_file():
        print("[!] programs.json not found. Please create it with program names and domains.")
        # Create stub
        stub = [
            {"name": "Program A", "domains": ["example.com", "api.example.com"]},
            {"name": "Program B", "domains": ["app.example.org", "www.example.org"]}
        ]
        with open(programs_file, "w", encoding="utf-8") as f:
            json.dump(stub, f, indent=2)
        print(f"[+] Stub programs.json created at {programs_file}")
        print("[!] Edit it with real programs and re-run.")
        return

    programs = load_programs(programs_file)
    # Run recon in parallel (adjust max_workers based on your resources)
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {executor.submit(run_recon_for_program, prog): prog for prog in programs}
        results = []
        for future in as_completed(futures):
            prog = futures[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                print(f"[!] Exception for program {prog.get('name')}: {e}")
    combined = combine_recon(results)
    save_combined_recon(combined, combined_file)
    print_summary(combined)

if __name__ == "__main__":
    main()
