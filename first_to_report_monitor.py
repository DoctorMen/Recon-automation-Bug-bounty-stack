#!/usr/bin/env python3
"""
First‑to‑Report Monitor
Hooks SENTINEL_AGENT to watch program updates and trigger quick checks on new assets.
Integrates safely into your workflow without manual interaction.

Usage:
1. Configure monitor.json with programs and webhook/API sources.
2. Run: python3 first_to_report_monitor.py
3. Monitor runs in background, checks for updates, and triggers fast checks on new assets.
"""

import json
import time
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
import hashlib

def load_config(path):
    """Load monitor configuration."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[!] Error loading monitor.json: {e}")
        sys.exit(1)

def get_asset_hash(asset):
    """Generate a simple hash for an asset to detect changes."""
    s = f"{asset.get('host','')}{asset.get('path','')}{asset.get('method','')}"
    return hashlib.sha256(s.encode()).hexdigest()

def load_known_assets(path):
    """Load known assets from previous run."""
    if path.is_file():
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_known_assets(assets, path):
    """Save known assets for next run."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(assets, f, indent=2)

def check_program_updates(program, known_assets):
    """
    Check for new assets in a program.
    Returns list of new assets.
    """
    name = program.get("name")
    print(f"[*] Checking updates for {name}...")
    # For this example, we simulate by calling a recon script that outputs assets.
    # Replace with your actual method (API polling, webhook processing, etc.)
    try:
        # Run a quick recon to list assets (adjust command)
        result = subprocess.run(
            ["python3", "run_pipeline.py", "--targets", " ".join(program.get("domains", [])), "--output", f"temp_{name}.json"],
            capture_output=True, text=True, timeout=600  # 10 min
        )
        if result.returncode != 0:
            print(f"[!] Recon failed for {name}: {result.stderr}")
            return []
        # Load temp assets
        temp_file = Path(f"temp_{name}.json")
        if not temp_file.is_file():
            print(f"[!] No recon output for {name}")
            return []
        with open(temp_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assets = data.get("assets", [])
        new_assets = []
        for asset in assets:
            h = get_asset_hash(asset)
            if h not in known_assets.get(name, {}):
                new_assets.append(asset)
                known_assets.setdefault(name, {})[h] = {
                    "first_seen": datetime.now(timezone.utc).isoformat(),
                    "asset": asset
                }
        # Clean up temp file
        temp_file.unlink(missing_ok=True)
        if new_assets:
            print(f"[+] Found {len(new_assets)} new assets for {name}")
        else:
            print(f"[-] No new assets for {name}")
        return new_assets
    except subprocess.TimeoutExpired:
        print(f"[!] Recon timed out for {name}")
        return []
    except Exception as e:
        print(f"[!] Unexpected error for {name}: {e}")
        return []

def run_fast_check_on_assets(program_name, assets):
    """
    Run a fast, low‑impact check on new assets.
    Uses SENTINEL_AGENT logic in a safe, limited way.
    """
    print(f"[*] Running fast checks on {len(assets)} new assets for {program_name}...")
    # For each asset, run a minimal check (e.g., liveness, headers, basic auth test)
    # Replace with your actual fast check logic (e.g., call check_live.py)
    results = []
    for asset in assets:
        host = asset.get("host")
        path = asset.get("path", "")
        method = asset.get("method", "GET")
        # Example: run a simple liveness check
        try:
            # Use your check_live.py or equivalent
            result = subprocess.run(
                ["python3", "check_live.py"],
                input=f"{host}{path}\n",
                capture_output=True, text=True, timeout=30
            )
            alive = result.returncode == 0 and result.stdout.strip()
            results.append({
                "host": host,
                "path": path,
                "method": method,
                "alive": alive,
                "checked_at": datetime.now(timezone.utc).isoformat()
            })
        except Exception as e:
            print(f"[!] Fast check failed for {host}{path}: {e}")
            results.append({
                "host": host,
                "path": path,
                "method": method,
                "alive": False,
                "error": str(e),
                "checked_at": datetime.now(timezone.utc).isoformat()
            })
    # Save results
    results_file = Path(f"fast_checks_{program_name}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json")
    with open(results_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"[+] Saved fast check results to {results_file}")
    return results

def monitor_loop(config):
    """Main monitoring loop."""
    known_assets_file = Path("known_assets.json")
    known_assets = load_known_assets(known_assets_file)
    programs = config.get("programs", [])
    interval = config.get("check_interval_seconds", 3600)  # default 1 hour
    print(f"[*] Starting monitor (interval: {interval}s)...")
    try:
        while True:
            for prog in programs:
                new_assets = check_program_updates(prog, known_assets)
                if new_assets:
                    # Trigger fast checks
                    run_fast_check_on_assets(prog["name"], new_assets)
            # Save known assets after each cycle
            save_known_assets(known_assets, known_assets_file)
            print(f"[*] Sleeping for {interval} seconds...")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[*] Monitor stopped by user.")
        save_known_assets(known_assets, known_assets_file)

def main():
    config_file = Path("monitor.json")
    if not config_file.is_file():
        print("[!] monitor.json not found. Creating stub.")
        stub = {
            "programs": [
                {"name": "Program A", "domains": ["example.com", "api.example.com"]},
                {"name": "Program B", "domains": ["app.example.org"]}
            ],
            "check_interval_seconds": 3600
        }
        with open(config_file, "w", encoding="utf-8") as f:
            json.dump(stub, f, indent=2)
        print(f"[+] Stub monitor.json created at {config_file}")
        print("[!] Edit it with real programs and re-run.")
        return

    config = load_config(config_file)
    monitor_loop(config)

if __name__ == "__main__":
    main()
