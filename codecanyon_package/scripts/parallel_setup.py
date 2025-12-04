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
Parallel Setup Runner
Runs all setup/preparation tasks in parallel while tools download
Maximizes efficiency by using downtime productively
"""

import subprocess
import sys
import time
from pathlib import Path
from datetime import datetime
import concurrent.futures

REPO_ROOT = Path(__file__).parent.parent

def log(message: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def run_script(script_name: str, description: str):
    """Run a Python script"""
    script_path = REPO_ROOT / "scripts" / script_name
    if not script_path.exists():
        return False, f"Script not found: {script_name}"
    
    try:
        result = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=600
        )
        return result.returncode == 0, result.stderr if result.returncode != 0 else None
    except subprocess.TimeoutExpired:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)

def main():
    """Main parallel setup function - OPTIMIZED FOR 24GB RAM"""
    print("=" * 70)
    print("Parallel Setup Runner (OPTIMIZED)")
    print("Running setup tasks while tools download...")
    print("=" * 70)
    print()
    
    # List of tasks to run in parallel
    tasks = [
        ("validate_targets.py", "Target Validation"),
        ("update_nuclei_templates.py", "Templates Update"),
        ("prepare_scan_environment.py", "Environment Setup"),
    ]
    
    log(f"Starting {len(tasks)} parallel tasks (max_workers: 10)...")
    print()
    
    # Run tasks in parallel - INCREASED CONCURRENCY
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_task = {
            executor.submit(run_script, script, desc): (script, desc)
            for script, desc in tasks
        }
        
        for future in concurrent.futures.as_completed(future_to_task):
            script, desc = future_to_task[future]
            try:
                success, error = future.result()
                status = "✓" if success else "✗"
                results[desc] = success
                log(f"{status} {desc} {'completed' if success else 'failed'}")
                if error:
                    log(f"   Error: {error[:100]}")
            except Exception as e:
                results[desc] = False
                log(f"✗ {desc} failed: {e}")
    
    print()
    print("=" * 70)
    print("Parallel Setup Summary")
    print("=" * 70)
    
    success_count = sum(1 for v in results.values() if v)
    for task, success in results.items():
        status = "✓" if success else "✗"
        print(f"{status} {task}")
    
    print()
    print(f"Completed: {success_count}/{len(tasks)} tasks")
    print()
    print("Next steps:")
    print("  1. Wait for tool installation to complete")
    print("  2. Run: python3 scripts/scan_monitor.py (check status)")
    print("  3. Run: python3 start_scan.py (start scanning)")
    print()

if __name__ == "__main__":
    main()


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
