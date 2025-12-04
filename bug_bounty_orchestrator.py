#!/usr/bin/env python3
"""
Bug Bounty Orchestrator
Ties together the entire unfair-advantage pipeline:
- Target scoring
- Parallel recon
- Attack template generation
- Monitoring (polling/webhook)
- Report generation
- Performance loop updates

Usage:
1. Configure config.json with programs and preferences.
2. Run: python3 bug_bounty_orchestrator.py
3. Orchestrator runs the full pipeline continuously.
"""

import json
import subprocess
import time
import threading
from pathlib import Path
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

class BugBountyOrchestrator:
    def __init__(self, config_path="config.json"):
        self.config = self.load_config(config_path)
        self.state = self.load_state("orchestrator_state.json")
        self.running = True

    def load_config(self, path):
        """Load orchestrator configuration."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"[!] Error loading config.json: {e}")
            print("[!] Creating stub config.json")
            stub = {
                "programs": [
                    {"name": "Program A", "domains": ["example.com", "api.example.com"]},
                    {"name": "Program B", "domains": ["app.example.org"]}
                ],
                "scoring_weights": {
                    "recent_activity": 0.30,
                    "scope_clarity": 0.20,
                    "strength_fit": 0.25,
                    "competition_level": 0.25
                },
                "monitoring": {
                    "method": "webhook",  # or "polling"
                    "webhook_port": 8080,
                    "polling_interval_seconds": 3600
                },
                "automation": {
                    "max_parallel_programs": 3,
                    "fast_check_timeout_seconds": 30,
                    "report_templates": ["idor", "ssrf", "xss"]
                },
                "performance": {
                    "batch_interval_hours": 24,
                    "auto_update_scores": True
                }
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(stub, f, indent=2)
            print(f"[+] Stub config.json created at {path}")
            print("[!] Edit it with real programs and re-run.")
            sys.exit(1)

    def load_state(self, path):
        """Load orchestrator state."""
        if Path(path).is_file():
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {"last_batch": None, "last_score_update": None}

    def save_state(self, path="orchestrator_state.json"):
        """Save orchestrator state."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.state, f, indent=2)

    def run_target_scorer(self):
        """Run target scorer and update rankings."""
        print("[*] Running target scorer...")
        try:
            result = subprocess.run(
                ["python3", "bug_bounty_target_scorer.py"],
                capture_output=True, text=True, timeout=300
            )
            if result.returncode == 0:
                print("[+] Target scorer completed successfully")
                return True
            else:
                print(f"[!] Target scorer failed: {result.stderr}")
                return False
        except subprocess.TimeoutExpired:
            print("[!] Target scorer timed out")
            return False

    def run_parallel_recon(self):
        """Run parallel recon on ranked programs."""
        print("[*] Running parallel recon...")
        try:
            result = subprocess.run(
                ["python3", "parallel_recon_runner.py"],
                capture_output=True, text=True, timeout=1800
            )
            if result.returncode == 0:
                print("[+] Parallel recon completed")
                return True
            else:
                print(f"[!] Parallel recon failed: {result.stderr}")
                return False
        except subprocess.TimeoutExpired:
            print("[!] Parallel recon timed out")
            return False

    def generate_attack_templates(self):
        """Generate attack templates for new recon data."""
        print("[*] Generating attack templates...")
        templates = ["idor", "ssrf", "xss"]
        for template in templates:
            try:
                result = subprocess.run(
                    ["python3", f"attack_template_{template}.py"],
                    capture_output=True, text=True, timeout=300
                )
                if result.returncode == 0:
                    print(f"[+] {template.upper()} template generation completed")
                else:
                    print(f"[!] {template.upper()} template generation failed: {result.stderr}")
            except subprocess.TimeoutExpired:
                print(f"[!] {template.upper()} template generation timed out")

    def start_monitoring(self):
        """Start monitoring (webhook or polling)."""
        method = self.config["monitoring"]["method"]
        if method == "webhook":
            print("[*] Starting webhook listener...")
            # Run webhook listener in background thread
            threading.Thread(
                target=self._run_webhook_listener,
                daemon=True
            ).start()
        elif method == "polling":
            print("[*] Starting polling monitor...")
            # Run polling monitor in background thread
            threading.Thread(
                target=self._run_polling_monitor,
                daemon=True
            ).start()
        else:
            print(f"[!] Unknown monitoring method: {method}")

    def _run_webhook_listener(self):
        """Run webhook listener."""
        port = self.config["monitoring"]["webhook_port"]
        try:
            subprocess.run(
                ["python3", "webhook_monitor_listener.py"],
                cwd=Path.cwd(),
                timeout=None
            )
        except Exception as e:
            print(f"[!] Webhook listener error: {e}")

    def _run_polling_monitor(self):
        """Run polling monitor."""
        interval = self.config["monitoring"]["polling_interval_seconds"]
        while self.running:
            try:
                result = subprocess.run(
                    ["python3", "first_to_report_monitor.py"],
                    capture_output=True, text=True,
                    timeout=interval + 300  # buffer
                )
                if result.returncode != 0:
                    print(f"[!] Polling monitor error: {result.stderr}")
            except subprocess.TimeoutExpired:
                print("[!] Polling monitor timed out")
            except Exception as e:
                print(f"[!] Polling monitor exception: {e}")
            time.sleep(interval)

    def process_findings(self):
        """Process any new findings and generate reports."""
        # Check for findings files
        for vuln_type in self.config["automation"]["report_templates"]:
            findings_file = Path(f"{vuln_type}_findings.json")
            if findings_file.is_file():
                print(f"[*] Processing {vuln_type} findings...")
                try:
                    result = subprocess.run(
                        ["python3", f"report_factory_{vuln_type}.py"],
                        capture_output=True, text=True, timeout=120
                    )
                    if result.returncode == 0:
                        print(f"[+] {vuln_type} report generated")
                        # Archive findings
                        findings_file.rename(f"{vuln_type}_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
                    else:
                        print(f"[!] {vuln_type} report generation failed: {result.stderr}")
                except subprocess.TimeoutExpired:
                    print(f"[!] {vuln_type} report generation timed out")

    def update_performance_loop(self):
        """Update performance loop with recent results."""
        # Check for batch results
        batch_file = Path("batch_results.json")
        if batch_file.is_file():
            print("[*] Updating performance loop...")
            try:
                result = subprocess.run(
                    ["python3", "performance_loop_updater.py"],
                    capture_output=True, text=True, timeout=120
                )
                if result.returncode == 0:
                    print("[+] Performance loop updated")
                    # Archive batch results
                    batch_file.rename(f"batch_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
                else:
                    print(f"[!] Performance loop update failed: {result.stderr}")
            except subprocess.TimeoutExpired:
                print("[!] Performance loop update timed out")

    def run_full_pipeline(self):
        """Execute the full pipeline once."""
        print("\n=== Running Full Pipeline ===")
        steps = [
            ("Target Scoring", self.run_target_scorer),
            ("Parallel Recon", self.run_parallel_recon),
            ("Attack Templates", self.generate_attack_templates),
            ("Process Findings", self.process_findings),
            ("Performance Loop", self.update_performance_loop)
        ]
        for name, func in steps:
            print(f"\n--- {name} ---")
            success = func()
            if not success and name in ["Target Scoring", "Parallel Recon"]:
                print(f"[!] Critical step {name} failed, pausing pipeline")
                break
        print("\n=== Pipeline Complete ===")

    def run_continuous(self):
        """Run orchestrator in continuous mode."""
        print("[*] Starting continuous orchestrator...")
        # Start monitoring first
        self.start_monitoring()
        # Initial pipeline run
        self.run_full_pipeline()
        # Schedule periodic runs
        batch_interval = self.config["performance"]["batch_interval_hours"]
        while self.running:
            try:
                time.sleep(batch_interval * 3600)
                if self.running:
                    self.run_full_pipeline()
            except KeyboardInterrupt:
                print("\n[*] Orchestrator stopped by user")
                self.running = False
                break

    def run_once(self):
        """Run orchestrator once."""
        self.run_full_pipeline()

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Bug Bounty Orchestrator")
    parser.add_argument("--mode", choices=["once", "continuous"], default="once", help="Run mode")
    args = parser.parse_args()

    orchestrator = BugBountyOrchestrator()
    if args.mode == "continuous":
        orchestrator.run_continuous()
    else:
        orchestrator.run_once()

if __name__ == "__main__":
    main()
