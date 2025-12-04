#!/usr/bin/env python3
"""
Bug Bounty Orchestrator - Fully Automated Version
Ties together the entire unfair-advantage pipeline with auto-discovery:
- Auto-discover bug bounty programs
- Target scoring with EV optimization
- Parallel recon with compliance checking
- Attack template generation
- Monitoring (polling/webhook)
- Report generation
- Performance loop updates

Usage:
1. Configure config.json with programs and preferences.
2. Run: python3 bug_bounty_orchestrator_fixed.py
3. Orchestrator runs the full pipeline with auto-discovery.
"""

import json
import subprocess
import time
import threading
import sys
from pathlib import Path
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import policy compliance guard
try:
    from POLICY_COMPLIANCE_GUARD import COMPLIANCE_GUARD, check_target_compliance, check_action_compliance, validate_payload_safety
    COMPLIANCE_ENABLED = True
except ImportError:
    print("[!] WARNING: POLICY_COMPLIANCE_GUARD not found - running without compliance checks")
    COMPLIANCE_ENABLED = False

# Import auto authorization discovery
try:
    from AUTO_AUTHORIZATION_DISCOVERY import AutoAuthorizationDiscovery
    AUTO_DISCOVERY_ENABLED = True
    DISCOVERER = AutoAuthorizationDiscovery()
except ImportError:
    print("[!] WARNING: AUTO_AUTHORIZATION_DISCOVERY not found - running without auto-discovery")
    AUTO_DISCOVERY_ENABLED = False

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

    def auto_discover_targets(self):
        """Automatically discover and add authorized targets."""
        if not AUTO_DISCOVERY_ENABLED:
            print("[*] Auto-discovery not available")
            return 0
        
        print("[*] Running auto-discovery for potential targets...")
        
        # Get potential targets from config
        potential_targets = []
        for program in self.config.get("programs", []):
            potential_targets.extend(program.get("domains", []))
        
        # Also check common bug bounty platforms
        platform_targets = ["hackerone.com", "bugcrowd.com", "intigriti.com", "yeswehack.com"]
        potential_targets.extend(platform_targets)
        
        discovered_programs = []
        
        for target in set(potential_targets):  # Remove duplicates
            print(f"[*] Discovering authorization for: {target}")
            authorization = DISCOVERER.verify_authorization_status(target)
            
            if authorization:
                print(f"[+] Authorization discovered for {target}")
                
                # Create authorization file
                auth_filename = f"auto_auth_{target.replace('.', '_')}.json"
                with open(auth_filename, 'w') as f:
                    json.dump(authorization, f, indent=2)
                
                # Add to programs if not already present
                program_name = authorization.get('program_name', target)
                scope = authorization.get('scope', [target])
                
                # Check if already in config
                existing = False
                for program in self.config.get("programs", []):
                    if program.get("name") == program_name:
                        existing = True
                        break
                
                if not existing:
                    discovered_programs.append({
                        "name": program_name,
                        "domains": scope,
                        "authorization_file": auth_filename,
                        "discovered": True
                    })
                
                print(f"[+] Added {program_name} with {len(scope)} domains")
            else:
                print(f"[-] No authorization found for {target}")
        
        # Update config with discovered programs
        if discovered_programs:
            self.config["programs"].extend(discovered_programs)
            print(f"[+] Auto-discovered {len(discovered_programs)} new programs")
        
        return len(discovered_programs)

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
        
        # Check compliance before recon
        if COMPLIANCE_ENABLED:
            for program in self.config.get("programs", []):
                for domain in program.get("domains", []):
                    allowed, reason = check_target_compliance(domain)
                    if not allowed:
                        print(f"[!] BLOCKED: Recon on {domain} - {reason}")
                        return False
        
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
        """Execute the complete automated pipeline."""
        print("\n=== Running Full Pipeline ===")
        
        # Step 1: Auto-discover targets
        discovered_count = self.auto_discover_targets()
        if discovered_count > 0:
            print(f"[+] Auto-discovered {discovered_count} new programs")
        
        # Step 2: Target scoring
        if not self.run_target_scorer():
            print("[!] Pipeline failed at target scoring")
            return False
        
        # Step 3: Parallel recon
        if not self.run_parallel_recon():
            print("[!] Pipeline failed at parallel recon")
            return False
        
        # Step 4: Attack templates
        self.generate_attack_templates()
        
        # Step 5: Process findings
        self.process_findings()
        
        # Step 6: Performance loop
        self.update_performance_loop()
        
        # Step 7: Start monitoring
        self.start_monitoring()
        
        print("\n=== Pipeline Complete ===")
        return True

    def run_once(self):
        """Execute the full pipeline once with auto-discovery."""
        return self.run_full_pipeline()

    def run_continuous(self):
        """Run orchestrator continuously."""
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

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Bug Bounty Orchestrator - Fully Automated")
    parser.add_argument("--mode", choices=["once", "continuous"], default="once", help="Run mode")
    args = parser.parse_args()

    orchestrator = BugBountyOrchestrator()
    if args.mode == "continuous":
        orchestrator.run_continuous()
    else:
        orchestrator.run_once()

if __name__ == "__main__":
    main()
