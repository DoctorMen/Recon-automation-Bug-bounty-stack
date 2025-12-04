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
Main Pipeline Orchestrator - Windows Native
Runs all agents in sequence: Recon → Mapper → Hunter → Triage → Report
"""

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

# SAFETY SYSTEM - Critical protection layer
try:
    from MASTER_SAFETY_SYSTEM import verify_safe
    SAFETY_ENABLED = True
except ImportError:
    print("⚠️  WARNING: MASTER_SAFETY_SYSTEM not found - safety checks disabled")
    print("⚠️  This is dangerous - install safety system immediately")
    SAFETY_ENABLED = False

# LEGAL AUTHORIZATION SHIELD - MANDATORY for all scanning
try:
    from LEGAL_AUTHORIZATION_SYSTEM import LegalAuthorizationShield
    LEGAL_SHIELD_ENABLED = True
    print("✅ Legal Authorization Shield loaded")
except ImportError:
    print("❌ CRITICAL ERROR: Legal Authorization Shield not found!")
    print("   All scanning operations are DISABLED without authorization system")
    print("   Required file: LEGAL_AUTHORIZATION_SYSTEM.py")
    sys.exit(1)

# NEURAL NETWORK BRAIN - Intelligence integration
try:
    from NEURAL_INTEGRATION_WRAPPER import get_neural_integration
    NEURAL_BRAIN_ENABLED = True
    neural = get_neural_integration()
    print("✅ Neural Network Brain loaded")
except ImportError:
    NEURAL_BRAIN_ENABLED = False
    neural = None
    print("⚠️  Neural Network Brain not found - using standard pipeline")

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
    
    # LEGAL AUTHORIZATION CHECK - MANDATORY (Cannot be bypassed)
    log("")
    log("⚖️  LEGAL AUTHORIZATION SHIELD - Verifying written authorization...")
    log("="* 60)
    
    shield = LegalAuthorizationShield()
    all_authorized = True
    
    for target in targets:
        authorized, reason, auth_data = shield.check_authorization(target)
        if not authorized:
            log(f"❌ BLOCKED: {target}")
            log(f"   Reason: {reason}")
            log(f"   Required: python3 CREATE_AUTHORIZATION.py --target {target} --client 'CLIENT_NAME'")
            all_authorized = False
        else:
            client = auth_data.get('client_name', 'Unknown')
            log(f"✅ AUTHORIZED: {target} (Client: {client})")
    
    if not all_authorized:
        log("")
        log("🚫 LEGAL AUTHORIZATION FAILED")
        log("="* 60)
        log("⚠️  CRITICAL: Cannot scan without written authorization")
        log("   Scanning unauthorized targets = FEDERAL CRIME (CFAA violation)")
        log("   Penalty: Up to 10 years prison + fines")
        log("")
        log("REQUIRED ACTIONS:")
        log("1. Get written authorization from target owner")
        log("2. Create authorization file using CREATE_AUTHORIZATION.py")
        log("3. Get client signature on authorization")
        log("4. Try again")
        log("="* 60)
        sys.exit(1)
    
    log("")
    log("✅ All targets legally authorized - proceeding with scan")
    log("="* 60)
    
    # SAFETY CHECK - Verify all targets are authorized
    if SAFETY_ENABLED:
        log("")
        log("🛡️  SAFETY SYSTEM - Verifying all targets...")
        log("="* 60)
        
        all_safe = True
        for target in targets:
            log(f"Checking: {target}")
            if not verify_safe(target, "full_scan"):
                log(f"❌ BLOCKED: {target} failed safety checks")
                all_safe = False
            else:
                log(f"✅ SAFE: {target}")
        
        if not all_safe:
            log("")
            log("🚨 SAFETY CHECK FAILED - Some targets are not authorized")
            log("Fix authorization issues before scanning")
            log("See above for details")
            sys.exit(1)
        
        log("")
        log("✅ All targets passed safety checks")
        log("="* 60)
    else:
        log("")
        log("⚠️  WARNING: Safety checks disabled - scanning without verification")
        log("="* 60)
    
    # NEURAL ENHANCEMENT: Prioritize targets before scanning
    if NEURAL_BRAIN_ENABLED and neural:
        log("")
        log("🧠 NEURAL BRAIN - Prioritizing targets...")
        log("="* 60)
        
        # Create asset representations
        asset_targets = [{'name': target, 'type': 'domain'} for target in targets]
        
        # Get neural prioritization
        ranked_targets = neural.prioritize_targets(asset_targets, top_n=len(targets))
        
        if ranked_targets:
            log(f"Neural prioritization complete:")
            for i, (asset, score) in enumerate(ranked_targets[:5], 1):
                log(f"  {i}. {asset['name']}: {score:.3f}")
            
            # Update targets order based on neural scoring
            targets = [asset['name'] for asset, score in ranked_targets]
            log(f"Scanning order optimized by neural brain")
        else:
            log("Neural prioritization failed - using default order")
    
    # Agent 1: Recon Scanner
    log("")
    log(">>> Starting Agent 1: Recon Scanner")
    if RESUME and is_stage_complete("recon"):
        log("Skipping recon (already complete, use RESUME=false to rerun)")
    else:
        if run_agent("run_recon.py", "Recon Scanner"):
            mark_stage_complete("recon")
            
            # NEURAL ENHANCEMENT: Score recon results
            if NEURAL_BRAIN_ENABLED and neural:
                log("🧠 Neural scoring of recon results...")
                try:
                    # Load recon results
                    recon_file = OUTPUT_DIR / "recon.json"
                    if recon_file.exists():
                        with open(recon_file) as f:
                            recon_data = json.load(f)
                        
                        # Enhance with neural scoring
                        enhancement = neural.enhance_pipeline_stage('recon', recon_data)
                        if 'ranked_assets' in enhancement:
                            log(f"  Ranked {len(enhancement['ranked_assets'])} assets by neural score")
                except Exception as e:
                    log(f"  Neural enhancement failed: {e}")
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
    
    # Agent 6: Unified Scanner (Quantum Accelerator V2)
    log("")
    log(">>> Starting Agent 6: Unified Scanner (Quantum Accelerator V2)")
    if RESUME and is_stage_complete("unified_scan"):
        log("Skipping unified scan (already complete)")
    else:
        try:
            from UNIFIED_SCANNER_INTEGRATION import UnifiedScanner
            scanner = UnifiedScanner(dry_run=False)
            for target in targets:
                log(f"   Running unified scan on: {target}")
                results = scanner.scan_target(target, scan_type="comprehensive")
                if results.get("findings"):
                    log(f"   Found {len(results['findings'])} vulnerabilities")
            mark_stage_complete("unified_scan")
        except ImportError as e:
            log(f"WARNING: Unified Scanner not available: {e}")
        except Exception as e:
            log(f"WARNING: Unified scanner failed: {e}")
    
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
    
    # Unified Scanner (Quantum Accelerator V2) results
    unified_results = list(REPO_ROOT.glob("unified_scan_*.json"))
    if unified_results:
        log(f"Unified Scan Results: {len(unified_results)} files")
        try:
            with open(unified_results[-1], "r", encoding="utf-8") as f:
                latest = json.load(f)
            log(f"  - Latest scan findings: {len(latest.get('findings', []))}")
            if latest.get('submissions'):
                log(f"  - Submissions prepared: {len(latest['submissions'])}")
        except:
            pass
    
    log("")
    log("=== Output Files ===")
    log(f"  - Subdomains: {OUTPUT_DIR / 'subs.txt'}")
    log(f"  - HTTP Endpoints: {OUTPUT_DIR / 'http.json'}")
    log(f"  - Nuclei Findings: {OUTPUT_DIR / 'nuclei-findings.json'}")
    log(f"  - Triaged Findings: {OUTPUT_DIR / 'triage.json'}")
    log(f"  - Reports: {OUTPUT_DIR / 'reports'}")
    log(f"  - Unified Scan: unified_scan_*.json")
    log(f"  - Submissions: submission_*.md")
    log("")
    log(f"View summary report: {OUTPUT_DIR / 'reports' / 'summary.md'}")
    log("")
    log("To rerun from start: RESUME=false python run_pipeline.py")
    log("")
    log("⚠️  REMINDER: Review submission_*.md files before submitting to bug bounty platforms")
    log("")

if __name__ == "__main__":
    main()


# System ID: BB_20251102_5946
# Owner: DoctorMen
# Build Date: 2025-11-02 02:45:55
