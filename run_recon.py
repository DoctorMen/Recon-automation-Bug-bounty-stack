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
Recon Scanner Agent - Windows Native
Runs Subfinder + Amass to enumerate subdomains, validates with DNSx
Output: output/subs.txt
"""

import subprocess
import sys
import os
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

# Import tools manager for local tool paths
sys.path.insert(0, str(Path(__file__).parent))
try:
    from tools_manager import get_tool_path, check_tool
except ImportError:
    # Fallback if tools_manager not available
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

# Get script directory and repo root - works from any location
SCRIPT_DIR = Path(__file__).parent.absolute()
REPO_ROOT = SCRIPT_DIR
OUTPUT_DIR = REPO_ROOT / "output"
TARGETS_FILE = REPO_ROOT / "targets.txt"

# Configuration - OPTIMIZED FOR 24GB RAM SYSTEM
RECON_TIMEOUT = int(os.getenv("RECON_TIMEOUT", "1800"))  # 30 minutes default
SUBFINDER_THREADS = int(os.getenv("SUBFINDER_THREADS", "50"))  # 50 concurrent DNS queries
AMASS_MAX_DNS = int(os.getenv("AMASS_MAX_DNS", "10000"))  # 10000 DNS queries (2GB RAM)
DNSX_THREADS = int(os.getenv("DNSX_THREADS", "100"))  # 100 concurrent validations
RESOLVER_COUNT = int(os.getenv("RESOLVER_COUNT", "25"))  # 25 DNS resolvers

def log(message):
    """Log message with timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_msg = f"[{timestamp}] {message}"
    print(log_msg)
    log_file = OUTPUT_DIR / "recon-run.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(log_msg + "\n")


def main():
    log("=== Recon Scanner Agent Starting ===")
    
    # Ensure output directory exists
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Check if targets.txt exists
    if not TARGETS_FILE.exists():
        log(f"ERROR: targets.txt not found at {TARGETS_FILE}")
        log("Please create targets.txt with authorized domains (one per line)")
        sys.exit(1)
    
    # Check tools (use local tools first)
    subfinder_path = get_tool_path("subfinder")
    amass_path = get_tool_path("amass")
    dnsx_path = get_tool_path("dnsx")
    
    if not check_tool("subfinder") and subfinder_path == "subfinder":
        log("ERROR: subfinder not found. Run: python setup_tools.py")
        sys.exit(1)
    amass_available = True
    if not check_tool("amass") and amass_path == "amass":
        amass_available = False
        log("WARNING: amass not found (will run subfinder-only). Run: python setup_tools.py to install amass for deeper coverage")
    
    dnsx_available = check_tool("dnsx")
    if not dnsx_available and dnsx_path == "dnsx":
        log("WARNING: dnsx not found (will skip validation). Run: python setup_tools.py")
    
    # Read targets
    targets = []
    with open(TARGETS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    
    if not targets:
        log("ERROR: No valid targets found in targets.txt")
        sys.exit(1)
    
    target_count = len(targets)
    log(f"Processing {target_count} target(s): {', '.join(targets)}")
    
    # Temporary files
    temp_subfinder = OUTPUT_DIR / "temp_subfinder.txt"
    temp_amass = OUTPUT_DIR / "temp_amass.txt"
    temp_combined = OUTPUT_DIR / "temp_combined_subs.txt"
    temp_validated = OUTPUT_DIR / "temp_validated_subs.txt"
    final_subs = OUTPUT_DIR / "subs.txt"
    
    # Run Subfinder - OPTIMIZED
    log(f"Running Subfinder (threads: {SUBFINDER_THREADS}, timeout: {RECON_TIMEOUT}s)...")
    try:
        result = subprocess.run(
            [subfinder_path, "-dL", str(TARGETS_FILE), "-silent", 
             "-o", str(temp_subfinder), "-t", str(SUBFINDER_THREADS),
             "-all", "-recursive", "-timeout", "10"],
            timeout=RECON_TIMEOUT,
            capture_output=True,
            text=True,
            check=False
        )
        if temp_subfinder.exists():
            subfinder_count = len(temp_subfinder.read_text(encoding="utf-8").strip().splitlines())
            log(f"Subfinder found {subfinder_count} subdomains")
        else:
            log("WARNING: Subfinder produced no output")
            temp_subfinder.write_text("")
    except subprocess.TimeoutExpired:
        log(f"WARNING: Subfinder timed out after {RECON_TIMEOUT}s")
        temp_subfinder.write_text("")
    except Exception as e:
        log(f"WARNING: Subfinder encountered errors: {e}")
        temp_subfinder.write_text("")
    
    # Run Amass (optional) - OPTIMIZED
    if amass_available:
        log(f"Running Amass enum (max-dns-queries: {AMASS_MAX_DNS}, timeout: {RECON_TIMEOUT}s)...")
        try:
            result = subprocess.run(
                [amass_path, "enum", "-passive", "-df", str(TARGETS_FILE), 
                 "-o", str(temp_amass), "-max-dns-queries", str(AMASS_MAX_DNS),
                 "-timeout", "10"],
                timeout=RECON_TIMEOUT,
                capture_output=True,
                text=True,
                check=False
            )
            if temp_amass.exists():
                amass_count = len(temp_amass.read_text(encoding="utf-8").strip().splitlines())
                log(f"Amass found {amass_count} subdomains")
            else:
                log("WARNING: Amass produced no output")
                temp_amass.write_text("")
        except subprocess.TimeoutExpired:
            log(f"WARNING: Amass timed out after {RECON_TIMEOUT}s")
            temp_amass.write_text("")
        except Exception as e:
            log(f"WARNING: Amass encountered errors: {e}")
            temp_amass.write_text("")
    else:
        # Ensure file exists for downstream combine step
        temp_amass.write_text("")
    
    # Combine and deduplicate
    log("Combining and deduplicating results...")
    combined = set()
    for temp_file in [temp_subfinder, temp_amass]:
        if temp_file.exists():
            combined.update(temp_file.read_text(encoding="utf-8").strip().splitlines())
    
    # Filter empty strings and sort (keep as list for later use)
    combined_list = sorted(s for s in combined if s)
    temp_combined.write_text("\n".join(combined_list), encoding="utf-8")
    log(f"Combined results: {len(combined_list)} unique subdomains")
    
    # Validate with DNSx if available - OPTIMIZED
    # Track the final list of subdomains to avoid re-reading the file
    final_subdomain_list = None
    
    if dnsx_available and combined_list:
        log(f"Validating subdomains with DNSx (threads: {DNSX_THREADS})...")
        try:
            result = subprocess.run(
                [dnsx_path, "-l", str(temp_combined), "-a", "-aaaa", "-cname", 
                 "-mx", "-ns", "-txt", "-soa", "-resp", "-o", str(temp_validated),
                 "-t", str(DNSX_THREADS), "-retry", "2", "-timeout", "10"],
                timeout=600,
                capture_output=True,
                text=True,
                check=False
            )
            if temp_validated.exists():
                validated_lines = [l.split()[0] for l in temp_validated.read_text(encoding="utf-8").strip().splitlines() if l.strip()]
                validated = sorted(set(validated_lines))
                validated_count = len(validated)
                log(f"DNSx validated {validated_count} subdomains")
                if validated:
                    final_subdomain_list = validated
                    final_subs.write_text("\n".join(validated), encoding="utf-8")
                else:
                    log("WARNING: DNSx validation found no live subdomains, using raw results")
                    final_subdomain_list = combined_list
                    final_subs.write_text("\n".join(combined_list), encoding="utf-8")
            else:
                log("WARNING: DNSx validation failed, using raw results")
                final_subdomain_list = combined_list
                final_subs.write_text("\n".join(combined_list), encoding="utf-8")
        except Exception as e:
            log(f"WARNING: DNSx validation failed: {e}, using raw results")
            final_subdomain_list = combined_list
            final_subs.write_text("\n".join(combined_list), encoding="utf-8")
    else:
        # No DNSx, use raw results
        final_subdomain_list = combined_list
        final_subs.write_text("\n".join(combined_list), encoding="utf-8")
    
    # Final count - use the tracked list directly instead of re-reading file
    if final_subs.exists():
        sub_count = len(final_subdomain_list) if final_subdomain_list else 0
        log(f"Final result: {sub_count} validated subdomains")
        if sub_count == 0:
            log("WARNING: No subdomains discovered. Check your targets and network connectivity.")
    else:
        log("ERROR: Failed to create subs.txt")
        sys.exit(1)
    
    # Cleanup temp files
    for temp_file in [temp_subfinder, temp_amass, temp_combined, temp_validated]:
        if temp_file.exists():
            temp_file.unlink()
    
    log("=== Recon Scanner Agent Complete ===")
    log(f"Output: {final_subs}")

if __name__ == "__main__":
    main()


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
