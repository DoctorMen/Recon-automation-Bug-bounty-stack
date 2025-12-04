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
Target Validation Agent
Validates targets from targets.txt - checks if domains are reachable and in scope
Runs while tools are downloading to prepare for scanning
"""

import sys
import socket
import requests
import ssl
from pathlib import Path
from datetime import datetime
from typing import List, Dict
import concurrent.futures
import json

REPO_ROOT = Path(__file__).parent.parent
TARGETS_FILE = REPO_ROOT / "targets.txt"
OUTPUT_DIR = REPO_ROOT / "output"
VALIDATION_OUTPUT = OUTPUT_DIR / "targets-validation.json"

def log(message: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def check_dns(domain: str, timeout: int = 5) -> bool:
    """Check if domain resolves to an IP"""
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False
    except Exception:
        return False

def check_http(domain: str, timeout: int = 10) -> Dict:
    """Check if domain has HTTP/HTTPS endpoints"""
    result = {
        "http": False,
        "https": False,
        "status_code": None,
        "ssl_valid": False
    }
    
    # Try HTTPS first
    try:
        response = requests.get(
            f"https://{domain}",
            timeout=timeout,
            allow_redirects=True,
            verify=False
        )
        result["https"] = True
        result["status_code"] = response.status_code
        result["ssl_valid"] = True
    except requests.exceptions.SSLError:
        result["https"] = True
        result["ssl_valid"] = False
    except requests.exceptions.RequestException:
        pass
    
    # Try HTTP if HTTPS failed
    if not result["https"]:
        try:
            response = requests.get(
                f"http://{domain}",
                timeout=timeout,
                allow_redirects=True
            )
            result["http"] = True
            result["status_code"] = response.status_code
        except requests.exceptions.RequestException:
            pass
    
    return result

def validate_target(domain: str) -> Dict:
    """Validate a single target domain"""
    log(f"Validating {domain}...")
    
    validation = {
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "dns_resolves": False,
        "http_accessible": False,
        "https_accessible": False,
        "ssl_valid": False,
        "status_code": None,
        "valid": False
    }
    
    # Check DNS
    validation["dns_resolves"] = check_dns(domain)
    
    if validation["dns_resolves"]:
        # Check HTTP/HTTPS
        http_result = check_http(domain)
        validation["http_accessible"] = http_result["http"]
        validation["https_accessible"] = http_result["https"]
        validation["ssl_valid"] = http_result["ssl_valid"]
        validation["status_code"] = http_result["status_code"]
        validation["valid"] = http_result["http"] or http_result["https"]
    
    return validation

def main():
    """Main validation function"""
    log("=== Target Validation Agent Starting ===")
    log("Validating targets while tools download...")
    
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Load targets
    if not TARGETS_FILE.exists():
        log(f"ERROR: {TARGETS_FILE} not found")
        sys.exit(1)
    
    targets = []
    with open(TARGETS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    
    if not targets:
        log("ERROR: No valid targets found in targets.txt")
        sys.exit(1)
    
    log(f"Found {len(targets)} target(s) to validate")
    log("")
    
    # Validate targets in parallel
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_target = {executor.submit(validate_target, target): target for target in targets}
        
        for future in concurrent.futures.as_completed(future_to_target):
            try:
                result = future.result()
                results.append(result)
                
                status = "✓" if result["valid"] else "✗"
                log(f"{status} {result['domain']}: "
                    f"DNS={result['dns_resolves']}, "
                    f"HTTP={result['http_accessible']}, "
                    f"HTTPS={result['https_accessible']}")
            except Exception as e:
                log(f"ERROR validating {future_to_target[future]}: {e}")
    
    # Save results
    with open(VALIDATION_OUTPUT, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    # Summary
    valid_count = sum(1 for r in results if r["valid"])
    dns_count = sum(1 for r in results if r["dns_resolves"])
    
    log("")
    log("=== Validation Summary ===")
    log(f"Total targets: {len(targets)}")
    log(f"DNS resolvable: {dns_count}")
    log(f"HTTP/HTTPS accessible: {valid_count}")
    log(f"Results saved to: {VALIDATION_OUTPUT}")
    log("")
    
    # Warn about invalid targets
    invalid = [r["domain"] for r in results if not r["valid"]]
    if invalid:
        log("⚠️  WARNING: Some targets are not accessible:")
        for domain in invalid:
            log(f"   - {domain}")
        log("")
    
    log("=== Target Validation Complete ===")

if __name__ == "__main__":
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    main()


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
