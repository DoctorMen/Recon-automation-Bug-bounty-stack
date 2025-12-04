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
Immediate ROI Bug Bounty Hunter
Idempotent automation for high-value vulnerabilities with maximum profit potential.
Focuses on: IDOR, Auth Bypass, Secrets, API Issues, Subdomain Takeover
"""

import json
import sys
import subprocess
import time
import asyncio
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
import os
import re

# License protection - must be first
try:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from license_check import check_license
    check_license()
except ImportError:
    print("⚠️  Warning: License check module not found")
except SystemExit:
    # License check failed, exit
    raise

# Paths
SCRIPT_DIR = Path(__file__).parent
REPO_ROOT = SCRIPT_DIR.parent

# Import bug classifier
try:
    import sys
    sys.path.insert(0, str(SCRIPT_DIR))
    from bug_classifier import BugClassifier
except ImportError:
    # Fallback if classifier not available
    BugClassifier = None

# Import speed optimizer
try:
    sys.path.insert(0, str(SCRIPT_DIR))
    from speed_optimizer import SpeedOptimizer
except ImportError:
    SpeedOptimizer = None

    # Import instant submission helper
    try:
        sys.path.insert(0, str(SCRIPT_DIR))
        from instant_submission_helper import InstantSubmissionHelper
    except ImportError:
        InstantSubmissionHelper = None
try:
    sys.path.insert(0, str(SCRIPT_DIR))
    from crypto_vulnerability_scanner import CryptoVulnerabilityScanner
except ImportError:
    CryptoVulnerabilityScanner = None

# Import penetration testing enhancer
try:
    sys.path.insert(0, str(SCRIPT_DIR))
    from penetration_testing_enhancer import PenetrationTestingEnhancer
except ImportError:
    PenetrationTestingEnhancer = None

# Import IoT scanner
try:
    sys.path.insert(0, str(SCRIPT_DIR))
    from iot_vulnerability_scanner import IoTVulnerabilityScanner
except ImportError:
    IoTVulnerabilityScanner = None

# Import secure design scanner
try:
    sys.path.insert(0, str(SCRIPT_DIR))
    from secure_design_scanner import SecureDesignScanner
except ImportError:
    SecureDesignScanner = None

# Import duplicate detector
try:
    sys.path.insert(0, str(SCRIPT_DIR))
    from duplicate_detector import DuplicateDetector
except ImportError:
    DuplicateDetector = None
    # Note: log() not available yet, will log warning later if needed
OUTPUT_DIR = REPO_ROOT / "output"
TARGETS_FILE = REPO_ROOT / "targets.txt"
ROI_OUTPUT_DIR = OUTPUT_DIR / "immediate_roi"
LOG_FILE = ROI_OUTPUT_DIR / "roi_hunter.log"
STATUS_FILE = ROI_OUTPUT_DIR / ".status"

# High-ROI vulnerability categories (in priority order)
HIGH_ROI_CATEGORIES = {
    "critical": {
        "secrets": "Exposed API keys, credentials, tokens",
        "auth_bypass": "Authentication bypass vulnerabilities",
        "rce": "Remote code execution",
        "ssrf": "Server-side request forgery",
        "subdomain_takeover": "Subdomain takeover opportunities"
    },
    "high": {
        "idor": "Insecure direct object reference",
        "sqli": "SQL injection",
        "xxe": "XML external entity",
        "lfi": "Local file inclusion",
        "privilege_escalation": "Privilege escalation"
    },
    "medium": {
        "api_security": "API authentication bypass, mass assignment",
        "xss": "Cross-site scripting",
        "cors": "CORS misconfiguration",
        "open_redirect": "Open redirect vulnerabilities",
        "information_disclosure": "Information disclosure"
    }
}

# High-value Nuclei tags for immediate ROI
HIGH_VALUE_TAGS = [
    "auth", "api", "idor", "sqli", "ssrf", "rce", "xss", "cors",
    "secrets", "exposed", "credential-disclosure", "api-key",
    "subdomain-takeover", "oauth", "jwt", "privilege-escalation"
]


def log(message: str, level: str = "INFO"):
    """Write log message to both stdout and log file"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_msg = f"[{timestamp}] [{level}] {message}"
    print(log_msg)
    ROI_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_msg + "\n")


def check_tool(tool_name: str) -> bool:
    """Check if a tool is installed"""
    try:
        subprocess.run([tool_name, "--version"], 
                      capture_output=True, timeout=5, check=False)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def mark_stage_complete(stage: str, complete: bool = True):
    """Mark a stage as complete or incomplete for idempotency"""
    ROI_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    if complete:
        # Add to status file
        with open(STATUS_FILE, "a", encoding="utf-8") as f:
            f.write(f"{stage}\n")
    else:
        # Remove from status file
        if STATUS_FILE.exists():
            try:
                with open(STATUS_FILE, "r", encoding="utf-8") as f:
                    lines = [l.strip() for l in f if l.strip() != stage]
                with open(STATUS_FILE, "w", encoding="utf-8") as f:
                    f.write("\n".join(lines) + "\n")
            except:
                pass


def is_stage_complete(stage: str) -> bool:
    """Check if a stage is already complete"""
    if not STATUS_FILE.exists():
        return False
    try:
        with open(STATUS_FILE, "r", encoding="utf-8") as f:
            return stage in f.read()
    except:
        return False


def get_targets() -> List[str]:
    """Load targets from targets.txt"""
    if not TARGETS_FILE.exists():
        log(f"ERROR: {TARGETS_FILE} not found", "ERROR")
        log("Please create targets.txt with authorized domains (one per line)", "ERROR")
        sys.exit(1)
    
    targets = []
    with open(TARGETS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    
    if not targets:
        log("ERROR: No valid targets found in targets.txt", "ERROR")
        sys.exit(1)
    
    return targets


def run_command(cmd: List[str], description: str, timeout: int = 3600):
    """Run a command and return success status and output"""
    log(f"Running: {description}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        return result.returncode == 0, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        log(f"WARNING: {description} timed out after {timeout}s", "WARNING")
        return False, f"Command timed out after {timeout}s"
    except Exception as e:
        log(f"ERROR: {description} failed: {e}", "ERROR")
        return False, str(e)


def _enumerate_single_domain(target: str, all_subs: list):
    """Helper function to enumerate a single domain (for parallel processing)"""
    log(f"Enumerating subdomains for {target}...")
    
    # Try subfinder first (fast)
    if check_tool("subfinder"):
        cmd = ["subfinder", "-d", target, "-silent"]
        success, output = run_command(cmd, f"subfinder for {target}", timeout=300)
        if success and output.strip():
            all_subs.extend(output.strip().split("\n"))
    
    # Try amass (slower but more thorough) - with shorter timeout
    if check_tool("amass"):
        cmd = ["amass", "enum", "-passive", "-d", target, "-silent"]
        success, output = run_command(cmd, f"amass for {target}", timeout=180)  # Reduced from 600s
        if success and output.strip():
            all_subs.extend(output.strip().split("\n"))


def stage_1_recon(targets: List[str], resume: bool = False) -> bool:
    """Stage 1: Quick reconnaissance - subdomain enumeration"""
    if resume and is_stage_complete("recon"):
        log("Skipping recon (already complete)")
        return True
    
    log("=" * 60)
    log("STAGE 1: Quick Reconnaissance")
    log("=" * 60)
    
    # Check if we already have subdomains
    subs_file = OUTPUT_DIR / "subs.txt"
    if subs_file.exists() and subs_file.stat().st_size > 0:
        # Check if subs are from example.com (old test data)
        with open(subs_file, "r", encoding="utf-8") as f:
            first_lines = [l.strip() for l in f if l.strip()][:10]
            if first_lines and all("example.com" in line or "example.org" in line for line in first_lines):
                log("WARNING: Found old example.com subdomains. Clearing for fresh scan...", "WARNING")
                subs_file.unlink()
            else:
                log("Found existing subdomains file, using it")
                mark_stage_complete("recon")
                return True
    
    # Run quick recon
    subs_output = OUTPUT_DIR / "subs.txt"
    all_subs = []
    
    # Separate root domains from subdomains
    root_domains = []
    existing_subdomains = []
    
    for target in targets:
        # Check if target is already a subdomain (has 3+ parts: subdomain.domain.tld)
        parts = target.split('.')
        if len(parts) >= 3:  # subdomain.domain.tld format
            existing_subdomains.append(target)
            log(f"Detected as subdomain (skipping enumeration): {target}")
        else:
            root_domains.append(target)
    
    # Add existing subdomains directly
    all_subs.extend(existing_subdomains)
    if existing_subdomains:
        log(f"Added {len(existing_subdomains)} existing subdomains directly")
    
    # Enumerate subdomains only for root domains
    # Use parallel processing if speed config allows
    import os
    parallel_domains = int(os.getenv("PARALLEL_DOMAINS", "1"))
    
    if parallel_domains > 1 and len(root_domains) > 1:
        log(f"Using parallel enumeration ({parallel_domains} domains at once)")
        # Parallel enumeration (speed optimized)
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=parallel_domains) as executor:
            futures = []
            for target in root_domains:
                future = executor.submit(_enumerate_single_domain, target, all_subs)
                futures.append(future)
            concurrent.futures.wait(futures)
    else:
        # Sequential enumeration
        for target in root_domains:
            _enumerate_single_domain(target, all_subs)
    
    # Deduplicate and save
    unique_subs = sorted(set(filter(None, all_subs)))
    if unique_subs:
        with open(subs_output, "w", encoding="utf-8") as f:
            f.write("\n".join(unique_subs))
        log(f"Found {len(unique_subs)} unique subdomains")
    
    mark_stage_complete("recon")
    return True


def stage_2_httpx(resume: bool = False) -> bool:
    """Stage 2: HTTP probing - find alive endpoints"""
    if resume and is_stage_complete("httpx"):
        log("Skipping httpx (already complete)")
        return True
    
    log("=" * 60)
    log("STAGE 2: HTTP Probing")
    log("=" * 60)
    
    # Check if http.json already exists
    http_file = OUTPUT_DIR / "http.json"
    if http_file.exists() and http_file.stat().st_size > 0:
        log("Found existing http.json, using it")
        mark_stage_complete("httpx")
        return True
    
    # Check for subs.txt
    subs_file = OUTPUT_DIR / "subs.txt"
    if not subs_file.exists() or subs_file.stat().st_size == 0:
        log("ERROR: subs.txt not found. Run recon first.", "ERROR")
        return False
    
    if not check_tool("httpx"):
        log("ERROR: httpx not installed", "ERROR")
        return False
    
    log("Probing alive endpoints...")
    
    # Get optimized rate limit and threads from speed config
    import os
    rate_limit = int(os.getenv("HTTPX_RATE_LIMIT", "50"))
    threads = int(os.getenv("HTTPX_THREADS", "50"))
    timeout = int(os.getenv("HTTPX_TIMEOUT", "10"))
    
    cmd = [
        "httpx",
        "-l", str(subs_file),
        "-json",
        "-o", str(http_file),
        "-status-code",
        "-title",
        "-content-length",
        "-tech-detect",
        "-rate-limit", str(rate_limit),
        "-threads", str(threads),
        "-timeout", str(timeout),
        "-retries", "2",
        "-silent"
    ]
    
    success, output = run_command(cmd, "httpx probing", timeout=1800)
    if success:
        # Count results
        try:
            with open(http_file, "r", encoding="utf-8") as f:
                lines = [l.strip() for l in f if l.strip()]
                count = len(lines)
                log(f"Found {count} alive endpoints")
        except:
            log("Could not count httpx results", "WARNING")
    
    mark_stage_complete("httpx")
    return success


def stage_3_high_roi_scan(resume: bool = False) -> bool:
    """Stage 3: High-ROI vulnerability scanning"""
    if resume and is_stage_complete("high_roi_scan"):
        log("Skipping high-ROI scan (already complete)")
        return True
    
    log("=" * 60)
    log("STAGE 3: High-ROI Vulnerability Scanning")
    log("=" * 60)
    
    http_file = OUTPUT_DIR / "http.json"
    if not http_file.exists():
        log("ERROR: http.json not found. Run httpx first.", "ERROR")
        return False
    
    if not check_tool("nuclei"):
        log("ERROR: nuclei not installed", "ERROR")
        return False
    
    # Extract URLs from http.json
    urls_file = ROI_OUTPUT_DIR / "urls.txt"
    try:
        urls = []
        
        # Check file size first
        if http_file.stat().st_size == 0:
            log("ERROR: http.json is empty. Re-running httpx...", "ERROR")
            # Force re-run httpx
            mark_stage_complete("httpx", False)  # Mark as incomplete
            if not stage_2_httpx(resume=False):
                return False
            # Re-read the file
            if not http_file.exists() or http_file.stat().st_size == 0:
                log("ERROR: Still no URLs after httpx re-run", "ERROR")
                return False
        
        with open(http_file, "r", encoding="utf-8") as f:
            content = f.read().strip()
            
            # Try parsing as single JSON array first
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            if "url" in item:
                                urls.append(item["url"])
                            elif "input" in item:
                                urls.append(item["input"])
                            elif "host" in item:
                                # Construct URL from host
                                host = item["host"]
                                scheme = item.get("scheme", "https")
                                path = item.get("path", "")
                                port = item.get("port", "")
                                if port and port not in ["80", "443"]:
                                    url = f"{scheme}://{host}:{port}{path}"
                                else:
                                    url = f"{scheme}://{host}{path}"
                                urls.append(url)
                    if urls:
                        log(f"Parsed {len(urls)} URLs from JSON array format")
            except json.JSONDecodeError:
                # Try NDJSON format (line by line)
                f.seek(0)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        if isinstance(data, dict):
                            if "url" in data:
                                urls.append(data["url"])
                            elif "input" in data:
                                urls.append(data["input"])
                            elif "host" in data:
                                # Construct URL from host
                                host = data["host"]
                                scheme = data.get("scheme", "https")
                                path = data.get("path", "")
                                port = data.get("port", "")
                                if port and port not in ["80", "443"]:
                                    url = f"{scheme}://{host}:{port}{path}"
                                else:
                                    url = f"{scheme}://{host}{path}"
                                urls.append(url)
                    except json.JSONDecodeError:
                        continue
        
        # Deduplicate URLs
        urls = list(set(urls))
        
        if not urls:
            log("ERROR: No URLs found in http.json after parsing. The file may be empty or malformed.", "ERROR")
            log("Attempting to regenerate http.json...", "INFO")
            # Force re-run httpx
            mark_stage_complete("httpx", False)
            if not stage_2_httpx(resume=False):
                return False
            # Try again
            return stage_3_high_roi_scan(resume=False)
        
        with open(urls_file, "w", encoding="utf-8") as f:
            f.write("\n".join(urls))
        
        log(f"Extracted {len(urls)} URLs for scanning")
    except Exception as e:
        log(f"ERROR: Failed to extract URLs: {e}", "ERROR")
        import traceback
        log(traceback.format_exc(), "ERROR")
        return False
    
    # Run high-ROI Nuclei scan
    roi_findings_file = ROI_OUTPUT_DIR / "high_roi_findings.json"
    
    log("Running high-ROI Nuclei scan (focusing on critical/high vulnerabilities)...")
    
    # Focus on high-value tags
    tags_str = ",".join(HIGH_VALUE_TAGS)
    
    # Get optimized Nuclei config from speed
    import os
    nuclei_rate_limit = int(os.getenv("NUCLEI_RATE_LIMIT", "30"))
    nuclei_concurrency = int(os.getenv("NUCLEI_CONCURRENCY", "50"))
    nuclei_timeout = int(os.getenv("NUCLEI_TIMEOUT", "10"))
    
    cmd = [
        "nuclei",
        "-l", str(urls_file),
        "-tags", tags_str,
        "-severity", "critical,high,medium",
        "-json",
        "-o", str(roi_findings_file),
        "-rate-limit", str(nuclei_rate_limit),
        "-c", str(nuclei_concurrency),  # Concurrency for parallel processing
        "-timeout", str(nuclei_timeout),
        "-retries", "1",
        "-exclude-tags", "dos,fuzzing,malware,intrusive",
        "-silent"
    ]
    
    success, output = run_command(cmd, "High-ROI Nuclei scan", timeout=3600)
    
    # Process results
    if roi_findings_file.exists():
        try:
            # Convert NDJSON to JSON array
            findings = []
            with open(roi_findings_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            findings.append(json.loads(line))
                        except:
                            continue
            
            if findings:
                # Save as JSON array
                with open(roi_findings_file, "w", encoding="utf-8") as f:
                    json.dump(findings, f, indent=2, ensure_ascii=False)
                
                # Count by severity
                severity_counts = {"critical": 0, "high": 0, "medium": 0}
                for finding in findings:
                    sev = finding.get("info", {}).get("severity", "").lower()
                    if sev in severity_counts:
                        severity_counts[sev] += 1
                
                log(f"Found {len(findings)} high-ROI vulnerabilities:")
                log(f"  - Critical: {severity_counts['critical']}")
                log(f"  - High: {severity_counts['high']}")
                log(f"  - Medium: {severity_counts['medium']}")
        except Exception as e:
            log(f"WARNING: Failed to process findings: {e}", "WARNING")
    
    mark_stage_complete("high_roi_scan")
    return True


def stage_4_secrets_scan(resume: bool = False) -> bool:
    """Stage 4: Secrets and credentials scanning"""
    if resume and is_stage_complete("secrets_scan"):
        log("Skipping secrets scan (already complete)")
        return True
    
    log("=" * 60)
    log("STAGE 4: Secrets & Credentials Scanning")
    log("=" * 60)
    
    http_file = OUTPUT_DIR / "http.json"
    if not http_file.exists():
        log("ERROR: http.json not found", "ERROR")
        return False
    
    if not check_tool("nuclei"):
        log("ERROR: nuclei not installed", "ERROR")
        return False
    
    # Extract URLs
    urls_file = ROI_OUTPUT_DIR / "urls.txt"
    if not urls_file.exists():
        # Extract from http.json
        try:
            with open(http_file, "r", encoding="utf-8") as f:
                urls = []
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            if isinstance(data, dict) and "url" in data:
                                urls.append(data["url"])
                            elif isinstance(data, list):
                                for item in data:
                                    if isinstance(item, dict) and "url" in item:
                                        urls.append(item["url"])
                        except:
                            continue
            
            if urls:
                with open(urls_file, "w", encoding="utf-8") as f:
                    f.write("\n".join(urls))
        except Exception as e:
            log(f"ERROR: Failed to extract URLs: {e}", "ERROR")
            return False
    
    secrets_file = ROI_OUTPUT_DIR / "secrets_found.json"
    
    log("Scanning for exposed secrets and credentials...")
    
    # Get optimized Nuclei config
    import os
    nuclei_rate_limit = int(os.getenv("NUCLEI_RATE_LIMIT", "30"))
    nuclei_concurrency = int(os.getenv("NUCLEI_CONCURRENCY", "50"))
    nuclei_timeout = int(os.getenv("NUCLEI_TIMEOUT", "10"))
    
    cmd = [
        "nuclei",
        "-l", str(urls_file),
        "-tags", "credential-disclosure,exposed,secrets,api-key,github-token,aws-key,azure-key,gcp-key",
        "-severity", "critical,high,medium",
        "-json",
        "-o", str(secrets_file),
        "-rate-limit", str(nuclei_rate_limit),
        "-c", str(nuclei_concurrency),
        "-timeout", str(nuclei_timeout),
        "-retries", "1",
        "-silent"
    ]
    
    success, output = run_command(cmd, "Secrets scan", timeout=1800)
    
    if secrets_file.exists():
        try:
            findings = []
            with open(secrets_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            findings.append(json.loads(line))
                        except:
                            continue
            
            if findings:
                with open(secrets_file, "w", encoding="utf-8") as f:
                    json.dump(findings, f, indent=2, ensure_ascii=False)
                
                log(f"⚠️  Found {len(findings)} exposed secrets/credentials!")
                for finding in findings[:5]:  # Show first 5
                    name = finding.get("info", {}).get("name", "Unknown")
                    url = finding.get("matched-at", "Unknown")
                    log(f"  - {name} at {url}")
        except Exception as e:
            log(f"WARNING: Failed to process secrets: {e}", "WARNING")
    
    mark_stage_complete("secrets_scan")
    return True


def stage_5_api_discovery(resume: bool = False) -> bool:
    """Stage 5: API endpoint discovery and testing"""
    if resume and is_stage_complete("api_discovery"):
        log("Skipping API discovery (already complete)")
        return True
    
    log("=" * 60)
    log("STAGE 5: API Endpoint Discovery")
    log("=" * 60)
    
    http_file = OUTPUT_DIR / "http.json"
    if not http_file.exists():
        log("ERROR: http.json not found", "ERROR")
        return False
    
    if not check_tool("httpx") or not check_tool("nuclei"):
        log("ERROR: Required tools not installed", "ERROR")
        return False
    
    # Extract base URLs
    try:
        base_urls = set()
        with open(http_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        data = json.loads(line)
                        url = data.get("url", "") if isinstance(data, dict) else ""
                        if url:
                            # Extract base URL
                            from urllib.parse import urlparse
                            parsed = urlparse(url)
                            base = f"{parsed.scheme}://{parsed.netloc}"
                            base_urls.add(base)
                    except:
                        continue
        
        if not base_urls:
            log("No base URLs found", "WARNING")
            return False
        
        api_paths_file = ROI_OUTPUT_DIR / "api_paths.txt"
        
        # Import enhanced API scanner
        try:
            sys.path.insert(0, str(SCRIPT_DIR))
            from api_vulnerability_scanner import APIVulnerabilityScanner
            use_enhanced_api = True
        except ImportError:
            APIVulnerabilityScanner = None
            use_enhanced_api = False
        
        if use_enhanced_api:
            log("Using enhanced API scanner (hacking APIs PDF methodology)")
            api_endpoints = APIVulnerabilityScanner.discover_api_endpoints(list(base_urls))
            with open(api_paths_file, "w", encoding="utf-8") as f:
                f.write("\n".join(api_endpoints) + "\n")
            log(f"Generated {len(api_endpoints)} API endpoint paths (enhanced discovery)")
        else:
            with open(api_paths_file, "w", encoding="utf-8") as f:
                for base in base_urls:
                    # Common API paths
                    paths = [
                        f"{base}/api", f"{base}/api/v1", f"{base}/api/v2",
                        f"{base}/v1", f"{base}/v2", f"{base}/graphql",
                        f"{base}/graphiql", f"{base}/swagger", f"{base}/swagger.json",
                        f"{base}/openapi.json", f"{base}/api-docs"
                    ]
                    f.write("\n".join(paths) + "\n")
        
        # Probe API endpoints
        api_results_file = ROI_OUTPUT_DIR / "api_endpoints.json"
        log("Probing API endpoints...")
        
        # Use os module that's already imported at top of file
        cmd = [
            "httpx",
            "-l", str(api_paths_file),
            "-json",
            "-o", str(api_results_file),
            "-status-code",
            "-title",
            "-rate-limit", str(os.getenv("HTTPX_RATE_LIMIT", "50")),
            "-threads", str(os.getenv("HTTPX_THREADS", "50")),
            "-timeout", str(os.getenv("HTTPX_TIMEOUT", "10")),
            "-match-code", "200,201,202,300,301,302",
            "-silent"
        ]
        
        success, output = run_command(cmd, "API endpoint probing", timeout=600)
        
        # Scan API endpoints with Nuclei
        if api_results_file.exists():
            log("Scanning API endpoints for vulnerabilities...")
            api_vulns_file = ROI_OUTPUT_DIR / "api_vulnerabilities.json"
            
            # os is already imported at top of file
            cmd = [
                "nuclei",
                "-l", str(api_paths_file),
                "-tags", "api,graphql,swagger,openapi,graphql-introspection,rest,oauth,jwt",
                "-severity", "critical,high,medium",
                "-json",
                "-o", str(api_vulns_file),
                "-rate-limit", str(os.getenv("NUCLEI_RATE_LIMIT", "30")),
                "-c", str(os.getenv("NUCLEI_CONCURRENCY", "50")),
                "-timeout", str(os.getenv("NUCLEI_TIMEOUT", "10")),
                "-silent"
            ]
            
            run_command(cmd, "API vulnerability scan", timeout=1800)
            
            if api_vulns_file.exists():
                findings = []
                with open(api_vulns_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                findings.append(json.loads(line))
                            except:
                                continue
                
                if findings:
                    with open(api_vulns_file, "w", encoding="utf-8") as f:
                        json.dump(findings, f, indent=2, ensure_ascii=False)
                    log(f"Found {len(findings)} API vulnerabilities")
        
    except Exception as e:
        log(f"ERROR: API discovery failed: {e}", "ERROR")
        return False
    
    mark_stage_complete("api_discovery")
    return True


def stage_6_5_exploit_discoveries(resume: bool = False) -> bool:
    """
    STAGE 6.5: Ultra-Fast Parallel Exploitation
    Actually tests discovered endpoints and confirms vulnerabilities
    This bridges the gap between discovery and value
    """
    log("=" * 60)
    log("STAGE 6.5: Ultra-Fast Parallel Exploitation")
    log("=" * 60)
    
    try:
        # Import ultra-fast exploiter
        sys.path.insert(0, str(SCRIPT_DIR))
        try:
            from ultra_fast_exploiter import UltraFastExploiter
        except ImportError:
            log("WARNING: Ultra-fast exploiter not available. Skipping exploitation stage.", "WARNING")
            return True
        
        # Load discovered endpoints from all sources (not just one program)
        endpoints = []
        
        # Try multiple locations for endpoints
        endpoint_sources = [
            ROI_OUTPUT_DIR / "api_vulnerabilities.json",
            ROI_OUTPUT_DIR / "api_endpoints.json",
            OUTPUT_DIR / "http.json",
            OUTPUT_DIR / "api-endpoints.json"
        ]
        
        # Also check program-specific directories
        if OUTPUT_DIR.exists():
            for program_dir in OUTPUT_DIR.iterdir():
                if program_dir.is_dir():
                    program_endpoints = program_dir / "discovered_endpoints.json"
                    if program_endpoints.exists():
                        endpoint_sources.append(program_endpoints)
        
        for endpoint_file in endpoint_sources:
            if endpoint_file.exists():
                try:
                    with open(endpoint_file) as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            for item in data:
                                if isinstance(item, dict):
                                    url = item.get("url") or item.get("input") or item.get("endpoint")
                                    if url:
                                        endpoints.append(url)
                                elif isinstance(item, str):
                                    endpoints.append(item)
                        elif isinstance(data, dict):
                            endpoint_list = data.get("endpoints", []) or data.get("data", [])
                            endpoints.extend(endpoint_list)
                except Exception as e:
                    log(f"WARNING: Failed to load endpoints from {endpoint_file}: {e}", "WARNING")
        
        # Deduplicate endpoints
        endpoints = list(set(endpoints))
        
        if not endpoints:
            log("No endpoints found to exploit. Skipping exploitation stage.", "WARNING")
            return True
        
        log(f"Found {len(endpoints)} endpoints to exploit from all programs")
        
        # Generate test cases
        test_cases = [
            {"type": "auth_bypass"},
            {"type": "idor"},
            {"type": "rate_limit"},
            {"type": "api_mass_assignment", "payload": {"role": "admin", "is_admin": True}},
            {"type": "generic"}
        ]
        
        # Create exploiter - use universal output directory
        output_dir = OUTPUT_DIR / "exploitation"
        output_dir.mkdir(parents=True, exist_ok=True)
        exploiter = UltraFastExploiter(output_dir, max_concurrent=100)
        
        # Run exploitation (async, falls back to sync)
        log("Starting ultra-fast parallel exploitation...")
        try:
            confirmed = asyncio.run(exploiter.exploit_all_async(endpoints, test_cases))
        except Exception as e:
            log(f"Async failed, using sync mode: {e}", "WARNING")
            confirmed = exploiter.exploit_all_sync(endpoints, test_cases)
        
        log(f"Exploitation complete: {len(confirmed)} confirmed vulnerabilities")
        log(f"Estimated value: ${sum(r.get('value', 0) for r in confirmed):,}")
        
        return True
        
    except Exception as e:
        log(f"Exploitation stage failed: {e}", "ERROR")
        return False

def stage_6_generate_reports(resume: bool = False) -> bool:
    """Stage 6: Generate submission-ready reports with advanced classification"""
    if resume and is_stage_complete("reports"):
        log("Skipping report generation (already complete)")
        return True
    
    log("=" * 60)
    log("STAGE 6: Generating Submission-Ready Reports")
    log("=" * 60)
    
    reports_dir = ROI_OUTPUT_DIR / "submission_reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    all_findings = []
    
    # Collect findings from all scans
    finding_files = [
        ROI_OUTPUT_DIR / "high_roi_findings.json",
        ROI_OUTPUT_DIR / "secrets_found.json",
        ROI_OUTPUT_DIR / "api_vulnerabilities.json"
    ]
    
    for findings_file in finding_files:
        if findings_file.exists():
            try:
                with open(findings_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        all_findings.extend(data)
                    elif isinstance(data, dict):
                        all_findings.append(data)
            except Exception as e:
                log(f"WARNING: Failed to load {findings_file}: {e}", "WARNING")
    
    if not all_findings:
        log("No findings to report", "WARNING")
        mark_stage_complete("reports")
        return True
    
    # Deduplicate findings
    seen = set()
    unique_findings = []
    for finding in all_findings:
        template_id = finding.get("template-id", "")
        matched_at = finding.get("matched-at", finding.get("host", ""))
        key = f"{template_id}:{matched_at}"
        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)
    
    log(f"Processing {len(unique_findings)} unique findings...")
    
    # Scan for cryptographic vulnerabilities (from PDF methodologies)
    crypto_findings = []
    if CryptoVulnerabilityScanner:
        log("Scanning for cryptographic vulnerabilities (crypto dictionary methodology)...")
        for finding in unique_findings:
            try:
                crypto_issues = CryptoVulnerabilityScanner.scan_finding(finding)
                if crypto_issues:
                    crypto_findings.extend(crypto_issues)
                    # Add crypto findings to unique findings
                    for crypto_issue in crypto_issues:
                        # Convert to Nuclei format for consistency
                        crypto_finding = {
                            "template-id": f"crypto-{crypto_issue['type']}",
                            "matched-at": crypto_issue.get("url", ""),
                            "info": {
                                "name": crypto_issue.get("description", ""),
                                "severity": crypto_issue.get("severity", "medium"),
                                "description": crypto_issue.get("description", ""),
                                "cwe-id": crypto_issue.get("cwe", ""),
                            },
                            "crypto_analysis": crypto_issue
                        }
                        unique_findings.append(crypto_finding)
            except Exception as e:
                log(f"WARNING: Failed to scan crypto vulnerability: {e}", "WARNING")
        
        if crypto_findings:
            log(f"Found {len(crypto_findings)} cryptographic vulnerabilities!")
    
    # Analyze duplicate risk (using knowledge stack)
    if DuplicateDetector:
        log("Analyzing duplicate risk using bug bounty knowledge...")
        duplicate_report = DuplicateDetector.generate_duplicate_report(unique_findings)
        
        # Add duplicate risk to each finding
        for finding in unique_findings:
            risk_score, risk_level, details = DuplicateDetector.calculate_duplicate_risk(finding)
            finding["duplicate_risk"] = {
                "score": risk_score,
                "level": risk_level,
                "details": details,
                "recommendation": DuplicateDetector._get_recommendation(risk_score, risk_level)
            }
        
        # Filter high-risk duplicates (optional - can be enabled)
        # safe_findings, risky_findings = DuplicateDetector.filter_high_risk_duplicates(unique_findings, threshold=0.70)
        # log(f"Duplicate risk analysis: {len(safe_findings)} safe, {len(risky_findings)} high-risk")
        
        # Save duplicate report
        duplicate_report_path = ROI_OUTPUT_DIR / "duplicate_risk_analysis.json"
        with open(duplicate_report_path, "w", encoding="utf-8") as f:
            json.dump(duplicate_report, f, indent=2)
        log(f"Duplicate risk analysis saved to {duplicate_report_path}")
        
        # Log recommendations
        for rec in duplicate_report.get("recommendations", []):
            log(rec, "INFO")
    
    # Classify findings using bug bounty methodology
    classifications = []
    if BugClassifier:
        log("Classifying findings using bug bounty methodology...")
        for finding in unique_findings:
            try:
                classification = BugClassifier.classify_vulnerability(finding)
                finding["bug_classification"] = classification
                classifications.append(classification)
            except Exception as e:
                log(f"WARNING: Failed to classify finding: {e}", "WARNING")
                finding["bug_classification"] = {}
    
    # Sort by classification priority (bounty tier, then exploitability)
    def sort_key(finding):
        cls = finding.get("bug_classification", {})
        bounty_tier = cls.get("bounty_tier", "medium")
        tier_priority = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(bounty_tier, 2)
        exploitability = cls.get("exploitability_score", 0)
        base_severity = finding.get("info", {}).get("severity", "low").lower()
        severity_order = {"critical": 3, "high": 2, "medium": 1, "low": 0}
        return (tier_priority, exploitability, severity_order.get(base_severity, 0))
    
    unique_findings.sort(key=sort_key, reverse=True)
    
    # Generate individual reports
    report_count = 0
    for idx, finding in enumerate(unique_findings, 1):
        try:
            info = finding.get("info", {})
            severity = info.get("severity", "unknown").lower()
            template_id = finding.get("template-id", "unknown")
            matched_at = finding.get("matched-at", finding.get("host", "unknown"))
            name = info.get("name", template_id)
            
            # Create filename
            from urllib.parse import urlparse
            parsed = urlparse(matched_at)
            domain = parsed.netloc.replace(".", "_")
            safe_name = re.sub(r'[^\w\-_]', '_', template_id)[:50]
            filename = f"{idx:03d}_{severity}_{domain}_{safe_name}.md"
            report_path = reports_dir / filename
            
            # Get classification data
            classification = finding.get("bug_classification", {})
            primary_category = classification.get("primary_category", "unknown")
            bounty_tier = classification.get("bounty_tier", "medium")
            bounty_estimate = classification.get("bounty_estimate", {})
            exploitability = classification.get("exploitability_score", 0)
            is_api = classification.get("is_api_vulnerability", False)
            is_payment = classification.get("is_payment_related", False)
            is_crypto = classification.get("is_crypto_vulnerability", False)
            adjusted_severity = classification.get("adjusted_severity", severity)
            cwe_ids = classification.get("cwe_ids", [])
            
            # Build classification section
            classification_section = ""
            if classification:
                classification_section = f"""
## Bug Classification (Bug Bounty Methodology)

**Primary Category**: {primary_category.replace('_', ' ').title()}  
**Bounty Tier**: {bounty_tier.upper()}  
**Estimated Bounty Range**: {bounty_estimate.get('estimated_range', 'N/A')}  
**Exploitability Score**: {exploitability}/10  
**Adjusted Severity**: {adjusted_severity.upper()}

**Special Classifications**:
- API Vulnerability: {'✅ Yes' if is_api else '❌ No'}
- Payment-Related: {'✅ Yes' if is_payment else '❌ No'}
- Crypto-Related: {'✅ Yes' if is_crypto else '❌ No'}

"""
                if cwe_ids:
                    classification_section += f"**CWE IDs**: {', '.join(cwe_ids)}\n\n"
            
            # Add duplicate risk information
            duplicate_risk_section = ""
            duplicate_risk = finding.get("duplicate_risk", {})
            if duplicate_risk:
                risk_level = duplicate_risk.get("level", "unknown")
                risk_score = duplicate_risk.get("score", 0)
                recommendation = duplicate_risk.get("recommendation", "")
                
                duplicate_risk_section = f"""
## Duplicate Risk Analysis

**Risk Level**: {risk_level.upper()}  
**Risk Score**: {risk_score:.0%}  
**Recommendation**: {recommendation}

**Note**: Based on bug bounty knowledge and vulnerability patterns. Crypto vulnerabilities typically have lower duplicate rates (10-20%). Always verify uniqueness before submission.

---
"""
            
            # Generate report
            report_content = f"""# {name}

**Severity**: {adjusted_severity.upper()} ({severity.upper()} base)  
**Target**: `{matched_at}`  
**Discovered**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}  
**Template ID**: `{template_id}`  
**Bounty Tier**: {bounty_tier.upper()}  
**Estimated Value**: {bounty_estimate.get('estimated_range', 'N/A')}

{duplicate_risk_section}## Description

{info.get("description", "No description available")}

{classification_section}
## Proof of Concept

### Target URL
```
{matched_at}
```

### Request
```http
{finding.get("request", "N/A")}
```

### Response
```http
{finding.get("response", "N/A")[:2000]}
```

## Impact

{info.get("impact", "Refer to severity level and description above.")}

{f'**Impact Note**: This is a **{bounty_tier.upper()}** tier vulnerability with an estimated bounty range of **{bounty_estimate.get("estimated_range", "N/A")}** based on bug bounty program standards.' if classification else ''}

## Remediation

{info.get("remediation", "1. Review and patch the vulnerability according to the description.\n2. Implement proper input validation.\n3. Apply security best practices.")}

## Instant Submission Instructions (Get Paid Fast!)

{InstantSubmissionHelper._get_instant_submission_instructions(finding) if InstantSubmissionHelper else "Use Open Bug Bounty: https://www.openbugbounty.org"}

## References

{chr(10).join([f"- {ref}" for ref in (info.get("reference", []) if isinstance(info.get("reference"), list) else [info.get("reference")] if info.get("reference") else [])])}

---

**Report Generated**: {datetime.now().isoformat()}  
**Priority**: HIGH (Immediate ROI Target)  
**Classification Confidence**: {classification.get('classification_confidence', 0)}%
"""
            
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(report_content)
            
            report_count += 1
        except Exception as e:
            log(f"WARNING: Failed to generate report for finding {idx}: {e}", "WARNING")
    
    # Generate summary report with classification
    summary_path = ROI_OUTPUT_DIR / "ROI_SUMMARY.md"
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    bounty_tier_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    category_counts = {}
    api_count = 0
    payment_count = 0
    crypto_count = 0
    crypto_findings_list = []
    
    for finding in unique_findings:
        sev = finding.get("info", {}).get("severity", "low").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
        
        # Check for crypto scanner findings first
        if finding.get("crypto_analysis"):
            if finding not in crypto_findings_list:
                crypto_findings_list.append(finding)
                crypto_count += 1
        
        # Classification counts
        cls = finding.get("bug_classification", {})
        if cls:
            tier = cls.get("bounty_tier", "medium")
            bounty_tier_counts[tier] = bounty_tier_counts.get(tier, 0) + 1
            
            cat = cls.get("primary_category", "unknown")
            category_counts[cat] = category_counts.get(cat, 0) + 1
            
            if cls.get("is_api_vulnerability"):
                api_count += 1
            if cls.get("is_payment_related"):
                payment_count += 1
            if cls.get("is_crypto_vulnerability") and finding not in crypto_findings_list:
                crypto_findings_list.append(finding)
                crypto_count += 1
    
    # Generate classification summary if available
    classification_summary = ""
    if classifications and BugClassifier:
        classification_summary = BugClassifier.generate_classification_report(classifications)
    
    summary_content = f"""# Immediate ROI Bug Bounty Report Summary

**Generated**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}  
**Total Findings**: {len(unique_findings)}  
**Submission-Ready Reports**: {report_count}  
**🔐 Cryptographic Vulnerabilities**: {crypto_count} (from PDF knowledge integration)

---

## Severity Breakdown (Base)

- 🔴 **CRITICAL**: {severity_counts['critical']} findings
- 🟠 **HIGH**: {severity_counts['high']} findings  
- 🟡 **MEDIUM**: {severity_counts['medium']} findings
- 🟢 **LOW**: {severity_counts['low']} findings

---

## Bounty Tier Breakdown (Adjusted)

- 💰 **CRITICAL TIER**: {bounty_tier_counts['critical']} findings
- 💵 **HIGH TIER**: {bounty_tier_counts['high']} findings  
- 💴 **MEDIUM TIER**: {bounty_tier_counts['medium']} findings
- 💷 **LOW TIER**: {bounty_tier_counts['low']} findings

---

## Special Classifications

- **API Vulnerabilities**: {api_count}
- **Payment-Related**: {payment_count}  
- **Crypto-Related**: {crypto_count}

---

{classification_summary if classification_summary else ''}
## Top Findings (Priority Order - By Bounty Tier & Exploitability)

"""
    
    for idx, finding in enumerate(unique_findings[:20], 1):  # Top 20
        info = finding.get("info", {})
        severity = info.get("severity", "unknown").lower()
        matched_at = finding.get("matched-at", "unknown")
        name = info.get("name", "Unknown")
        
        # Get classification data
        cls = finding.get("bug_classification", {})
        bounty_tier = cls.get("bounty_tier", "medium") if cls else "medium"
        primary_category = cls.get("primary_category", "unknown") if cls else "unknown"
        exploitability = cls.get("exploitability_score", 0) if cls else 0
        bounty_estimate = cls.get("bounty_estimate", {}) if cls else {}
        
        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(bounty_tier, "⚪")
        
        category_label = primary_category.replace('_', ' ').title() if primary_category != "unknown" else "Unknown"
        
        summary_content += f"""### {idx}. {emoji} {name}

- **Severity**: {severity.upper()} (Adjusted: {cls.get('adjusted_severity', severity).upper() if cls else severity.upper()})
- **Bounty Tier**: {bounty_tier.upper()}
- **Category**: {category_label}
- **Exploitability**: {exploitability}/10
- **Estimated Bounty**: {bounty_estimate.get('estimated_range', 'N/A') if bounty_estimate else 'N/A'}
- **Target**: `{matched_at}`
- **Description**: {info.get("description", "N/A")[:150]}...

"""
    
    summary_content += f"""
---

## Next Steps

1. **Review individual reports** in `{reports_dir.name}/` directory
2. **Verify findings** manually before submission
3. **Submit to bug bounty platform** using the generated reports
4. **Track submissions** and follow up

---

## Files Generated

- Individual reports: `{reports_dir.name}/` ({report_count} files)
- This summary: `ROI_SUMMARY.md`
- Raw findings: `high_roi_findings.json`, `secrets_found.json`, `api_vulnerabilities.json`

---

**Status**: ✅ Ready for Submission  
**Estimated Value**: High (Critical/High findings prioritized)
"""
    
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(summary_content)
    
    log(f"Generated {report_count} submission-ready reports")
    log(f"Summary report: {summary_path}")
    
    mark_stage_complete("reports")
    return True


def main():
    """Main execution function"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Immediate ROI Bug Bounty Hunter - Idempotent automation for high-value vulnerabilities"
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from last completed stage (idempotent)"
    )
    parser.add_argument(
        "--stage",
        type=int,
        help="Run specific stage only (1-6)"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-run even if stage is complete"
    )
    
    args = parser.parse_args()
    
    # Ensure output directory exists
    ROI_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    log("=" * 60)
    log("IMMEDIATE ROI BUG BOUNTY HUNTER")
    log("=" * 60)
    log("Focus: High-value vulnerabilities for maximum profit")
    log("Targets: IDOR, Auth Bypass, Secrets, API Issues, Subdomain Takeover")
    log("=" * 60)
    
    # Check required tools
    required_tools = ["nuclei", "httpx"]
    missing_tools = [t for t in required_tools if not check_tool(t)]
    if missing_tools:
        log(f"ERROR: Missing required tools: {', '.join(missing_tools)}", "ERROR")
        log("Please install missing tools: ./install.sh", "ERROR")
        sys.exit(1)
    
    # Get targets
    targets = get_targets()
    
    # Optimize for connection speed (while maintaining OPSEC)
    speed_config = None
    if SpeedOptimizer is not None:
        log("=" * 60)
        log("Speed Optimization Detection")
        log("=" * 60)
        speed_tier = SpeedOptimizer.detect_connection_speed()
        speed_config = SpeedOptimizer.get_optimized_config(speed_tier)
        speed_config = SpeedOptimizer.optimize_for_speed(speed_config, maintain_opsec=True)
        SpeedOptimizer.apply_speed_config(speed_config)
        
        log(f"Detected connection: {speed_config['speed_label']}")
        log(f"Optimized configuration:")
        log(f"  - HTTPX Rate Limit: {speed_config['httpx_rate_limit']}/s")
        log(f"  - HTTPX Threads: {speed_config['httpx_threads']}")
        log(f"  - Nuclei Rate Limit: {speed_config['nuclei_rate_limit']}/s")
        log(f"  - Nuclei Concurrency: {speed_config['nuclei_concurrency']}")
        log(f"  - Parallel Domains: {speed_config['parallel_domains']}")
        log(f"✅ OPSEC safety maintained (max 200 req/s)")
        log("=" * 60)
    else:
        # Default configuration
        speed_config = {
            "httpx_rate_limit": 50,
            "httpx_threads": 50,
            "nuclei_rate_limit": 30,
            "nuclei_concurrency": 50,
            "parallel_domains": 1
        }
        import os
        os.environ["HTTPX_RATE_LIMIT"] = str(speed_config["httpx_rate_limit"])
        os.environ["HTTPX_THREADS"] = str(speed_config["httpx_threads"])
    
    # Validate targets for OPSEC and scope
    try:
        sys.path.insert(0, str(SCRIPT_DIR))
        from opsec_validator import OPSECValidator
        
        log("=" * 60)
        log("OPSEC & Scope Validation")
        log("=" * 60)
        
        opsec_report = OPSECValidator.generate_opsec_report(TARGETS_FILE)
        
        if not opsec_report["opsec_ready"]:
            log("⚠️  WARNING: Some targets failed OPSEC validation!", "WARNING")
            log(f"Invalid targets: {len(opsec_report['targets']['invalid'])}", "WARNING")
            
            for invalid in opsec_report["targets"]["invalid"][:5]:
                log(f"  - {invalid['target']}: {invalid['reason']}", "WARNING")
            
            if len(opsec_report["targets"]["invalid"]) > 5:
                log(f"  ... and {len(opsec_report['targets']['invalid']) - 5} more", "WARNING")
            
            log("", "WARNING")
            log("⚠️  RECOMMENDATION: Review and remove unauthorized targets", "WARNING")
            log("⚠️  Verify scope at: https://hackerone.com/programs or https://bugcrowd.com/programs", "WARNING")
            log("", "WARNING")
            
            response = input("Continue anyway? (yes/no): ").strip().lower()
            if response != "yes":
                log("Scan cancelled by user", "INFO")
                sys.exit(0)
        
        if opsec_report["warnings"]:
            log(f"⚠️  {len(opsec_report['warnings'])} targets require scope verification", "WARNING")
            for warning in opsec_report["warnings"][:3]:
                log(f"  - {warning['target']}: {warning['warning']}", "WARNING")
        
        log(f"✅ Validated {opsec_report['valid_targets']} targets", "INFO")
        log("✅ OPSEC configuration applied", "INFO")
        
        # Apply OPSEC config to environment
        opsec_config = opsec_report["opsec_config"]
        import os
        os.environ["HTTPX_RATE_LIMIT"] = str(opsec_config["rate_limiting"]["httpx_rate_limit"])
        os.environ["NUCLEI_RATE_LIMIT"] = str(opsec_config["rate_limiting"]["nuclei_rate_limit"])
        
        log("=" * 60)
        
        # Merge speed config with OPSEC config
        if speed_config:
            import os
            # Use speed config but respect OPSEC limits
            opsec_max_rate = opsec_config.get("rate_limiting", {}).get("httpx_rate_limit", 200)
            os.environ["HTTPX_RATE_LIMIT"] = str(min(speed_config["httpx_rate_limit"], opsec_max_rate))
            os.environ["HTTPX_THREADS"] = str(speed_config["httpx_threads"])
            os.environ["NUCLEI_RATE_LIMIT"] = str(min(speed_config["nuclei_rate_limit"], opsec_config.get("rate_limiting", {}).get("nuclei_rate_limit", 100)))
            os.environ["NUCLEI_CONCURRENCY"] = str(speed_config["nuclei_concurrency"])
            os.environ["PARALLEL_DOMAINS"] = str(speed_config["parallel_domains"])
            os.environ["HTTPX_TIMEOUT"] = str(max(5, int(10 * speed_config.get("timeout_multiplier", 1.0))))
            os.environ["NUCLEI_TIMEOUT"] = str(max(5, int(10 * speed_config.get("timeout_multiplier", 1.0))))
            log(f"✅ Speed optimization applied: {speed_config['speed_label']}")
            log(f"✅ OPSEC limits respected (max rate: {min(speed_config['httpx_rate_limit'], opsec_max_rate)}/s)")
        
    except ImportError:
        log("OPSEC validator not available - proceeding without validation", "WARNING")
    except Exception as e:
        log(f"WARNING: OPSEC validation failed: {e}", "WARNING")
    
    log(f"Targets: {', '.join(targets)}")
    
    # Clear status if force
    if args.force and STATUS_FILE.exists():
        STATUS_FILE.unlink()
        log("Cleared status file (force mode)")
    
    resume = args.resume and not args.force
    
    # Run stages
    stages = [
        ("1", stage_1_recon, "Reconnaissance"),
        ("2", stage_2_httpx, "HTTP Probing"),
        ("3", stage_3_high_roi_scan, "High-ROI Vulnerability Scan"),
        ("4", stage_4_secrets_scan, "Secrets & Credentials Scan"),
        ("5", stage_5_api_discovery, "API Discovery & Testing"),
        ("6.5", stage_6_5_exploit_discoveries, "Ultra-Fast Parallel Exploitation"),
        ("6", stage_6_generate_reports, "Report Generation")
    ]
    
    if args.stage:
        # Run specific stage
        stage_num = args.stage
        # Find stage by number (handles both int and float like 6.5)
        stage_found = None
        for stage_name, stage_func, description in stages:
            if stage_name == str(stage_num) or (isinstance(stage_num, float) and stage_name == str(stage_num)):
                stage_found = (stage_name, stage_func, description)
                break
        
        if not stage_found:
            log(f"ERROR: Invalid stage number: {stage_num}. Valid stages: {', '.join([s[0] for s in stages])}", "ERROR")
            sys.exit(1)
        
        stage_name, stage_func, description = stage_found
        log(f"Running Stage {stage_name}: {description}")
        targets = get_targets()  # Get targets for stage 1
        if stage_name == "1":
            success = stage_func(targets, resume=False if args.force else resume)
        else:
            success = stage_func(resume=False if args.force else resume)
        if not success:
            log(f"Stage {stage_name} failed", "ERROR")
            sys.exit(1)
    else:
        # Run all stages
        targets = get_targets()  # Get targets once
        for stage_name, stage_func, description in stages:
            log(f"\nStarting Stage {stage_name}: {description}")
            # Stage 1 needs targets parameter
            if stage_name == "1":
                success = stage_func(targets, resume)
            else:
                success = stage_func(resume)
            if not success:
                log(f"Stage {stage_name} failed, but continuing...", "WARNING")
    
    log("=" * 60)
    log("IMMEDIATE ROI HUNT COMPLETE")
    log("=" * 60)
    log(f"Check reports in: {ROI_OUTPUT_DIR}")
    log(f"Summary: {ROI_OUTPUT_DIR / 'ROI_SUMMARY.md'}")
    log("=" * 60)


if __name__ == "__main__":
    main()


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
