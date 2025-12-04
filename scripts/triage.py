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
Triage / Correlator Agent
Filters false positives and scores findings by severity and exploitability
Input: ~/recon-stack/output/nuclei-findings.json
Output: ~/recon-stack/output/triage.json
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
import re

# Paths
SCRIPT_DIR = Path(__file__).parent
REPO_ROOT = SCRIPT_DIR.parent
OUTPUT_DIR = REPO_ROOT / "output"
NUCLEI_FILE = OUTPUT_DIR / "nuclei-findings.json"
TRIAGE_OUTPUT = OUTPUT_DIR / "triage.json"
LOG_FILE = OUTPUT_DIR / "triage.log"

# Severity scores
SEVERITY_SCORES = {
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}

# False positive indicators (keywords that might indicate false positives)
# Pre-compile regex patterns for better performance (avoids recompilation on each call)
FP_INDICATORS_RAW = [
    r"test\.example\.com",
    r"localhost",
    r"127\.0\.0\.1",
    r"example\.com",
]
FP_INDICATORS = [re.compile(pattern, re.IGNORECASE) for pattern in FP_INDICATORS_RAW]


def log(message: str):
    """Write log message to both stdout and log file"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_msg = f"[{timestamp}] {message}"
    print(log_msg)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_msg + "\n")


def is_false_positive(finding: Dict[str, Any]) -> bool:
    """Check if a finding might be a false positive"""
    url = finding.get("matched-at", finding.get("host", ""))
    info = finding.get("info", {})
    # Keep description original (not lowercased) since regex patterns are case-insensitive
    description = info.get("description", "")
    
    # Check against pre-compiled FP indicator patterns (performance optimization)
    # Note: patterns use re.IGNORECASE so both url and description matching is case-insensitive
    for pattern in FP_INDICATORS:
        if pattern.search(url):
            return True
        if pattern.search(description):
            return True
    
    # Check for common false positive patterns (these use lowercase comparison)
    description_lower = description.lower()
    name = finding.get("name", "").lower()
    if "test" in name and ("environment" in description_lower or "staging" in description_lower):
        # Might be intentional test endpoints
        pass
    
    # Skip very low severity info findings that are often noise
    severity = info.get("severity", "info").lower()
    if severity == "info" and "exposed" not in description_lower and "leak" not in description_lower:
        # Many info-level findings are informational only
        pass
    
    # Check for duplicate/very similar findings
    # (This is a simple check, can be enhanced with more sophisticated deduplication)
    
    return False


def calculate_exploitability_score(finding: Dict[str, Any]) -> int:
    """Calculate exploitability score (1-10) based on multiple factors"""
    score = 0
    info = finding.get("info", {})
    
    # Base score from severity
    severity = info.get("severity", "info").lower()
    score += SEVERITY_SCORES.get(severity, 1)
    
    # Bonus for verified findings (verified means exploit confirmed)
    if info.get("verified", False):
        score += 2
    
    # Bonus for CVE references (indicates known vulnerability)
    if info.get("cve-id"):
        score += 1
        # Multiple CVEs indicate more serious issue
        if isinstance(info.get("cve-id"), list) and len(info.get("cve-id", [])) > 1:
            score += 1
    
    # Bonus for CWE references (indicates vulnerability class)
    if info.get("cwe-id"):
        score += 1
    
    # Bonus for findings with exploit references
    reference = info.get("reference", [])
    if reference:
        ref_str = " ".join(reference if isinstance(reference, list) else [reference]).lower()
        if any(x in ref_str for x in ["exploit", "poc", "proof-of-concept", "github.com"]):
            score += 1
    
    # Bonus for findings with classification metadata (more reliable)
    if "classification" in info:
        score += 1
    
    # Penalty for info-level findings (usually less exploitable)
    if severity == "info":
        score = max(1, score - 1)
    
    # Cap at 10
    return min(score, 10)


def calculate_cvss_score(finding: Dict[str, Any]) -> float:
    """Extract or estimate CVSS score"""
    info = finding.get("info", {})
    
    # If CVSS score is provided, use it
    if "classification" in info:
        cvss = info.get("classification", {}).get("cvss-score")
        if cvss:
            return float(cvss)
    
    # Estimate based on severity
    severity = info.get("severity", "info").lower()
    cvss_map = {
        "info": 0.0,
        "low": 3.0,
        "medium": 5.0,
        "high": 7.5,
        "critical": 9.5,
    }
    return cvss_map.get(severity, 0.0)


def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove duplicate findings based on template-id and matched URL"""
    seen = set()
    unique = []
    
    for finding in findings:
        template_id = finding.get("template-id", "")
        matched_at = finding.get("matched-at", finding.get("host", ""))
        
        # Create unique key
        key = f"{template_id}:{matched_at}"
        
        if key not in seen:
            seen.add(key)
            unique.append(finding)
        else:
            log(f"Removing duplicate: {template_id} at {matched_at}")
    
    return unique


def triage_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Process and score findings"""
    triaged = []
    fp_count = 0
    
    # First, deduplicate
    log(f"Deduplicating {len(findings)} findings...")
    findings = deduplicate_findings(findings)
    log(f"After deduplication: {len(findings)} unique findings")
    
    for finding in findings:
        # Skip false positives
        if is_false_positive(finding):
            fp_count += 1
            log(f"Skipping potential false positive: {finding.get('name', 'unknown')} at {finding.get('matched-at', 'unknown')}")
            continue
        
        # Add scoring
        triaged_finding = finding.copy()
        exploit_score = calculate_exploitability_score(finding)
        cvss_score = calculate_cvss_score(finding)
        
        triaged_finding["triage"] = {
            "exploitability_score": exploit_score,
            "cvss_score": cvss_score,
            "triaged_at": datetime.now().isoformat(),
            "priority": "high" if exploit_score >= 7 else ("medium" if exploit_score >= 4 else "low"),
        }
        
        triaged.append(triaged_finding)
    
    if fp_count > 0:
        log(f"Filtered {fp_count} potential false positives")
    
    # Sort by exploitability score (descending), then by CVSS
    triaged.sort(key=lambda x: (x["triage"]["exploitability_score"], x["triage"]["cvss_score"]), reverse=True)
    
    return triaged


def main():
    """Main triage function"""
    import os
    log("=== Triage Agent Starting ===")
    
    # Ensure output directory exists
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # Check if we should filter to medium+ severity only (bug bounty focus)
    MIN_SEVERITY = os.getenv("TRIAGE_MIN_SEVERITY", "medium").lower()
    severity_priority = ["critical", "high", "medium", "low", "info"]
    
    # Load nuclei findings
    if not NUCLEI_FILE.exists():
        log(f"ERROR: {NUCLEI_FILE} not found")
        log("Please run vulnerability hunter agent first (scripts/run_nuclei.sh)")
        sys.exit(1)
    
    try:
        with open(NUCLEI_FILE, "r", encoding="utf-8") as f:
            findings = json.load(f)
    except json.JSONDecodeError as e:
        log(f"ERROR: Invalid JSON in {NUCLEI_FILE}: {e}")
        sys.exit(1)
    except Exception as e:
        log(f"ERROR: Failed to read {NUCLEI_FILE}: {e}")
        sys.exit(1)
    
    if not isinstance(findings, list):
        findings = [findings] if findings else []
    
    log(f"Loaded {len(findings)} findings from Nuclei")
    
    # Filter by minimum severity if specified
    if MIN_SEVERITY in severity_priority:
        min_idx = severity_priority.index(MIN_SEVERITY)
        allowed_severities = severity_priority[:min_idx+1]
        original_count = len(findings)
        findings = [
            f for f in findings 
            if f.get("info", {}).get("severity", "info").lower() in allowed_severities
        ]
        filtered_count = original_count - len(findings)
        if filtered_count > 0:
            log(f"Filtered {filtered_count} findings below {MIN_SEVERITY} severity (bug bounty focus)")
            log(f"Remaining: {len(findings)} {MIN_SEVERITY}+ severity findings")
    
    # Triage findings
    triaged = triage_findings(findings)
    
    log(f"After triage: {len(triaged)} findings remaining")
    
    # Write output
    with open(TRIAGE_OUTPUT, "w", encoding="utf-8") as f:
        json.dump(triaged, f, indent=2, ensure_ascii=False)
    
    # Summary by severity
    if triaged:
        severity_counts = {}
        for finding in triaged:
            sev = finding.get("info", {}).get("severity", "unknown").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        log("")
        log("=== Triage Summary ===")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                log(f"  {sev.capitalize()}: {count} findings")
        
        medium_plus = sum(severity_counts.get(s, 0) for s in ["critical", "high", "medium"])
        if medium_plus > 0:
            log(f"  >>> Bug Bounty Priority (Medium+): {medium_plus} findings")
    
    log("=== Triage Agent Complete ===")
    log(f"Output: {TRIAGE_OUTPUT}")


if __name__ == "__main__":
    main()


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
