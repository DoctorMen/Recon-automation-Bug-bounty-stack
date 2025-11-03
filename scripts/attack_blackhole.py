#!/usr/bin/env python3
"""
Blackhole DEX Attack Script - Code4rena
Target: Blackhole DEX on Avalanche
Max Bounty: $100,000 in $BLACK tokens
Focus: Smart contracts, API endpoints, web frontend

Using:
- hackingapis.pdf methodology for API testing
- penetrationtesting.pdf methodology for web/smart contract testing
- DeFi security best practices for smart contract testing
- Known issues filtering to avoid duplicates
"""

import json
import sys
import subprocess
import time
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
import os
import re

# Paths
SCRIPT_DIR = Path(__file__).parent
REPO_ROOT = SCRIPT_DIR.parent
OUTPUT_DIR = REPO_ROOT / "output"
BLACKHOLE_OUTPUT_DIR = OUTPUT_DIR / "blackhole_code4rena"
BLACKHOLE_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Import modules
sys.path.insert(0, str(SCRIPT_DIR))
try:
    from code4rena_integration import Code4renaIntegration
except ImportError:
    Code4renaIntegration = None

try:
    from api_vulnerability_scanner import APIVulnerabilityScanner
except ImportError:
    APIVulnerabilityScanner = None

try:
    from crypto_vulnerability_scanner import CryptoVulnerabilityScanner
except ImportError:
    CryptoVulnerabilityScanner = None

try:
    from penetration_testing_enhancer import PenetrationTestingEnhancer
except ImportError:
    PenetrationTestingEnhancer = None

def log(message: str, level: str = "INFO"):
    """Log message with timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")
    log_file = BLACKHOLE_OUTPUT_DIR / "blackhole_attack.log"
    with open(log_file, "a") as f:
        f.write(f"[{timestamp}] [{level}] {message}\n")

def discover_blackhole_endpoints():
    """Discover Blackhole DEX endpoints"""
    log("=" * 60)
    log("DISCOVERING BLACKHOLE DEX ENDPOINTS")
    log("=" * 60)
    
    base_urls = [
        "https://blackhole-exchange.com",
        "https://app.blackhole-exchange.com",
        "https://api.blackhole-exchange.com",
        "https://www.blackhole-exchange.com"
    ]
    
    discovered_endpoints = []
    
    if APIVulnerabilityScanner:
        log("Using API vulnerability scanner to discover endpoints...")
        discovered_endpoints = APIVulnerabilityScanner.discover_api_endpoints(base_urls)
        log(f"Discovered {len(discovered_endpoints)} potential API endpoints")
    else:
        log("API scanner not available, using manual endpoint list")
        # Manual high-value endpoints for DEX
        discovered_endpoints = [
            "https://app.blackhole-exchange.com/api/v1/pairs",
            "https://app.blackhole-exchange.com/api/v1/tokens",
            "https://app.blackhole-exchange.com/api/v1/pools",
            "https://app.blackhole-exchange.com/api/v1/swaps",
            "https://app.blackhole-exchange.com/api/v1/quote",
            "https://app.blackhole-exchange.com/api/v1/approve",
            "https://app.blackhole-exchange.com/api/v1/transactions",
            "https://app.blackhole-exchange.com/api/v1/user",
            "https://app.blackhole-exchange.com/api/v1/liquidity",
            "https://app.blackhole-exchange.com/api/v1/farms",
            "https://api.blackhole-exchange.com/graphql",
            "https://api.blackhole-exchange.com/swagger.json",
            "https://api.blackhole-exchange.com/openapi.json"
        ]
    
    endpoints_file = BLACKHOLE_OUTPUT_DIR / "discovered_endpoints.json"
    with open(endpoints_file, "w") as f:
        json.dump(discovered_endpoints, f, indent=2)
    
    log(f"Saved {len(discovered_endpoints)} endpoints to {endpoints_file}")
    return discovered_endpoints

def test_dex_vulnerabilities_with_pt():
    """Test DEX-specific vulnerabilities using penetration testing methodology"""
    log("=" * 60)
    log("TESTING DEX VULNERABILITIES WITH PT METHODOLOGY")
    log("=" * 60)
    
    if not Code4renaIntegration:
        log("Code4rena integration not available", "WARNING")
        return []
    
    test_cases = Code4renaIntegration.get_dex_test_cases()
    findings = []
    
    for test_case in test_cases:
        finding = {
            "type": test_case["type"],
            "severity": test_case["severity"],
            "title": f"{test_case['type'].replace('_', ' ').title()} Vulnerability",
            "description": test_case["description"],
            "methodology": f"{test_case['methodology']} + penetrationtesting.pdf methodology",
            "tests": test_case["tests"],
            "focus": test_case["focus"],
            "program": "blackhole",
            "platform": "code4rena"
        }
        
        # Enhance with PT methodology
        if PenetrationTestingEnhancer:
            finding = PenetrationTestingEnhancer.enhance_finding_with_pt_methodology(finding)
            pt_analysis = finding.get("pt_analysis", {})
            if pt_analysis:
                finding["exploitation_steps"] = pt_analysis.get("exploitation_steps", [])
                finding["impact_assessment"] = pt_analysis.get("impact_assessment", {})
                log(f"Enhanced {test_case['type']} with PT analysis")
        
        # Filter known issues
        if Code4renaIntegration.filter_known_issues(finding, "blackhole"):
            findings.append(finding)
            log(f"Generated test case: {test_case['type']} ({test_case['severity']})")
        else:
            log(f"Filtered out known issue: {test_case['type']}", "WARNING")
    
    findings_file = BLACKHOLE_OUTPUT_DIR / "dex_test_cases_with_pt.json"
    with open(findings_file, "w") as f:
        json.dump(findings, f, indent=2)
    
    log(f"Generated {len(findings)} DEX test cases (filtered for known issues)")
    return findings

def scan_api_endpoints(endpoints: List[str]):
    """Scan discovered API endpoints for vulnerabilities using PT methodology"""
    log("=" * 60)
    log("SCANNING API ENDPOINTS WITH PT METHODOLOGY")
    log("=" * 60)
    
    if not APIVulnerabilityScanner:
        log("API scanner not available", "WARNING")
        return []
    
    findings = []
    
    # Test authentication with PT methodology
    log("Testing API authentication vulnerabilities (PT methodology)...")
    for endpoint in endpoints[:20]:  # Limit to first 20 for speed
        auth_findings = APIVulnerabilityScanner.test_api_authentication(endpoint)
        
        # Enhance with PT methodology
        for finding in auth_findings:
            if PenetrationTestingEnhancer:
                finding = PenetrationTestingEnhancer.enhance_finding_with_pt_methodology(finding)
            
            # Filter known issues
            if Code4renaIntegration and Code4renaIntegration.filter_known_issues(finding, "blackhole"):
                findings.append(finding)
        
        auth_findings = APIVulnerabilityScanner.test_api_authorization(endpoint)
        
        # Enhance with PT methodology
        for finding in auth_findings:
            if PenetrationTestingEnhancer:
                finding = PenetrationTestingEnhancer.enhance_finding_with_pt_methodology(finding)
            
            # Filter known issues
            if Code4renaIntegration and Code4renaIntegration.filter_known_issues(finding, "blackhole"):
                findings.append(finding)
    
    # Generate test cases with PT methodology
    log("Generating API test cases (PT methodology)...")
    for endpoint in endpoints[:20]:
        test_cases = APIVulnerabilityScanner.generate_test_cases(endpoint)
        for test_case in test_cases:
            finding = {
                "type": f"api_{test_case['type']}",
                "url": endpoint,
                "severity": "medium",
                "description": test_case["description"],
                "test_case": test_case,
                "methodology": f"{test_case.get('methodology', 'hackingapis.pdf')} + penetrationtesting.pdf",
                "recommendation": f"Manually test: {test_case['description']}"
            }
            
            # Enhance with PT methodology
            if PenetrationTestingEnhancer:
                finding = PenetrationTestingEnhancer.enhance_finding_with_pt_methodology(finding)
            
            # Filter known issues
            if Code4renaIntegration and Code4renaIntegration.filter_known_issues(finding, "blackhole"):
                findings.append(finding)
    
    log(f"Found {len(findings)} potential API vulnerabilities (filtered for known issues)")
    return findings

def generate_code4rena_reports(findings: List[Dict[str, Any]]):
    """Generate Code4rena submission-ready reports with PT methodology"""
    log("=" * 60)
    log("GENERATING CODE4RENA SUBMISSION REPORTS (PT ENHANCED)")
    log("=" * 60)
    
    if not Code4renaIntegration:
        log("Code4rena integration not available", "WARNING")
        return
    
    reports_dir = BLACKHOLE_OUTPUT_DIR / "reports"
    reports_dir.mkdir(exist_ok=True)
    
    for i, finding in enumerate(findings, 1):
        # Add PT methodology info if available
        if finding.get("pt_analysis"):
            finding["methodology"] = f"{finding.get('methodology', '')} + penetrationtesting.pdf"
            finding["exploitation_steps"] = finding.get("exploitation_steps", [])
            finding["impact_assessment"] = finding.get("impact_assessment", {})
        
        submission = Code4renaIntegration.generate_code4rena_submission(finding, "blackhole")
        formatted_report = Code4renaIntegration.format_finding_for_code4rena(finding, "blackhole")
        
        # Add PT methodology section if available
        if finding.get("pt_analysis"):
            pt_section = f"""
## Penetration Testing Analysis

**Attack Vector**: {finding.get('pt_analysis', {}).get('attack_vector', 'N/A')}
**Technique**: {finding.get('pt_analysis', {}).get('technique', 'N/A')}

### Exploitation Steps
{chr(10).join([step for step in finding.get('exploitation_steps', [])])}

### Impact Assessment
- **Confidentiality**: {finding.get('impact_assessment', {}).get('confidentiality', 'N/A')}
- **Integrity**: {finding.get('impact_assessment', {}).get('integrity', 'N/A')}
- **Availability**: {finding.get('impact_assessment', {}).get('availability', 'N/A')}
- **Business Impact**: {finding.get('impact_assessment', {}).get('business_impact', 'N/A')}

---
"""
            formatted_report += pt_section
        
        report_file = reports_dir / f"finding_{i:03d}_{finding.get('type', 'vulnerability')}.md"
        with open(report_file, "w") as f:
            f.write(formatted_report)
        
        submission_file = reports_dir / f"submission_{i:03d}.json"
        with open(submission_file, "w") as f:
            json.dump(submission, f, indent=2)
        
        log(f"Generated report {i}: {finding.get('type', 'vulnerability')}")
    
    log(f"Generated {len(findings)} Code4rena submission reports (PT enhanced)")
    log(f"All reports filtered for known issues")
    log(f"Reports saved to: {reports_dir}")

def main():
    """Main attack function"""
    log("=" * 60)
    log("BLACKHOLE DEX ATTACK - CODE4RENA")
    log("=" * 60)
    log("Target: Blackhole DEX on Avalanche")
    log("Max Bounty: $100,000 in $BLACK tokens")
    log("Platform: Code4rena")
    log("=" * 60)
    
    # Step 1: Discover endpoints
    endpoints = discover_blackhole_endpoints()
    
    # Step 2: Test DEX vulnerabilities with PT methodology
    dex_findings = test_dex_vulnerabilities_with_pt()
    
    # Step 3: Scan API endpoints with PT methodology
    api_findings = scan_api_endpoints(endpoints)
    
    # Step 4: Combine and filter findings
    all_findings = dex_findings + api_findings
    
    # Step 5: Filter out known issues
    filtered_findings = []
    if Code4renaIntegration:
        log("Filtering known issues...")
        for finding in all_findings:
            if Code4renaIntegration.filter_known_issues(finding, "blackhole"):
                filtered_findings.append(finding)
            else:
                log(f"Filtered out known issue: {finding.get('type', 'unknown')}", "WARNING")
        all_findings = filtered_findings
        log(f"Filtered {len(all_findings)} unique findings (excluding known issues)")
    
    # Step 6: Generate reports
    generate_code4rena_reports(all_findings)
    
    # Summary
    log("=" * 60)
    log("ATTACK COMPLETE")
    log("=" * 60)
    log(f"Total endpoints discovered: {len(endpoints)}")
    log(f"Total findings (after filtering): {len(all_findings)}")
    log(f"Critical: {len([f for f in all_findings if f.get('severity') == 'critical'])}")
    log(f"High: {len([f for f in all_findings if f.get('severity') == 'high'])}")
    log(f"Medium: {len([f for f in all_findings if f.get('severity') == 'medium'])}")
    log(f"Reports directory: {BLACKHOLE_OUTPUT_DIR / 'reports'}")
    log("=" * 60)
    log("Next steps:")
    log("1. Review findings in reports directory")
    log("2. Verify vulnerabilities manually")
    log("3. Check GitHub repo: https://github.com/BlackHoleDEX/Contracts")
    log("4. Review previous audits: https://docs.blackhole.xyz/security")
    log("5. Submit via Code4rena: https://code4rena.com/bounties/blackhole/make-submission")
    log("=" * 60)
    log("⚠️ IMPORTANT: All findings filtered for known issues")
    log("⚠️ Focus on in-scope contracts only")
    log("⚠️ TVL-based payouts: Critical = Loss of user funds")
    log("=" * 60)

if __name__ == "__main__":
    main()

