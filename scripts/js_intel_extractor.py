#!/usr/bin/env python3
"""
JS Intelligence Extractor (JSINT)
Upgrades your recon by mining JavaScript files for:
1. Hidden API endpoints
2. GraphQL URLs
3. Hardcoded secrets/keys (AWS, Stripe, etc.)
4. Parameter names (for parameter fuzzing)

Usage: python3 js_intel_extractor.py --target <domain_or_file> --output <output_dir>
"""

import re
import sys
import os
import argparse
import requests
import concurrent.futures
from urllib.parse import urljoin, urlparse
import json

# Regex patterns for secrets and sensitive info
PATTERNS = {
    "aws_key": r"((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})",
    "aws_secret": r"([a-zA-Z0-9+/]{40})",
    "stripe_key": r"(sk_live_[0-9a-zA-Z]{24})",
    "google_api": r"(AIza[0-9A-Za-z-_]{35})",
    "slack_token": r"(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "private_key": r"-----BEGIN PRIVATE KEY-----",
    "authorization": r"Bearer [a-zA-Z0-9\-\._~\+\/]+",
    "graphql_url": r"['\"](/[a-zA-Z0-9_/-]*graphql[a-zA-Z0-9_/-]*)['\"]",
    "api_endpoint": r"['\"](/[a-zA-Z0-9_/-]{3,})['\"]",
    "potential_params": r"['\"]([a-zA-Z0-9_]+Id)['\"]"
}

def get_js_links(url, session):
    """Extracts script src links from a page."""
    try:
        response = session.get(url, timeout=10, verify=False)
        # Simple regex to find <script src="...">
        scripts = re.findall(r'<script[^>]+src=["\'](.*?)["\']', response.text)
        full_links = []
        for script in scripts:
            if script.startswith("//"):
                full_links.append("https:" + script)
            elif script.startswith("http"):
                full_links.append(script)
            else:
                full_links.append(urljoin(url, script))
        return list(set(full_links))
    except Exception as e:
        # print(f"[-] Error extracting JS from {url}: {e}")
        return []

def analyze_js(js_url, session):
    """Fetches and analyzes a single JS file."""
    findings = {"url": js_url, "secrets": [], "endpoints": [], "graphql": [], "params": []}
    try:
        response = session.get(js_url, timeout=10, verify=False)
        content = response.text
        
        # Scan for patterns
        for name, pattern in PATTERNS.items():
            matches = re.findall(pattern, content)
            if matches:
                unique_matches = list(set(matches))
                if name == "graphql_url":
                    findings["graphql"].extend(unique_matches)
                elif name == "api_endpoint":
                    findings["endpoints"].extend(unique_matches)
                elif name == "potential_params":
                    findings["params"].extend(unique_matches)
                else:
                    for m in unique_matches:
                        findings["secrets"].append(f"{name}: {m}")
                        
        return findings
    except Exception as e:
        return None

def process_target(target, output_dir):
    """Main runner for a target."""
    print(f"[*] Starting JSINT analysis on {target}")
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"})
    
    # If target is a file of URLs
    urls_to_scan = []
    if os.path.isfile(target):
        with open(target, 'r') as f:
            urls_to_scan = [line.strip() for line in f if line.strip()]
    else:
        urls_to_scan = [target]

    all_findings = []
    
    # 1. Find JS files
    js_files = set()
    print(f"[*] Extracting JS links from {len(urls_to_scan)} pages...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(get_js_links, url, session): url for url in urls_to_scan}
        for future in concurrent.futures.as_completed(future_to_url):
            js_links = future.result()
            for link in js_links:
                js_files.add(link)
                
    print(f"[*] Found {len(js_files)} unique JS files. Analyzing contents...")
    
    # 2. Analyze JS files
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        future_to_js = {executor.submit(analyze_js, js_url, session): js_url for js_url in js_files}
        for future in concurrent.futures.as_completed(future_to_js):
            result = future.result()
            if result and (result["secrets"] or result["endpoints"] or result["graphql"]):
                all_findings.append(result)
                # Real-time alert for high value
                if result["secrets"]:
                    print(f"[!] SECRET FOUND in {result['url']}: {result['secrets']}")
                if result["graphql"]:
                    print(f"[+] GraphQL Found in {result['url']}: {result['graphql']}")

    # 3. Save Results
    output_file = os.path.join(output_dir, "js_intel_report.json")
    with open(output_file, 'w') as f:
        json.dump(all_findings, f, indent=2)
        
    print(f"[*] JS Intelligence Report saved to {output_file}")
    
    # Generate summary text
    summary_file = os.path.join(output_dir, "js_intel_summary.txt")
    with open(summary_file, 'w') as f:
        for finding in all_findings:
            f.write(f"File: {finding['url']}\n")
            if finding['secrets']:
                f.write(f"  SECRETS: {finding['secrets']}\n")
            if finding['graphql']:
                f.write(f"  GRAPHQL: {finding['graphql']}\n")
            if finding['endpoints']:
                f.write(f"  ENDPOINTS: {finding['endpoints'][:10]}...\n")
            f.write("\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="JS Intelligence Extractor")
    parser.add_argument("--target", required=True, help="Target URL or file with list of URLs")
    parser.add_argument("--output", required=True, help="Output directory")
    args = parser.parse_args()
    
    if not os.path.exists(args.output):
        os.makedirs(args.output)
        
    process_target(args.target, args.output)
