#!/usr/bin/env python3
"""
API Hunter - Discovers undocumented API endpoints and secrets
Part of the autonomous bug bounty workflow
"""

import re
import json
import sys
import os
import hashlib
from urllib.parse import urljoin, urlparse
import subprocess

# Patterns for finding interesting data
PATTERNS = {
    'api_endpoints': [
        r'["\']/?api/v?\d*/[^"\']+["\']',
        r'["\']/?v\d+/[^"\']+["\']',
        r'["\']/?graphql["\']',
        r'["\']/?rest/[^"\']+["\']',
        r'["\']/?internal/[^"\']+["\']',
        r'["\']/?admin/[^"\']+["\']',
        r'["\']/?private/[^"\']+["\']',
    ],
    'secrets': [
        r'(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)["\'\s]*[:=]["\'\s]*["\'][a-zA-Z0-9_\-]{16,}["\']',
        r'(?i)(password|passwd|pwd)["\'\s]*[:=]["\'\s]*["\'][^"\']{6,}["\']',
        r'(?i)bearer\s+[a-zA-Z0-9_\-\.]+',
        r'(?i)basic\s+[a-zA-Z0-9+/=]+',
    ],
    'aws': [
        r'AKIA[0-9A-Z]{16}',
        r'(?i)aws[_-]?secret[_-]?access[_-]?key["\'\s]*[:=]["\'\s]*["\'][a-zA-Z0-9/+=]{40}["\']',
        r's3\.amazonaws\.com/[a-zA-Z0-9\-\.]+',
        r'[a-zA-Z0-9\-]+\.s3\.amazonaws\.com',
    ],
    'google': [
        r'AIza[0-9A-Za-z_-]{35}',
        r'[0-9]+-[a-z0-9_]+\.apps\.googleusercontent\.com',
        r'ya29\.[0-9A-Za-z_-]+',
    ],
    'firebase': [
        r'[a-zA-Z0-9-]+\.firebaseio\.com',
        r'[a-zA-Z0-9-]+\.firebaseapp\.com',
    ],
    'internal_urls': [
        r'https?://[a-zA-Z0-9\-\.]*(?:internal|staging|dev|test|admin|api)[a-zA-Z0-9\-\.]*\.[a-zA-Z]{2,}',
        r'https?://(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9\.]+[:/]?[^\s"\']*',
        r'https?://localhost[:/][^\s"\']*',
    ],
    'debug': [
        r'(?i)console\.(log|debug|info|warn|error)\([^)]*\)',
        r'(?i)debugger;',
        r'(?i)//\s*TODO',
        r'(?i)//\s*FIXME',
        r'(?i)//\s*HACK',
    ],
    'jwt': [
        r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
    ],
    'private_keys': [
        r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
    ],
    'emails': [
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    ],
}

def fetch_url(url):
    """Fetch URL content using curl"""
    try:
        result = subprocess.run(
            ['curl', '-s', '-L', '--max-time', '30', url],
            capture_output=True,
            text=True
        )
        return result.stdout
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return ""

def extract_js_urls(html, base_url):
    """Extract JavaScript URLs from HTML"""
    js_urls = set()
    
    # Match src attributes
    patterns = [
        r'src=["\']([^"\']+\.js[^"\']*)["\']',
        r'src=([^\s>]+\.js)',
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        for match in matches:
            if match.startswith('//'):
                js_urls.add('https:' + match)
            elif match.startswith('/'):
                js_urls.add(urljoin(base_url, match))
            elif match.startswith('http'):
                js_urls.add(match)
            else:
                js_urls.add(urljoin(base_url, match))
    
    return js_urls

def analyze_content(content, source=""):
    """Analyze content for secrets and endpoints"""
    findings = {}
    
    for category, patterns_list in PATTERNS.items():
        findings[category] = []
        for pattern in patterns_list:
            matches = re.findall(pattern, content)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                finding = {
                    'match': match[:200],  # Truncate long matches
                    'source': source,
                    'pattern': pattern[:50]
                }
                if finding not in findings[category]:
                    findings[category].append(finding)
    
    return findings

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 api_hunter.py <target_url> <output_dir>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    output_dir = sys.argv[2]
    
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(f"{output_dir}/js_files", exist_ok=True)
    
    print(f"[*] Target: {target_url}")
    print(f"[*] Output: {output_dir}")
    
    # Fetch main page
    print("\n[*] Fetching main page...")
    html = fetch_url(target_url)
    
    with open(f"{output_dir}/page.html", 'w') as f:
        f.write(html)
    
    # Extract JS URLs
    print("[*] Extracting JavaScript URLs...")
    js_urls = extract_js_urls(html, target_url)
    print(f"[*] Found {len(js_urls)} JavaScript files")
    
    with open(f"{output_dir}/js_urls.txt", 'w') as f:
        for url in sorted(js_urls):
            f.write(url + '\n')
            print(f"  - {url}")
    
    # Download and analyze JS files
    all_findings = {cat: [] for cat in PATTERNS.keys()}
    
    print("\n[*] Downloading and analyzing JavaScript files...")
    for js_url in js_urls:
        print(f"  Analyzing: {js_url}")
        content = fetch_url(js_url)
        
        if content:
            # Save JS file
            filename = hashlib.md5(js_url.encode()).hexdigest() + '.js'
            with open(f"{output_dir}/js_files/{filename}", 'w') as f:
                f.write(content)
            
            # Analyze
            findings = analyze_content(content, js_url)
            for cat, items in findings.items():
                all_findings[cat].extend(items)
    
    # Analyze main HTML too
    print("\n[*] Analyzing HTML page...")
    html_findings = analyze_content(html, target_url)
    for cat, items in html_findings.items():
        all_findings[cat].extend(items)
    
    # Remove duplicates
    for cat in all_findings:
        seen = set()
        unique = []
        for item in all_findings[cat]:
            key = item['match']
            if key not in seen:
                seen.add(key)
                unique.append(item)
        all_findings[cat] = unique
    
    # Save results
    with open(f"{output_dir}/findings.json", 'w') as f:
        json.dump(all_findings, f, indent=2)
    
    # Print summary
    print("\n" + "="*60)
    print("ANALYSIS RESULTS")
    print("="*60)
    
    total_findings = 0
    for category, items in all_findings.items():
        if items:
            print(f"\n[{category.upper()}] ({len(items)} findings)")
            for item in items[:10]:  # Show first 10
                print(f"  • {item['match'][:100]}")
            if len(items) > 10:
                print(f"  ... and {len(items) - 10} more")
            total_findings += len(items)
    
    print(f"\n{'='*60}")
    print(f"TOTAL: {total_findings} potential findings")
    print(f"Full results saved to: {output_dir}/findings.json")
    
    # Generate markdown report
    with open(f"{output_dir}/FINDINGS_REPORT.md", 'w') as f:
        f.write(f"# API Hunter Report\n\n")
        f.write(f"**Target:** {target_url}\n\n")
        f.write(f"**Total Findings:** {total_findings}\n\n")
        
        for category, items in all_findings.items():
            if items:
                f.write(f"## {category.replace('_', ' ').title()}\n\n")
                for item in items:
                    f.write(f"- `{item['match'][:150]}`\n")
                    f.write(f"  - Source: {item['source']}\n\n")
    
    print(f"Report saved to: {output_dir}/FINDINGS_REPORT.md")
    
    return all_findings

if __name__ == "__main__":
    main()
