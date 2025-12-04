#!/usr/bin/env python3
import requests
import json
import os
import re
import sys
from urllib.parse import urljoin
from colorama import Fore, Style, init

# Initialize colors
init(autoreset=True)

class SourceMapAnalyzer:
    def __init__(self):
        self.target_maps = [
            "https://app.euler.finance/_next/static/chunks/main-app-6024770d299d11b6.js.map",
            "https://app.euler.finance/_next/static/chunks/app/%5Blocale%5D/layout-400a5e9ebc36ea6c.js.map",
            "https://app.euler.finance/_next/static/chunks/5720-e87a6ab5e7d5fc0b.js.map",
            "https://app.euler.finance/_next/static/chunks/2350-2c8c0ada11de8f05.js.map"
        ]
        self.output_dir = "source_code_analysis"
        self.findings = []
        
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def log(self, type, message):
        if type == "INFO":
            print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {message}")
        elif type == "SUCCESS":
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {message}")
        elif type == "WARNING":
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {message}")

    def analyze_map(self, map_url):
        self.log("INFO", f"Downloading and analyzing: {map_url}")
        try:
            response = requests.get(map_url, verify=False)
            data = response.json()
            
            sources = data.get('sources', [])
            sources_content = data.get('sourcesContent', [])
            
            self.log("INFO", f"Found {len(sources)} source files in map")
            
            for i, source_path in enumerate(sources):
                if i < len(sources_content) and sources_content[i]:
                    content = sources_content[i]
                    self.scan_content(source_path, content)
                    
        except Exception as e:
            self.log("WARNING", f"Failed to process {map_url}: {str(e)}")

    def scan_content(self, path, content):
        # 1. Search for Comments
        todos = re.findall(r'//\s*(TODO|FIXME|HACK|NOTE|XXX):?(.*)', content, re.IGNORECASE)
        for tag, msg in todos:
            self.findings.append({
                "type": "Developer Comment",
                "detail": f"{tag}: {msg.strip()}",
                "file": path
            })

        # 2. Search for Hidden/Internal API Routes
        routes = re.findall(r'["\'](/[a-zA-Z0-9/_.-]+)["\']', content)
        for route in routes:
            if route.startswith("/api") or route.startswith("/v1") or "admin" in route:
                self.findings.append({
                    "type": "Internal Route",
                    "detail": route,
                    "file": path
                })

        # 3. Search for Hardcoded Secrets (Broader patterns)
        secrets = re.findall(r'(api_key|secret|token|password|auth)["\']\s*[:=]\s*["\']([a-zA-Z0-9_\-]{10,})["\']', content, re.IGNORECASE)
        for name, value in secrets:
            self.findings.append({
                "type": "Potential Secret",
                "detail": f"{name} = {value[:5]}...",
                "file": path
            })

        # 4. Search for Feature Flags
        flags = re.findall(r'(is[A-Z][a-zA-Z]+Enabled|FEATURE_[A-Z_]+)', content)
        for flag in flags:
            self.findings.append({
                "type": "Feature Flag",
                "detail": flag,
                "file": path
            })

    def run(self):
        print(f"{Fore.CYAN}=============================================")
        print(f"{Fore.CYAN}   SOURCE CODE EXTRACTION & ANALYSIS         ")
        print(f"{Fore.CYAN}============================================={Style.RESET_ALL}")
        
        for map_url in self.target_maps:
            self.analyze_map(map_url)
            
        # Report
        print(f"\n{Fore.CYAN}=============================================")
        print(f"{Fore.CYAN}   ANALYSIS FINDINGS                         ")
        print(f"{Fore.CYAN}============================================={Style.RESET_ALL}")
        
        # Deduplicate findings
        unique_findings = []
        seen = set()
        for f in self.findings:
            key = f"{f['type']}:{f['detail']}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        # Group by type
        grouped = {}
        for f in unique_findings:
            if f['type'] not in grouped:
                grouped[f['type']] = []
            grouped[f['type']].append(f)

        for type_name, items in grouped.items():
            print(f"\n{Fore.YELLOW}{type_name}s ({len(items)}):{Style.RESET_ALL}")
            for item in items[:10]:  # Limit output
                print(f"  - {item['detail']}")
                print(f"    File: {item['file']}")
            if len(items) > 10:
                print(f"    ... and {len(items)-10} more")

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    analyzer = SourceMapAnalyzer()
    analyzer.run()
