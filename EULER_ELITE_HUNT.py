#!/usr/bin/env python3
import requests
import re
import os
import sys
import time
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style, init

# Initialize colors
init(autoreset=True)

class EulerEliteHunter:
    def __init__(self):
        self.target = "https://app.euler.finance"
        self.session = requests.Session()
        self.session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        self.js_files = set()
        self.findings = []
        
        # Regex patterns for finding secrets
        self.patterns = {
            "google_api": r"AIza[0-9A-Za-z-_]{35}",
            "firebase": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
            "aws_key": r"AKIA[0-9A-Z]{16}",
            "private_key": r"-----BEGIN PRIVATE KEY-----",
            "github_token": r"ghp_[0-9a-zA-Z]{36}",
            "slack_token": r"xox[baprs]-([0-9a-zA-Z]{10,48})"
        }

        # DOM XSS Sinks to hunt for
        self.dangerous_sinks = [
            "innerHTML",
            "outerHTML",
            "document.write",
            "dangerouslySetInnerHTML",
            "location.href =",
            "eval("
        ]

    def log(self, type, message):
        timestamp = time.strftime("%H:%M:%S")
        if type == "INFO":
            print(f"[{timestamp}] {Fore.BLUE}[*]{Style.RESET_ALL} {message}")
        elif type == "SUCCESS":
            print(f"[{timestamp}] {Fore.GREEN}[+]{Style.RESET_ALL} {message}")
        elif type == "WARNING":
            print(f"[{timestamp}] {Fore.YELLOW}[!]{Style.RESET_ALL} {message}")
        elif type == "ERROR":
            print(f"[{timestamp}] {Fore.RED}[-]{Style.RESET_ALL} {message}")

    def crawl_js_files(self):
        self.log("INFO", f"Crawling {self.target} for JavaScript files...")
        try:
            response = self.session.get(self.target, verify=False)
            # Find all .js files
            scripts = re.findall(r'src=["\'](.*?.js)["\']', response.text)
            
            for script in scripts:
                full_url = urljoin(self.target, script)
                self.js_files.add(full_url)
            
            # Also look for "main" or "app" bundles specifically as they contain logic
            self.log("SUCCESS", f"Found {len(self.js_files)} JavaScript files to analyze.")
            
        except Exception as e:
            self.log("ERROR", f"Failed to crawl target: {str(e)}")

    def analyze_js_content(self, url):
        try:
            self.log("INFO", f"Analyzing: {url.split('/')[-1]}")
            response = self.session.get(url, verify=False)
            content = response.text

            # 1. Check for Secrets
            for name, pattern in self.patterns.items():
                matches = re.findall(pattern, content)
                for match in matches:
                    self.findings.append({
                        "type": "Secret Exposed",
                        "detail": f"{name}: {match[:10]}...",
                        "source": url
                    })
                    self.log("SUCCESS", f"FOUND SECRET: {name} in {url}")

            # 2. Check for Hidden API Endpoints
            # Looking for /api/, /v1/, /admin/ patterns
            endpoints = re.findall(r'["\'](/api/[^"\']+|/v1/[^"\']+|/admin/[^"\']+)["\']', content)
            for endpoint in endpoints:
                self.findings.append({
                    "type": "API Endpoint",
                    "detail": endpoint,
                    "source": url
                })
                self.log("INFO", f"Found API Endpoint: {endpoint}")

            # 3. Check for Dangerous Sinks (DOM XSS)
            for sink in self.dangerous_sinks:
                if sink in content:
                    # Context is needed to verify, but this is a good lead
                    self.findings.append({
                        "type": "Dangerous Sink",
                        "detail": sink,
                        "source": url
                    })
                    # self.log("WARNING", f"Potential DOM XSS Sink: {sink} in {url}")

        except Exception as e:
            self.log("ERROR", f"Error analyzing {url}: {str(e)}")

    def check_source_maps(self):
        self.log("INFO", "Checking for Source Maps (.js.map)...")
        # Source maps allow us to reconstruct the original source code
        found_maps = 0
        for js_url in self.js_files:
            map_url = js_url + ".map"
            try:
                resp = self.session.head(map_url, verify=False)
                if resp.status_code == 200:
                    self.findings.append({
                        "type": "Source Map Exposed",
                        "detail": map_url,
                        "source": js_url
                    })
                    self.log("SUCCESS", f"Source Map Found: {map_url}")
                    found_maps += 1
            except:
                pass
        
        if found_maps == 0:
            self.log("INFO", "No source maps found (Good security practice).")

    def run(self):
        print(f"{Fore.CYAN}=============================================")
        print(f"{Fore.CYAN}   EULER ELITE HUNTER - Deep JS Analysis     ")
        print(f"{Fore.CYAN}============================================={Style.RESET_ALL}")
        
        self.crawl_js_files()
        
        print(f"\n{Fore.YELLOW}[*] Starting Deep Analysis of {len(self.js_files)} files...{Style.RESET_ALL}")
        for js_file in self.js_files:
            self.analyze_js_content(js_file)
            
        self.check_source_maps()
        
        print(f"\n{Fore.CYAN}=============================================")
        print(f"{Fore.CYAN}   ELITE HUNT COMPLETE - SUMMARY             ")
        print(f"{Fore.CYAN}============================================={Style.RESET_ALL}")
        
        secrets = [f for f in self.findings if f['type'] == 'Secret Exposed']
        endpoints = [f for f in self.findings if f['type'] == 'API Endpoint']
        maps = [f for f in self.findings if f['type'] == 'Source Map Exposed']
        
        print(f"Secrets Found: {len(secrets)}")
        print(f"API Endpoints: {len(endpoints)}")
        print(f"Source Maps:   {len(maps)}")
        
        if len(secrets) > 0:
            print(f"\n{Fore.RED}[!] CRITICAL: SECRETS FOUND{Style.RESET_ALL}")
            for s in secrets:
                print(f"  - {s['detail']} ({s['source']})")

        if len(maps) > 0:
            print(f"\n{Fore.GREEN}[+] OPPORTUNITY: SOURCE MAPS FOUND{Style.RESET_ALL}")
            print("  (This allows us to read the original TypeScript/React code)")
            for m in maps:
                print(f"  - {m['detail']}")

if __name__ == "__main__":
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    hunter = EulerEliteHunter()
    hunter.run()
