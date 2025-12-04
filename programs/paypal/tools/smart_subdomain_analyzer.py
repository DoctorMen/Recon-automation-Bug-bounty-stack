#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
SMART SUBDOMAIN ANALYZER
Analyzes subdomains to find high-value targets and prioritize testing

Usage:
    python3 smart_subdomain_analyzer.py --input ../recon/shadowstep_paypal_live.txt
"""

import requests
import json
import sys
import argparse
from urllib.parse import urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

class SmartSubdomainAnalyzer:
    """
    Intelligent subdomain analyzer that identifies high-value targets
    """
    
    def __init__(self, input_file):
        self.input_file = input_file
        self.subdomains = []
        self.analyzed = []
        
        # High-value indicators
        self.high_value_keywords = [
            'test', 'staging', 'stage', 'dev', 'qa', 'sandbox',
            'api', 'admin', 'internal', 'debug', 'console',
            'developer', 'docs', 'swagger', 'graphql'
        ]
        
        self.critical_keywords = [
            'admin', 'internal', 'debug', 'console', 'management'
        ]
    
    def load_subdomains(self):
        """Load subdomains from file"""
        print(f"[*] Loading subdomains from {self.input_file}")
        try:
            with open(self.input_file, 'r') as f:
                self.subdomains = [line.strip() for line in f if line.strip()]
            print(f"[+] Loaded {len(self.subdomains)} subdomains")
        except FileNotFoundError:
            print(f"[-] File not found: {self.input_file}")
            sys.exit(1)
    
    def calculate_priority_score(self, url):
        """Calculate priority score for a subdomain"""
        score = 0
        parsed = urlparse(url)
        hostname = parsed.netloc or parsed.path
        
        # Check for high-value keywords
        for keyword in self.high_value_keywords:
            if keyword in hostname.lower():
                score += 10
        
        # Critical keywords get extra points
        for keyword in self.critical_keywords:
            if keyword in hostname.lower():
                score += 50
        
        # Staging/test environments are valuable
        if 'stage' in hostname.lower() or 'test' in hostname.lower():
            score += 30
        
        # API endpoints are valuable
        if 'api' in hostname.lower():
            score += 20
        
        # Numbered test environments (test01, stage2d0014)
        if any(char.isdigit() for char in hostname):
            score += 15
        
        return score
    
    def analyze_subdomain(self, url):
        """Analyze a single subdomain"""
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc or parsed.path
            
            # Calculate priority
            priority = self.calculate_priority_score(url)
            
            # Quick probe
            try:
                resp = requests.get(url, timeout=5, allow_redirects=True)
                status_code = resp.status_code
                content_length = len(resp.content)
                headers = dict(resp.headers)
                
                # Check for interesting response headers
                interesting_headers = []
                if 'X-Powered-By' in headers:
                    interesting_headers.append(f"X-Powered-By: {headers['X-Powered-By']}")
                if 'Server' in headers:
                    interesting_headers.append(f"Server: {headers['Server']}")
                
            except:
                status_code = 0
                content_length = 0
                interesting_headers = []
            
            result = {
                'url': url,
                'hostname': hostname,
                'priority_score': priority,
                'status_code': status_code,
                'content_length': content_length,
                'interesting_headers': interesting_headers,
                'category': self.categorize_subdomain(hostname)
            }
            
            return result
            
        except Exception as e:
            return None
    
    def categorize_subdomain(self, hostname):
        """Categorize subdomain by type"""
        hostname_lower = hostname.lower()
        
        if any(k in hostname_lower for k in ['api', 'rest', 'graphql']):
            return 'API'
        elif any(k in hostname_lower for k in ['admin', 'console', 'management']):
            return 'ADMIN'
        elif any(k in hostname_lower for k in ['test', 'staging', 'stage', 'qa']):
            return 'TESTING'
        elif any(k in hostname_lower for k in ['dev', 'developer', 'docs']):
            return 'DEVELOPER'
        elif any(k in hostname_lower for k in ['sandbox']):
            return 'SANDBOX'
        else:
            return 'PRODUCTION'
    
    def analyze_all(self):
        """Analyze all subdomains with threading"""
        print(f"\n[*] Analyzing {len(self.subdomains)} subdomains...")
        print(f"[*] This may take a few minutes...\n")
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self.analyze_subdomain, url): url for url in self.subdomains}
            
            for i, future in enumerate(as_completed(futures)):
                result = future.result()
                if result:
                    self.analyzed.append(result)
                
                # Progress indicator
                if (i + 1) % 20 == 0:
                    print(f"[*] Analyzed {i + 1}/{len(self.subdomains)} subdomains...")
        
        print(f"[+] Analysis complete!\n")
    
    def generate_report(self):
        """Generate prioritized report"""
        # Sort by priority score
        sorted_results = sorted(self.analyzed, key=lambda x: x['priority_score'], reverse=True)
        
        print(f"\n{'='*80}")
        print(f"SMART SUBDOMAIN ANALYSIS REPORT")
        print(f"{'='*80}\n")
        
        # Top 20 high-value targets
        print(f"TOP 20 HIGH-VALUE TARGETS:")
        print(f"{'-'*80}")
        for i, result in enumerate(sorted_results[:20], 1):
            print(f"{i:2d}. [Score: {result['priority_score']:3d}] [{result['category']:10s}] {result['url']}")
            if result['status_code'] > 0:
                print(f"    Status: {result['status_code']} | Size: {result['content_length']} bytes")
            if result['interesting_headers']:
                print(f"    Headers: {', '.join(result['interesting_headers'])}")
            print()
        
        # Category breakdown
        print(f"\nCATEGORY BREAKDOWN:")
        print(f"{'-'*80}")
        categories = {}
        for result in self.analyzed:
            cat = result['category']
            categories[cat] = categories.get(cat, 0) + 1
        
        for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
            print(f"{cat:15s}: {count:3d} subdomains")
        
        # Save detailed report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # JSON report
        json_file = f"../findings/subdomain_analysis_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(sorted_results, f, indent=2)
        print(f"\n[+] Detailed JSON report saved: {json_file}")
        
        # High-priority targets file (for focused scanning)
        priority_file = f"../recon/high_priority_targets.txt"
        with open(priority_file, 'w') as f:
            for result in sorted_results[:50]:  # Top 50
                if result['priority_score'] >= 20:
                    f.write(f"{result['url']}\n")
        print(f"[+] High-priority targets saved: {priority_file}")
        
        print(f"\n{'='*80}\n")

def main():
    parser = argparse.ArgumentParser(description='Smart Subdomain Analyzer')
    parser.add_argument('--input', required=True, help='Input file with subdomains')
    
    args = parser.parse_args()
    
    analyzer = SmartSubdomainAnalyzer(args.input)
    analyzer.load_subdomains()
    analyzer.analyze_all()
    analyzer.generate_report()

if __name__ == '__main__':
    main()
