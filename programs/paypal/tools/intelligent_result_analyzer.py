#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
INTELLIGENT RESULT ANALYZER
Filters false positives and prioritizes real vulnerabilities

Usage:
    python3 intelligent_result_analyzer.py --scan-results ../findings/shadowstep_quick_scan.txt
"""

import json
import re
import argparse
from datetime import datetime
from collections import defaultdict

class IntelligentResultAnalyzer:
    """
    Analyzes scan results to filter false positives and prioritize findings
    """
    
    def __init__(self, scan_file):
        self.scan_file = scan_file
        self.findings = []
        self.verified_findings = []
        self.false_positives = []
        
        # False positive patterns (common in nuclei)
        self.fp_patterns = [
            r'404.*not.*found',
            r'403.*forbidden.*nginx',  # Common CDN/firewall blocks
            r'cloudflare.*checking',
            r'access.*denied.*generic',
            r'default.*error.*page',
        ]
        
        # High-value vulnerability indicators
        self.high_value_indicators = [
            'admin', 'password', 'api_key', 'secret', 'token',
            'database', 'sql', 'injection', 'xss', 'ssrf',
            'idor', 'authentication', 'authorization', 'bypass'
        ]
    
    def load_findings(self):
        """Load scan results"""
        print(f"[*] Loading scan results from {self.scan_file}")
        try:
            with open(self.scan_file, 'r') as f:
                content = f.read()
                
            # Parse nuclei output
            lines = content.strip().split('\n')
            for line in lines:
                if line.strip():
                    self.findings.append(line)
            
            print(f"[+] Loaded {len(self.findings)} findings")
            
        except FileNotFoundError:
            print(f"[-] File not found: {self.scan_file}")
            return False
        
        return True
    
    def is_false_positive(self, finding):
        """Check if finding is likely a false positive"""
        finding_lower = finding.lower()
        
        for pattern in self.fp_patterns:
            if re.search(pattern, finding_lower):
                return True
        
        return False
    
    def calculate_severity(self, finding):
        """Calculate severity score for finding"""
        score = 0
        finding_lower = finding.lower()
        
        # Check for severity tags from nuclei
        if '[critical]' in finding_lower:
            score += 100
        elif '[high]' in finding_lower:
            score += 75
        elif '[medium]' in finding_lower:
            score += 50
        elif '[low]' in finding_lower:
            score += 25
        
        # Check for high-value indicators
        for indicator in self.high_value_indicators:
            if indicator in finding_lower:
                score += 10
        
        return score
    
    def extract_url(self, finding):
        """Extract URL from finding"""
        # Look for URLs in the finding
        url_match = re.search(r'https?://[^\s\]]+', finding)
        if url_match:
            return url_match.group(0)
        return None
    
    def analyze_findings(self):
        """Analyze all findings"""
        print(f"\n[*] Analyzing findings...")
        
        for finding in self.findings:
            if self.is_false_positive(finding):
                self.false_positives.append(finding)
            else:
                severity = self.calculate_severity(finding)
                url = self.extract_url(finding)
                
                self.verified_findings.append({
                    'finding': finding,
                    'severity_score': severity,
                    'url': url,
                    'requires_manual_verification': severity >= 50
                })
        
        print(f"[+] Analysis complete!")
        print(f"    - Real findings: {len(self.verified_findings)}")
        print(f"    - False positives filtered: {len(self.false_positives)}")
    
    def generate_report(self):
        """Generate prioritized report"""
        # Sort by severity
        sorted_findings = sorted(self.verified_findings, key=lambda x: x['severity_score'], reverse=True)
        
        print(f"\n{'='*80}")
        print(f"INTELLIGENT ANALYSIS REPORT")
        print(f"{'='*80}\n")
        
        # Critical/High findings
        critical_high = [f for f in sorted_findings if f['severity_score'] >= 75]
        if critical_high:
            print(f"🔴 CRITICAL/HIGH SEVERITY ({len(critical_high)} findings)")
            print(f"{'-'*80}")
            for i, finding in enumerate(critical_high, 1):
                print(f"\n{i}. [Score: {finding['severity_score']}]")
                print(f"   {finding['finding']}")
                if finding['url']:
                    print(f"   Target: {finding['url']}")
                if finding['requires_manual_verification']:
                    print(f"   ⚠️  MANUAL VERIFICATION REQUIRED")
            print()
        else:
            print(f"🟢 No critical/high severity findings\n")
        
        # Medium findings
        medium = [f for f in sorted_findings if 50 <= f['severity_score'] < 75]
        if medium:
            print(f"🟡 MEDIUM SEVERITY ({len(medium)} findings)")
            print(f"{'-'*80}")
            for i, finding in enumerate(medium, 1):
                print(f"{i}. {finding['finding'][:100]}...")
            print()
        
        # Low findings
        low = [f for f in sorted_findings if f['severity_score'] < 50]
        if low:
            print(f"🔵 LOW SEVERITY ({len(low)} findings)")
            print(f"    - Review if time permits")
            print()
        
        # Action items
        print(f"📋 RECOMMENDED ACTIONS:")
        print(f"{'-'*80}")
        if critical_high:
            print(f"1. MANUALLY VERIFY all critical/high findings ({len(critical_high)} items)")
            print(f"2. Document proof of concept for each")
            print(f"3. Prepare HackerOne reports")
            print(f"4. Submit valid findings")
        else:
            print(f"1. Review medium severity findings")
            print(f"2. Perform additional manual testing")
            print(f"3. Try different attack vectors")
        
        # Save reports
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Verified findings JSON
        verified_file = f"../findings/verified_findings_{timestamp}.json"
        with open(verified_file, 'w') as f:
            json.dump(sorted_findings, f, indent=2)
        print(f"\n[+] Verified findings saved: {verified_file}")
        
        # Manual verification checklist
        if critical_high:
            checklist_file = f"../findings/manual_verification_checklist_{timestamp}.txt"
            with open(checklist_file, 'w') as f:
                f.write("MANUAL VERIFICATION CHECKLIST\n")
                f.write("="*80 + "\n\n")
                for i, finding in enumerate(critical_high, 1):
                    f.write(f"{i}. [ ] {finding['finding']}\n")
                    if finding['url']:
                        f.write(f"    URL: {finding['url']}\n")
                    f.write(f"    Steps to verify:\n")
                    f.write(f"    1. Navigate to URL in browser\n")
                    f.write(f"    2. Attempt to reproduce the finding\n")
                    f.write(f"    3. Document proof of concept\n")
                    f.write(f"    4. Assess actual impact\n")
                    f.write(f"    5. Prepare bug report if valid\n\n")
            print(f"[+] Manual checklist saved: {checklist_file}")
        
        print(f"\n{'='*80}\n")
        
        return len(critical_high)

def main():
    parser = argparse.ArgumentParser(description='Intelligent Result Analyzer')
    parser.add_argument('--scan-results', required=True, help='Nuclei scan results file')
    
    args = parser.parse_args()
    
    analyzer = IntelligentResultAnalyzer(args.scan_results)
    
    if analyzer.load_findings():
        analyzer.analyze_findings()
        critical_count = analyzer.generate_report()
        
        if critical_count > 0:
            print(f"[!] {critical_count} critical/high findings require your attention!")
        else:
            print(f"[*] No critical findings. Consider expanding testing scope.")

if __name__ == '__main__':
    main()
