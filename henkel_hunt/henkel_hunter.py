#!/usr/bin/env python3
"""
Henkel Bug Bounty Hunter
Focused on: SQLi, RCE, Personal Data Leakage, Privilege Escalation

IMPORTANT: This script requires LEGAL AUTHORIZATION before running against live targets.
Only run against targets you have explicit permission to test.
"""

import subprocess
import os
import json
import sys
from datetime import datetime
from pathlib import Path

# Add legal authorization check
sys.path.insert(0, str(Path(__file__).parent.parent))
try:
    from LEGAL_AUTHORIZATION_SYSTEM import check_authorization
    LEGAL_CHECK_ENABLED = True
except ImportError:
    LEGAL_CHECK_ENABLED = False
    print("[WARNING] Legal authorization system not found. Manual verification required.")


class HenkelHunter:
    """Automated vulnerability hunting for Henkel bug bounty program."""
    
    def __init__(self, h1_username: str):
        self.h1_username = h1_username
        self.output_dir = Path(__file__).parent / "output"
        self.output_dir.mkdir(exist_ok=True)
        
        # High-value targets from scope
        self.priority_targets = {
            "chinese_domains": [
                "smartshelf.henkel.cn",
                "smc-analyzer.henkel-consumer-brands.cn",
                "auth.eshop-henkel-adhesives.cn",
                "scrm-weconnect-api.schwarzkopfclub.com.cn",
                "pattex.com.cn",
                "aigc.henkel.cn",
            ],
            "uat_test_environments": [
                "uat.www.shrndconsumer.henkel-consumer-brands.cn",
                "uat-smc-analyzer.henkel-consumer-brands.cn",
                "test-console.ar.magic-mirror.cn",
                "tpm-qa.henkel-consumer-brands.cn",
            ],
            "consumer_portals": [
                "www.joico.com",
                "www.joico.eu",
            ],
            "wildcards": [
                "*.loctite.com",
                "*.schwarzkopf.de",
                "*.henkel-consumer-brands.cn",
            ]
        }
        
        # SQLi payloads for testing
        self.sqli_payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "1' AND '1'='1",
            "1' ORDER BY 1--",
            "1 UNION SELECT NULL--",
            "'; WAITFOR DELAY '0:0:5'--",
            "1' AND SLEEP(5)--",
        ]
        
        # RCE test patterns
        self.rce_endpoints = [
            "/upload",
            "/api/upload",
            "/file/upload",
            "/admin/upload",
            "/api/export",
            "/download",
            "/convert",
            "/generate",
        ]
        
        # IDOR patterns for data leakage
        self.idor_patterns = [
            "/api/user/{id}",
            "/api/profile/{id}",
            "/api/order/{id}",
            "/api/invoice/{id}",
            "/account/{id}",
            "/user/{id}/details",
        ]
        
        # Information disclosure paths
        self.disclosure_paths = [
            "/.git/config",
            "/.env",
            "/api/swagger.json",
            "/api/docs",
            "/graphql",
            "/debug",
            "/phpinfo.php",
            "/server-status",
            "/actuator/health",
            "/actuator/env",
            "/.well-known/security.txt",
            "/crossdomain.xml",
            "/robots.txt",
            "/sitemap.xml",
        ]
    
    def check_legal_authorization(self, target: str) -> bool:
        """Verify legal authorization before scanning."""
        if LEGAL_CHECK_ENABLED:
            authorized, reason, _ = check_authorization(target)
            if not authorized:
                print(f"[BLOCKED] {target}: {reason}")
                return False
        else:
            print(f"[WARNING] Manual authorization verification required for: {target}")
            response = input("Do you have written authorization to test this target? (yes/no): ")
            if response.lower() != "yes":
                print("[BLOCKED] Authorization not confirmed")
                return False
        return True
    
    def get_request_headers(self) -> dict:
        """Get headers with H1 username as required by program."""
        return {
            "X-HackerOne-Research": self.h1_username,
            "User-Agent": f"HackerOne-Research-{self.h1_username}",
        }
    
    def subdomain_enum(self, domain: str) -> list:
        """Enumerate subdomains for a domain."""
        print(f"[*] Enumerating subdomains for: {domain}")
        
        subdomains = []
        
        # Using subfinder if available
        try:
            result = subprocess.run(
                ["subfinder", "-d", domain, "-silent"],
                capture_output=True,
                text=True,
                timeout=120
            )
            subdomains.extend(result.stdout.strip().split("\n"))
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("[!] subfinder not available or timed out")
        
        # Filter empty and save
        subdomains = [s for s in subdomains if s]
        
        output_file = self.output_dir / f"{domain.replace('.', '_')}_subdomains.txt"
        with open(output_file, "w") as f:
            f.write("\n".join(subdomains))
        
        print(f"[+] Found {len(subdomains)} subdomains, saved to {output_file}")
        return subdomains
    
    def check_alive_hosts(self, domains: list) -> list:
        """Check which domains are alive."""
        print(f"[*] Checking {len(domains)} hosts for availability...")
        
        alive = []
        domains_file = self.output_dir / "temp_domains.txt"
        
        with open(domains_file, "w") as f:
            f.write("\n".join(domains))
        
        try:
            result = subprocess.run(
                ["httpx", "-l", str(domains_file), "-silent", "-nc"],
                capture_output=True,
                text=True,
                timeout=300
            )
            alive = [h for h in result.stdout.strip().split("\n") if h]
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print("[!] httpx not available or timed out")
            # Fallback: assume all are alive
            alive = [f"https://{d}" for d in domains]
        
        print(f"[+] {len(alive)} hosts are alive")
        return alive
    
    def scan_sqli(self, url: str) -> list:
        """Check for SQL injection vulnerabilities."""
        print(f"[*] Scanning for SQLi: {url}")
        findings = []
        
        # This is a detection-only check, not exploitation
        headers = self.get_request_headers()
        
        test_params = ["id", "user", "search", "q", "query", "page", "cat", "category"]
        
        for param in test_params:
            for payload in self.sqli_payloads[:3]:  # Only test safe payloads
                test_url = f"{url}?{param}={payload}"
                
                try:
                    import requests
                    resp = requests.get(test_url, headers=headers, timeout=10, verify=False)
                    
                    # Check for SQL error patterns
                    error_patterns = [
                        "SQL syntax",
                        "mysql_fetch",
                        "ORA-",
                        "PostgreSQL",
                        "SQLite",
                        "JDBC",
                        "ODBC",
                        "syntax error",
                        "unclosed quotation",
                    ]
                    
                    for pattern in error_patterns:
                        if pattern.lower() in resp.text.lower():
                            finding = {
                                "type": "SQLi",
                                "url": test_url,
                                "evidence": pattern,
                                "severity": "CRITICAL"
                            }
                            findings.append(finding)
                            print(f"[!!!] POTENTIAL SQLi FOUND: {test_url}")
                            break
                            
                except Exception as e:
                    pass
        
        return findings
    
    def scan_info_disclosure(self, base_url: str) -> list:
        """Check for information disclosure."""
        print(f"[*] Scanning for info disclosure: {base_url}")
        findings = []
        
        headers = self.get_request_headers()
        
        for path in self.disclosure_paths:
            url = f"{base_url.rstrip('/')}{path}"
            
            try:
                import requests
                resp = requests.get(url, headers=headers, timeout=10, verify=False)
                
                if resp.status_code == 200:
                    # Check for sensitive content
                    sensitive_patterns = [
                        ("/.git", "[core]"),
                        ("/.env", "DB_PASSWORD"),
                        ("/swagger", "swagger"),
                        ("/graphql", "introspection"),
                        ("/actuator", "status"),
                    ]
                    
                    for pattern_path, content in sensitive_patterns:
                        if pattern_path in path and content.lower() in resp.text.lower():
                            finding = {
                                "type": "Information Disclosure",
                                "url": url,
                                "evidence": f"Found {pattern_path}",
                                "severity": "HIGH" if "git" in path or "env" in path else "MEDIUM"
                            }
                            findings.append(finding)
                            print(f"[!] INFO DISCLOSURE: {url}")
                            break
                            
            except Exception as e:
                pass
        
        return findings
    
    def scan_idor(self, base_url: str) -> list:
        """Check for IDOR vulnerabilities."""
        print(f"[*] Scanning for IDOR: {base_url}")
        findings = []
        
        # This requires authentication - placeholder for manual testing
        print("[i] IDOR testing requires authenticated session - manual testing recommended")
        
        return findings
    
    def run_nuclei_scan(self, targets: list, template_tags: list = None) -> list:
        """Run nuclei scans with specific templates."""
        print(f"[*] Running nuclei scan on {len(targets)} targets...")
        
        findings = []
        targets_file = self.output_dir / "nuclei_targets.txt"
        results_file = self.output_dir / f"nuclei_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(targets_file, "w") as f:
            f.write("\n".join(targets))
        
        # Focus on high-impact templates
        tags = template_tags or ["sqli", "rce", "lfi", "ssrf", "idor", "exposure"]
        
        cmd = [
            "nuclei",
            "-l", str(targets_file),
            "-tags", ",".join(tags),
            "-severity", "critical,high",
            "-json-export", str(results_file),
            "-silent",
            "-H", f"X-HackerOne-Research: {self.h1_username}"
        ]
        
        try:
            subprocess.run(cmd, timeout=600)
            
            if results_file.exists():
                with open(results_file) as f:
                    for line in f:
                        try:
                            finding = json.loads(line)
                            findings.append(finding)
                            print(f"[!!!] NUCLEI FINDING: {finding.get('info', {}).get('name', 'Unknown')}")
                        except json.JSONDecodeError:
                            pass
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print(f"[!] Nuclei scan failed: {e}")
        
        return findings
    
    def generate_report(self, findings: list):
        """Generate a report of all findings."""
        report_file = self.output_dir / f"henkel_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        
        with open(report_file, "w") as f:
            f.write("# Henkel Bug Bounty Findings\n\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n")
            f.write(f"Researcher: {self.h1_username}\n\n")
            
            if not findings:
                f.write("No findings to report.\n")
            else:
                # Group by severity
                critical = [x for x in findings if x.get("severity") == "CRITICAL"]
                high = [x for x in findings if x.get("severity") == "HIGH"]
                medium = [x for x in findings if x.get("severity") == "MEDIUM"]
                
                if critical:
                    f.write("## Critical Findings\n\n")
                    for finding in critical:
                        f.write(f"### {finding.get('type', 'Unknown')}\n")
                        f.write(f"- URL: {finding.get('url', 'N/A')}\n")
                        f.write(f"- Evidence: {finding.get('evidence', 'N/A')}\n\n")
                
                if high:
                    f.write("## High Findings\n\n")
                    for finding in high:
                        f.write(f"### {finding.get('type', 'Unknown')}\n")
                        f.write(f"- URL: {finding.get('url', 'N/A')}\n")
                        f.write(f"- Evidence: {finding.get('evidence', 'N/A')}\n\n")
                
                if medium:
                    f.write("## Medium Findings\n\n")
                    for finding in medium:
                        f.write(f"### {finding.get('type', 'Unknown')}\n")
                        f.write(f"- URL: {finding.get('url', 'N/A')}\n")
                        f.write(f"- Evidence: {finding.get('evidence', 'N/A')}\n\n")
        
        print(f"[+] Report saved to: {report_file}")
        return report_file
    
    def hunt(self, target_category: str = "chinese_domains"):
        """Main hunting workflow."""
        print("=" * 60)
        print("HENKEL BUG BOUNTY HUNTER")
        print("=" * 60)
        print(f"Researcher: {self.h1_username}")
        print(f"Category: {target_category}")
        print("=" * 60)
        
        targets = self.priority_targets.get(target_category, [])
        if not targets:
            print(f"[!] Unknown category: {target_category}")
            return
        
        all_findings = []
        
        for target in targets:
            print(f"\n[*] Processing: {target}")
            
            # Check authorization
            if not self.check_legal_authorization(target):
                continue
            
            # Check if alive
            alive_hosts = self.check_alive_hosts([target])
            
            for host in alive_hosts:
                # Scan for vulnerabilities
                all_findings.extend(self.scan_sqli(host))
                all_findings.extend(self.scan_info_disclosure(host))
                all_findings.extend(self.scan_idor(host))
        
        # Generate report
        self.generate_report(all_findings)
        
        print("\n" + "=" * 60)
        print(f"HUNT COMPLETE - {len(all_findings)} findings")
        print("=" * 60)


def main():
    """Entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Henkel Bug Bounty Hunter")
    parser.add_argument("--username", required=True, help="HackerOne username")
    parser.add_argument("--category", default="chinese_domains", 
                       choices=["chinese_domains", "uat_test_environments", "consumer_portals", "wildcards"],
                       help="Target category to hunt")
    parser.add_argument("--target", help="Specific target domain to scan")
    
    args = parser.parse_args()
    
    hunter = HenkelHunter(args.username)
    
    if args.target:
        # Single target mode
        if hunter.check_legal_authorization(args.target):
            findings = []
            findings.extend(hunter.scan_sqli(f"https://{args.target}"))
            findings.extend(hunter.scan_info_disclosure(f"https://{args.target}"))
            hunter.generate_report(findings)
    else:
        # Category mode
        hunter.hunt(args.category)


if __name__ == "__main__":
    main()
