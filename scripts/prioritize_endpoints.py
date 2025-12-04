#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Priority Endpoint Selector
Identifies the most valuable endpoints for manual testing
"""

import json
import sys
from pathlib import Path
from urllib.parse import urlparse
from typing import List, Dict, Any
from collections import defaultdict

REPO_ROOT = Path(__file__).parent.parent
OUTPUT_DIR = REPO_ROOT / "output"
ROI_OUTPUT_DIR = OUTPUT_DIR / "immediate_roi"

def load_endpoints() -> List[Dict[str, Any]]:
    """Load all discovered endpoints"""
    endpoints = []
    
    # Check multiple sources (expand search)
    sources = [
        ROI_OUTPUT_DIR / "api_endpoints.json",
        ROI_OUTPUT_DIR / "api_paths.txt",
        ROI_OUTPUT_DIR / "urls.txt",
        OUTPUT_DIR / "http.json",
        OUTPUT_DIR / "api-endpoints.json",
        OUTPUT_DIR / "endpoints.txt",
        OUTPUT_DIR / "live.txt",
    ]
    
    # Also check subdirectories
    if OUTPUT_DIR.exists():
        for subdir in OUTPUT_DIR.iterdir():
            if subdir.is_dir():
                sources.extend([
                    subdir / "discovered_endpoints.json",
                    subdir / "api_endpoints.json",
                    subdir / "endpoints.txt"
                ])
    
    print(f"[*] Checking {len(sources)} possible sources...")
    found_sources = []
    
    for source in sources:
        if not source.exists():
            continue
        
        found_sources.append(str(source))
        print(f"[*] Found: {source}")
        
        try:
            if source.suffix == '.txt':
                # Text file with URLs
                with open(source, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if line and (line.startswith('http') or line.startswith('https')):
                            endpoints.append({"url": line, "source": source.name})
                        # Also check for URLs in the middle of lines
                        elif 'http' in line:
                            import re
                            urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', line)
                            for url in urls:
                                endpoints.append({"url": url, "source": source.name})
            else:
                # JSON file - try NDJSON first (most common format)
                with open(source, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                    if not content:
                        continue
                    
                    # Try NDJSON (one JSON object per line)
                    lines_parsed = 0
                    for line in content.split('\n'):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            if isinstance(data, dict):
                                url = (data.get("url") or 
                                      data.get("input") or 
                                      data.get("matched-at") or
                                      data.get("host") or
                                      data.get("endpoint"))
                                
                                # If no direct URL, try to construct from host
                                if not url and isinstance(data, dict):
                                    host = data.get("host") or data.get("domain")
                                    scheme = data.get("scheme", "https")
                                    path = data.get("path", "")
                                    if host:
                                        url = f"{scheme}://{host}{path}"
                                
                                if url and (url.startswith('http://') or url.startswith('https://')):
                                    endpoints.append({"url": url, "data": data, "source": source.name})
                                    lines_parsed += 1
                        except json.JSONDecodeError:
                            continue
                    
                    # If NDJSON didn't work, try JSON array
                    if lines_parsed == 0:
                        try:
                            data = json.loads(content)
                            if isinstance(data, list):
                                for item in data:
                                    if isinstance(item, dict):
                                        url = (item.get("url") or 
                                              item.get("input") or 
                                              item.get("matched-at") or
                                              item.get("host") or
                                              item.get("endpoint"))
                                        
                                        if not url and isinstance(item, dict):
                                            host = item.get("host") or item.get("domain")
                                            scheme = item.get("scheme", "https")
                                            path = item.get("path", "")
                                            if host:
                                                url = f"{scheme}://{host}{path}"
                                        
                                        if url and (url.startswith('http://') or url.startswith('https://')):
                                            endpoints.append({"url": url, "data": item, "source": source.name})
                        except json.JSONDecodeError:
                            pass
                            
        except Exception as e:
            print(f"Warning: Failed to load {source}: {e}", file=sys.stderr)
    
    if found_sources:
        print(f"[*] Loaded from {len(found_sources)} source(s)")
    else:
        print("[!] No source files found!")
        print(f"[!] Checked in: {OUTPUT_DIR}")
        print(f"[!] Checked in: {ROI_OUTPUT_DIR}")
        print("[!] Run discovery scan first: python3 scripts/immediate_roi_hunter.py")
    
    return endpoints

def score_endpoint(endpoint: Dict[str, Any]) -> Dict[str, Any]:
    """Score an endpoint for manual testing priority"""
    url = endpoint.get("url", "")
    if not url:
        return {"score": 0, "endpoint": endpoint}
    
    parsed = urlparse(url)
    path = parsed.path.lower()
    domain = parsed.netloc.lower()
    
    score = 0
    reasons = []
    
    # High-value domains (bug bounty programs)
    high_value_domains = [
        "rapyd", "mastercard", "apple", "microsoft", "atlassian",
        "kraken", "whitebit", "nicehash", "paypal", "stripe"
    ]
    for hvd in high_value_domains:
        if hvd in domain:
            score += 50
            reasons.append(f"High-value domain ({hvd})")
            break
    
    # API endpoints (higher priority)
    api_indicators = ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/"]
    for indicator in api_indicators:
        if indicator in path:
            score += 30
            reasons.append(f"API endpoint ({indicator})")
            break
    
    # Authentication endpoints
    auth_paths = ["/auth", "/login", "/oauth", "/token", "/session"]
    for auth_path in auth_paths:
        if auth_path in path:
            score += 40
            reasons.append(f"Authentication endpoint ({auth_path})")
            break
    
    # Payment endpoints
    payment_paths = ["/payment", "/pay", "/checkout", "/transaction", "/order"]
    for pay_path in payment_paths:
        if pay_path in path:
            score += 45
            reasons.append(f"Payment endpoint ({pay_path})")
            break
    
    # User/admin endpoints
    user_paths = ["/user", "/account", "/profile", "/admin", "/dashboard"]
    for user_path in user_paths:
        if user_path in path:
            score += 35
            reasons.append(f"User endpoint ({user_path})")
            break
    
    # GraphQL endpoints
    if "graphql" in path or "graphiql" in path:
        score += 35
        reasons.append("GraphQL endpoint")
    
    # Swagger/OpenAPI
    if "swagger" in path or "openapi" in path or "api-docs" in path:
        score += 25
        reasons.append("API documentation")
    
    # Status code from data
    data = endpoint.get("data", {})
    status_code = data.get("status-code") or data.get("status_code")
    if status_code:
        if status_code == 200:
            score += 10
            reasons.append("Returns 200 OK")
        elif status_code in [401, 403]:
            score += 15
            reasons.append(f"Protected endpoint ({status_code})")
    
    # HTTPS
    if parsed.scheme == "https":
        score += 5
    
    return {
        "score": score,
        "endpoint": endpoint,
        "url": url,
        "domain": domain,
        "path": path,
        "reasons": reasons
    }

def prioritize_endpoints(endpoints: List[Dict[str, Any]], top_n: int = 50) -> List[Dict[str, Any]]:
    """Prioritize endpoints for manual testing"""
    scored = []
    
    for endpoint in endpoints:
        scored.append(score_endpoint(endpoint))
    
    # Sort by score (highest first)
    scored.sort(key=lambda x: x["score"], reverse=True)
    
    # Deduplicate by URL
    seen = set()
    unique_scored = []
    for item in scored:
        url = item["url"]
        if url not in seen:
            seen.add(url)
            unique_scored.append(item)
    
    return unique_scored[:top_n]

def group_by_domain(endpoints: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Group endpoints by domain"""
    grouped = defaultdict(list)
    
    for item in endpoints:
        domain = item.get("domain", "unknown")
        grouped[domain].append(item)
    
    return dict(grouped)

def generate_testing_plan(prioritized: List[Dict[str, Any]]) -> str:
    """Generate a manual testing plan"""
    plan = []
    plan.append("# Manual Testing Priority Plan")
    plan.append("")
    plan.append(f"**Total Endpoints Discovered:** {len(prioritized)}")
    plan.append(f"**Top Priority Endpoints:** {min(50, len(prioritized))}")
    plan.append("")
    plan.append("---")
    plan.append("")
    
    # Group by domain
    grouped = group_by_domain(prioritized)
    
    plan.append("## Top Priority Endpoints by Domain")
    plan.append("")
    
    for domain, endpoints in sorted(grouped.items(), key=lambda x: len(x[1]), reverse=True):
        plan.append(f"### {domain}")
        plan.append(f"**Endpoints:** {len(endpoints)}")
        plan.append("")
        
        for idx, item in enumerate(endpoints[:10], 1):  # Top 10 per domain
            url = item["url"]
            score = item["score"]
            reasons = ", ".join(item["reasons"])
            
            plan.append(f"{idx}. **Score: {score}** - `{url}`")
            plan.append(f"   - Reasons: {reasons}")
            plan.append("")
        
        if len(endpoints) > 10:
            plan.append(f"   ... and {len(endpoints) - 10} more endpoints")
            plan.append("")
        
        plan.append("---")
        plan.append("")
    
    # Top 20 overall
    plan.append("## Top 20 Overall Priority Endpoints")
    plan.append("")
    
    for idx, item in enumerate(prioritized[:20], 1):
        url = item["url"]
        score = item["score"]
        reasons = ", ".join(item["reasons"])
        
        plan.append(f"{idx}. **Score: {score}**")
        plan.append(f"   - URL: `{url}`")
        plan.append(f"   - Reasons: {reasons}")
        plan.append("")
    
    plan.append("---")
    plan.append("")
    plan.append("## Manual Testing Checklist")
    plan.append("")
    plan.append("For each priority endpoint:")
    plan.append("")
    plan.append("- [ ] **IDOR Testing**")
    plan.append("  - [ ] Test with different user IDs")
    plan.append("  - [ ] Test with other users' resources")
    plan.append("  - [ ] Test with invalid IDs")
    plan.append("")
    plan.append("- [ ] **Authentication Bypass**")
    plan.append("  - [ ] Test without authentication")
    plan.append("  - [ ] Test with invalid tokens")
    plan.append("  - [ ] Test with expired tokens")
    plan.append("")
    plan.append("- [ ] **Authorization Testing**")
    plan.append("  - [ ] Test with different roles")
    plan.append("  - [ ] Test privilege escalation")
    plan.append("")
    plan.append("- [ ] **API Security**")
    plan.append("  - [ ] Test mass assignment")
    plan.append("  - [ ] Test rate limiting")
    plan.append("  - [ ] Test input validation")
    plan.append("")
    plan.append("- [ ] **Information Disclosure**")
    plan.append("  - [ ] Check error messages")
    plan.append("  - [ ] Check response headers")
    plan.append("  - [ ] Check for sensitive data")
    plan.append("")
    
    return "\n".join(plan)

def main():
    print("=" * 60)
    print("Priority Endpoint Selector")
    print("=" * 60)
    print()
    
    print("[*] Loading discovered endpoints...")
    endpoints = load_endpoints()
    
    if not endpoints:
        print("❌ No endpoints found!")
        print("Run the discovery scan first: python3 scripts/immediate_roi_hunter.py")
        sys.exit(1)
    
    print(f"[*] Found {len(endpoints)} endpoints")
    print()
    
    print("[*] Prioritizing endpoints for manual testing...")
    prioritized = prioritize_endpoints(endpoints, top_n=50)
    
    print(f"[*] Selected top {len(prioritized)} priority endpoints")
    print()
    
    # Save prioritized list
    output_file = ROI_OUTPUT_DIR / "priority_endpoints.json"
    ROI_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(prioritized, f, indent=2)
    
    print(f"[*] Saved prioritized endpoints to: {output_file}")
    print()
    
    # Generate testing plan
    plan_file = ROI_OUTPUT_DIR / "MANUAL_TESTING_PLAN.md"
    plan_content = generate_testing_plan(prioritized)
    
    with open(plan_file, 'w') as f:
        f.write(plan_content)
    
    print(f"[*] Generated testing plan: {plan_file}")
    print()
    
    # Show top 10
    print("=" * 60)
    print("Top 10 Priority Endpoints for Manual Testing")
    print("=" * 60)
    print()
    
    for idx, item in enumerate(prioritized[:10], 1):
        url = item["url"]
        score = item["score"]
        reasons = ", ".join(item["reasons"])
        
        print(f"{idx}. Score: {score}")
        print(f"   URL: {url}")
        print(f"   Reasons: {reasons}")
        print()
    
    print("=" * 60)
    print("Next Steps:")
    print("=" * 60)
    print("1. Review: output/immediate_roi/MANUAL_TESTING_PLAN.md")
    print("2. Start manual testing with top priority endpoints")
    print("3. Focus on one domain at a time for depth")
    print("=" * 60)

if __name__ == "__main__":
    main()

