#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Extract Rapyd-specific endpoints from discovery files
"""

import json
import sys
from pathlib import Path
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).parent.parent
OUTPUT_DIR = REPO_ROOT / "output"
ROI_OUTPUT_DIR = OUTPUT_DIR / "immediate_roi"

def extract_rapyd_endpoints():
    """Extract all Rapyd endpoints from discovery files"""
    
    rapyd_endpoints = []
    
    # Check all discovery sources
    sources = [
        ROI_OUTPUT_DIR / "api_paths.txt",
        ROI_OUTPUT_DIR / "api_endpoints.json",
        ROI_OUTPUT_DIR / "urls.txt",
        OUTPUT_DIR / "http.json",
        OUTPUT_DIR / "endpoints.txt",
    ]
    
    print("=" * 60)
    print("Extracting Rapyd Endpoints")
    print("=" * 60)
    print()
    
    rapyd_domains = ["rapyd.net", "rapyd.com", "dashboard.rapyd", "sandboxapi.rapyd", "api.rapyd"]
    
    for source in sources:
        if not source.exists():
            continue
        
        print(f"[*] Checking: {source.name}")
        
        try:
            if source.suffix == '.txt':
                with open(source, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if any(domain in line.lower() for domain in rapyd_domains):
                            if line.startswith('http'):
                                rapyd_endpoints.append({"url": line, "source": source.name})
                            else:
                                # Try to construct URL
                                if 'rapyd' in line.lower():
                                    rapyd_endpoints.append({"url": f"https://{line}", "source": source.name})
            else:
                # JSON file
                with open(source, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                    if not content:
                        continue
                    
                    # Try NDJSON
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
                                      data.get("host"))
                                
                                if not url and isinstance(data, dict):
                                    host = data.get("host")
                                    scheme = data.get("scheme", "https")
                                    path = data.get("path", "")
                                    if host:
                                        url = f"{scheme}://{host}{path}"
                                
                                if url and any(domain in url.lower() for domain in rapyd_domains):
                                    rapyd_endpoints.append({"url": url, "data": data, "source": source.name})
                        except json.JSONDecodeError:
                            continue
                    
                    # Try JSON array
                    try:
                        data = json.loads(content)
                        if isinstance(data, list):
                            for item in data:
                                if isinstance(item, dict):
                                    url = (item.get("url") or 
                                          item.get("input") or 
                                          item.get("matched-at") or
                                          item.get("host"))
                                    
                                    if not url and isinstance(item, dict):
                                        host = item.get("host")
                                        scheme = item.get("scheme", "https")
                                        path = item.get("path", "")
                                        if host:
                                            url = f"{scheme}://{host}{path}"
                                    
                                    if url and any(domain in url.lower() for domain in rapyd_domains):
                                        rapyd_endpoints.append({"url": url, "data": item, "source": source.name})
                    except json.JSONDecodeError:
                        pass
        except Exception as e:
            print(f"  Warning: {e}")
    
    # Deduplicate
    seen = set()
    unique_endpoints = []
    for ep in rapyd_endpoints:
        url = ep.get("url", "")
        if url and url not in seen:
            seen.add(url)
            unique_endpoints.append(ep)
    
    print(f"[*] Found {len(unique_endpoints)} unique Rapyd endpoints")
    print()
    
    if not unique_endpoints:
        print("⚠️  No Rapyd endpoints found in discovery files!")
        print()
        print("This means:")
        print("1. Rapyd subdomains might not have been discovered")
        print("2. Or Rapyd endpoints are in targets.txt but weren't probed")
        print()
        print("Recommendation:")
        print("1. Check targets.txt contains: rapyd.net, api.rapyd.net, dashboard.rapyd.net")
        print("2. Re-run discovery: python3 scripts/immediate_roi_hunter.py")
        print("3. Or manually test known Rapyd endpoints:")
        print("   - https://sandboxapi.rapyd.net/v1/payments")
        print("   - https://dashboard.rapyd.net/collect/payments")
        return
    
    # Score and prioritize Rapyd endpoints
    print("=" * 60)
    print("Top Rapyd Endpoints for Manual Testing")
    print("=" * 60)
    print()
    
    # Score endpoints
    scored = []
    for ep in unique_endpoints:
        url = ep.get("url", "")
        if not url:
            continue
        
        parsed = urlparse(url)
        path = parsed.path.lower()
        score = 0
        reasons = []
        
        # High priority paths
        if "/api/v1/payments" in path or "/v1/payments" in path:
            score += 50
            reasons.append("Payment API")
        if "/api/v1/customers" in path or "/v1/customers" in path:
            score += 45
            reasons.append("Customer API")
        if "/collect/payments" in path:
            score += 50
            reasons.append("Payment collection endpoint")
        if "/api/" in path:
            score += 30
            reasons.append("API endpoint")
        if "sandboxapi" in url:
            score += 20
            reasons.append("Sandbox API")
        if "dashboard" in url:
            score += 25
            reasons.append("Dashboard")
        
        scored.append({
            "url": url,
            "score": score,
            "reasons": reasons,
            "source": ep.get("source", "unknown")
        })
    
    # Sort by score
    scored.sort(key=lambda x: x["score"], reverse=True)
    
    # Show top 20
    print(f"Showing top {min(20, len(scored))} Rapyd endpoints:")
    print()
    
    for idx, ep in enumerate(scored[:20], 1):
        print(f"{idx}. Score: {ep['score']}")
        print(f"   URL: {ep['url']}")
        print(f"   Reasons: {', '.join(ep['reasons']) if ep['reasons'] else 'General endpoint'}")
        print(f"   Source: {ep['source']}")
        print()
    
    # Save to file
    output_file = ROI_OUTPUT_DIR / "rapyd_endpoints.json"
    ROI_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(scored, f, indent=2)
    
    print(f"[*] Saved to: {output_file}")
    print()
    
    print("=" * 60)
    print("Manual Testing Recommendations")
    print("=" * 60)
    print()
    print("Top Priority Rapyd Endpoints:")
    print()
    
    # Group by endpoint type
    payment_apis = [e for e in scored if "payment" in e["url"].lower()][:5]
    customer_apis = [e for e in scored if "customer" in e["url"].lower()][:5]
    dashboard = [e for e in scored if "dashboard" in e["url"].lower()][:5]
    
    if payment_apis:
        print("💰 Payment APIs:")
        for ep in payment_apis:
            print(f"   - {ep['url']}")
        print()
    
    if customer_apis:
        print("👤 Customer APIs:")
        for ep in customer_apis:
            print(f"   - {ep['url']}")
        print()
    
    if dashboard:
        print("📊 Dashboard Endpoints:")
        for ep in dashboard:
            print(f"   - {ep['url']}")
        print()
    
    print("=" * 60)

if __name__ == "__main__":
    extract_rapyd_endpoints()








