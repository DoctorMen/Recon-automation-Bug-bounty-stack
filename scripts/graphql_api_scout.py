#!/usr/bin/env python3
"""
GraphQL & API Scout
Part of the "Top Tier" upgrade.
1. Probes identified GraphQL endpoints for Introspection
2. Classifies API endpoints by "IDOR Potential" (e.g. /users/123)
3. Generates specific attack advice

Usage: python3 graphql_api_scout.py --input <js_intel_report.json> --output <output_dir>
"""

import json
import requests
import argparse
import os
import re

def check_introspection(url, session):
    """Checks if GraphQL introspection is enabled."""
    query = """
    {
      __schema {
        types {
          name
        }
      }
    }
    """
    try:
        # Clean URL if it's relative (should have been full from JSINT, but safety first)
        if not url.startswith("http"):
            return {"url": url, "status": "Error", "introspection": False, "msg": "Relative URL"}
            
        r = session.post(url, json={"query": query}, timeout=10, verify=False)
        if r.status_code == 200 and "__schema" in r.text:
            return {"url": url, "status": "VULNERABLE", "introspection": True, "msg": "Introspection Enabled!"}
        else:
            return {"url": url, "status": "Safe", "introspection": False, "msg": "Introspection Disabled"}
    except Exception as e:
        return {"url": url, "status": "Error", "introspection": False, "msg": str(e)}

def classify_api_endpoint(endpoint):
    """Classifies an API endpoint for IDOR/BOLA potential."""
    # Look for patterns like /users/123, /orgs/abc-123, /orders/99
    # We assume 'endpoint' is a path string
    
    score = 0
    category = "Generic"
    
    if re.search(r"/[0-9]+(/|$)", endpoint):
        score += 5
        category = "Numeric ID (High Risk)"
    elif re.search(r"/[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}", endpoint):
        score += 3
        category = "UUID (Medium Risk)"
    elif re.search(r"/(user|account|org|order|invoice|payment|wallet)s?/", endpoint, re.I):
        score += 2
        category = "Sensitive Resource"
        
    return {"endpoint": endpoint, "score": score, "category": category}

def process_report(input_file, output_dir):
    print(f"[*] Loading JS Intelligence Report: {input_file}")
    with open(input_file, 'r') as f:
        data = json.load(f)
        
    session = requests.Session()
    session.headers.update({"User-Agent": "BugBountyScout/1.0"})
    
    graphql_findings = []
    api_findings = []
    
    # 1. Process GraphQL
    print("[*] Probing GraphQL endpoints...")
    seen_gql = set()
    for item in data:
        for gql_url in item.get("graphql", []):
            # Construct full URL if relative
            full_url = gql_url
            if not gql_url.startswith("http"):
                base = item["url"].split("/")[0] + "//" + item["url"].split("/")[2]
                full_url = base + gql_url if gql_url.startswith("/") else base + "/" + gql_url
                
            if full_url in seen_gql:
                continue
            seen_gql.add(full_url)
            
            print(f"  > Checking {full_url}")
            result = check_introspection(full_url, session)
            if result["introspection"]:
                print(f"    [!] INTROSPECTION ENABLED: {full_url}")
            graphql_findings.append(result)

    # 2. Process API Endpoints for IDOR
    print("[*] Classifying API endpoints for IDOR potential...")
    for item in data:
        for endpoint in item.get("endpoints", []):
            classification = classify_api_endpoint(endpoint)
            if classification["score"] > 0:
                api_findings.append({
                    "source_js": item["url"], 
                    **classification
                })
    
    # Sort API findings by score
    api_findings.sort(key=lambda x: x["score"], reverse=True)
    
    # 3. Save Reports
    gql_file = os.path.join(output_dir, "graphql_scan_results.json")
    api_file = os.path.join(output_dir, "api_idor_candidates.json")
    
    with open(gql_file, 'w') as f:
        json.dump(graphql_findings, f, indent=2)
        
    with open(api_file, 'w') as f:
        json.dump(api_findings, f, indent=2)
        
    print(f"[*] Results saved:\n  - {gql_file}\n  - {api_file}")
    
    # Generate actionable summary
    action_file = os.path.join(output_dir, "IMMEDIATE_ACTIONS.md")
    with open(action_file, 'w') as f:
        f.write("# Immediate Action Plan (Generated Tonight)\n\n")
        f.write("## 1. GraphQL Introspection (Critical)\n")
        vuln_gql = [g for g in graphql_findings if g["introspection"]]
        if vuln_gql:
            for v in vuln_gql:
                f.write(f"- [ ] Run `graphql-voyager` or `inql` on: `{v['url']}`\n")
        else:
            f.write("No introspection enabled endpoints found yet.\n")
            
        f.write("\n## 2. IDOR Candidates (High Priority)\n")
        high_risk = [a for a in api_findings if a["score"] >= 5]
        if high_risk:
            for a in high_risk[:10]:
                f.write(f"- [ ] Test access control on `{a['endpoint']}` (Found in {a['source_js']})\n")
        else:
            f.write("No obvious numeric ID endpoints found.\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Input JS report file")
    parser.add_argument("--output", required=True, help="Output directory")
    args = parser.parse_args()
    
    if not os.path.exists(args.output):
        os.makedirs(args.output)
        
    process_report(args.input, args.output)
