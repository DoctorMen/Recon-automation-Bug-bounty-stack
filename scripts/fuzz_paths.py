#!/usr/bin/env python3
"""
Smart Path Fuzzer
Sprays discovered JS paths against live domains to find valid endpoints.
"""

import requests
import sys
import concurrent.futures
import argparse
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def check_endpoint(url, session):
    try:
        r = session.get(url, timeout=5, verify=False, allow_redirects=False)
        # We care about 200 (OK), 401/403 (Auth required = exists), 500 (Error = exists)
        # We ignore 404 (Not Found)
        if r.status_code in [200, 401, 403, 500]:
            return f"[{r.status_code}] {url} (Size: {len(r.content)})"
    except:
        pass
    return None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--domains", required=True, help="List of domains")
    parser.add_argument("--paths", required=True, help="List of paths")
    args = parser.parse_args()

    with open(args.domains) as f:
        domains = [l.strip() for l in f if l.strip()]
    
    with open(args.paths) as f:
        paths = [l.strip() for l in f if l.strip() and l.startswith('/')]

    print(f"[*] Fuzzing {len(domains)} domains with {len(paths)} discovered paths...")
    print(f"[*] Total combinations: {len(domains) * len(paths)}")
    
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (BugBounty)"})

    tasks = []
    # Limit to top 5 domains to save time if list is huge, or do all if small
    # For tonight, let's do all from alive.txt (which was ~15)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        for d in domains:
            base = d if d.startswith("http") else f"https://{d}"
            for p in paths:
                url = f"{base.rstrip('/')}{p}"
                tasks.append(executor.submit(check_endpoint, url, session))
        
        for future in concurrent.futures.as_completed(tasks):
            res = future.result()
            if res:
                print(res)

if __name__ == "__main__":
    main()
