#!/usr/bin/env python3
"""Extract API subdomains from discovery.jsonl"""
import json
import sys

discovery_file = sys.argv[1] if len(sys.argv) > 1 else "/home/ubuntu/Recon-automation-Bug-bounty-stack/runs/20251201_2115/discovery.jsonl"

api_domains = set()

with open(discovery_file, 'r') as f:
    for line in f:
        try:
            data = json.loads(line.strip())
            input_domain = data.get('input', '')
            url = data.get('url', '')
            
            if 'api.' in input_domain or 'api.' in url:
                api_domains.add(input_domain)
        except:
            continue

for domain in sorted(api_domains):
    print(domain)

print(f"\nTotal API subdomains: {len(api_domains)}", file=sys.stderr)
