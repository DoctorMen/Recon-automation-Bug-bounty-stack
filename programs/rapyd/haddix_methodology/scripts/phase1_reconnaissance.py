#!/usr/bin/env python3
"""
Copyright (c) 2025 YOUR_NAME_HERE
Proprietary and Confidential
All Rights Reserved

This software is proprietary and confidential.
Unauthorized copying, modification, or distribution is prohibited.

System ID: BB_20251102_5946
Owner: YOUR_NAME_HERE
"""

import subprocess
import json
import yaml
from pathlib import Path
from datetime import datetime

SCRIPT_DIR = Path(__file__).parent
CONFIG_FILE = SCRIPT_DIR.parent / 'config' / 'methodology_config.yaml'
OUTPUT_DIR = SCRIPT_DIR.parent / 'output' / 'phase1_recon'
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def load_config():
    with open(CONFIG_FILE, 'r') as f:
        return yaml.safe_load(f)

def log(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f'[{timestamp}] {message}')

def subdomain_enumeration(config):
    log('PHASE 1.1: Subdomain Enumeration')
    targets = config['targets']['rapyd_domains']
    all_subs = set()
    for target in targets:
        domain = target.split('//')[-1].split('/')[0]
        log(f'Enumerating: {domain}')
        output_file = OUTPUT_DIR / f'{domain}_subfinder.txt'
        subprocess.run(f'subfinder -d {domain} -silent -o {output_file} 2>/dev/null || echo', shell=True)
        if output_file.exists():
            with open(output_file, 'r') as f:
                all_subs.update([line.strip() for line in f if line.strip()])
    combined_file = OUTPUT_DIR / 'all_subdomains.txt'
    with open(combined_file, 'w') as f:
        for sub in sorted(all_subs):
            f.write(f'{sub}
')
    log(f'Found {len(all_subs)} subdomains')
    return list(all_subs)

def main():
    log('PHASE 1: RECONNAISSANCE')
    config = load_config()
    subdomains = subdomain_enumeration(config)
    summary = {'subdomains_found': len(subdomains), 'subdomains': subdomains[:100]}
    with open(OUTPUT_DIR / 'phase1_summary.json', 'w') as f:
        json.dump(summary, f, indent=2)
    log('PHASE 1 COMPLETE')

if __name__ == '__main__':
    main()

# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
