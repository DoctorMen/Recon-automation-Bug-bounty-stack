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
from urllib.parse import urlparse

SCRIPT_DIR = Path(__file__).parent
CONFIG_FILE = SCRIPT_DIR.parent / 'config' / 'methodology_config.yaml'
OUTPUT_DIR = SCRIPT_DIR.parent / 'output' / 'phase2_content'
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def load_config():
    with open(CONFIG_FILE, 'r') as f:
        return yaml.safe_load(f)

def log(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f'[{timestamp}] {message}')

def api_discovery(config, urls):
    log('PHASE 2.2: API Discovery')
    api_endpoints = []
    api_patterns = ['/api/v1', '/api/v2', '/v1', '/v2', '/swagger.json', '/openapi.json', '/graphql']
    for url in urls:
        parsed = urlparse(url if '://' in url else f'https://{url}')
        base_url = f'{parsed.scheme}://{parsed.netloc}'
        for pattern in api_patterns:
            api_endpoints.append(f'{base_url}{pattern}')
    log(f'Found {len(api_endpoints)} API endpoints')
    return api_endpoints

def main():
    log('PHASE 2: CONTENT DISCOVERY')
    config = load_config()
    phase1_output = SCRIPT_DIR.parent / 'output' / 'phase1_recon' / 'all_subdomains.txt'
    if phase1_output.exists():
        with open(phase1_output, 'r') as f:
            urls = [f'https://{line.strip()}' for line in f if line.strip()]
    else:
        urls = [f'https://{d}' for d in config['targets']['rapyd_domains']]
    api_endpoints = api_discovery(config, urls)
    summary = {'api_endpoints': len(api_endpoints), 'api_endpoints_list': api_endpoints[:50]}
    with open(OUTPUT_DIR / 'phase2_summary.json', 'w') as f:
        json.dump(summary, f, indent=2)
    log('PHASE 2 COMPLETE')

if __name__ == '__main__':
    main()

# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
