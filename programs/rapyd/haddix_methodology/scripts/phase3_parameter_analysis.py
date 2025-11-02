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

import json
import yaml
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, parse_qs

SCRIPT_DIR = Path(__file__).parent
CONFIG_FILE = SCRIPT_DIR.parent / 'config' / 'methodology_config.yaml'
OUTPUT_DIR = SCRIPT_DIR.parent / 'output' / 'phase3_parameters'
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def load_config():
    with open(CONFIG_FILE, 'r') as f:
        return yaml.safe_load(f)

def log(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f'[{timestamp}] {message}')

def parameter_enumeration(config, urls):
    log('PHASE 3.1: Parameter Enumeration')
    all_params = set()
    for url in urls[:20]:
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            all_params.update(params.keys())
    params_file = OUTPUT_DIR / 'all_parameters.txt'
    with open(params_file, 'w') as f:
        for param in sorted(all_params):
            f.write(f'{param}
')
    log(f'Found {len(all_params)} parameters')
    return list(all_params)

def main():
    log('PHASE 3: PARAMETER ANALYSIS')
    config = load_config()
    phase2_output = SCRIPT_DIR.parent / 'output' / 'phase2_content' / 'phase2_summary.json'
    urls = []
    if phase2_output.exists():
        with open(phase2_output, 'r') as f:
            data = json.load(f)
            urls = data.get('api_endpoints_list', [])
    if not urls:
        urls = [f'https://{d}' for d in config['targets']['rapyd_domains']]
    params = parameter_enumeration(config, urls)
    summary = {'parameters_found': len(params), 'parameters': params}
    with open(OUTPUT_DIR / 'phase3_summary.json', 'w') as f:
        json.dump(summary, f, indent=2)
    log('PHASE 3 COMPLETE')

if __name__ == '__main__':
    main()

# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
