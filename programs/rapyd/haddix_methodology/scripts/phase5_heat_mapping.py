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

SCRIPT_DIR = Path(__file__).parent
CONFIG_FILE = SCRIPT_DIR.parent / 'config' / 'methodology_config.yaml'
OUTPUT_DIR = SCRIPT_DIR.parent / 'output' / 'phase5_heatmap'
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def load_config():
    with open(CONFIG_FILE, 'r') as f:
        return yaml.safe_load(f)

def log(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f'[{timestamp}] {message}')

def categorize_endpoints(config, endpoints):
    log('PHASE 5: HEAT MAPPING')
    heat_map = {'high_priority': [], 'medium_priority': [], 'low_priority': []}
    high_keywords = config['phases']['heat_mapping']['high_priority']
    medium_keywords = config['phases']['heat_mapping']['medium_priority']
    for endpoint in endpoints:
        endpoint_lower = endpoint.lower()
        if any(k in endpoint_lower for k in high_keywords):
            heat_map['high_priority'].append(endpoint)
        elif any(k in endpoint_lower for k in medium_keywords):
            heat_map['medium_priority'].append(endpoint)
        else:
            heat_map['low_priority'].append(endpoint)
    high_count = len(heat_map['high_priority'])
    med_count = len(heat_map['medium_priority'])
    low_count = len(heat_map['low_priority'])
    log(f'High: {high_count}, Medium: {med_count}, Low: {low_count}')
    return heat_map

def main():
    log('PHASE 5: HEAT MAPPING')
    config = load_config()
    phase2_output = SCRIPT_DIR.parent / 'output' / 'phase2_content' / 'phase2_summary.json'
    endpoints = []
    if phase2_output.exists():
        with open(phase2_output, 'r') as f:
            data = json.load(f)
            endpoints = data.get('api_endpoints_list', [])
    if not endpoints:
        endpoints = [f'https://{d}' for d in config['targets']['rapyd_domains']]
    heat_map = categorize_endpoints(config, endpoints)
    report = {'heat_map': heat_map, 'recommendations': {'start_with': heat_map['high_priority'][:10]}}
    with open(OUTPUT_DIR / 'heat_map_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    log('PHASE 5 COMPLETE')

if __name__ == '__main__':
    main()

# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
