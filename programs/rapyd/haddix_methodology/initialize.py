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

from pathlib import Path
import yaml

BASE_DIR = Path(__file__).parent

def create_output_dirs():
    output_dirs = [
        'output/phase1_recon',
        'output/phase2_content',
        'output/phase3_parameters',
        'output/phase4_testing',
        'output/phase5_heatmap'
    ]
    for dir_path in output_dirs:
        (BASE_DIR / dir_path).mkdir(parents=True, exist_ok=True)
    print('âœ… Output directories created')

def verify_config():
    config_file = BASE_DIR / 'config' / 'methodology_config.yaml'
    if not config_file.exists():
        print('âŒ Configuration file missing!')
        return False
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        print('âœ… Configuration file valid')
        return True
    except Exception as e:
        print(f'âŒ Configuration file error: {e}')
        return False

def verify_scripts():
    scripts = [
        'phase1_reconnaissance.py',
        'phase2_content_discovery.py',
        'phase3_parameter_analysis.py',
        'phase4_testing_layers.py',
        'phase5_heat_mapping.py',
        'run_full_methodology.py'
    ]
    scripts_dir = BASE_DIR / 'scripts'
    missing = []
    for script in scripts:
        if not (scripts_dir / script).exists():
            missing.append(script)
    if missing:
        print(f'âŒ Missing scripts: {missing}')
        return False
    else:
        print('âœ… All scripts present')
        return True

def main():
    print('=' * 60)
    print('INITIALIZING JASON HADDIX METHODOLOGY')
    print('=' * 60)
    print()
    create_output_dirs()
    config_ok = verify_config()
    scripts_ok = verify_scripts()
    print()
    print('=' * 60)
    if config_ok and scripts_ok:
        print('âœ… SYSTEM READY')
        print('=' * 60)
        print()
        print('To run full methodology:')
        print('  python3 scripts/run_full_methodology.py')
        print()
        print('To run individual phases:')
        print('  python3 scripts/phase1_reconnaissance.py')
        print('  python3 scripts/phase2_content_discovery.py')
        print('  python3 scripts/phase3_parameter_analysis.py')
        print('  python3 scripts/phase4_testing_layers.py')
        print('  python3 scripts/phase5_heat_mapping.py')
        return True
    else:
        print('âŒ INITIALIZATION FAILED')
        print('=' * 60)
        return False

if __name__ == '__main__':
    main()

# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
