#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Quick runner script for Jason Haddix Methodology

cd ~/Recon-automation-Bug-bounty-stack/programs/rapyd/haddix_methodology

echo '============================================================'
echo 'JASON HADDIX METHODOLOGY - QUICK RUNNER'
echo '============================================================'
echo ''
echo 'Current directory:' C:\Users\Doc Lab
echo ''

# Check if initialize.py exists
if [ -f initialize.py ]; then
    echo 'âœ… Running initialization check...'
    python3 initialize.py
    echo ''
fi

echo '============================================================'
echo 'Starting Full Methodology...'
echo '============================================================'
echo ''

python3 scripts/run_full_methodology.py
