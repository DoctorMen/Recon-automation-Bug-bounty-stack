#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
# Quick execution script for high ROI bug hunting

echo '============================================================'
echo 'HIGH-PRIORITY BUG HUNTING - RAPYD'
echo '============================================================'
echo ''

# Step 1: IDOR Evidence Capture
echo 'Step 1: IDOR Evidence Capture'
echo '------------------------------'
cd findings
if [ -f automated_browser_evidence_capture.py ]; then
    echo 'âœ… IDOR evidence capture script found'
    echo 'Run: python3 automated_browser_evidence_capture.py'
else
    echo 'âŒ IDOR script not found'
fi
cd ..

echo ''
echo 'Step 2: API Discovery'
echo '---------------------'
cd haddix_methodology
if [ -f scripts/phase2_content_discovery.py ]; then
    echo 'âœ… Content discovery script found'
    echo 'Run: python3 scripts/phase2_content_discovery.py'
else
    echo 'âŒ Content discovery script not found'
fi
cd ..

echo ''
echo '============================================================'
echo 'NEXT STEPS:'
echo '1. Complete IDOR evidence capture'
echo '2. Test authentication bypass manually'
echo '3. Test payment manipulation'
echo '4. Document findings'
echo '============================================================'
