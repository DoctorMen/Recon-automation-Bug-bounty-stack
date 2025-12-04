#!/bin/bash
# Cantina Submission Tracking Script
# Generated: 2025-12-01 14:20:09

echo "CANTINA SUBMISSION TRACKING"
echo "Date: $(date)"
echo

# Check submission status
if [ -f "cantina_organization_data.json" ]; then
    echo "Current Status:"
    python3 -c "
import json
with open('cantina_organization_data.json', 'r') as f:
    data = json.load(f)

submissions = data.get('submissions', [])
status_counts = {}
total_value = 0

for sub in submissions:
    status = sub.get('status', 'unknown')
    status_counts[status] = status_counts.get(status, 0) + 1
    total_value += sub.get('bounty_min', 0)

for status, count in status_counts.items():
    if count > 0:
        print(f'   {status.title()}: {count} submissions')

print(f'\nTotal Potential: ${total_value:,}')
"
else
    echo "No data file found"
fi

echo
echo "NEXT ACTIONS:"
echo "1. Submit pending vulnerabilities to Cantina"
echo "2. Update status when accepted/rejected"
echo "3. Track earnings and optimize strategy"
