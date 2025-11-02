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
output = []
with open(output/temp_httpx.json) as f:
    for line in f:
        line = line.strip()
        if line:
            try:
                output.append(json.loads(line))
            except:
                pass
with open(output/http.json, w) as f:
    json.dump(output, f, indent=2)
print(Converted, len(output), endpoints

# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
