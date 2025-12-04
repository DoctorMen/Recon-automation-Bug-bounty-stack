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

with open('workflows/rapyd-hourly-monitor-enhanced.json', 'r', encoding='utf-8-sig') as f:
    workflow = json.load(f)

# Find and update the HTTP Request node for Rapyd API
for node in workflow.get('nodes', []):
    if 'Check Rapyd API Status' in node.get('name', ''):
        # Remove credentials requirement (public endpoint)
        if 'credentials' in node:
            del node['credentials']
        
        # Set authentication to none
        if 'parameters' in node:
            if 'authentication' in node['parameters']:
                node['parameters']['authentication'] = 'none'
            
            # Add required X-Bugcrowd header
            if 'options' not in node['parameters']:
                node['parameters']['options'] = {}
            
            if 'headers' not in node['parameters']['options']:
                node['parameters']['options']['headers'] = {}
            
            # Add X-Bugcrowd header (required by program)
            node['parameters']['options']['headers']['X-Bugcrowd'] = 'Bugcrowd-DoctorMen'
            
            # Ensure method is GET (read-only, idempotent)
            if 'method' not in node['parameters']:
                node['parameters']['method'] = 'GET'
            elif node['parameters']['method'] != 'GET':
                node['parameters']['method'] = 'GET'
        
        print('Updated node:', node.get('name'))
        break

# Verify workflow is idempotent (no write operations)
print('Verifying idempotency:')
for node in workflow.get('nodes', []):
    node_type = node.get('type', '')
    node_name = node.get('name', '')
    
    if 'HTTP' in node_type:
        method = node.get('parameters', {}).get('method', 'GET')
        url = node.get('parameters', {}).get('url', '')
        
        if method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            print('WARNING:', node_name, 'uses', method, 'method')
        else:
            print('OK:', node_name, ':', method, url)

# Save updated workflow
with open('workflows/rapyd-hourly-monitor-enhanced.json', 'w', encoding='utf-8') as f:
    json.dump(workflow, f, indent=2)

print('Workflow updated successfully')

# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
