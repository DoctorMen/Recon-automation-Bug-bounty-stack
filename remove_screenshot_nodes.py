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

# Read workflow
with open('workflows/rapyd-hourly-monitor-enhanced.json', 'r', encoding='utf-8-sig') as f:
    workflow = json.load(f)

# Nodes to remove (screenshot-related)
nodes_to_remove = [
    'Take Screenshot',
    'Save Screenshot',
    'Prepare Screenshot Targets',
    'Aggregate Screenshots',
    'Check Screenshot Enabled'
]

# Build name to ID mapping
name_to_id = {}
for node in workflow.get('nodes', []):
    name_to_id[node.get('name', '')] = node.get('id')

# Filter out screenshot nodes
original_nodes = workflow.get('nodes', [])
new_nodes = []
removed_node_ids = set()
removed_node_names = set()

for node in original_nodes:
    node_name = node.get('name', '')
    if node_name in nodes_to_remove:
        removed_node_ids.add(node.get('id'))
        removed_node_names.add(node_name)
        print(f'Removing node: {node_name}')
    else:
        new_nodes.append(node)

# Update workflow
workflow['nodes'] = new_nodes

# Remove connections to/from removed nodes
connections = workflow.get('connections', {})
new_connections = {}

for source_node, targets in connections.items():
    # Check if source node is removed
    source_name = None
    for node in original_nodes:
        if node.get('id') == source_node:
            source_name = node.get('name')
            break
    
    if source_name not in removed_node_names:
        new_targets = {}
        for target_key, target_list in targets.items():
            # target_list is a list of lists, each inner list contains dicts
            filtered_list = []
            for conn_group in target_list:
                if isinstance(conn_group, list):
                    filtered_group = []
                    for conn in conn_group:
                        if isinstance(conn, dict):
                            node_name = conn.get('node')
                            if node_name and node_name not in removed_node_names:
                                filtered_group.append(conn)
                    if filtered_group:
                        filtered_list.append(filtered_group)
            if filtered_list:
                new_targets[target_key] = filtered_list
        if new_targets:
            new_connections[source_node] = new_targets

workflow['connections'] = new_connections

# Find Initialize Config and Check Rapyd API Status nodes
init_config_id = None
check_api_id = None

for node in new_nodes:
    if node.get('name') == 'Initialize Config':
        init_config_id = node.get('id')
    elif node.get('name') == 'Check Rapyd API Status':
        check_api_id = node.get('id')

# Connect Initialize Config directly to Check Rapyd API Status
if init_config_id and check_api_id:
    init_config_name = None
    check_api_name = None
    for node in new_nodes:
        if node.get('id') == init_config_id:
            init_config_name = node.get('name')
        elif node.get('id') == check_api_id:
            check_api_name = node.get('name')
    
    if init_config_name and check_api_name:
        if init_config_id not in new_connections:
            new_connections[init_config_id] = {}
        if 'main' not in new_connections[init_config_id]:
            new_connections[init_config_id]['main'] = []
        
        # Check if connection already exists
        existing_connection = False
        for conn_group in new_connections[init_config_id].get('main', []):
            for conn in conn_group:
                if isinstance(conn, dict) and conn.get('node') == check_api_name:
                    existing_connection = True
                    break
        
        if not existing_connection:
            new_connections[init_config_id]['main'].append([
                {'node': check_api_name, 'type': 'main', 'index': 0}
            ])

workflow['connections'] = new_connections

# Save updated workflow
with open('workflows/rapyd-hourly-monitor-enhanced.json', 'w', encoding='utf-8') as f:
    json.dump(workflow, f, indent=2, ensure_ascii=False)

print(f'\nâœ… Removed {len(original_nodes) - len(new_nodes)} screenshot-related nodes')
print(f'âœ… Updated workflow connections')
print(f'âœ… Workflow saved')

# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
