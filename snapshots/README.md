<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Snapshot System
# ==============

## Overview
Snapshot system captures current project state for tracking and debugging.

## Manual Snapshot Creation

\\ash
# Create snapshot directory
mkdir -p snapshots/current-state

# Capture system info
date > snapshots/current-state/timestamp.txt
uname -a > snapshots/current-state/system.txt
node --version > snapshots/current-state/node_version.txt 2>&1
docker --version > snapshots/current-state/docker_version.txt 2>&1
ps aux | grep -E '(node|npm|n8n|docker)' > snapshots/current-state/processes.txt

# Copy important files
cp workflows/*.json snapshots/current-state/
cp programs/rapyd/targets.txt snapshots/current-state/ 2>/dev/null
\
## Current Snapshot
Location: snapshots/current-state/

Contains:
- System information
- Version numbers
- Active processes
- Workflow files
- Configuration files

