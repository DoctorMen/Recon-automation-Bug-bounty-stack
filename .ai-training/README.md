<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# AI Training Materials - Recon Automation Bug Bounty Stack

## Overview
Comprehensive training materials enabling AI agents to fully understand and operate the bug bounty automation system using public APIs and natural language commands.

## Quick Start
1. Read `training-index.md` for complete overview
2. Study `agent-training-manifest.json` for system architecture
3. Review `command-reference.md` for all commands
4. Practice with `usage-examples.md` scenarios

## Training Files

### Core Specifications
- `openapi-spec.yaml` - Complete API specification
- `api-schemas.json` - Data structure definitions
- `agent-training-manifest.json` - System manifest

### Command References
- `command-reference.md` - Complete command catalog
- `intent-patterns.json` - Natural language patterns
- `validation-rules.json` - Safety and validation rules

### Guides & Examples
- `usage-examples.md` - 11 real-world scenarios
- `integration-patterns.md` - External system integration
- `ai-assistant-guide.md` - AI operation guide
- `training-index.md` - Master index

## Key Concepts
1. **Idempotent Protocol** - All operations safe to run multiple times
2. **Multi-Agent Architecture** - 6 specialized agents coordinate tasks
3. **OPSEC-First** - Security checks before all operations
4. **Natural Language** - Understand user intent, not just literal commands

## For AI Agents
You can understand and execute user requests like:
- "Scan example.com" → Full security assessment
- "Show results" → Parse and present findings
- "Quick scan" → Fast mode with optimized settings
- "Resume" → Continue from last checkpoint

## Validation
All operations include:
- Authorization checks
- OPSEC verification
- Input validation
- Output sanitization

## System Entry Points
- Full pipeline: `python3 run_pipeline.py`
- Agent orchestration: `python3 scripts/agent_orchestrator.py`
- Individual stages: `run_recon.py`, `run_nuclei.py`, etc.

**Generated:** 2025-11-04  
**Version:** 1.0.0  
**Purpose:** Enable AI agents to interact with repository via public APIs
