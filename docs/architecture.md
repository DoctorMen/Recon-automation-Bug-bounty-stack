# Architecture Overview

This document describes the architecture of Recon Bounty Stack.

## System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Command-Line Interface                   │
│                      (recon-bounty CLI)                      │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│                    Pipeline Orchestrator                     │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ Stage 1: Recon    → Stage 2: HTTPx   → Stage 3: Nuclei │  │
│  │         ↓                ↓                   ↓         │  │
│  │ Stage 4: Triage  → Stage 5: Report Generation         │  │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│                 Legal Authorization Shield                   │
│         (Validates authorization before any scan)            │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. CLI Interface (`cli.py`)

The command-line interface built with Click:

- `scan` - Run reconnaissance scan
- `status` - Show pipeline status
- `auth` - Manage authorizations
- `reset` - Reset pipeline state

### 2. Pipeline Orchestrator (`core/pipeline.py`)

Coordinates the execution of all scan stages:

- **Recon** - Subdomain enumeration with Subfinder/Amass
- **HTTPx** - HTTP endpoint probing
- **Nuclei** - Vulnerability scanning
- **Triage** - Finding prioritization
- **Report** - Report generation

Features:
- Resume capability (continue from last stage)
- Stage tracking and status
- Parallel execution support

### 3. Scanners (`scanners/`)

Scanner implementations for external tools:

```python
class BaseScanner(ABC):
    """Abstract base class for all scanners."""
    
    def check_tool(self) -> bool: ...
    def run_command(self, cmd) -> subprocess.CompletedProcess: ...
    @abstractmethod
    def scan(self, targets) -> dict: ...
```

Implementations:
- `ReconScanner` - Subdomain enumeration
- `HttpxScanner` - HTTP probing
- `NucleiScanner` - Vulnerability detection

### 4. Agents (`agents/`)

Multi-agent orchestration system:

- **AgentOrchestrator** - Coordinates agent roles
- **TriageAgent** - Prioritizes findings

Agent roles:
- Strategist - Planning and sequencing
- Executor - Running scans
- Composer - Automation and optimization
- Reporter - Documentation

### 5. Utils (`utils/`)

Utility modules:

- `legal.py` - Legal authorization system
- `safety.py` - Safety verification
- `helpers.py` - Common utilities

## Data Flow

```
targets.txt
    ↓
[Recon Scanner]
    ↓
subs.txt (subdomains)
    ↓
[HTTPx Scanner]
    ↓
http.json (endpoints)
    ↓
[Nuclei Scanner]
    ↓
nuclei-findings.json
    ↓
[Triage Agent]
    ↓
triage.json (prioritized)
    ↓
[Report Generator]
    ↓
reports/*.md
```

## Configuration System

Configuration is managed through:

1. **Environment Variables** - Runtime configuration
2. **.env File** - Local development settings
3. **Config Class** - Pydantic-based validation

```python
from recon_bounty_stack import Config

config = Config.from_env()
config.output_dir = Path("./custom_output")
config.scan.threads = 100
```

## Legal Authorization

The Legal Authorization Shield is a critical component:

```python
class LegalAuthorizationShield:
    """
    BLOCKS ALL SCANS unless:
    1. Written authorization file exists
    2. Target is in authorized scope
    3. Current time is within authorized window
    4. Authorization signature is valid
    """
```

Authorization files are JSON documents containing:
- Client information
- Authorized scope (domains)
- Time window
- Testing types allowed/forbidden

## Extension Points

### Custom Scanners

```python
from recon_bounty_stack.scanners import BaseScanner

class CustomScanner(BaseScanner):
    def scan(self, targets: list[str]) -> dict:
        # Implement custom scanning logic
        return {"findings": [...]}
```

### Custom Agents

```python
from recon_bounty_stack.agents import TriageAgent

class CustomTriageAgent(TriageAgent):
    def _calculate_exploitability(self, finding):
        # Custom scoring logic
        return custom_score
```

## Security Considerations

1. **Authorization Required** - No scanning without proper authorization
2. **Audit Logging** - All scan attempts are logged
3. **Scope Enforcement** - Targets must be in authorized scope
4. **Time Windows** - Authorizations have expiration dates
