# API Reference

Complete reference for Recon Bounty Stack modules and classes.

## Core Package

### `recon_bounty_stack`

Main package exports:

```python
from recon_bounty_stack import Pipeline, Config, get_logger

__version__ = "2.0.0"
```

---

## Configuration

### `Config`

Configuration management using Pydantic.

```python
from recon_bounty_stack import Config

# Load from environment
config = Config.from_env()

# Access settings
config.output_dir          # Path to output directory
config.auth_dir           # Path to authorizations
config.log_level          # Logging level
config.scan.timeout       # Scan timeout in seconds
config.scan.rate_limit    # Requests per second
config.tools.nuclei       # Path to nuclei binary
```

#### Methods

- `Config.from_env(env_file=None)` - Load from environment variables
- `config.ensure_directories()` - Create required directories
- `config.get(key, default=None)` - Get config value by key

---

## Pipeline

### `Pipeline`

Main pipeline orchestrator.

```python
from recon_bounty_stack import Pipeline

pipeline = Pipeline(
    config=config,          # Configuration object
    output_dir=None,        # Override output directory
    dry_run=False,          # Simulate without executing
)

# Run full pipeline
results = pipeline.run(
    targets=["example.com"],
    resume=False,           # Continue from last stage
    skip_auth=False,        # Skip authorization (dangerous!)
)

# Get status
status = pipeline.status()

# Reset for fresh run
pipeline.reset()
```

#### Results Dictionary

```python
{
    "start_time": "2024-01-01T00:00:00",
    "end_time": "2024-01-01T00:05:00",
    "duration_seconds": 300.0,
    "targets": ["example.com"],
    "stages": {
        "recon": {"completed": True, "duration": 60.0, "results": {...}},
        # ... other stages
    },
    "summary": {
        "subdomains": 100,
        "http_endpoints": 50,
        "triaged_findings": 10,
        "severity_critical": 1,
        "severity_high": 3,
    }
}
```

---

## Scanners

### `BaseScanner`

Abstract base class for scanners.

```python
from recon_bounty_stack.scanners import BaseScanner

class CustomScanner(BaseScanner):
    def scan(self, targets: list[str]) -> dict:
        # Implementation
        return {"findings": [...]}
```

#### Methods

- `check_tool()` - Check if external tool is available
- `get_tool_path()` - Get path to external tool
- `run_command(cmd, timeout=None)` - Run external command
- `write_temp_file(content, filename)` - Write temp file
- `cleanup_temp_files(*files)` - Remove temp files
- `scan(targets)` - Abstract: perform scan (must implement)

### `ReconScanner`

Subdomain enumeration scanner.

```python
from recon_bounty_stack.scanners import ReconScanner

scanner = ReconScanner(config=config)
results = scanner.scan(["example.com"])

# results = {
#     "subdomains": ["www.example.com", "api.example.com"],
#     "count": 2,
#     "output_file": "/path/to/subs.txt"
# }
```

### `HttpxScanner`

HTTP endpoint prober.

```python
from recon_bounty_stack.scanners import HttpxScanner

scanner = HttpxScanner(config=config)
results = scanner.scan(["www.example.com", "api.example.com"])

# results = {
#     "endpoints": [{"url": "...", "status-code": 200}],
#     "count": 2,
#     "https_count": 2,
#     "output_file": "/path/to/http.json"
# }
```

### `NucleiScanner`

Vulnerability scanner.

```python
from recon_bounty_stack.scanners import NucleiScanner

scanner = NucleiScanner(config=config)
results = scanner.scan(["https://www.example.com"])

# results = {
#     "findings": [{"template-id": "...", "info": {...}}],
#     "count": 5,
#     "severity_counts": {"high": 2, "medium": 3},
#     "output_file": "/path/to/nuclei-findings.json"
# }
```

---

## Agents

### `TriageAgent`

Finding prioritization agent.

```python
from recon_bounty_stack.agents import TriageAgent

agent = TriageAgent(config=config)
results = agent.triage(
    findings=raw_findings,
    min_severity="medium",
)

# results = {
#     "findings": [...],  # Triaged and prioritized
#     "count": 10,
#     "summary": {"critical": 1, "high": 3, "medium": 6},
#     "output_file": "/path/to/triage.json"
# }
```

### `AgentOrchestrator`

Multi-agent orchestration.

```python
from recon_bounty_stack.agents import AgentOrchestrator

orchestrator = AgentOrchestrator(config=config)

# List available roles
roles = orchestrator.list_roles()

# Run a task
exit_code = orchestrator.run_task("Strategist", "plan")
```

---

## Reports

### `ReportGenerator`

Generate vulnerability reports.

```python
from recon_bounty_stack.reports import ReportGenerator

generator = ReportGenerator(config=config)
results = generator.generate(triaged_findings)

# results = {
#     "individual_reports": ["/path/to/report1.md", ...],
#     "summary_report": "/path/to/summary.md",
#     "count": 10
# }
```

---

## Utils

### `LegalAuthorizationShield`

Legal authorization enforcement.

```python
from recon_bounty_stack.utils import LegalAuthorizationShield

shield = LegalAuthorizationShield(auth_dir="./authorizations")

# Check authorization
authorized, reason, data = shield.check_authorization("example.com")

# Create template
shield.create_authorization_template("target.com", "Client Name")
```

### `SafetyChecker`

Safety verification.

```python
from recon_bounty_stack.utils import SafetyChecker

checker = SafetyChecker(config=config)

# Verify single target
is_safe = checker.verify_safe("example.com")

# Verify multiple targets
all_safe, unsafe_list = checker.verify_all(["t1.com", "t2.com"])
```

### Helper Functions

```python
from recon_bounty_stack.utils import (
    sanitize_filename,
    format_timestamp,
)

# Sanitize for filename
safe_name = sanitize_filename("test/file:name")  # "test_file_name"

# Format timestamp
formatted = format_timestamp("2024-01-01T00:00:00Z")
```

---

## Logging

### `get_logger`

Get a configured logger.

```python
from recon_bounty_stack import get_logger

logger = get_logger("my_module", level="DEBUG")
logger.info("Starting operation...")
logger.error("Something went wrong!")
```
