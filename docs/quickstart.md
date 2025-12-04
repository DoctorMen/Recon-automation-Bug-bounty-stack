# Quick Start Guide

Get started with Recon Bounty Stack in 5 minutes.

## Prerequisites

Ensure you have:
- Recon Bounty Stack installed (see [Installation](installation.md))
- External tools (subfinder, httpx, nuclei) in PATH
- A target you're authorized to test

## Step 1: Create Authorization

Before scanning any target, you must create a legal authorization file:

```bash
recon-bounty auth create example.com --client "Your Company Name"
```

This creates a file in `./authorizations/example.com_authorization.json`.

**Important**: Edit this file with proper authorization details before scanning!

## Step 2: Run Your First Scan

```bash
# Quick scan (fastest)
recon-bounty scan example.com --mode quick

# Full scan (comprehensive)
recon-bounty scan example.com --mode full

# Dry run (simulate without scanning)
recon-bounty scan example.com --dry-run
```

## Step 3: Check Status

```bash
recon-bounty status
```

This shows the pipeline status and any available results.

## Step 4: Review Results

Scan results are saved to the output directory:

```
output/
├── subs.txt               # Discovered subdomains
├── http.json              # Live HTTP endpoints
├── nuclei-findings.json   # Raw vulnerability findings
├── triage.json            # Prioritized findings
└── reports/
    ├── summary.md         # Executive summary
    └── *.md               # Individual finding reports
```

## Using the Python API

```python
from recon_bounty_stack import Pipeline, Config

# Load configuration
config = Config.from_env()

# Create pipeline
pipeline = Pipeline(config=config)

# Run scan
results = pipeline.run(
    targets=["example.com"],
    resume=False,  # Set True to continue from last stage
)

# Access results
print(f"Duration: {results['duration_seconds']:.1f}s")
print(f"Findings: {results['summary'].get('triaged_findings', 0)}")
```

## Demo Mode

Try the demo script to see sample output:

```bash
# Simulate a scan with sample data
python scripts/demo.py --simulate

# Show what would happen without executing
python scripts/demo.py --dry-run
```

## Next Steps

- Read the [Architecture Overview](architecture.md)
- Learn about [Custom Configuration](api-reference.md#configuration)
- Explore [Agent Orchestration](architecture.md#multi-agent-system)
