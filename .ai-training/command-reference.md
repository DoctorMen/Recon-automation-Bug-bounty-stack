<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Complete Command Reference for AI Agents

## Core Philosophy
This system uses IDEMPOTENT PROTOCOL - all operations are safe to run multiple times. Commands check state before executing and skip completed work automatically.

---

## 🎯 Quick Navigation
- [Pipeline Commands](#pipeline-commands) - Full workflow orchestration
- [Recon Commands](#recon-commands) - Subdomain discovery
- [Scanning Commands](#scanning-commands) - Vulnerability detection
- [Agent Orchestration](#agent-orchestration) - Multi-agent coordination
- [OPSEC Commands](#opsec-commands) - Security and privacy
- [Reporting Commands](#reporting-commands) - Analytics and reports
- [Utility Commands](#utility-commands) - Helper scripts

---

## Pipeline Commands

### 1. Run Full Pipeline
```bash
python3 run_pipeline.py
```
**Purpose:** Execute complete bug bounty automation stack  
**Stages:** Recon → HTTP Mapping → Nuclei Scanning → Triage → Reporting  
**Inputs:** `targets.txt` (authorized domains, one per line)  
**Outputs:**
- `output/subs.txt` - Validated subdomains
- `output/http.json` - HTTP endpoints with metadata
- `output/nuclei-findings.json` - Raw vulnerability findings
- `output/triage.json` - Deduplicated, prioritized findings
- `output/reports/summary.md` - Executive summary

**Environment Variables:**
- `RESUME=true` - Resume from last completed stage
- `RECON_TIMEOUT=1800` - Recon timeout (seconds)
- `NUCLEI_SEVERITY=medium,high,critical` - Severity filter

**Example:**
```bash
# First run
python3 run_pipeline.py

# Resume after interruption
RESUME=true python3 run_pipeline.py

# Custom configuration
NUCLEI_SEVERITY=critical RECON_TIMEOUT=3600 python3 run_pipeline.py
```

**Exit Codes:**
- `0` - Success
- `1` - Configuration error (missing targets.txt)
- `2` - Stage failure (check logs)

**Logs:** `output/recon-run.log`

---

### 2. Run Pipeline via Shell (Linux/WSL)
```bash
./scripts/run_pipeline.sh
```
**Purpose:** Bash wrapper for pipeline with environment setup  
**Features:**
- Auto-creates output directories
- Sets optimal resource limits
- Enables resume by default

---

## Recon Commands

### 1. Subdomain Enumeration
```bash
python3 run_recon.py
```
**Purpose:** Discover and validate subdomains using multiple tools  
**Tools:** Subfinder + Amass + DNSx validation  
**Inputs:** `targets.txt`  
**Outputs:** `output/subs.txt` (validated, live subdomains)

**Environment Variables:**
```bash
RECON_TIMEOUT=1800        # Total timeout (30 minutes)
SUBFINDER_THREADS=50      # Concurrent DNS queries
AMASS_MAX_DNS=10000       # Max DNS queries (RAM-dependent)
DNSX_THREADS=100          # Concurrent DNS validations
RESOLVER_COUNT=25         # Number of DNS resolvers
```

**Optimization Guide:**
- **8GB RAM:** `SUBFINDER_THREADS=30 AMASS_MAX_DNS=5000 DNSX_THREADS=50`
- **16GB RAM:** `SUBFINDER_THREADS=50 AMASS_MAX_DNS=10000 DNSX_THREADS=100`
- **24GB+ RAM:** `SUBFINDER_THREADS=100 AMASS_MAX_DNS=20000 DNSX_THREADS=150`

**Example:**
```bash
# Fast scan (limited RAM)
SUBFINDER_THREADS=30 AMASS_MAX_DNS=5000 python3 run_recon.py

# Deep scan (high RAM)
SUBFINDER_THREADS=100 AMASS_MAX_DNS=20000 RECON_TIMEOUT=3600 python3 run_recon.py
```

---

### 2. HTTP Endpoint Discovery
```bash
python3 run_httpx.py
```
**Purpose:** Probe subdomains for live HTTP/HTTPS services  
**Tool:** httpx  
**Inputs:** `output/subs.txt`  
**Outputs:** `output/http.json` (includes status codes, titles, tech stack)

**Environment Variables:**
```bash
HTTPX_THREADS=50          # Concurrent probes
HTTPX_TIMEOUT=10          # Per-request timeout
HTTPX_RATE_LIMIT=150      # Requests per second
```

---

## Scanning Commands

### 1. Nuclei Vulnerability Scanning
```bash
python3 run_nuclei.py
```
**Purpose:** Scan HTTP endpoints for vulnerabilities using Nuclei templates  
**Inputs:** `output/http.json`  
**Outputs:** `output/nuclei-findings.json`

**Environment Variables:**
```bash
NUCLEI_RATE_LIMIT=150     # Requests/second
NUCLEI_BULK_SIZE=25       # Parallel template execution
NUCLEI_THREADS=50         # Concurrent executions
NUCLEI_TIMEOUT=10         # Per-request timeout
NUCLEI_SCAN_TIMEOUT=3600  # Total scan timeout
NUCLEI_SEVERITY=medium,high,critical  # Severity filter
NUCLEI_MAX_HOST_ERROR=30  # Skip after N errors
NUCLEI_RETRIES=2          # Retry failed requests
```

**Severity Filters:**
- `info` - Informational only
- `low` - Low severity
- `medium,high,critical` - Bug bounty focus (recommended)
- `critical` - Critical vulnerabilities only

**Performance Modes:**
```bash
# Speed mode (may miss findings)
NUCLEI_RATE_LIMIT=300 NUCLEI_THREADS=100 python3 run_nuclei.py

# Accuracy mode (thorough, slower)
NUCLEI_RATE_LIMIT=50 NUCLEI_THREADS=25 NUCLEI_RETRIES=5 python3 run_nuclei.py

# Balanced mode (default)
python3 run_nuclei.py
```

**Parallel Scanning:**
The system automatically splits URLs into batches and scans in parallel (6x speed boost).

---

## Agent Orchestration

### Agent Orchestrator
```bash
python3 scripts/agent_orchestrator.py --role <ROLE> --task <TASK>
```

**Purpose:** Coordinate multi-agent tasks based on role definitions  
**Configuration:** `agents.json`

### Available Roles & Tasks

#### 1. Strategist (Planning & Orchestration)
```bash
# View workflow plan
python3 scripts/agent_orchestrator.py --role Strategist --task plan

# Execute full pipeline
python3 scripts/agent_orchestrator.py --role Strategist --task pipeline
```

#### 2. Executor (Command Execution)
```bash
# Full pipeline run
python3 scripts/agent_orchestrator.py --role Executor --task full-run

# Individual stages
python3 scripts/agent_orchestrator.py --role Executor --task recon
python3 scripts/agent_orchestrator.py --role Executor --task httpx
python3 scripts/agent_orchestrator.py --role Executor --task nuclei
```

#### 3. Composer 1 — Automation Engineer
```bash
# Run recon automation
python3 scripts/agent_orchestrator.py --role "Composer 1 — Automation Engineer" --task recon

# Post-scan processing
python3 scripts/agent_orchestrator.py --role "Composer 1 — Automation Engineer" --task post-scan
```

#### 4. Composer 2 — Parallelization & Optimization
```bash
# Setup parallel processing
python3 scripts/agent_orchestrator.py --role "Composer 2 — Parallelization & Optimization" --task parallel-setup

# Monitor running scans
python3 scripts/agent_orchestrator.py --role "Composer 2 — Parallelization & Optimization" --task monitor
```

#### 5. Composer 3 — Documentation & Reporting
```bash
# Generate reports
python3 scripts/agent_orchestrator.py --role "Composer 3 — Documentation & Reporting" --task reports

# View summary
python3 scripts/agent_orchestrator.py --role "Composer 3 — Documentation & Reporting" --task summary
```

#### 6. Composer 4 — CI/CD & Security Ops
```bash
# Check CI configuration
python3 scripts/agent_orchestrator.py --role "Composer 4 — CI/CD & Security Ops" --task ci-check
```

### List All Roles & Tasks
```bash
python3 scripts/agent_orchestrator.py --list
```

---

## OPSEC Commands

### 1. Check All OPSEC Status
```bash
bash scripts/opsec_check_all.sh
```
**Verifies:**
- VPN connection
- DNS leak protection
- Secrets sanitization
- Privacy settings

### 2. VPN Status Check
```bash
bash scripts/opsec_check_vpn.sh
```

### 3. Secrets Manager
```bash
bash scripts/opsec_secrets_manager.sh
```
**Purpose:** Sanitize API keys, tokens, and credentials from outputs

### 4. System Hardening
```bash
bash scripts/opsec_system_harden.sh
```
**Features:**
- Firewall configuration
- Secure DNS setup
- Process isolation

### 5. Emergency Stop (Panic Mode)
```bash
bash scripts/opsec_system_panic.sh
```
**Actions:**
- Kill all scanning processes
- Clear sensitive data
- Disable network connections

### 6. Daily OPSEC Routine
```bash
bash scripts/opsec_system_daily.sh
```
**Runs:**
- Privacy checks
- Backup verification
- Log sanitization

---

## Reporting Commands

### 1. Generate Reports
```bash
python3 scripts/generate_report.py
```
**Inputs:** `output/triage.json`  
**Outputs:**
- `output/reports/summary.md` - Executive summary
- `output/reports/findings_by_severity.md` - Organized by severity
- `output/reports/findings_by_target.md` - Organized by target

### 2. Triage Findings
```bash
python3 scripts/triage.py
```
**Purpose:** Deduplicate and prioritize findings  
**Inputs:** `output/nuclei-findings.json`  
**Outputs:** `output/triage.json`

**Features:**
- Duplicate detection
- False positive filtering
- Severity-based prioritization
- CVSS scoring

---

## Utility Commands

### 1. Process All Results
```bash
python3 process_all.py
```
**Purpose:** Batch process multiple target results

### 2. Scan Monitor
```bash
python3 scripts/scan_monitor.py
```
**Purpose:** Real-time monitoring of active scans  
**Features:**
- Progress tracking
- Performance metrics
- Error detection

### 3. Parallel Setup
```bash
python3 scripts/parallel_setup.py
```
**Purpose:** Configure parallel scanning infrastructure

### 4. Tool Setup
```bash
python3 setup_tools.py
```
**Purpose:** Install and configure all required tools  
**Tools Installed:**
- subfinder
- amass
- dnsx
- httpx
- nuclei

### 5. License Check
```bash
python3 license_check.py
```
**Purpose:** Verify proprietary license validity

### 6. Quick Status
```bash
./scripts/check_scan_status.py
```
**Purpose:** Get current pipeline status and progress

---

## Environment Variables Reference

### Global Configuration
```bash
RESUME=true                    # Resume from last checkpoint
OUTPUT_DIR=output              # Output directory path
TARGETS_FILE=targets.txt       # Targets file path
```

### Recon Configuration
```bash
RECON_TIMEOUT=1800             # Total recon timeout (seconds)
SUBFINDER_THREADS=50           # Subfinder concurrency
AMASS_MAX_DNS=10000            # Amass DNS query limit
DNSX_THREADS=100               # DNSx validation threads
RESOLVER_COUNT=25              # DNS resolver count
```

### HTTP Mapping Configuration
```bash
HTTPX_THREADS=50               # httpx concurrency
HTTPX_TIMEOUT=10               # Request timeout
HTTPX_RATE_LIMIT=150           # Requests per second
```

### Nuclei Configuration
```bash
NUCLEI_RATE_LIMIT=150          # Requests per second
NUCLEI_BULK_SIZE=25            # Parallel template count
NUCLEI_THREADS=50              # Concurrent threads
NUCLEI_TIMEOUT=10              # Per-request timeout
NUCLEI_SCAN_TIMEOUT=3600       # Total scan timeout
NUCLEI_SEVERITY=medium,high,critical  # Severity filter
NUCLEI_MAX_HOST_ERROR=30       # Error threshold
NUCLEI_RETRIES=2               # Retry count
```

### Notification Configuration
```bash
DISCORD_WEBHOOK=https://...    # Discord webhook URL
SLACK_WEBHOOK=https://...      # Slack webhook URL
NOTIFY_ON_FINDING=true         # Notify on findings
```

---

## Common Workflows

### Workflow 1: First Time Setup
```bash
# 1. Install tools
python3 setup_tools.py

# 2. Create targets file
echo "example.com" > targets.txt

# 3. Run pipeline
python3 run_pipeline.py

# 4. View results
cat output/reports/summary.md
```

### Workflow 2: Quick Scan (Speed Priority)
```bash
# Fast settings
RECON_TIMEOUT=600 \
SUBFINDER_THREADS=100 \
NUCLEI_RATE_LIMIT=300 \
NUCLEI_SEVERITY=high,critical \
python3 run_pipeline.py
```

### Workflow 3: Deep Scan (Accuracy Priority)
```bash
# Thorough settings
RECON_TIMEOUT=3600 \
AMASS_MAX_DNS=20000 \
NUCLEI_RATE_LIMIT=50 \
NUCLEI_SEVERITY=low,medium,high,critical \
NUCLEI_RETRIES=5 \
python3 run_pipeline.py
```

### Workflow 4: Resume After Interruption
```bash
# Resume automatically
RESUME=true python3 run_pipeline.py
```

### Workflow 5: Agent-Based Execution
```bash
# 1. Plan
python3 scripts/agent_orchestrator.py --role Strategist --task plan

# 2. Execute
python3 scripts/agent_orchestrator.py --role Executor --task full-run

# 3. Report
python3 scripts/agent_orchestrator.py --role "Composer 3 — Documentation & Reporting" --task reports
```

---

## Troubleshooting

### Issue: No subdomains found
**Solutions:**
- Check network connectivity
- Verify targets.txt contains valid domains
- Increase RECON_TIMEOUT
- Check tool installation: `python3 setup_tools.py`

### Issue: Nuclei scan too slow
**Solutions:**
- Increase NUCLEI_RATE_LIMIT (if bandwidth allows)
- Reduce NUCLEI_SEVERITY to focus on high/critical only
- Increase NUCLEI_THREADS (if RAM allows)

### Issue: Out of memory
**Solutions:**
- Reduce AMASS_MAX_DNS
- Reduce NUCLEI_THREADS
- Split targets into smaller batches

### Issue: Pipeline hangs
**Solutions:**
- Check `output/recon-run.log` for errors
- Kill hung processes: `bash scripts/opsec_system_panic.sh`
- Resume: `RESUME=true python3 run_pipeline.py`

---

## File Structure

```
Repository Root
├── targets.txt                    # Input: Target domains
├── run_pipeline.py                # Main orchestrator
├── run_recon.py                   # Subdomain enumeration
├── run_httpx.py                   # HTTP mapping
├── run_nuclei.py                  # Vulnerability scanning
├── agents.json                    # Agent role definitions
├── output/                        # All outputs
│   ├── subs.txt                   # Discovered subdomains
│   ├── http.json                  # HTTP endpoints
│   ├── nuclei-findings.json       # Raw findings
│   ├── triage.json                # Triaged findings
│   ├── reports/                   # Generated reports
│   │   ├── summary.md
│   │   └── findings_*.md
│   └── recon-run.log              # Execution logs
├── scripts/                       # Utility scripts
│   ├── agent_orchestrator.py      # Agent coordination
│   ├── generate_report.py         # Report generation
│   ├── triage.py                  # Finding triage
│   ├── opsec_*.sh                 # OPSEC utilities
│   └── ...
└── .ai-training/                  # AI training data
    ├── openapi-spec.yaml          # API specification
    ├── api-schemas.json           # Data schemas
    ├── command-reference.md       # This file
    └── ...
```

---

## Exit Codes

- `0` - Success
- `1` - Configuration error (missing files, invalid targets)
- `2` - Execution error (stage failed, tool missing)
- `127` - Command not found

---

## Security Notes

1. **Always check OPSEC before scanning:**
   ```bash
   bash scripts/opsec_check_all.sh
   ```

2. **Only scan authorized targets** - Ensure you have permission

3. **Sanitize outputs before sharing:**
   ```bash
   bash scripts/opsec_secrets_manager.sh
   ```

4. **Use VPN for anonymity:**
   ```bash
   bash scripts/opsec_check_vpn.sh
   ```

---

## Performance Benchmarks

**Typical Performance (24GB RAM, 1Gbps network):**
- Recon: 100-500 subdomains in 10-30 minutes
- HTTP Mapping: 500 endpoints in 2-5 minutes
- Nuclei Scan: 500 endpoints in 15-45 minutes
- Total Pipeline: 30-90 minutes

**Optimization Impact:**
- Parallel Nuclei: 6x speed improvement
- DNSx validation: 3x faster than pinging
- Resume capability: Save hours on interruptions

---

## Support & Documentation

- Full docs: `README.md`
- Windows guide: `README_WINDOWS.md`
- Processing guide: `README_PROCESS_RESULTS.md`
- Training materials: `.ai-training/`
- Agent mapping: `AGENTS.md`

---

**Generated:** 2025-11-04  
**System:** Recon Automation Bug Bounty Stack v1.0  
**License:** Proprietary - DoctorMen
