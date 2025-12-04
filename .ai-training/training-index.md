<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# AI Training Index - Recon Automation Bug Bounty Stack

## 📚 Training Material Overview

This directory contains comprehensive training materials to enable AI agents to fully understand and operate the bug bounty automation system.

---

## 🎯 Quick Start for AI Agents

**Read These Files First:**
1. `agent-training-manifest.json` - System overview and core concepts
2. `command-reference.md` - Complete command catalog
3. `intent-patterns.json` - Natural language understanding patterns

**Then Deep Dive Into:**
4. `openapi-spec.yaml` - Complete API specification
5. `usage-examples.md` - Real-world scenarios
6. `integration-patterns.md` - External system integration

---

## 📖 File Directory

### Core Specifications
| File | Purpose | Priority |
|------|---------|----------|
| `openapi-spec.yaml` | Complete API spec with all endpoints | ⭐⭐⭐ Critical |
| `api-schemas.json` | JSON schemas for data structures | ⭐⭐⭐ Critical |
| `agent-training-manifest.json` | System manifest and entry points | ⭐⭐⭐ Critical |

### Command References
| File | Purpose | Priority |
|------|---------|----------|
| `command-reference.md` | Complete command catalog with examples | ⭐⭐ High |
| `intent-patterns.json` | NLP patterns for intent recognition | ⭐⭐ High |

### Usage Guides
| File | Purpose | Priority |
|------|---------|----------|
| `usage-examples.md` | 11 real-world usage scenarios | ⭐ Medium |
| `integration-patterns.md` | Integration code examples | ⭐ Medium |

---

## 🧠 Core Concepts AI Agents Must Know

### 1. Idempotent Protocol
- **Principle:** All operations safe to run multiple times
- **Implementation:** Commands check state and skip completed work
- **Benefit:** Crash recovery, no duplicates, safe resumption

### 2. Multi-Agent Architecture
- **Definition:** 6 specialized agents coordinate via `agents.json`
- **Roles:** Strategist, Executor, 4 Composers (automation, optimization, docs, CI/CD)
- **Orchestration:** `scripts/agent_orchestrator.py --role <ROLE> --task <TASK>`

### 3. OPSEC-First Approach
- **Rule:** Always check security before scanning
- **Command:** `bash scripts/opsec_check_all.sh`
- **Verifies:** VPN, DNS leaks, secrets sanitization, privacy settings

### 4. Pipeline Stages
```
targets.txt → Recon → HTTP Mapping → Nuclei Scan → Triage → Reports
```
- **Resumable:** Use `RESUME=true` to skip completed stages
- **Monitored:** Check `output/.pipeline_status` for progress

---

## 🎬 Common User Requests → AI Actions

| User Says | AI Should Do |
|-----------|--------------|
| "Scan example.com" | Create targets.txt → Check OPSEC → Run pipeline |
| "What's the status?" | Read logs + pipeline_status → Report progress |
| "Show results" | Parse triage.json → Present findings by severity |
| "Resume scan" | Set RESUME=true → Run pipeline |
| "Quick scan" | Use fast settings → High/critical severity only |
| "Deep scan" | Use thorough settings → All severities |
| "Check security" | Run opsec_check_all.sh → Report OPSEC status |
| "Stop everything" | Run opsec_system_panic.sh → Kill all scans |

---

## ⚙️ Performance Profiles

### Fast Scan (Speed Priority)
```bash
RECON_TIMEOUT=600 \
SUBFINDER_THREADS=100 \
NUCLEI_RATE_LIMIT=300 \
NUCLEI_SEVERITY=high,critical \
python3 run_pipeline.py
```
**Use When:** Time-critical, quick check, testing

### Balanced Scan (Default)
```bash
python3 run_pipeline.py
```
**Use When:** Normal operations, good coverage

### Thorough Scan (Accuracy Priority)
```bash
RECON_TIMEOUT=3600 \
AMASS_MAX_DNS=20000 \
NUCLEI_RATE_LIMIT=50 \
NUCLEI_SEVERITY=low,medium,high,critical \
NUCLEI_RETRIES=5 \
python3 run_pipeline.py
```
**Use When:** Comprehensive assessment, bug bounty submission

---

## 🔐 Safety Protocols

### Always Check Before Scanning
1. OPSEC status: `bash scripts/opsec_check_all.sh`
2. Authorization: Confirm user has permission to scan target
3. Target validity: Ensure domain is properly formatted

### Never Do
- Scan unauthorized targets
- Share unsanitized outputs (may contain secrets)
- Hardcode API keys or credentials
- Ignore OPSEC warnings

---

## 🚀 Entry Points

| Purpose | Command |
|---------|---------|
| Full pipeline | `python3 run_pipeline.py` |
| Recon only | `python3 run_recon.py` |
| HTTP mapping | `python3 run_httpx.py` |
| Vuln scanning | `python3 run_nuclei.py` |
| Triage findings | `python3 scripts/triage.py` |
| Generate reports | `python3 scripts/generate_report.py` |
| Agent orchestration | `python3 scripts/agent_orchestrator.py` |

---

## 📊 Output Files AI Should Monitor

| File | Contains |
|------|----------|
| `output/subs.txt` | Discovered subdomains |
| `output/http.json` | Live HTTP endpoints |
| `output/nuclei-findings.json` | Raw vulnerability findings |
| `output/triage.json` | Deduplicated, prioritized findings |
| `output/reports/summary.md` | Executive summary |
| `output/recon-run.log` | Execution logs (check for errors) |
| `output/.pipeline_status` | Completed stages |

---

## 🔧 Troubleshooting Guide

| Problem | Solution |
|---------|----------|
| No subdomains found | Check network, increase RECON_TIMEOUT, verify targets.txt |
| Tool not found | Run `python3 setup_tools.py` |
| Out of memory | Reduce AMASS_MAX_DNS and NUCLEI_THREADS |
| Scan too slow | Increase NUCLEI_RATE_LIMIT and THREADS |
| VPN warning | Run `bash scripts/opsec_check_vpn.sh` |
| Scan stuck | Kill processes + `RESUME=true python3 run_pipeline.py` |

---

## 💡 AI Agent Best Practices

### Context Awareness
```python
# Check for existing state
if os.path.exists('output/.pipeline_status'):
    # Scan in progress or completed - suggest resume
    pass

if os.path.exists('targets.txt'):
    # Previous targets exist - ask if using same
    pass
```

### Smart Defaults
- **Fast scan** when user mentions: "quick", "fast", "urgent"
- **Thorough scan** when user mentions: "comprehensive", "deep", "complete"
- **Resume** when partial results exist
- **OPSEC check** always before scanning

### User Communication
- Show progress for long operations
- Highlight critical findings immediately
- Estimate completion times
- Provide actionable next steps
- Explain errors in plain language

### Error Recovery
```python
# Tool missing
if not check_tool("nuclei"):
    run("python3 setup_tools.py")

# VPN down
if not vpn_active():
    alert_user("⚠️ VPN not active - scanning without VPN is not recommended")
    
# Out of memory
if memory_error:
    suggest("Reduce concurrency: AMASS_MAX_DNS=5000 NUCLEI_THREADS=25")
```

---

## 📈 Success Metrics

AI agents should track and report:
- **Subdomains discovered:** From `output/subs.txt`
- **Live endpoints:** From `output/http.json`
- **Total findings:** From `output/triage.json`
- **Critical/High findings:** Filter by severity
- **Scan duration:** Calculate from logs
- **Success rate:** Completed vs failed stages

---

## 🎓 Learning Path for AI Agents

### Level 1: Basic Operations (Read First)
1. Read `agent-training-manifest.json`
2. Study `command-reference.md`
3. Review `intent-patterns.json`

### Level 2: Practical Application
4. Study `usage-examples.md` scenarios 1-5
5. Practice with `openapi-spec.yaml`
6. Understand OPSEC protocols

### Level 3: Advanced Integration
7. Review remaining `usage-examples.md` scenarios
8. Study `integration-patterns.md`
9. Master agent orchestration

### Level 4: Expert Mode
10. Understand all environment variables
11. Optimize performance profiles
12. Handle edge cases and errors

---

## 📝 Training Validation

AI agents should be able to:
- [ ] Start a scan given a domain name
- [ ] Check scan status and report progress
- [ ] View and filter results by severity
- [ ] Resume interrupted scans
- [ ] Configure fast vs thorough scans
- [ ] Verify OPSEC before scanning
- [ ] Handle common errors gracefully
- [ ] Orchestrate multi-agent workflows
- [ ] Export results for submission
- [ ] Set up continuous monitoring

---

## 🔄 Training Material Updates

**Version:** 1.0.0  
**Generated:** 2025-11-04T02:01:00Z  
**Next Review:** As system evolves

**Update Triggers:**
- New features added
- Commands changed
- API endpoints modified
- Agent roles updated

---

## 📞 Support Resources

- **Full Documentation:** `../README.md`
- **Windows Guide:** `../README_WINDOWS.md`
- **Agent Mapping:** `../AGENTS.md`
- **OPSEC Guide:** `../docs/OPSEC_FRAMEWORK.md`

---

**🎯 Mission:** Enable AI agents to autonomously operate bug bounty automation with full understanding of commands, safety protocols, and user intent recognition.

**⚡ Status:** Training materials complete and ready for AI agent consumption.
