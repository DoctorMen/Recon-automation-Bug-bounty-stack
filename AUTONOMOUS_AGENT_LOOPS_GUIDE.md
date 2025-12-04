<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# 🤖 Autonomous Agent Loops - Complete Guide

## 🎯 Overview

**4-hour autonomous agent loop system** with idempotent operations, self-healing capabilities, and bleeding-edge monitoring.

### Features

✅ **Idempotent Execution** - Safe to run multiple times, same result  
✅ **Self-Healing** - Automatic error recovery  
✅ **Multi-Repository** - Coordinate agents across projects  
✅ **Real-Time Monitoring** - Bleeding-edge dashboard  
✅ **Resource Management** - Smart CPU/memory allocation  
✅ **Task Scheduling** - Intelligent interval-based execution  
✅ **State Persistence** - SQLite-based state tracking  
✅ **Performance Metrics** - Comprehensive analytics  

---

## 🚀 Quick Start

### Single Repository (4 Hours)

```bash
# Run autonomous loop for 4 hours
python3 scripts/autonomous_agent_loop.py

# Custom runtime
python3 scripts/autonomous_agent_loop.py --hours 8

# Quick test (5 minutes)
python3 scripts/autonomous_agent_loop.py --quick
```

### Multiple Repositories

```bash
# Coordinate across all repos
python3 scripts/multi_repo_coordinator.py

# Check status
python3 scripts/multi_repo_coordinator.py --status

# Custom runtime for all repos
python3 scripts/multi_repo_coordinator.py --hours 6
```

### Monitoring Dashboard

```bash
# Open bleeding-edge monitoring UI
explorer.exe "AGENT_LOOP_DASHBOARD.html"
# Or on Linux/Mac:
open AGENT_LOOP_DASHBOARD.html
```

---

## 📊 System Architecture

```
┌─────────────────────────────────────────────────────────┐
│           AUTONOMOUS AGENT LOOP ENGINE                  │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ Idempotent   │  │   Self-      │  │   Resource   │ │
│  │   Task Mgr   │  │   Healing    │  │  Management  │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │   State DB   │  │  Performance │  │   Task       │ │
│  │  (SQLite)    │  │   Metrics    │  │  Scheduler   │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                  6 SPECIALIZED AGENTS                    │
│                                                          │
│  Strategist │ Executor │ Automation │ Parallelization   │
│  Documentation │ Security Ops                           │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                      7 TASK TYPES                        │
│                                                          │
│  • recon_scan (every 30min)                             │
│  • httpx_probe (every 40min)                            │
│  • nuclei_scan (every 1hr)                              │
│  • generate_report (every 20min)                        │
│  • update_readme (every 15min)                          │
│  • monitor_performance (every 5min)                     │
│  • strategy_review (every 1hr)                          │
└─────────────────────────────────────────────────────────┘
```

---

## 🔧 Configuration

### Agents Configuration (`agents.json`)

```json
{
  "agents": [
    {
      "name": "Strategist",
      "model": "gpt-5",
      "role": "Plans workflow, task sequencing, logic verification"
    },
    {
      "name": "Executor",
      "model": "gpt-5",
      "role": "Executes scripts, validates syntax, runs tests"
    },
    {
      "name": "Composer 1 — Automation Engineer",
      "model": "composer",
      "role": "Maintains recon scripts and automation"
    },
    {
      "name": "Composer 2 — Parallelization & Optimization",
      "model": "composer",
      "role": "Concurrent execution and resource optimization"
    },
    {
      "name": "Composer 3 — Documentation & Reporting",
      "model": "composer",
      "role": "Auto-updates docs and generates reports"
    },
    {
      "name": "Composer 4 — CI/CD & Security Ops",
      "model": "composer",
      "role": "GitHub workflows and security hardening"
    }
  ]
}
```

### Multi-Repo Configuration (`multi_repo_config.json`)

```json
{
  "repositories": [
    {
      "name": "Recon-automation-Bug-bounty-stack",
      "path": "~/Recon-automation-Bug-bounty-stack",
      "priority": 1,
      "max_resources": 0.4,
      "agent_script": "scripts/autonomous_agent_loop.py",
      "enabled": true
    },
    {
      "name": "notification_system",
      "path": "~/Recon-automation-Bug-bounty-stack/notification_system",
      "priority": 2,
      "max_resources": 0.3,
      "agent_script": "agent1_automation/delivery_monitor.py",
      "enabled": true
    }
  ]
}
```

---

## 📋 Task Types

### 1. **Recon Scan** (Priority 1)
- **Interval**: Every 30 minutes
- **Agent**: Automation Engineer
- **Script**: `scripts/run_recon.sh`
- **Purpose**: Subdomain enumeration and reconnaissance

### 2. **HTTPx Probe** (Priority 2)
- **Interval**: Every 40 minutes
- **Agent**: Executor
- **Script**: `scripts/run_httpx.sh`
- **Purpose**: HTTP/HTTPS probing and validation

### 3. **Nuclei Scan** (Priority 3)
- **Interval**: Every 1 hour
- **Agent**: Executor
- **Script**: `scripts/run_nuclei.sh`
- **Purpose**: Vulnerability scanning (medium/high/critical)

### 4. **Generate Report** (Priority 4)
- **Interval**: Every 20 minutes
- **Agent**: Documentation & Reporting
- **Script**: `scripts/generate_report.py`
- **Purpose**: Markdown/HTML report generation

### 5. **Update README** (Priority 5)
- **Interval**: Every 15 minutes
- **Agent**: Documentation & Reporting
- **Script**: Updates README with latest stats
- **Purpose**: Keep documentation current

### 6. **Monitor Performance** (Priority 6)
- **Interval**: Every 5 minutes
- **Agent**: Parallelization & Optimization
- **Script**: Built-in `psutil` monitoring
- **Purpose**: Track CPU, memory, disk usage

### 7. **Strategy Review** (Priority 7)
- **Interval**: Every 1 hour
- **Agent**: Strategist
- **Script**: Built-in analysis
- **Purpose**: Review targets and prioritize work

---

## 🔄 Idempotent Operation

### How It Works

All tasks are **idempotent** - running the same task multiple times produces the same result:

```python
def execute_task(task_type, inputs):
    # 1. Generate unique task ID from inputs
    task_id = hash(task_type + inputs)
    
    # 2. Check if already completed
    if is_completed(task_id):
        return get_cached_result(task_id)
    
    # 3. Execute if not completed
    result = run_task(task_type, inputs)
    
    # 4. Store result
    save_result(task_id, result)
    
    return result
```

### Benefits

✅ **Safe Restarts** - Can stop/start without duplicates  
✅ **Crash Recovery** - Resume from where it left off  
✅ **No Duplicates** - Same scan won't run twice  
✅ **Predictable** - Deterministic results  

---

## 🩺 Self-Healing

### Error Recovery Strategies

1. **Automatic Retry** (up to 3 times)
   - Exponential backoff
   - Different retry strategies per task type

2. **Graceful Degradation**
   - Skip failed tasks
   - Continue with others
   - Log errors for review

3. **State Persistence**
   - SQLite database tracks all tasks
   - Survives crashes and restarts
   - Full audit trail

4. **Resource Management**
   - CPU throttling
   - Memory limits
   - Process prioritization

---

## 📈 Performance Metrics

### Tracked Metrics

| Metric | Description | Storage |
|--------|-------------|---------|
| `tasks_completed` | Successful task count | In-memory + DB |
| `tasks_failed` | Failed task count | In-memory + DB |
| `tasks_cached` | Idempotent cache hits | In-memory + DB |
| `execution_time` | Time per task | DB (performance_metrics) |
| `success_rate` | % successful tasks | Calculated |
| `session_runtime` | Total loop runtime | DB (loop_sessions) |

### Database Schema

```sql
-- Task execution history
CREATE TABLE task_executions (
    id INTEGER PRIMARY KEY,
    task_id TEXT NOT NULL UNIQUE,
    task_type TEXT NOT NULL,
    input_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    result TEXT,
    error TEXT,
    started_at INTEGER NOT NULL,
    completed_at INTEGER,
    execution_time REAL,
    retry_count INTEGER DEFAULT 0
);

-- Agent loop sessions
CREATE TABLE loop_sessions (
    id INTEGER PRIMARY KEY,
    session_id TEXT NOT NULL UNIQUE,
    started_at INTEGER NOT NULL,
    ended_at INTEGER,
    total_tasks INTEGER DEFAULT 0,
    successful_tasks INTEGER DEFAULT 0,
    failed_tasks INTEGER DEFAULT 0,
    status TEXT NOT NULL
);

-- Performance metrics
CREATE TABLE performance_metrics (
    id INTEGER PRIMARY KEY,
    session_id TEXT NOT NULL,
    metric_type TEXT NOT NULL,
    metric_value REAL NOT NULL,
    timestamp INTEGER NOT NULL
);
```

---

## 🎨 Monitoring Dashboard

### Features

- **Real-Time Stats** - Live task counts, success rate, runtime
- **Agent Grid** - Visual status of all 6 agents
- **Activity Log** - Scrolling log of all operations
- **Progress Bar** - 4-hour runtime visualization
- **Control Panel** - Pause/Resume/Stop/Export
- **Bleeding Edge UI** - Glassmorphism, gradient orbs, custom cursor

### Opening Dashboard

```bash
# Windows
explorer.exe "AGENT_LOOP_DASHBOARD.html"

# Linux
xdg-open AGENT_LOOP_DASHBOARD.html

# Mac
open AGENT_LOOP_DASHBOARD.html

# Or just drag into browser
```

### Dashboard Metrics

| Metric | Update Interval | Source |
|--------|----------------|--------|
| Runtime | 1 second | Real-time clock |
| Tasks Completed | 5 seconds | Task counter |
| Success Rate | 5 seconds | Calculation |
| Active Agents | Real-time | Agent status |
| Activity Log | 3 seconds | Simulated events |

---

## 🔐 Security & Safety

### Built-in Safeguards

1. **Rate Limiting** - Prevents overload
2. **Resource Caps** - CPU/memory limits per repo
3. **Timeout Protection** - Tasks have max runtime
4. **State Isolation** - Each repo has separate state
5. **Audit Logging** - Full trail in database

### Best Practices

✅ Run during off-peak hours  
✅ Monitor system resources  
✅ Review logs regularly  
✅ Test with `--quick` first  
✅ Use `--status` to check before starting  

---

## 📊 Example Output

### Console Output

```
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║       AUTONOMOUS AGENT LOOP ENGINE                       ║
║       4-Hour Continuous Operation                        ║
║                                                          ║
║  ✓ Idempotent Task Execution                            ║
║  ✓ Self-Healing Error Recovery                          ║
║  ✓ Multi-Agent Coordination                             ║
║  ✓ Real-Time Monitoring                                 ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝

2025-01-04 01:00:00 [INFO] 🚀 Starting autonomous agent loop - Session: session_1704326400
2025-01-04 01:00:00 [INFO] ⏱️  Runtime: 4.0 hours (14400s)
2025-01-04 01:00:00 [INFO] 🤖 Agents loaded: 6
2025-01-04 01:00:00 [INFO] 📋 Generated 7 tasks

============================================================
🔁 Cycle #1 - Elapsed: 0.00h / 4.0h
============================================================
2025-01-04 01:00:05 [INFO] 🔨 Executing recon_scan with Automation Engineer
2025-01-04 01:00:35 [INFO] ✅ recon_scan completed in 30.21s
2025-01-04 01:00:40 [INFO] 🔨 Executing httpx_probe with Executor
2025-01-04 01:01:20 [INFO] ✅ httpx_probe completed in 40.15s
2025-01-04 01:01:25 [INFO] 🔨 Executing nuclei_scan with Executor
2025-01-04 01:02:45 [INFO] ✅ nuclei_scan completed in 80.33s

📊 METRICS:
  Total Tasks: 7
  ✅ Completed: 7
  💾 Cached: 0
  ❌ Failed: 0
  📈 Success Rate: 100.0%

💤 Sleeping 120s until next cycle...
```

---

## 🛠️ Advanced Usage

### Custom Task Addition

Add your own tasks to the loop:

```python
# In autonomous_agent_loop.py, add to generate_tasks():
tasks.append({
    'type': 'custom_task',
    'agent': 'Executor',
    'priority': 8,
    'inputs': {'param': 'value'},
    'interval': 600  # Every 10 minutes
})

# Add handler in _run_task_logic():
def _custom_task_handler(inputs):
    # Your custom logic here
    return {'status': 'success'}
```

### Integration with Existing Scripts

```python
# Call from your own scripts
from scripts.autonomous_agent_loop import AutonomousAgentLoop

loop = AutonomousAgentLoop(runtime_hours=2.0)
loop.run()
```

### Export Metrics

```bash
# From dashboard - click "Export Metrics"
# Or programmatically:
python3 -c "
from scripts.autonomous_agent_loop import IdempotentTaskManager
mgr = IdempotentTaskManager('.agent_loop_state.db')
# Query metrics from DB
"
```

---

## 🎯 Use Cases

### 1. **Bug Bounty Automation**
Run recon, scanning, and reporting for 4 hours daily while you sleep.

### 2. **Multi-Project Management**
Coordinate development tasks across multiple repositories.

### 3. **CI/CD Integration**
Continuous testing and deployment monitoring.

### 4. **Performance Monitoring**
Long-running system health checks.

### 5. **Data Processing**
Batch processing with automatic retries.

---

## 🚨 Troubleshooting

### Loop Won't Start

```bash
# Check Python version (3.8+)
python3 --version

# Install dependencies
pip install psutil

# Check file permissions
chmod +x scripts/autonomous_agent_loop.py

# Test quick mode first
python3 scripts/autonomous_agent_loop.py --quick
```

### High Resource Usage

```bash
# Reduce repo resource allocation in multi_repo_config.json
"max_resources": 0.2  # Lower from 0.4

# Increase task intervals
'interval': 3600  # From 1800 (double the time)
```

### Database Locked

```bash
# Close other connections
lsof .agent_loop_state.db | grep python | awk '{print $2}' | xargs kill

# Or delete and restart (loses history)
rm .agent_loop_state.db
```

### Tasks Not Running

```bash
# Check script paths exist
ls -la scripts/run_recon.sh

# Test scripts manually
bash scripts/run_recon.sh

# Check logs
tail -f logs/agent_loop.log
```

---

## 📚 Documentation Files

1. **`AUTONOMOUS_AGENT_LOOPS_GUIDE.md`** - This guide
2. **`scripts/autonomous_agent_loop.py`** - Main loop engine
3. **`scripts/multi_repo_coordinator.py`** - Multi-repo coordination
4. **`AGENT_LOOP_DASHBOARD.html`** - Monitoring dashboard
5. **`agents.json`** - Agent configuration
6. **`multi_repo_config.json`** - Repository configuration

---

## 🎉 Success Metrics

After 4-hour loop completion, you should see:

✅ **100+ tasks executed** (depending on intervals)  
✅ **95%+ success rate** (idempotent caching)  
✅ **Zero duplicates** (idempotent guarantee)  
✅ **Complete audit trail** (SQLite database)  
✅ **Performance metrics** (execution times, resource usage)  
✅ **Updated documentation** (README auto-updated)  
✅ **Fresh reports** (generated every 20 min)  

---

## 🚀 Next Steps

1. **Run Quick Test**: `python3 scripts/autonomous_agent_loop.py --quick`
2. **Check Dashboard**: Open `AGENT_LOOP_DASHBOARD.html`
3. **Review Logs**: `tail -f logs/agent_loop.log`
4. **Run Full Loop**: `python3 scripts/autonomous_agent_loop.py`
5. **Monitor Progress**: Watch dashboard for 4 hours
6. **Export Metrics**: Click "Export Metrics" button
7. **Analyze Results**: Review `.agent_loop_state.db`

---

**The autonomous agent loop is now running. Sit back and watch it work for 4 hours straight.** 🤖✨
