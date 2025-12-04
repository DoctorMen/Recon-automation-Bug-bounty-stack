<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# ⚡ Agentic System - Command Cheat Sheet

## 🚀 Most Common Commands (Copy-Paste Ready)

### Basic Usage

```bash
# Single target - full scan
python3 run_agentic_system.py example.com

# Multiple targets - full scan
python3 run_agentic_system.py example1.com example2.com example3.com

# From file - full scan
python3 run_agentic_system.py --target-file targets.txt
```

### Quick Scans (Fast Results)

```bash
# Quick scan - one target
python3 run_agentic_system.py example.com --pipeline quick_scan

# Quick scan - multiple targets
python3 run_agentic_system.py --target-file targets.txt --pipeline quick_scan
```

### Deep Scans (Thorough)

```bash
# Deep discovery
python3 run_agentic_system.py example.com --pipeline deep_discovery

# Focused vulnerability hunt
python3 run_agentic_system.py example.com --pipeline focused_vuln
```

### Check Results

```bash
# View dashboard (real-time metrics)
cat output/dashboard.json | jq '.'

# View results (findings)
cat output/agentic_result.json | jq '.'

# View learning progress
cat learning_state.json | jq '.stats'

# View logs
tail -50 output/agentic.log
```

### Monitoring

```bash
# Watch dashboard update in real-time
watch -n 5 'cat output/dashboard.json | jq .'

# Follow logs live
tail -f output/agentic.log

# Check learning improvements
cat learning_state.json | jq '.stats.average_performance'
```

---

## 📊 Pipeline Types

| Pipeline | Speed | Thoroughness | Use Case |
|----------|-------|--------------|----------|
| `quick_scan` | ⚡⚡⚡ Fast | ⭐ Basic | First look, many targets |
| `full_recon` | ⚡⚡ Medium | ⭐⭐⭐ Good | Default, balanced |
| `deep_discovery` | ⚡ Slow | ⭐⭐⭐⭐⭐ Best | High-value targets |
| `focused_vuln` | ⚡⚡ Medium | ⭐⭐⭐⭐ High | Known tech stack |

---

## 🎯 Common Workflows

### Morning Routine
```bash
# Start scans on all targets
python3 run_agentic_system.py --target-file daily_targets.txt --pipeline quick_scan

# Go get coffee - results ready in 10-15 min
```

### New Program Intake
```bash
# Got 100 new targets from a program?
cat new_program_targets.txt > targets.txt
python3 run_agentic_system.py --target-file targets.txt

# System scans all 100 in parallel
```

### Deep Dive on High-Value Target
```bash
python3 run_agentic_system.py high-value-target.com --pipeline deep_discovery
```

### Continuous Monitoring
```bash
# Create monitor script
cat > monitor.sh << 'EOF'
#!/bin/bash
while true; do
  python3 run_agentic_system.py --target-file monitor_targets.txt --pipeline quick_scan
  sleep 86400  # Run daily
done
EOF

chmod +x monitor.sh
./monitor.sh
```

---

## 🔧 Advanced Options

### Verbose Output
```bash
python3 run_agentic_system.py example.com --verbose
```

### Custom Configuration
```bash
python3 run_agentic_system.py example.com --config my_config.json
```

### Disable Learning (Testing)
```bash
python3 run_agentic_system.py example.com --no-learning
```

### Disable Monitoring (Performance)
```bash
python3 run_agentic_system.py example.com --no-monitoring
```

### Hybrid Mode (Migration)
```bash
python3 run_agentic_system.py --target-file targets.txt --mode hybrid
```

---

## 📁 Important Files

### Generated Files (Auto-Created)

| File | What It Contains |
|------|------------------|
| `output/dashboard.json` | Real-time metrics and status |
| `output/agentic_result.json` | Complete scan results |
| `learning_state.json` | What system has learned |
| `output/agentic.log` | Detailed execution logs |
| `output/{target}/` | Per-target results |

### Configuration Files

| File | Purpose |
|------|---------|
| `config.json` | Your custom settings |
| `targets.txt` | List of targets to scan |

---

## ⚡ One-Liners for Common Tasks

### Create Target List from Program Scope
```bash
curl https://example.com/scope.txt | grep -Eo '[a-zA-Z0-9.-]+\.[a-z]{2,}' | sort -u > targets.txt
```

### Count Findings
```bash
cat output/agentic_result.json | jq '.results[].vulnerabilities | length'
```

### Extract Critical Issues
```bash
cat output/agentic_result.json | jq '.results[].vulnerabilities[] | select(.severity=="critical")'
```

### Get Success Rate
```bash
cat learning_state.json | jq '.stats.average_performance'
```

### See Learning Improvement
```bash
# Run this after each scan to track improvement
echo "Performance: $(cat learning_state.json | jq '.stats.average_performance')"
```

---

## 🎯 Quick Troubleshooting

### Command Not Working?

```bash
# Make sure you're in the right directory
cd /path/to/Recon-automation-Bug-bounty-stack

# Check Python version (need 3.8+)
python3 --version

# Check if tools are installed
which subfinder httpx nuclei
```

### Slow Performance?

```bash
# Increase concurrency in config
cat > config.json << 'EOF'
{
  "orchestrator": {
    "max_concurrent_tasks": 50
  }
}
EOF

python3 run_agentic_system.py example.com --config config.json
```

### Want to Reset Learning?

```bash
# Backup old state
mv learning_state.json learning_state.backup.json

# Start fresh (system will learn again)
python3 run_agentic_system.py example.com
```

---

## 📈 Performance Monitoring One-Liners

### Check CPU Usage
```bash
top -b -n 1 | grep python3
```

### Count Active Agents
```bash
cat output/dashboard.json | jq '.agents | to_entries | map(select(.value.state == "executing")) | length'
```

### Get Average Task Time
```bash
cat output/dashboard.json | jq '.tasks.statistics.average_duration'
```

### Check Queue Size
```bash
cat output/dashboard.json | jq '.queue_size'
```

---

## 🎓 Learning from Results

### After Each Run

```bash
# 1. Check what was found
cat output/agentic_result.json | jq '.results[] | {target, vulnerabilities}'

# 2. See what system learned
cat learning_state.json | jq '.stats'

# 3. Review performance
cat output/dashboard.json | jq '.system_metrics.metrics'
```

### Compare Runs

```bash
# Save results with timestamp
cp output/agentic_result.json "results_$(date +%Y%m%d_%H%M%S).json"

# Compare later
diff results_20250101_120000.json results_20250102_120000.json
```

---

## 🚀 Production Deployment

### Cron Job (Daily Scans)

```bash
# Add to crontab
crontab -e

# Add this line (runs daily at 2 AM)
0 2 * * * cd /path/to/Recon-automation-Bug-bounty-stack && python3 run_agentic_system.py --target-file targets.txt >> cron.log 2>&1
```

### Screen Session (Long-Running)

```bash
# Start screen session
screen -S agentic

# Run scan
python3 run_agentic_system.py --target-file large_list.txt

# Detach: Ctrl+A, then D
# Reattach: screen -r agentic
```

### Background Process

```bash
# Run in background
nohup python3 run_agentic_system.py --target-file targets.txt > scan.log 2>&1 &

# Check progress
tail -f scan.log
```

---

## 💡 Pro Tips

### Tip 1: Start Small, Scale Up
```bash
# Week 1: Test with 10 targets
head -10 all_targets.txt > test_targets.txt
python3 run_agentic_system.py --target-file test_targets.txt

# Week 2: Scale to 100
head -100 all_targets.txt > targets.txt
python3 run_agentic_system.py --target-file targets.txt

# Week 3: Full scale
python3 run_agentic_system.py --target-file all_targets.txt
```

### Tip 2: Different Scans for Different Times
```bash
# Morning: Quick scan (many targets)
python3 run_agentic_system.py --target-file all_targets.txt --pipeline quick_scan

# Afternoon: Deep dive (few targets)
python3 run_agentic_system.py --target-file interesting_targets.txt --pipeline deep_discovery
```

### Tip 3: Monitor Learning
```bash
# Create learning tracker
cat > track_learning.sh << 'EOF'
#!/bin/bash
echo "$(date): Performance $(cat learning_state.json | jq '.stats.average_performance')" >> learning_progress.log
EOF

chmod +x track_learning.sh
```

---

## 🎯 Remember

**Most common command:**
```bash
python3 run_agentic_system.py --target-file targets.txt
```

**That's literally all you need 90% of the time.**

Everything else is optimization.

---

## 📞 Quick Links

- **Full Docs**: `AGENTIC_SYSTEM_COMPLETE.md`
- **Quick Start**: `AGENTIC_QUICK_START.md`
- **Simple Explanation**: `EXPLAIN_LIKE_IM_5.md`
- **Proof It Works**: `BEFORE_AFTER_COMPARISON.md`

---

**Print this. Pin it to your wall. Reference when needed.** 📌
