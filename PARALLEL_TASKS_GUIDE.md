# Parallel Tasks Guide

While tools are downloading, you can run these tasks in parallel to prepare for scanning and reduce downtime.

## 🚀 Quick Start

Run all parallel setup tasks at once:
```bash
python3 scripts/parallel_setup.py
```

Or run individual tasks:

## 📋 Available Parallel Tasks

### 1. Target Validation Agent
**Script**: `scripts/validate_targets.py`

**What it does:**
- Validates all targets in `targets.txt`
- Checks DNS resolution for each domain
- Tests HTTP/HTTPS accessibility
- Identifies which targets are reachable before scanning

**Run:**
```bash
python3 scripts/validate_targets.py
```

**Output**: `output/targets-validation.json`

**Benefits:**
- Know which targets are valid before scanning
- Save time by not scanning unreachable domains
- Get early warnings about configuration issues

---

### 2. Nuclei Templates Updater
**Script**: `scripts/update_nuclei_templates.py`

**What it does:**
- Updates Nuclei vulnerability templates to latest version
- Ensures you have the newest detection signatures
- Falls back to cloning templates repo if nuclei not ready yet

**Run:**
```bash
python3 scripts/update_nuclei_templates.py
```

**Output**: Updated templates in `nuclei-templates/` directory

**Benefits:**
- Latest vulnerability detection patterns
- More accurate scanning results
- Ready when scanning starts

---

### 3. Scan Environment Preparer
**Script**: `scripts/prepare_scan_environment.py`

**What it does:**
- Creates all necessary output directories
- Validates targets.txt exists and has content
- Checks tool installation status
- Creates scan configuration file

**Run:**
```bash
python3 scripts/prepare_scan_environment.py
```

**Output**: 
- Creates directories
- `output/scan-config.json`

**Benefits:**
- Ensures environment is ready
- Validates setup before scanning
- Saves time during actual scan startup

---

### 4. Scan Monitor & Dashboard
**Script**: `scripts/scan_monitor.py`

**What it does:**
- Shows real-time scan status
- Displays pipeline stage completion
- Lists output files and their sizes
- Summarizes findings by severity
- Shows recent log entries

**Run:**
```bash
python3 scripts/scan_monitor.py
```

**Output**: Console dashboard (run anytime to check status)

**Benefits:**
- Real-time visibility into scan progress
- Quick status checks
- Find issues early

---

## ⚡ Run All Tasks in Parallel

**Master Script**: `scripts/parallel_setup.py`

This runs tasks 1-3 simultaneously while tools download:

```bash
python3 scripts/parallel_setup.py
```

**What it does:**
- Runs target validation, template updates, and environment prep in parallel
- Maximizes efficiency
- Shows summary of all tasks

---

## 📊 Task Execution Timeline

While `setup_tools.py` runs (5-10 minutes):

```
┌─────────────────────────────────────────────────────────┐
│ Tool Installation (5-10 min)                            │
│ ├─ subfinder download                                   │
│ ├─ httpx download                                       │
│ ├─ nuclei download                                      │
│ └─ amass, dnsx download                                 │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ Parallel Tasks (Run simultaneously)                     │
│ ├─ Target Validation (2-3 min)                         │
│ ├─ Templates Update (1-2 min)                          │
│ └─ Environment Setup (< 1 min)                         │
└─────────────────────────────────────────────────────────┘

Result: Tools ready + Environment prepared = Ready to scan!
```

---

## 🔄 Workflow

1. **Start tool installation:**
   ```bash
   python3 setup_tools.py
   ```

2. **While tools download, run parallel setup:**
   ```bash
   python3 scripts/parallel_setup.py
   ```

3. **Check status anytime:**
   ```bash
   python3 scripts/scan_monitor.py
   ```

4. **When tools finish, start scanning:**
   ```bash
   python3 start_scan.py
   ```

---

## 📁 Output Files Created

After running parallel tasks, you'll have:

- `output/targets-validation.json` - Domain validation results
- `output/scan-config.json` - Scan configuration
- `nuclei-templates/` - Updated vulnerability templates
- `output/` directory structure ready

---

## 💡 Tips

1. **Run parallel tasks immediately** after starting tool installation
2. **Check validation results** to ensure targets are reachable
3. **Monitor status** periodically with scan_monitor.py
4. **All tasks are safe to re-run** if needed

---

## 🎯 Next Steps

After parallel tasks complete:

1. Wait for tool installation to finish
2. Verify with: `python3 scripts/scan_monitor.py`
3. Start scanning: `python3 start_scan.py`

---

**Time Saved**: Running parallel tasks during download saves **5-10 minutes** of setup time!

