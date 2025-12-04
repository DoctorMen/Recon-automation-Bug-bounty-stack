<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Migrate Recon Stack to Cursor (Windows Native)

Complete guide to move everything from WSL/Ubuntu to Cursor workspace on Windows.

## 🎯 Goal

Remove all WSL dependencies and run everything natively in Cursor on Windows.

## 📋 Migration Steps

### Step 1: Copy Files to Windows Location

Choose a location on your Windows machine (not in WSL):

```
C:\Users\YourName\recon-stack\
```

Or use a project folder:
```
C:\Projects\recon-stack\
```

**Copy these from your current WSL location:**
```powershell
# From PowerShell or Cursor terminal
# Copy the entire recon-stack folder to Windows
```

### Step 2: File Structure in Cursor

Your Cursor workspace should look like:

```
recon-stack/
├── run_recon.py              # ✅ Windows native
├── run_httpx.py              # ✅ Windows native  
├── run_nuclei.py             # ✅ Windows native
├── run_pipeline.py           # ✅ Windows native
├── process_all.py            # ✅ Process existing results
├── targets.txt               # Your scan targets
├── scripts/
│   ├── triage.py             # Already Python
│   ├── generate_report.py    # Already Python
│   └── parse_nuclei_text_results.py
├── output/                   # All outputs (auto-created)
├── nuclei-templates/         # Custom templates (optional)
└── README_WINDOWS.md         # This guide
```

### Step 3: Install Tools on Windows

Install all recon tools on Windows (not in WSL):

**Option A: Via Go (if installed)**
```powershell
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@master
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

**Option B: Download Binaries**
- Download from GitHub releases
- Extract to a folder (e.g., `C:\Tools\`)
- Add to Windows PATH

**Verify installation:**
```powershell
where subfinder
where amass
where httpx
where nuclei
```

### Step 4: Update Your Workspace Paths

All Python scripts now use **absolute paths** based on script location, so they work from anywhere:

- ✅ No hardcoded `~/home/ubuntu` paths
- ✅ No WSL paths (`\\wsl$\...`)
- ✅ Works from any Windows location

### Step 5: Process Your Existing Results

If you have results from your WSL scan:

```powershell
# Copy your results_web_scan.txt to the workspace
# Then process:
python process_all.py path/to/results_web_scan.txt
```

Or move it to a convenient location and reference it.

## ✅ Test Everything Works

```powershell
# Test individual agents
python run_recon.py
python run_httpx.py
python run_nuclei.py

# Or run full pipeline
python run_pipeline.py
```

## 🗑️ Clean Up WSL (After Migration)

Once everything works in Cursor:

1. ✅ Test all scripts work in Cursor
2. ✅ Verify output files are created
3. ✅ Confirm tools are accessible
4. ⚠️ Then you can delete the WSL version

**But keep a backup first!**

## 📁 Where Files Are Created

All outputs go to `output/` folder relative to your workspace:

```
recon-stack/
├── output/
│   ├── subs.txt
│   ├── http.json
│   ├── nuclei-findings.json
│   ├── triage.json
│   ├── recon-run.log
│   └── reports/
│       ├── summary.md
│       └── *.md (individual reports)
```

## 🔧 Key Points

- ✅ **All Python** - No bash scripts needed
- ✅ **Relative paths** - Works from any location
- ✅ **Windows native** - No WSL required
- ✅ **Same functionality** - Everything preserved

## 🚀 Quick Start in Cursor

1. Open folder in Cursor: `File > Open Folder > recon-stack`
2. Create `targets.txt` with your domains
3. Run: `python run_pipeline.py`

That's it! Everything runs natively in Cursor.

## ❓ Troubleshooting

**"Tool not found" errors:**
- Tools must be in Windows PATH
- Check with: `where toolname`
- Add to PATH if needed

**Path errors:**
- All scripts use absolute paths now
- Should work from any location
- If issues, check file permissions

**Import errors:**
- Python scripts should work as-is
- Ensure Python 3.8+ installed

---

**You're now running 100% in Cursor on Windows!** 🎉

No WSL, no Ubuntu, just pure Windows + Cursor.

