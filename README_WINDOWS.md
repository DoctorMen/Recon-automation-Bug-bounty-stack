<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Recon Stack - Windows Native (Cursor Workspace)

**100% Native Windows - No WSL/Ubuntu Required!**

This version runs entirely in your Cursor workspace on Windows. Everything is self-contained and uses relative paths.

## 🚀 Quick Start

### 1. Install Required Tools

All tools need to be installed and in your Windows PATH.

**Option A: Via Go (if you have Go installed)**
```powershell
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@master
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```
*Note: Add `%USERPROFILE%\go\bin` to your PATH after installing.*

**Option B: Download Pre-built Binaries**
- Download from [ProjectDiscovery releases](https://github.com/projectdiscovery) and [Amass releases](https://github.com/owasp-amass/amass/releases)
- Extract to a folder (e.g., `C:\Tools\`)
- Add folder to Windows PATH

**Option C: Use Scoop (Easiest)**
```powershell
scoop install subfinder amass dnsx httpx nuclei
```

**See `INSTALL_TOOLS.md` for detailed instructions and troubleshooting.**

### 2. Create targets.txt

Create `targets.txt` in the root directory:

```
example.com
authorized-target.io
```

### 3. Quick Setup (Optional)

Run the setup script to verify everything:

```powershell
.\setup_cursor.ps1
```

### 4. Run the Pipeline

```powershell
# Full pipeline
python run_pipeline.py

# Or individual steps:
python run_recon.py          # Subdomain discovery
python run_httpx.py          # Web mapping
python run_nuclei.py         # Vulnerability scanning
python scripts/triage.py      # Triage and scoring
python scripts/generate_report.py  # Generate reports
```

### 5. Process Existing Results

If you have results from a previous scan:

```powershell
python process_all.py path\to\results_web_scan.txt
```

## 📁 File Structure

```
recon-stack/
├── run_recon.py              # Recon scanner (Windows native)
├── run_httpx.py              # Web mapper (Windows native)
├── run_nuclei.py             # Vulnerability hunter (Windows native)
├── run_pipeline.py           # Full pipeline orchestrator
├── process_all.py            # Process existing nuclei results
├── scripts/
│   ├── triage.py             # Triage and scoring
│   ├── generate_report.py    # Report generation
│   └── parse_nuclei_text_results.py  # Parse text results
├── output/                   # All outputs
├── targets.txt               # Your scan targets
└── README_WINDOWS.md        # This file
```

## 🔧 Key Differences from Linux Version

1. **All Python** - No bash scripts, everything is Python
2. **Windows Paths** - Uses `Path` objects that work on Windows
3. **Tool Detection** - Uses `where` instead of `which`
4. **Native Execution** - Runs directly in Windows Cursor environment

## 📊 Processing Existing Results

If you have nuclei text output:

```powershell
python process_all.py path/to/results_web_scan.txt
```

## ⚙️ Configuration

Set environment variables:

```powershell
$env:HTTPX_RATE_LIMIT = "50"
$env:NUCLEI_RATE_LIMIT = "25"
$env:RECON_TIMEOUT = "3600"
python run_pipeline.py
```

Or use PowerShell script:

```powershell
# Resume from last stage
$env:RESUME = "true"
python run_pipeline.py
```

## ✅ Benefits

- ✅ No WSL needed
- ✅ Runs directly in Cursor
- ✅ All Python - easier to debug
- ✅ Windows path compatibility
- ✅ Same functionality as Linux version

## 🐛 Troubleshooting

**Tools not found:**
- Ensure tools are in your Windows PATH
- Check with: `where subfinder`

**Python errors:**
- Ensure Python 3.8+ is installed
- Run: `python --version`

**File path issues:**
- All paths use `Path` objects - should work on Windows
- If issues, check file permissions

## 📝 Notes

- All scripts are now Python for maximum compatibility
- Output format is identical to Linux version
- Can still process Linux-generated results
- Resume capability works the same way

---

**Welcome to the Windows-native recon stack!** 🎉

