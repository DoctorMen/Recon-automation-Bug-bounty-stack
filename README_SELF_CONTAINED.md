<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Self-Contained Recon Stack - Zero Host Dependencies!

**100% Self-Contained - Everything in Cursor Workspace**

No host machine setup needed. No PATH configuration. No external dependencies. Everything downloads and runs from the workspace itself!

## 🎯 The Vision

- ✅ Tools auto-download to workspace
- ✅ No PATH configuration needed
- ✅ No host machine installation
- ✅ Completely portable
- ✅ Just run and go!

## 🚀 Quick Start (2 Steps!)

### Step 1: Download Tools (One Time)

```powershell
python setup_tools.py
```

This automatically:
- Downloads all 5 tools from GitHub releases
- Extracts them to `tools/bin/`
- Makes them ready to use
- No manual installation needed!

### Step 2: Run Pipeline

```powershell
python run_pipeline.py
```

That's it! Everything uses the local tools automatically.

## 📁 Workspace Structure

```
recon-stack/
├── setup_tools.py           # Auto-downloads tools
├── tools_manager.py         # Finds local tools
├── tools/
│   └── bin/                 # Local tools (auto-created)
│       ├── subfinder.exe
│       ├── amass.exe
│       ├── dnsx.exe
│       ├── httpx.exe
│       └── nuclei.exe
├── run_recon.py             # Uses local tools
├── run_httpx.py             # Uses local tools
├── run_nuclei.py            # Uses local tools
├── run_pipeline.py          # Full pipeline
├── targets.txt              # Your targets
├── output/                  # All outputs
└── scripts/                 # Triage & reports
```

## 🔧 How It Works

1. **Tools Manager** (`tools_manager.py`)
   - Checks `tools/bin/` first (local tools)
   - Falls back to system PATH if not found
   - Automatically finds the right paths

2. **All Scripts Updated**
   - `run_recon.py` → Uses local tools
   - `run_httpx.py` → Uses local tools
   - `run_nuclei.py` → Uses local tools
   - No PATH needed!

3. **Auto Setup**
   - `setup_tools.py` downloads latest releases
   - Extracts only the .exe files
   - Stores in workspace

## ✅ Benefits

- **Zero Configuration** - No PATH setup
- **Portable** - Copy folder anywhere, it works
- **Self-Contained** - Everything in one place
- **Auto-Update** - Run setup_tools.py anytime for latest
- **No Dependencies** - No Go, no manual installs

## 🔄 Updating Tools

To get latest versions:

```powershell
python setup_tools.py
```

It will skip already-installed tools or update if needed.

## 📦 What Gets Downloaded

From GitHub releases (automatically):
- `subfinder.exe` - Subdomain discovery
- `amass.exe` - Subdomain enumeration
- `dnsx.exe` - DNS validation
- `httpx.exe` - HTTP probing
- `nuclei.exe` - Vulnerability scanning

All Windows amd64 binaries, latest versions.

## 🎯 Usage

Everything works the same, just uses local tools:

```powershell
# Individual agents
python run_recon.py
python run_httpx.py
python run_nuclei.py

# Full pipeline
python run_pipeline.py

# Process existing results
python process_all.py path\to\results.txt
```

## 🗑️ No Host Machine Needed!

- ✅ No Go installation on host
- ✅ No PATH configuration
- ✅ No manual tool downloads
- ✅ No WSL/Ubuntu dependencies
- ✅ Just Python + Internet (for initial download)

## 💾 Workspace Size

Tools add ~50-100MB to workspace:
- Each tool: ~5-20MB
- Total: ~50-100MB (acceptable for portability)

## 🔒 Safety

- Only downloads from official GitHub releases
- Uses GitHub API (no random downloads)
- Extracts only executables
- Verifies file structure

## 🐛 Troubleshooting

**Setup fails:**
- Check internet connection
- GitHub API may be rate-limited (wait a bit)
- Firewall blocking downloads

**Tools not found after setup:**
- Check `tools/bin/` exists
- Verify .exe files are there
- Run `python setup_tools.py` again

**Permission errors:**
- Run PowerShell as Administrator (if needed)
- Check folder permissions

---

## 🎉 You're Now 100% Self-Contained!

No host machine setup. No external dependencies. Everything in Cursor workspace. Just download tools once and run!

---

**Perfect for:**
- 🚀 Quick setup
- 📦 Portable recon stack
- 🔄 Version control (tools can be excluded via .gitignore)
- 👥 Team sharing (just share workspace)

