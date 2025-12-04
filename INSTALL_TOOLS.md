<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Install Recon Tools on Windows

Complete installation guide for all required tools on Windows.

## 📦 Prerequisites

1. **Go Programming Language** (if installing via Go)
   - Download from: https://go.dev/dl/
   - Install and add to PATH
   - Verify: `go version`

2. **OR Download Pre-built Binaries**
   - No Go needed if using binaries
   - Just download and add to PATH

---

## 🚀 Installation Methods

### Method 1: Via Go (Recommended if you have Go)

Open PowerShell and run:

```powershell
# Install Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install Amass
go install -v github.com/owasp-amass/amass/v4/...@master

# Install DNSx
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Install httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

**Note:** Go installs binaries to `%USERPROFILE%\go\bin` by default. Add this to your Windows PATH:
1. Press `Win + X` → System → Advanced system settings
2. Environment Variables → User variables → Path → Edit
3. Add: `C:\Users\YourName\go\bin` (adjust for your username)
4. Restart PowerShell

---

### Method 2: Download Pre-built Binaries (No Go Required)

Download Windows binaries from GitHub releases:

#### Subfinder
- URL: https://github.com/projectdiscovery/subfinder/releases
- Download: `subfinder_X.X.X_windows_amd64.zip`
- Extract `subfinder.exe` to a folder (e.g., `C:\Tools\`)

#### Amass
- URL: https://github.com/owasp-amass/amass/releases
- Download: `amass_X.X.X_windows_amd64.zip`
- Extract `amass.exe` to same folder

#### DNSx
- URL: https://github.com/projectdiscovery/dnsx/releases
- Download: `dnsx_X.X.X_windows_amd64.zip`
- Extract `dnsx.exe` to same folder

#### httpx
- URL: https://github.com/projectdiscovery/httpx/releases
- Download: `httpx_X.X.X_windows_amd64.zip`
- Extract `httpx.exe` to same folder

#### Nuclei
- URL: https://github.com/projectdiscovery/nuclei/releases
- Download: `nuclei_X.X.X_windows_amd64.zip`
- Extract `nuclei.exe` to same folder

**Add folder to PATH:**
1. Create folder: `C:\Tools\` (or your choice)
2. Extract all `.exe` files there
3. Add `C:\Tools\` to Windows PATH (same steps as above)

---

## ✅ Verify Installation

After installation, verify in PowerShell:

```powershell
# Check each tool
where subfinder
where amass
where dnsx
where httpx
where nuclei

# Test commands
subfinder -version
amass -version
dnsx -version
httpx -version
nuclei -version
```

You should see paths and version numbers.

---

## 🔧 Alternative: Scoop Package Manager (Easiest)

If you use [Scoop](https://scoop.sh/):

```powershell
# Install Scoop (if not installed)
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
irm get.scoop.sh | iex

# Install tools
scoop bucket add main
scoop install subfinder
scoop install amass
scoop install dnsx
scoop install httpx
scoop install nuclei
```

Scoop automatically adds tools to PATH!

---

## 📋 Quick Checklist

- [ ] Go installed OR binary folder created
- [ ] All 5 tools installed (subfinder, amass, dnsx, httpx, nuclei)
- [ ] Tools folder added to Windows PATH
- [ ] Verified with `where toolname` command
- [ ] Tested with `toolname -version`

---

## 🐛 Troubleshooting

**"Tool not recognized"**
- Tool not in PATH
- Restart PowerShell after adding to PATH
- Check with: `$env:Path -split ';' | Select-String "go\bin\|Tools"`

**"Access denied"**
- Run PowerShell as Administrator
- Or adjust file permissions

**Go install fails**
- Ensure Go is installed: `go version`
- Check Go bin path is in PATH
- Try: `go env GOPATH` to find install location

---

## 🎯 Next Steps

Once tools are installed:

1. Run setup: `.\setup_cursor.ps1`
2. Edit `targets.txt` with your domains
3. Run: `python run_pipeline.py`

---

**You're ready to recon!** 🚀

