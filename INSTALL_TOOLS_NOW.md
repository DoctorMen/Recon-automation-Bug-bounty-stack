<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Install Tools - Quick Guide

You're in a **WSL/Linux environment**. Here are your options to install the required tools:

## 🚀 Option 1: Automated Script (Recommended)

Run this command:
```bash
python3 setup_tools.py
```

This will automatically:
- Detect your Linux/WSL platform
- Download the latest Linux binaries for all tools
- Extract them to `tools/bin/` directory
- Make them executable

**No manual installation needed!**

## 🔧 Option 2: Install via Go (If you have Go installed)

If you have Go installed, you can install tools via Go:

```bash
# Install Go (if not installed)
# For Ubuntu/Debian:
sudo apt update
sudo apt install golang-go

# Then install tools:
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@master
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Add Go bin to PATH (if not already)
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc
```

## 📦 Option 3: Manual Download (Linux/WSL)

Download Linux binaries manually:

1. **Subfinder**:
   ```bash
   wget https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_2.x.x_linux_amd64.zip
   unzip subfinder_*.zip
   chmod +x subfinder
   sudo mv subfinder /usr/local/bin/
   ```

2. **httpx** (most critical for your scan):
   ```bash
   wget https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_*.x.x_linux_amd64.zip
   unzip httpx_*.zip
   chmod +x httpx
   sudo mv httpx /usr/local/bin/
   ```

3. **nuclei**:
   ```bash
   wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_*.x.x_linux_amd64.zip
   unzip nuclei_*.zip
   chmod +x nuclei
   sudo mv nuclei /usr/local/bin/
   ```

4. **amass** and **dnsx**: Similar process

## ✅ Verify Installation

After installation, verify:
```bash
which httpx
which nuclei
which subfinder
httpx -version
nuclei -version
```

## 🎯 Quick Command

**Just run this from your workspace:**
```bash
cd /home/ubuntu/recon-stack
python3 setup_tools.py
```

The script will handle everything automatically!

