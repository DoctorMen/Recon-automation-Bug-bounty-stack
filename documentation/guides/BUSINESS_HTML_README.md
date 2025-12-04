<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Business.html - Quick Start Guide

## Use Local Server (Recommended)

The reliable way to view `business.html` is via a local HTTP server:

### Option 1: Use Server Scripts (Easiest)

**Linux/WSL:**
```bash
bash scripts/start_business_server.sh
```
This will:
- Start Python HTTP server on port 8000
- Open browser automatically
- Show URL: http://localhost:8000/business.html

**Windows:**
```batch
start_business_server.bat
```

### Option 2: Manual Server Start
```bash
cd /home/ubuntu/Recon-automation-Bug-bounty-stack
python3 -m http.server 8000
```
Then open: **http://localhost:8000/business.html**

## Why It Works Standalone

✅ All CSS embedded in `<style>` tag  
✅ No external dependencies  
✅ No backend required  
✅ Works offline  

## File Location
- Path: `Recon-automation-Bug-bounty-stack/business.html`
- Full path (WSL): `/home/ubuntu/Recon-automation-Bug-bounty-stack/business.html`
- Windows path: `\\wsl$\Ubuntu\home\ubuntu\Recon-automation-Bug-bounty-stack\business.html`

## Troubleshooting

**Problem**: Browser shows "can't connect to server"  
**Solution**: Don't use `http://business.html` - open the file directly or use `file://` protocol

**Problem**: File won't open  
**Solution**: Use the full path or one of the helper scripts above

**Problem**: Styling looks broken  
**Solution**: Check browser console for errors - the file should work standalone

