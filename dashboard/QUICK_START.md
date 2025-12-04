<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# 🚀 Dashboard Quick Start

**Get your secure visual dashboard running in 60 seconds**

---

## Step 1: Navigate to Dashboard

```bash
cd /home/ubuntu/Recon-automation-Bug-bounty-stack/dashboard
```

## Step 2: Make Launcher Executable (First Time Only)

```bash
chmod +x launch_dashboard.sh
```

## Step 3: Launch Dashboard

**Linux/WSL/Mac:**
```bash
./launch_dashboard.sh
```

**Windows PowerShell:**
```powershell
.\launch_dashboard.ps1
```

## Step 4: Access Dashboard

Your browser should auto-open to:
```
http://127.0.0.1:8888
```

If not, manually open that URL in your browser.

---

## ✅ You're Done!

You should now see:
- 🎯 Main Dashboard with metrics
- 🔒 Security banner (OPSEC ACTIVE)
- 🔘 Redaction toggle button (top-right)

---

## 🎬 Next Actions

### **View System Status:**
Click **"System Status"** → See tool installation & repo health

### **View Scan Results:**
1. First run a scan: `cd .. && ./scripts/run_pipeline.sh`
2. Return to dashboard
3. Click **"Scan Results"** → View findings visually

### **Take Screenshots Safely:**
1. Click 🔒 button (ensure "Redaction: ON")
2. Wait for sensitive data to hide
3. Take screenshot
4. ✓ Safe to share!

---

## ⚠️ Quick Security Notes

- ✅ Dashboard is **LOCAL ONLY** (127.0.0.1)
- ✅ Redaction is **ENABLED** by default
- ✅ No external connections (fully air-gapped)
- ❌ **DO NOT** disable redaction before reviewing data

---

## 🐛 Troubleshooting

**Problem:** Port 8888 already in use  
**Solution:** Launcher auto-finds next port, or use custom:
```bash
DASHBOARD_PORT=9000 ./launch_dashboard.sh
```

**Problem:** No scan data visible  
**Solution:** Run a scan first:
```bash
cd .. && ./scripts/run_pipeline.sh
```

**Problem:** Permission denied  
**Solution:** Make script executable:
```bash
chmod +x launch_dashboard.sh
```

---

## 📚 Learn More

- `README.md` - Full documentation
- `SECURITY.md` - OPSEC guidelines
- `../README.md` - Main system docs

---

**That's it! Enjoy your secure visual dashboard! 🎯🔒**

