<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# 🎯 Secure Bug Bounty Dashboard

**Visual Command Center for Your Recon Automation Stack**

🔒 **OPSEC-First Design** | 📡 **Local Only** | 🛡️ **No External Connections**

---

## 🚀 Quick Start

### **Launch Dashboard (Linux/WSL/Mac):**
```bash
cd dashboard
./launch_dashboard.sh
```

### **Launch Dashboard (Windows PowerShell):**
```powershell
cd dashboard
.\launch_dashboard.ps1
```

The dashboard will automatically open at `http://127.0.0.1:8888` ✓

---

## 📊 Features

### **Main Dashboard (`index.html`)**
- 📈 Real-time scan metrics
- 🎯 Quick actions panel
- 📊 Severity breakdown charts
- 🕒 Recent activity timeline
- 📁 Repository status

### **System Status Monitor (`system_status.html`)**
- 🔧 Tool installation checks
- 📁 Repository health
- 📂 Output file verification
- 🔄 Auto-refresh every minute

### **Scan Visualizer (`scan_visualizer.html`)**
- 🔍 Interactive findings browser
- 🎚️ Severity filters
- 🔎 Search functionality
- 📥 Export capabilities
- 📊 Real-time charts

---

## 🔒 Security Features

### **Built-In OPSEC:**
- ✅ **Local-only binding** (127.0.0.1 - never 0.0.0.0)
- ✅ **No external CDN** (all resources local)
- ✅ **Content Security Policy** (blocks external scripts)
- ✅ **Automatic redaction** (sensitive data hidden by default)
- ✅ **Secure file permissions** (0600 on sensitive files)
- ✅ **No telemetry** (zero external calls)

### **Redaction System:**
- 🔒 **Enabled by default** on dashboard load
- Toggle with button in top-right corner
- Automatically redacts:
  - Domain names → `target-*****.com`
  - IP addresses → `xxx.xxx.xxx.xxx`
  - Email addresses → `***@***.***`
  - API keys → `***REDACTED***`

---

## 📋 File Structure

```
dashboard/
├── index.html                 # Main dashboard
├── system_status.html         # Tool & repo status
├── scan_visualizer.html       # Findings viewer
├── SECURITY.md                # Security guidelines (READ THIS!)
├── README.md                  # This file
├── launch_dashboard.sh        # Linux/Mac launcher
├── launch_dashboard.ps1       # Windows launcher
└── assets/
    ├── styles.css             # Modern dark theme
    └── dashboard.js           # Interactive functionality
```

---

## 🎬 Usage Examples

### **View Scan Results:**
1. Run a scan: `cd .. && ./scripts/run_pipeline.sh`
2. Launch dashboard: `./dashboard/launch_dashboard.sh`
3. Click **"Scan Results"** to visualize findings

### **Check System Health:**
1. Launch dashboard
2. Click **"System Status"**
3. View tool installation status

### **Export Findings:**
1. Open **Scan Visualizer**
2. Apply filters (if needed)
3. Click **Export** button
4. Review redaction before sharing!

---

## ⚠️ OPSEC Best Practices

### **DO:**
- ✅ Only access on trusted, secure networks
- ✅ Keep redaction ENABLED when taking screenshots
- ✅ Review `SECURITY.md` before sharing any data
- ✅ Close dashboard when not in use
- ✅ Use VPN on public networks

### **DON'T:**
- ❌ Bind to 0.0.0.0 (exposes to network)
- ❌ Share URLs publicly
- ❌ Access on untrusted devices
- ❌ Disable redaction without reviewing data first
- ❌ Take screenshots with sensitive info visible

---

## 🔧 Customization

### **Change Port:**
```bash
# Linux/Mac
DASHBOARD_PORT=9000 ./launch_dashboard.sh

# Windows
.\launch_dashboard.ps1 -Port 9000
```

### **Customize Refresh Interval:**
Edit `assets/dashboard.js`:
```javascript
const CONFIG = {
    REFRESH_INTERVAL: 30000, // 30 seconds (change this)
    ...
};
```

---

## 🐛 Troubleshooting

### **Port Already in Use:**
- The launcher will automatically find next available port
- Or specify custom port (see Customization above)

### **Dashboard Won't Load:**
- Check Python is installed: `python3 --version`
- Check you're in dashboard directory
- Try different port: `./launch_dashboard.sh` (will auto-select)

### **No Scan Data Visible:**
- Run a scan first: `cd .. && ./scripts/run_pipeline.sh`
- Check `../output/` directory exists
- Verify `nuclei-findings.json` exists

### **Firewall Blocking:**
- Dashboard only binds to 127.0.0.1 (localhost)
- Should not trigger firewall warnings
- If blocked, allow Python HTTP server for localhost only

---

## 📸 Screenshots

### **Taking Safe Screenshots:**

1. **Enable Redaction** (🔒 button in top-right)
2. **Wait for redaction** to apply (sensitive data hidden)
3. **Take screenshot**
4. **Review before sharing** - ensure no leaks

### **What Gets Redacted:**
- ✅ Target domains
- ✅ IP addresses
- ✅ Email addresses
- ✅ API keys/tokens
- ✅ Sensitive paths

### **What Stays Visible:**
- ✅ Severity counts
- ✅ Tool names
- ✅ Chart data (aggregated)
- ✅ Scan status
- ✅ General statistics

---

## 🚨 Security Incident Response

**If dashboard is accidentally exposed:**

1. **Immediately stop server:** Press `Ctrl+C`
2. **Check access logs:** `dashboard/access.log`
3. **Rotate credentials:** Any API keys in scan data
4. **Review browser history:** Clear if needed
5. **Document incident:** For future prevention

---

## 📚 Related Documentation

- `SECURITY.md` - Complete security guidelines (READ FIRST!)
- `../README.md` - Main recon stack documentation
- `../MASTER_SYSTEM_UNIQUENESS_ANALYSIS.md` - System overview

---

## ✅ Pre-Launch Checklist

Before first use:
- [ ] Read `SECURITY.md`
- [ ] Understand redaction system
- [ ] Verify local-only binding (127.0.0.1)
- [ ] Test redaction toggle
- [ ] Review screenshot guidelines
- [ ] Set secure file permissions
- [ ] Configure firewall (if needed)

---

## 💡 Tips & Tricks

### **Keyboard Shortcuts:**
- `Ctrl+C` - Stop dashboard server
- `Ctrl+Shift+R` - Hard refresh dashboard
- `F12` - Open browser DevTools (check console)

### **Performance:**
- Dashboard uses minimal resources
- Auto-refresh every 30 seconds (configurable)
- Handles 1000+ findings efficiently

### **Data Persistence:**
- All data loaded from local files
- No database required
- Changes persist in `output/` directory

---

## 🎯 Next Steps

1. **Launch dashboard:** `./launch_dashboard.sh`
2. **Run your first scan:** `cd .. && ./scripts/run_pipeline.sh`
3. **Visualize results:** Click "Scan Results" in dashboard
4. **Export findings:** Use export button (with redaction!)
5. **Monitor system:** Check "System Status" regularly

---

## 📞 Support

**Security Issues:**
- Review `SECURITY.md`
- Check OPSEC guidelines
- Ensure redaction is working

**Technical Issues:**
- Check `output/` directory permissions
- Verify Python installation
- Review browser console (F12)

---

## 🔐 Security Guarantee

This dashboard is designed with **OPSEC-first principles**:

- ✅ **Zero telemetry**
- ✅ **Zero external calls**
- ✅ **Zero tracking**
- ✅ **100% local**
- ✅ **Fully air-gapped capable**

**Your data never leaves your machine. Period.**

---

**Built with security in mind. Use with confidence. 🛡️**

*Last updated: $(date)*

