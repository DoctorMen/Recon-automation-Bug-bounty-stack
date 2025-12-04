# 🚀 GHOST IDE™ LIVE - Quick Start

## ⚡ Start Everything in 30 Seconds

### **Option 1: One Command (Easiest)**

```bash
bash start_ghost_ide.sh
```

That's it! The script will:
1. ✅ Install dependencies (Flask)
2. ✅ Start API server
3. ✅ Open GHOST IDE in browser
4. ✅ Connect everything automatically

---

### **Option 2: Manual (If you want control)**

**Terminal 1 (API Server):**
```bash
python3 GHOST_API.py
```

**Terminal 2 (Open IDE):**
```bash
explorer.exe GHOST_IDE_LIVE.html
```

---

## 🎯 What You'll See

### **1. API Server Starts:**
```
🎯 GHOST IDE™ API Server Starting...
Owner: Khallid Hakeem Nurse
Port: 5000
URL: http://localhost:5000

✅ Server ready - GHOST IDE can now connect
```

### **2. IDE Opens in Browser:**
- Shows "🟢 API Online" in header
- All buttons become active
- Ready to run REAL scans

### **3. Click "Start Real Scan":**
- See live command execution
- Watch output stream in real-time
- Progress bar shows status
- Results appear as they're found

---

## 📋 First Test

1. **Start system:**
   ```bash
   bash start_ghost_ide.sh
   ```

2. **Wait for "API Online" (green light in IDE)**

3. **Click "Start Real Scan"**

4. **Watch the magic happen:**
   - Command executes
   - Output streams live
   - Results appear in real-time

---

## 🔍 What's Actually Running

**When you click "Start Real Scan":**

```
GHOST IDE (browser)
    ↓ HTTP POST to /api/scan
GHOST_API.py (Flask server)
    ↓ Executes command
Your Python Scripts (run_pipeline.py, etc.)
    ↓ Real security scan
Results stream back to IDE in real-time
    ↓
Displayed live in browser
```

**It's actually running your tools!**

---

## 🎯 Available Commands

### **In IDE Terminal:**
```
scan          → Start real security scan
verify        → Check authorization
status        → System status
help          → Show commands
```

### **In Sidebar Buttons:**
```
🔍 Start Real Scan       → Executes actual scan
✅ Verify Authorization  → Checks auth file
📊 System Status         → Shows metrics
```

---

## 🛠️ Troubleshooting

### **Problem: API Offline (Red)**

**Solution:**
```bash
# Terminal 1: Start API manually
python3 GHOST_API.py

# Should see:
✅ Server ready - GHOST IDE can now connect
```

**Then refresh browser.**

---

### **Problem: "No module named flask"**

**Solution:**
```bash
pip3 install flask flask-cors
```

Then restart API.

---

### **Problem: Scan starts but no output**

**Check:** Is your script actually installed?
```bash
ls -la run_pipeline.py
# OR
ls -la DIVERGENT_THINKING_ENGINE.py
# OR
ls -la scripts/run_recon.sh
```

If missing, API will use fallback commands (subfinder, etc.)

---

## ✅ Verify It's Working

### **Test 1: API Health**
```bash
curl http://localhost:5000/api/health
```

**Should return:**
```json
{
  "status": "online",
  "message": "GHOST API is running",
  "active_scans": 0
}
```

### **Test 2: Modes List**
```bash
curl http://localhost:5000/api/modes
```

**Should show all 7 Divergent modes.**

### **Test 3: Start Scan from IDE**
Click "Start Real Scan" and watch terminal output.

---

## 🎯 Your Workflow

### **Daily Use:**

**Morning:**
```bash
cd ~/Recon-automation-Bug-bounty-stack
bash start_ghost_ide.sh
```

**Working:**
- Set target in IDE
- Choose mode
- Click "Start Real Scan"
- Watch live execution
- Results stream in real-time

**Evening:**
- Ctrl+C to stop API
- All scans logged and saved

---

## 📊 What You See vs What Executes

### **In GHOST IDE (Browser):**
```
🎯 Target: demo.hackerone.com
🧠 Mode: perspective
⚡ Executing live scan...
✓ Scan started: scan_1730847890
📝 Command: python3 run_pipeline.py --target demo.hackerone.com

[Live output streams here...]
✅ Scan complete!
```

### **In Terminal (API Server):**
```
127.0.0.1 - - [05/Nov/2025 14:10:23] "POST /api/scan HTTP/1.1" 200 -
Starting scan on demo.hackerone.com...
Running reconnaissance...
Found 3 subdomains...
Testing vulnerabilities...
Scan completed.
```

### **In Your File System:**
```
output/
  demo.hackerone.com/
    recon_results.txt
    vulnerabilities.json
    scan_report.html
```

**All three are synchronized - you see it happen live!**

---

## 🚀 Advanced Usage

### **Run Multiple Scans:**
Each scan gets unique ID (scan_1730847890, etc.)
Track them all in metrics panel.

### **Stream Multiple Targets:**
Open multiple tabs, each can run different scan.
API handles them all in parallel.

### **Check Scan Status:**
```bash
curl http://localhost:5000/api/scan/scan_1730847890/status
```

---

## 🎯 Production Use

### **For Bug Bounty:**
1. Set target: `shopify.com`
2. Choose mode: Perspective (nation-state)
3. Click scan
4. Watch real Divergent analysis execute
5. Results saved + displayed live

### **For Client Demo:**
1. Start system
2. Share screen
3. Set client domain
4. Execute live scan during call
5. Client sees real-time execution
6. Professional + impressive

---

## ✅ Success Indicators

**You're all set when you see:**

IDE Header:
```
🟢 API Online
```

Auth Widget:
```
✓ LEGAL SHIELD ACTIVE
API connected
Ready for live scans
```

Terminal:
```
$ GHOST IDE™ LIVE - Connected to API
$ ✅ Connected to GHOST API
```

**Now click "Start Real Scan" and watch it work!**

---

## 🎯 Next Steps

**Now that it's running:**

1. ✅ Test with safe target (demo.hackerone.com)
2. ✅ Verify auth checking works
3. ✅ Watch live output stream
4. ✅ Use for real bug bounty work

**Your IDE now executes real scans and shows everything live!**

---

**Owner:** Khallid Hakeem Nurse  
**Copyright:** © 2025 Khallid Hakeem Nurse - All Rights Reserved  
**System:** GHOST IDE™ LIVE  
