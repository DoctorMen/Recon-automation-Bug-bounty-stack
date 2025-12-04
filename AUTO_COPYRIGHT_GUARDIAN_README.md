<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# AUTO COPYRIGHT GUARDIAN - Automated Copyright Protection
## Checks Every 10 Minutes to Keep Your Copyright Updated

---

## What It Does

**AUTO COPYRIGHT GUARDIAN** automatically:
- ✅ Scans your entire repository every 10 minutes
- ✅ Adds copyright headers to new files
- ✅ Updates copyright year in existing files
- ✅ Tracks file changes with MD5 hashing
- ✅ Logs all activity
- ✅ Runs idempotently (safe to run multiple times)

---

## Quick Start

### **Option 1: Run Once (Test)**

**Windows**:
```batch
python AUTO_COPYRIGHT_GUARDIAN.py
```

**Linux/WSL**:
```bash
python3 AUTO_COPYRIGHT_GUARDIAN.py
```

### **Option 2: Run Continuously (Recommended)**

**Windows**:
```batch
START_COPYRIGHT_GUARDIAN.bat
```

**Linux/WSL**:
```bash
chmod +x START_COPYRIGHT_GUARDIAN.sh
./START_COPYRIGHT_GUARDIAN.sh
```

### **Option 3: Auto-Start on Boot**

**Windows (Task Scheduler)**:
```batch
SETUP_COPYRIGHT_GUARDIAN_WINDOWS.bat
```
Choose option 2 to create scheduled task.

**Linux (systemd service)**:
```bash
chmod +x SETUP_COPYRIGHT_GUARDIAN_LINUX.sh
./SETUP_COPYRIGHT_GUARDIAN_LINUX.sh
```
Choose option 2 for systemd service.

---

## How It Works

### **10-Minute Cycle**:

```
Minute 0:  Scan all files → Add/update copyrights → Save state
Minute 10: Scan all files → Add/update copyrights → Save state
Minute 20: Scan all files → Add/update copyrights → Save state
...repeats forever
```

### **Protected File Types**:

- Python (`.py`)
- JavaScript (`.js`)
- HTML (`.html`)
- CSS (`.css`)
- Markdown (`.md`)
- Shell scripts (`.sh`)
- Batch files (`.bat`)
- JSON (`.json`)
- YAML (`.yml`, `.yaml`)
- SQL (`.sql`)
- Text (`.txt`)

### **Copyright Format by File Type**:

**Python**:
```python
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
```

**JavaScript**:
```javascript
/**
 * Copyright © 2025 DoctorMen. All Rights Reserved.
 */
```

**HTML/Markdown**:
```html
<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
```

**Shell Script**:
```bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
```

---

## State Tracking

### **Files Created**:

1. **`.auto_copyright_state.json`** - Tracks file hashes
2. **`.auto_copyright_log.txt`** - Activity log
3. **`AUTO_COPYRIGHT_GUARDIAN.py`** - Main script

### **State File Structure**:
```json
{
  "last_check": "2025-11-05T10:45:00",
  "files_tracked": {
    "script.py": "a3f5b8c9d2e1...",
    "README.md": "d4e6f7g8h9i0..."
  },
  "total_updates": 42,
  "last_update_time": "2025-11-05T10:45:00"
}
```

---

## Usage Examples

### **Manual Scan**:
```bash
python3 AUTO_COPYRIGHT_GUARDIAN.py
```

### **Start Daemon (10-minute checks)**:
```bash
python3 AUTO_COPYRIGHT_GUARDIAN.py --daemon --interval 10
```

### **Custom Interval (5-minute checks)**:
```bash
python3 AUTO_COPYRIGHT_GUARDIAN.py --daemon --interval 5
```

### **Different Repository**:
```bash
python3 AUTO_COPYRIGHT_GUARDIAN.py --repo /path/to/other/repo
```

---

## Windows Task Scheduler Setup

### **Manual Setup**:

1. Open Task Scheduler (`taskschd.msc`)
2. Create Basic Task → Name: "AutoCopyrightGuardian"
3. Trigger: "At startup"
4. Action: Start a program
5. Program: `C:\Path\To\START_COPYRIGHT_GUARDIAN.bat`
6. Settings:
   - ✅ Run whether user is logged on or not
   - ✅ Run with highest privileges
   - ✅ Start task if on batteries
7. Triggers → Edit → Advanced:
   - ✅ Repeat task every: 10 minutes
   - ✅ For a duration of: Indefinitely

### **Automated Setup**:
```batch
SETUP_COPYRIGHT_GUARDIAN_WINDOWS.bat
```

---

## Linux Systemd Service

### **Install Service**:
```bash
sudo cp copyright-guardian.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable copyright-guardian
sudo systemctl start copyright-guardian
```

### **Check Status**:
```bash
sudo systemctl status copyright-guardian
```

### **View Logs**:
```bash
sudo journalctl -u copyright-guardian -f
```

### **Stop/Restart**:
```bash
sudo systemctl stop copyright-guardian
sudo systemctl restart copyright-guardian
```

---

## Linux Cron Job (Alternative)

### **Add to Crontab**:
```bash
crontab -e
```

Add this line:
```
*/10 * * * * cd /home/ubuntu/Recon-automation-Bug-bounty-stack && /usr/bin/python3 AUTO_COPYRIGHT_GUARDIAN.py >> .auto_copyright_log.txt 2>&1
```

### **Verify**:
```bash
crontab -l
```

---

## Monitoring & Logs

### **View Log File**:
```bash
tail -f .auto_copyright_log.txt
```

### **Check State**:
```bash
cat .auto_copyright_state.json | python3 -m json.tool
```

### **Statistics**:
```bash
grep "✅ Scan complete" .auto_copyright_log.txt | tail -10
```

---

## What Gets Updated

### **New Files**:
- Copyright header is **added automatically**
- File is tracked in state

### **Modified Files**:
- Copyright year is **updated if outdated**
- Hash is updated in state

### **Example Log**:
```
[2025-11-05T10:30:00] 🔍 Starting copyright scan...
[2025-11-05T10:30:01] ✅ Added copyright to: new_script.py
[2025-11-05T10:30:01] ✅ Updated copyright year in: old_script.py
[2025-11-05T10:30:02] ✅ Scan complete: 487 files checked, 3 new, 5 updated
[2025-11-05T10:30:02] ⏳ Next check in 10 minutes...
```

---

## Directories Skipped

The guardian **automatically skips**:
- `.git` (version control)
- `__pycache__` (Python cache)
- `node_modules` (npm packages)
- `.cursor`, `.vscode` (IDE files)
- `dist`, `build` (compiled output)
- `env`, `venv` (virtual environments)
- `output`, `logs` (generated files)

---

## Stopping the Guardian

### **Windows**:
- Press `Ctrl+C` in the console
- Or: `schtasks /end /tn "AutoCopyrightGuardian"`

### **Linux**:
- Press `Ctrl+C` in terminal
- Or systemd: `sudo systemctl stop copyright-guardian`
- Or cron: `crontab -e` and remove the line

---

## Troubleshooting

### **"Permission denied" errors**:
```bash
chmod +x *.sh
chmod +x AUTO_COPYRIGHT_GUARDIAN.py
```

### **Python not found**:
- Windows: Ensure Python in PATH
- Linux: Install `python3`

### **Service won't start**:
```bash
sudo systemctl status copyright-guardian
sudo journalctl -u copyright-guardian -n 50
```

### **Task Scheduler fails**:
- Run as Administrator
- Check file paths (no spaces in path recommended)
- Verify Python installation

---

## Benefits

### **Automatic Protection**:
- ✅ Never forget to add copyright
- ✅ Always up-to-date year
- ✅ Consistent formatting
- ✅ Complete repository coverage

### **Legal Protection**:
- ✅ Clear ownership assertion
- ✅ Timestamp evidence in logs
- ✅ Comprehensive coverage
- ✅ Audit trail

### **Zero Maintenance**:
- ✅ Set and forget
- ✅ Runs in background
- ✅ No manual intervention
- ✅ Idempotent (safe)

---

## Integration with Other Systems

### **Git Pre-Commit Hook**:
```bash
# .git/hooks/pre-commit
#!/bin/bash
python3 AUTO_COPYRIGHT_GUARDIAN.py
git add -u
```

### **CI/CD Pipeline**:
```yaml
# .github/workflows/copyright.yml
name: Copyright Check
on: [push]
jobs:
  copyright:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - run: python3 AUTO_COPYRIGHT_GUARDIAN.py
```

---

## Advanced Configuration

### **Custom Copyright Text**:
Edit line 23 in `AUTO_COPYRIGHT_GUARDIAN.py`:
```python
self.copyright_text = "Copyright © 2025 YourName. All Rights Reserved."
```

### **Additional File Types**:
Edit line 27-29:
```python
self.protected_extensions = {
    '.py', '.js', '.html', '.rs', '.go', '.cpp'
}
```

### **Different Check Interval**:
```bash
python3 AUTO_COPYRIGHT_GUARDIAN.py --daemon --interval 5  # 5 minutes
python3 AUTO_COPYRIGHT_GUARDIAN.py --daemon --interval 60  # 1 hour
```

---

## Summary

**AUTO COPYRIGHT GUARDIAN** provides **24/7 automated copyright protection** with:
- 🕒 10-minute check intervals
- 🔄 Automatic updates
- 📝 Complete logging
- 🛡️ Idempotent operation
- 🚀 Zero maintenance

**Set it up once, protected forever.**

---

## Files Created

1. `AUTO_COPYRIGHT_GUARDIAN.py` - Main guardian script
2. `START_COPYRIGHT_GUARDIAN.bat` - Windows launcher
3. `START_COPYRIGHT_GUARDIAN.sh` - Linux launcher
4. `SETUP_COPYRIGHT_GUARDIAN_WINDOWS.bat` - Windows auto-setup
5. `SETUP_COPYRIGHT_GUARDIAN_LINUX.sh` - Linux auto-setup
6. `copyright-guardian.service` - Systemd service file
7. `AUTO_COPYRIGHT_GUARDIAN_README.md` - This file

---

**Copyright © 2025 DoctorMen. All Rights Reserved.**
