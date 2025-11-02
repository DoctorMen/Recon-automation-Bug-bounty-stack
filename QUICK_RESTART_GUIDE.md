# ✅ Quick Restart Guide

## What Happened:
- ✅ Scan was running but slow (amass timeout 600s)
- ✅ Optimization applied: Detects subdomains, skips enumeration
- ✅ Faster amass timeout: 180s instead of 600s

## 🚀 Quick Restart (Choose One):

### Option 1: Use the Script (Easiest)
```bash
cd ~/Recon-automation-Bug-bounty-stack
bash scripts/quick_restart.sh
```

### Option 2: Manual Commands
```bash
cd ~/Recon-automation-Bug-bounty-stack

# Stop current scan
pkill -f amass
pkill -f subfinder

# Clear status
rm -f output/immediate_roi/.status

# Restart with optimized code
python3 scripts/immediate_roi_hunter.py
```

### Option 3: One-Liner
```bash
cd ~/Recon-automation-Bug-bounty-stack && pkill -f amass 2>/dev/null; pkill -f subfinder 2>/dev/null; rm -f output/immediate_roi/.status && python3 scripts/immediate_roi_hunter.py
```

---

## 🎯 What Will Happen:

**With Optimized Code:**
1. ✅ **Instant**: Adds 200+ Squarespace subdomains directly (no enumeration)
2. ⚡ **Fast**: Only enumerates ~15 root domains (rapyd.net, mastercard.com, etc.)
3. ⚡ **Faster amass**: Max 180s per target (not 600s)
4. ✅ **Total time**: ~30-45 minutes instead of hours

**Expected Output:**
```
[INFO] Detected as subdomain (skipping enumeration): 2.squarespace.com
[INFO] Detected as subdomain (skipping enumeration): status.squarespace.com
...
[INFO] Added 200+ existing subdomains directly
[INFO] Enumerating subdomains for rapyd.net...
[INFO] Running: subfinder for rapyd.net
[INFO] Running: amass for rapyd.net (max 180s timeout)
```

---

## 💡 Pro Tip:

If you want to test with just a few targets first:

1. Edit `targets.txt` - comment out most targets, keep only:
   ```
   rapyd.net
   shopify.com
   ```

2. Run scan - will complete in ~5 minutes

3. If results look good, uncomment all targets and run full scan

---

**Run the restart command above to use optimized code!** 🚀

