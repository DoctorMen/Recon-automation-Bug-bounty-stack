<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Quick Commands Reference

## 🔧 Fix Directory Issues

**Problem:** Scripts are in `~/Recon-automation-Bug-bounty-stack/scripts/` not in `programs/rapyd/findings/`

**Solution:** Always change to repo root first:

```bash
cd ~/Recon-automation-Bug-bounty-stack
```

Then run scripts:

```bash
python3 scripts/find_apple_protected.py
python3 scripts/test_apple_improved.py
python3 scripts/test_apple_protected.py
```

## 📁 Directory Structure

```
~/Recon-automation-Bug-bounty-stack/
├── scripts/          ← Scripts are here
│   ├── find_apple_protected.py
│   ├── test_apple_improved.py
│   └── ...
├── programs/
│   └── rapyd/
│       └── findings/  ← You were here
└── output/
```

## 🚀 Quick Commands

**From anywhere:**
```bash
cd ~/Recon-automation-Bug-bounty-stack
python3 scripts/find_apple_protected.py
```

**Or use full path:**
```bash
python3 ~/Recon-automation-Bug-bounty-stack/scripts/find_apple_protected.py
```

---

**Always run from repo root:** `cd ~/Recon-automation-Bug-bounty-stack`








