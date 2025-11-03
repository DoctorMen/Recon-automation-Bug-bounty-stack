# Quick Fix: Running from Wrong Directory

## Problem
You're in: `~/Recon-automation-Bug-bounty-stack/programs/rapyd/findings`
But script is in: `~/Recon-automation-Bug-bounty-stack/scripts/`

## Solution

### Option 1: Navigate to repo root (Recommended)
```bash
cd ~/Recon-automation-Bug-bounty-stack
python3 scripts/immediate_roi_hunter.py
```

### Option 2: Use absolute path
```bash
python3 ~/Recon-automation-Bug-bounty-stack/scripts/immediate_roi_hunter.py
```

### Option 3: Use relative path from current location
```bash
python3 ../../scripts/immediate_roi_hunter.py
```

## Quick Command
```bash
cd ~/Recon-automation-Bug-bounty-stack && python3 scripts/immediate_roi_hunter.py
```

---

**The script needs to be run from the repo root because it references:**
- `targets.txt` (in repo root)
- `output/` directory (relative to repo root)
- Other scripts in `scripts/` directory

