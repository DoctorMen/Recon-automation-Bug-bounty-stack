# 🔒 Quick Guide: Set Your Name for Copyright

## Option 1: Edit the Script (Recommended)

```bash
cd ~/Recon-automation-Bug-bounty-stack
nano scripts/add_protection.py
```

**Find this line:**
```python
SYSTEM_OWNER = "YOUR_NAME_HERE"  # <-- CHANGE THIS LINE!
```

**Change it to:**
```python
SYSTEM_OWNER = "John Doe"  # Or whatever your name is
```

**Save and exit** (Ctrl+X, then Y, then Enter)

**Then run:**
```bash
python3 scripts/add_protection.py
```

---

## Option 2: Use Environment Variable (Faster)

```bash
cd ~/Recon-automation-Bug-bounty-stack
export SYSTEM_OWNER="Your Name Here"
python3 scripts/add_protection.py
```

---

## Option 3: One-Liner

```bash
cd ~/Recon-automation-Bug-bounty-stack && SYSTEM_OWNER="Your Name Here" python3 scripts/add_protection.py
```

---

## ✅ After Running

All copyrights will be in **YOUR NAME**!

Check a file to verify:
```bash
head -15 scripts/immediate_roi_hunter.py
```

You should see:
```
Copyright (c) 2025 Your Name Here
```

---

## 🎯 Quick Command

Replace `"Your Name Here"` with your actual name:

```bash
cd ~/Recon-automation-Bug-bounty-stack && SYSTEM_OWNER="Your Name Here" python3 scripts/add_protection.py
```

