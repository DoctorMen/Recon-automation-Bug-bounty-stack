<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# 🔄 DUAL BACKUP SYSTEM - Quick Reference

## ⚡ 3 Essential Commands

### 1. Backup This Repository
```bash
python3 scripts/dual_backup_system.py backup
```
**Creates TWO independent backups in separate locations**

---

### 2. Backup ALL Repositories
```bash
python3 scripts/backup_all_repos.py
```
**Backs up EVERY repository you have**

---

### 3. List Backups
```bash
python3 scripts/dual_backup_system.py list
```
**Shows all existing backups**

---

## 📍 Backup Locations

**Primary Path:**
```
../BACKUP_PRIMARY/Recon-automation-Bug-bounty-stack_[timestamp]/
```

**Secondary Path:**
```
../BACKUP_SECONDARY/Recon-automation-Bug-bounty-stack_[timestamp]/
```

**Both are COMPLETE, INDEPENDENT copies**

---

## 🔄 Quick Restore

### Restore Everything
```bash
cp -r /home/ubuntu/BACKUP_PRIMARY/[latest]/* \
      /home/ubuntu/Recon-automation-Bug-bounty-stack/
```

### Restore One File
```bash
cp /home/ubuntu/BACKUP_PRIMARY/[latest]/path/to/file \
   /home/ubuntu/Recon-automation-Bug-bounty-stack/path/to/file
```

### Restore from Secondary (if primary fails)
```bash
cp -r /home/ubuntu/BACKUP_SECONDARY/[latest]/* \
      /home/ubuntu/Recon-automation-Bug-bounty-stack/
```

---

## 🎯 When to Backup

✅ **Daily** (critical work)
✅ **Before major changes**
✅ **After completing important features**
✅ **Before system updates**
✅ **Weekly** (normal work)

---

## 🔍 Verify Backups

```bash
python3 scripts/dual_backup_system.py verify
```
**Checks all backups are intact (do monthly)**

---

## 📊 What Gets Backed Up

✅ All code files
✅ Documentation
✅ Configuration
✅ Monetization projects
✅ Everything important

**Excluded (auto):**
- `.git` internals
- `__pycache__`
- `node_modules`
- `.venv`
- `*.log`
- Previous backups

---

## 💡 Quick Tips

**Multiple versions:**
Each backup is timestamped, never overwritten

**Two paths:**
If one backup fails/corrupts, you have the other

**Fast:**
Typical backup: 2-5 seconds for most repos

**Safe:**
Integrity hashing detects any corruption

**Easy:**
Just copy files to restore

---

## 🚨 Emergency Restore

```bash
# 1. Verify backup
python3 scripts/dual_backup_system.py verify

# 2. List available backups
python3 scripts/dual_backup_system.py list

# 3. Restore (replace [latest] with actual backup name)
cp -r /home/ubuntu/BACKUP_PRIMARY/[latest]/* \
      /home/ubuntu/Recon-automation-Bug-bounty-stack/
```

---

## 🔥 Disaster Scenarios

### Hard Drive Failure
✅ Copy from external drive/cloud (offsite backup)

### Accidental Deletion
✅ Restore from either primary or secondary backup

### Ransomware
✅ Disconnect backups immediately, restore from clean backup

### Corruption
✅ Verify backup integrity, restore from latest good backup

---

## 🎯 Best Practice Workflow

```bash
# Morning: Check backups exist
python3 scripts/dual_backup_system.py list

# End of day: Create backup
python3 scripts/dual_backup_system.py backup

# Monthly: Verify integrity
python3 scripts/dual_backup_system.py verify

# Quarterly: Test restoration
cp -r [backup] /tmp/test && cd /tmp/test && [run tests]
```

---

## 💾 Offsite Backup (Recommended)

```bash
# Copy to external drive
cp -r /home/ubuntu/BACKUP_SECONDARY /media/external/

# Or compress and upload to cloud
tar -czf backup.tar.gz /home/ubuntu/BACKUP_SECONDARY
# Upload to Google Drive, Dropbox, etc.
```

---

## 📈 Storage Estimate

**Typical repository:** 50 MB
**With dual backup:** 100 MB (2 copies)
**30 days of backups:** 3 GB (30 × 2 × 50 MB)

**Reasonable for most systems**

---

## 🔐 Backup vs Vault

### Dual Backup (This System)
✅ Protection against data LOSS
✅ Two independent copies
✅ Easy restoration
❌ Not encrypted

### Secure Vault (Other System)
✅ Protection against THEFT
✅ Encrypted files
✅ Password protected
❌ Not for disaster recovery

**USE BOTH for complete protection** 🛡️

---

## ⚡ One-Liner Cheat Sheet

```bash
# Backup everything NOW
python3 scripts/backup_all_repos.py --yes

# List all backups
python3 scripts/dual_backup_system.py list

# Verify all backups
python3 scripts/dual_backup_system.py verify

# Quick restore
cp -r /home/ubuntu/BACKUP_PRIMARY/[latest]/* ./
```

---

## 📞 Documentation

**Full Guide:** `DUAL_BACKUP_GUIDE.md` (20+ pages)
**This Card:** `BACKUP_QUICK_REFERENCE.md` (you are here)

---

## 🎉 Remember

**3-2-1 Rule:**
- **3** copies of data (original + 2 backups)
- **2** different locations (primary + secondary)
- **1** offsite (external/cloud)

**You now have this implemented!** ✅

---

**Start backing up:**
```bash
python3 scripts/backup_all_repos.py
```

**Your data is precious. Protect it.** 💎
