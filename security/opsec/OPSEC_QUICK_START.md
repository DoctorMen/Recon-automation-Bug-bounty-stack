<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# OPSEC QUICK START GUIDE

```
Copyright © 2025 Security Research Operations
```

## 🚀 Get Protected in 5 Minutes

### Step 1: Verify Installation (30 seconds)

```bash
cd ~/Recon-automation-Bug-bounty-stack

# Check if scripts exist
ls -la scripts/opsec_*.sh

# You should see 7 OPSEC scripts
```

### Step 2: Run Security Check (1 minute)

```bash
# Run complete security audit
./scripts/opsec_check_all.sh
```

### Step 3: Initialize Secrets Manager (2 minutes)

```bash
# Initialize encrypted storage
./scripts/opsec_secrets_manager.sh init

# Add your first API key
./scripts/opsec_secrets_manager.sh add HACKERONE_API_KEY
```

### Step 4: Create First Backup (1 minute)

```bash
# Create encrypted backup
./scripts/opsec_backup.sh
```

### Step 5: Install Git Hooks (30 seconds)

```bash
# Install automatic protection
./scripts/opsec_install_hooks.sh
```

---

## 📋 Daily Workflow

### Before Scanning

```bash
# ALWAYS check VPN first!
./scripts/opsec_check_vpn.sh
```

### Before Committing

```bash
# Sanitize sensitive data
./scripts/opsec_sanitize_all.sh

# Then commit normally
git add .
git commit -m "Your message"
```

### Before Sharing

```bash
# Run sanitization
./scripts/opsec_sanitize_all.sh

# Then share safely
```

---

## 🆘 Emergency Commands

```bash
# Check everything NOW
./scripts/opsec_check_all.sh

# Backup immediately
./scripts/opsec_backup.sh

# Verify VPN
./scripts/opsec_check_vpn.sh

# Scan for leaks
./scripts/opsec_sanitize_all.sh
```

---

## 📚 Full Documentation

- **Complete Framework:** [OPSEC_FRAMEWORK.md](OPSEC_FRAMEWORK.md)
- **Deployment Details:** [OPSEC_DEPLOYMENT_COMPLETE.md](OPSEC_DEPLOYMENT_COMPLETE.md)
- **Legal Protection:** [COPYRIGHT_NOTICE.md](COPYRIGHT_NOTICE.md)

---

## ✅ Pre-Operation Checklist

Before ANY reconnaissance:

- [ ] VPN connected → `./scripts/opsec_check_vpn.sh`
- [ ] Authorization documented
- [ ] Scope verified
- [ ] Backup created (weekly)

---

## 🔒 What You're Protected Against

✅ Identity exposure  
✅ API key leaks  
✅ Email address disclosure  
✅ Private IP exposure  
✅ Credential compromise  
✅ Data loss (encrypted backups)  
✅ Git leaks (pre-commit hooks)  
✅ Legal liability (documentation)  

---

## 🎯 Key Features

- **20+ Threat Patterns Detected**
- **GPG Encrypted Secrets**
- **Automated Backups**
- **Git Hook Protection**
- **VPN Verification**
- **Legal Copyright Protection**

---

## 💡 Pro Tips

1. **Always** check VPN before scanning
2. **Never** commit without sanitization
3. **Rotate** API keys every 90 days
4. **Backup** weekly minimum
5. **Audit** security posture monthly

---

**Status:** 🟢 OPERATIONAL  
**Version:** 1.0.0  
**Last Updated:** November 3, 2025

---

**Copyright © 2025 Security Research Operations. All Rights Reserved.**

