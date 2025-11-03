# License Protection System

## Overview
This bug bounty automation system is protected by a license key system to prevent unauthorized use and copying.

## How It Works

### 1. License File (`.license`)
- Contains a secure 256-bit cryptographic key
- Protected with `chmod 600` (only owner can read)
- **Never committed to Git** (listed in `.gitignore`)
- Required for all main scripts to run

### 2. License Check Module (`license_check.py`)
- Validates the license key on startup
- Uses SHA256 hash comparison for security
- Exits immediately if license is invalid or missing
- Integrated into all critical scripts

### 3. Protected Scripts
The following scripts now require a valid license:
- `run_pipeline.py` - Main orchestrator
- `run_recon.py` - Reconnaissance agent
- `run_httpx.py` - Web mapper agent
- `run_nuclei.py` - Vulnerability hunter
- `scripts/immediate_roi_hunter.py` - ROI hunter

## Setup (System Owner Only)

### Your License Key
```
Key: da0c6d0fa4e4078e01e7d31c3e940f3435fa13c91c2c92fe52043996da2251cd
Hash: d49d9bf65891bfc7cc1be5b077b6c3a02f101c96fc1a8768ce70701fb2af13fc
```

**⚠️ KEEP THIS KEY SECRET! ⚠️**

### Verify License
```bash
cd ~/Recon-automation-Bug-bounty-stack
python3 license_check.py test
```

Expected output:
```
✅ License valid!
System ID: BB_RECON_2025_DOCTORMEN
```

## Security Features

1. **Cryptographic Protection**: Uses SHA256 hashing
2. **File Permissions**: `.license` is read-only for owner only (600)
3. **Git Exclusion**: License never leaves your machine
4. **Runtime Validation**: Checked every time scripts run
5. **Graceful Degradation**: Clear error messages if license missing

## For Licensing/Distribution

If you want to license this system to others:

1. **Generate new license key**:
   ```bash
   python3 license_check.py generate
   ```

2. **Give them**:
   - The codebase (without `.license` file)
   - A unique license key (generated above)
   
3. **They must**:
   - Create their own `.license` file with their key
   - Update `VALID_LICENSE_HASH` in `license_check.py` with their hash

## Troubleshooting

### "LICENSE FILE NOT FOUND"
```bash
# Restore your license
cd ~/Recon-automation-Bug-bounty-stack
echo 'da0c6d0fa4e4078e01e7d31c3e940f3435fa13c91c2c92fe52043996da2251cd' > .license
chmod 600 .license
```

### "INVALID LICENSE KEY"
Your `.license` file content doesn't match the expected hash. Verify:
```bash
python3 license_check.py hash $(cat .license)
```

Should output: `d49d9bf65891bfc7cc1be5b077b6c3a02f101c96fc1a8768ce70701fb2af13fc`

## Protection Level

This is **basic deterrent protection**, not military-grade encryption. It:
- ✅ Stops casual copying (friends, colleagues)
- ✅ Shows you're serious about IP protection
- ✅ Enables basic licensing model
- ❌ Won't stop determined hackers
- ❌ Not patent or copyright protection

For stronger protection, consider:
- Code obfuscation (PyArmor)
- SaaS model (hosted platform)
- Legal copyright/patent
- Compiled binaries

## System Information

- **System ID**: BB_RECON_2025_DOCTORMEN
- **Owner**: DoctorMen
- **Protection Date**: 2025-11-02
- **License Type**: Proprietary (see `LICENSE_PROPRIETARY.txt`)

---

**Remember**: This system represents significant work and value. Protect it accordingly.

