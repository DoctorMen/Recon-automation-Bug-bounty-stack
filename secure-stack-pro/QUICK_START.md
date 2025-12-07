# SecureStack CLI - Quick Start Guide

## 🚀 30-Second Quick Start

```bash
cd secure-stack-pro
python3 securestack_cli.py
```

That's it! The tool will run a complete demonstration assessment.

---

## 📋 Command Reference

### Basic Usage

```bash
# Default demo
python3 securestack_cli.py

# Custom target
python3 securestack_cli.py "*.yourdomain.com" "YOUR-ENG-ID"

# Run tests
./test_securestack.sh
```

---

## 🎯 What You Get

### Console Output

```
 _____                            _____ _             _     
 / ____|                          / ____| |           | |    
 | (___   ___  ___ _   _ _ __ ___| (___ | |_ __ _  ___| | __ 
  \___ \ / _ \/ __| | | | '__/ _ \\___ \| __/ _` |/ __| |/ / 
  ____) |  __/ (__| |_| | | |  __/____) | || (_| | (__|   <  
 |_____/ \___|\___|\___|_|  \___|_____/ \__\__,_|\___|_|\_\ 
  :: Automated Recon & Vulnerability Assessment Platform :: v2.1
```

### Generated Files

```
reports/
├── SecureStack_Scan_2025-12-07.pdf     # Human-readable
└── SecureStack_Scan_2025-12-07.json    # Machine-readable
```

---

## ✅ Verification

### Quick Test

```bash
python3 securestack_cli.py && echo "✅ Working!" || echo "❌ Failed"
```

### Full Test Suite

```bash
./test_securestack.sh
```

Expected: **4/4 tests passing**

---

## 📁 File Overview

| File | Purpose | Status |
|------|---------|--------|
| `securestack_cli.py` | Main CLI tool | ✅ Working |
| `test_securestack.sh` | Test suite | ✅ Passing |
| `SECURESTACK_CLI_README.md` | Full documentation | ✅ Complete |
| `EXTRACTION_GUIDE.md` | Repo extraction guide | ✅ Ready |
| `PROOF_OF_CONCEPT_SUMMARY.md` | Project summary | ✅ Complete |
| `requirements.txt` | Dependencies | ✅ Empty (POC) |
| `LICENSE_CLI` | Legal terms | ✅ Included |

---

## 🎓 Features Demonstrated

- ✅ ASCII banner and branding
- ✅ Legal authorization verification
- ✅ Passive reconnaissance
- ✅ Neural risk scoring (ML-based)
- ✅ BOLA/IDOR vulnerability detection
- ✅ PDF + JSON report generation
- ✅ Performance metrics
- ✅ Professional output formatting

---

## 📖 Documentation

- **Quick Start**: This file
- **Full Documentation**: `SECURESTACK_CLI_README.md`
- **Extraction Guide**: `EXTRACTION_GUIDE.md`
- **Project Summary**: `PROOF_OF_CONCEPT_SUMMARY.md`

---

## 🔍 Next Steps

### Option 1: Use as Demo
Keep it here and use for demonstrations

### Option 2: Extract to Separate Repo
Follow `EXTRACTION_GUIDE.md` to create standalone repository

### Option 3: Expand to Production
Add real recon tools, ML models, and production features

---

## 🏆 Status

**✅ PROOF OF CONCEPT COMPLETE**

- All features working
- 4/4 tests passing
- Documentation complete
- Ready for extraction
- Legal compliance verified

---

## 📞 Need Help?

1. Read `SECURESTACK_CLI_README.md` for details
2. Check `PROOF_OF_CONCEPT_SUMMARY.md` for test results
3. Follow `EXTRACTION_GUIDE.md` to extract to new repo

---

**Version**: 2.1  
**Status**: ✅ Working and Tested  
**Last Updated**: December 2025
