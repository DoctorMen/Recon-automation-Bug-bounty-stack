<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# 🔧 Generate PDFs - Fixed Installation

**Fix for WeasyPrint Installation Issue**

---

## ✅ SOLUTION 1: Install with --break-system-packages

**Run this:**

```bash
cd ~/Recon-automation-Bug-bounty-stack

# Install weasyprint with system packages flag
pip3 install weasyprint --break-system-packages

# Then generate PDFs
python3 scripts/convert_to_pdf.py
```

---

## ✅ SOLUTION 2: Use System Package Manager

**Run this:**

```bash
cd ~/Recon-automation-Bug-bounty-stack

# Install via apt (system package)
sudo apt-get update
sudo apt-get install -y python3-weasyprint

# Then generate PDFs
python3 scripts/convert_to_pdf.py
```

---

## ✅ SOLUTION 3: Generate HTML First (Easiest)

**If PDF conversion fails, use HTML files:**

The script will create HTML files that you can convert to PDF in your browser.

**After running script:**

1. Open HTML files in browser
2. File → Print → Save as PDF
3. Save as `upwork_sample1.pdf`, etc.

---

## 🚀 QUICK FIX COMMANDS

**Try This First:**

```bash
cd ~/Recon-automation-Bug-bounty-stack

# Install weasyprint
pip3 install weasyprint --break-system-packages

# Generate PDFs
python3 scripts/convert_to_pdf.py

# Copy to Windows
cp output/portfolio_samples/*.pdf /mnt/c/Users/'Doc Lab'/Downloads/
```

---

## 🔍 IF STILL FAILS

**Generate HTML Files:**

The script will automatically create HTML files if PDF conversion fails. Then:

1. Open HTML files in browser
2. Print → Save as PDF
3. Upload to Upwork

---

**Try Solution 1 first - it should work! 🚀**

