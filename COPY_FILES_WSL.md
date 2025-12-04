<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# 📁 Copy Files from WSL to Windows - Correct Commands

**You're Already in WSL - Use Linux Commands Directly**

---

## ✅ CORRECT COMMAND

**Since you're already in WSL (Ubuntu), use:**

```bash
# Copy all PDFs to Windows Downloads
cp ~/Recon-automation-Bug-bounty-stack/output/portfolio_samples/*.pdf /mnt/c/Users/'Doc Lab'/Downloads/

# Verify files copied
ls -lh /mnt/c/Users/'Doc Lab'/Downloads/upwork_sample*.pdf
```

**Note:** No need for `wsl` command - you're already in WSL!

---

## 🔍 TROUBLESHOOTING

### **If Path Has Spaces:**

**Option 1: Use Quotes**
```bash
cp ~/Recon-automation-Bug-bounty-stack/output/portfolio_samples/*.pdf "/mnt/c/Users/Doc Lab/Downloads/"
```

**Option 2: Use Escaped Spaces**
```bash
cp ~/Recon-automation-Bug-bounty-stack/output/portfolio_samples/*.pdf /mnt/c/Users/'Doc Lab'/Downloads/
```

**Option 3: Use Tab Completion**
```bash
# Type: /mnt/c/Users/ then press TAB to auto-complete
cp ~/Recon-automation-Bug-bounty-stack/output/portfolio_samples/*.pdf /mnt/c/Users/[TAB]
```

---

## ✅ VERIFY FILES COPIED

**Check if files are in Windows Downloads:**

```bash
# List files
ls -lh /mnt/c/Users/'Doc Lab'/Downloads/upwork_sample*.pdf

# Should show:
# upwork_sample1.pdf
# upwork_sample2.pdf
# upwork_sample3.pdf
```

---

## 🚀 QUICK COMMANDS

**Copy Files:**
```bash
cp ~/Recon-automation-Bug-bounty-stack/output/portfolio_samples/*.pdf /mnt/c/Users/'Doc Lab'/Downloads/
```

**Verify:**
```bash
ls /mnt/c/Users/'Doc Lab'/Downloads/upwork_sample*.pdf
```

**Then:** Go to Windows File Explorer → Downloads → Files will be there!

---

**Run the copy command above (no wsl needed - you're already in WSL)! 🚀**

