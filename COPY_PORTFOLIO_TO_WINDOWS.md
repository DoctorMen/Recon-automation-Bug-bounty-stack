<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# 📁 Copy Portfolio Files to Windows

**Your PDFs Are in WSL - Need to Access from Windows**

---

## 🎯 THE PROBLEM

**Files Location:** `/home/ubuntu/Recon-automation-Bug-bounty-stack/output/portfolio_samples/`  
**Trying to Upload From:** Windows Downloads folder  
**Issue:** Files are in WSL, not Windows Downloads

---

## ✅ SOLUTION OPTIONS

### **Option 1: Copy Files to Windows Downloads (Easiest)**

**From PowerShell:**

```powershell
# Copy all 3 PDFs to Windows Downloads
wsl bash -c "cp ~/Recon-automation-Bug-bounty-stack/output/portfolio_samples/*.pdf /mnt/c/Users/'Doc Lab'/Downloads/"
```

**Or copy individually:**

```powershell
# Copy Sample 1
wsl bash -c "cp ~/Recon-automation-Bug-bounty-stack/output/portfolio_samples/upwork_sample1.pdf /mnt/c/Users/'Doc Lab'/Downloads/"

# Copy Sample 2
wsl bash -c "cp ~/Recon-automation-Bug-bounty-stack/output/portfolio_samples/upwork_sample2.pdf /mnt/c/Users/'Doc Lab'/Downloads/"

# Copy Sample 3
wsl bash -c "cp ~/Recon-automation-Bug-bounty-stack/output/portfolio_samples/upwork_sample3.pdf /mnt/c/Users/'Doc Lab'/Downloads/"
```

**Then:** Upload from Downloads folder (they'll be there now)

---

### **Option 2: Access WSL Path Directly**

**In File Upload Dialog:**

1. In the address bar, type:
   ```
   \\wsl$\Ubuntu\home\ubuntu\Recon-automation-Bug-bounty-stack\output\portfolio_samples
   ```

2. Press Enter

3. You should see the 3 PDF files

4. Select `upwork_sample1.pdf` (or 2, or 3)

5. Click Open

---

### **Option 3: Use File Explorer First**

**Before Uploading:**

1. Open File Explorer
2. Type in address bar: `\\wsl$\Ubuntu\home\ubuntu\Recon-automation-Bug-bounty-stack\output\portfolio_samples`
3. Press Enter
4. You'll see the 3 PDF files
5. Copy them to Downloads (Ctrl+C, navigate to Downloads, Ctrl+V)
6. Then upload from Downloads

---

## 🚀 QUICKEST METHOD

**Run This in PowerShell:**

```powershell
wsl bash -c "cp ~/Recon-automation-Bug-bounty-stack/output/portfolio_samples/*.pdf /mnt/c/Users/'Doc Lab'/Downloads/"
```

**Then:**
- Go back to Upwork upload dialog
- Navigate to Downloads folder
- Files will be there!

---

## ✅ VERIFICATION

**After Copying:**

1. Open File Explorer
2. Go to Downloads folder
3. Look for:
   - `upwork_sample1.pdf`
   - `upwork_sample2.pdf`
   - `upwork_sample3.pdf`

**If you see them:** ✅ Ready to upload!

---

## 📋 STEP-BY-STEP

**1. Copy Files:**
```powershell
wsl bash -c "cp ~/Recon-automation-Bug-bounty-stack/output/portfolio_samples/*.pdf /mnt/c/Users/'Doc Lab'/Downloads/"
```

**2. Verify:**
- Open Downloads folder
- Confirm 3 PDFs are there

**3. Upload:**
- Go back to Upwork
- Click "Add content" → Document icon
- Navigate to Downloads
- Select PDF
- Upload

---

**Run the copy command above, then upload from Downloads! 🚀**

