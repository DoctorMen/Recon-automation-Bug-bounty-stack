<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# 📁 Generate Portfolio Samples - Windows Instructions

**How to Generate Portfolio Samples on Windows**

---

## 🪟 WINDOWS OPTIONS

### **Option 1: Use WSL (Recommended)**

**If you have WSL installed:**

```powershell
# Navigate to WSL Ubuntu directory
wsl

# Then run:
cd ~/Recon-automation-Bug-bounty-stack
./scripts/first_dollar_cli.sh portfolio
```

**Or run directly from PowerShell:**
```powershell
wsl bash -c "cd ~/Recon-automation-Bug-bounty-stack && ./scripts/first_dollar_cli.sh portfolio"
```

---

### **Option 2: Use Python Directly (Easier)**

**From PowerShell, navigate to your project:**

```powershell
# Navigate to project directory (adjust path if needed)
cd \\wsl$\Ubuntu\home\ubuntu\Recon-automation-Bug-bounty-stack

# Or if mapped to Windows:
# cd Z:\home\ubuntu\Recon-automation-Bug-bounty-stack

# Run Python script directly
python3 scripts/generate_portfolio_samples.py
```

---

### **Option 3: Manual Command (Step-by-Step)**

**Generate each sample individually:**

```powershell
# Navigate to project
cd \\wsl$\Ubuntu\home\ubuntu\Recon-automation-Bug-bounty-stack

# Generate Sample 1
python3 scripts/generate_report.py --format professional --client-name "Sample E-commerce" --output output/portfolio_samples/upwork_sample1.pdf --sample

# Generate Sample 2
python3 scripts/generate_report.py --format professional --client-name "Sample SaaS Platform" --output output/portfolio_samples/upwork_sample2.pdf --sample

# Generate Sample 3
python3 scripts/generate_report.py --format professional --client-name "Sample API" --output output/portfolio_samples/upwork_sample3.pdf --sample
```

---

## 🔍 TROUBLESHOOTING

### **If "python3" not found:**

**Try:**
```powershell
python scripts/generate_portfolio_samples.py
```

**Or:**
```powershell
py scripts/generate_portfolio_samples.py
```

---

### **If path doesn't work:**

**Find your actual project path:**
```powershell
# Check WSL paths
wsl ls ~/Recon-automation-Bug-bounty-stack
```

**Or use full path:**
```powershell
wsl python3 /home/ubuntu/Recon-automation-Bug-bounty-stack/scripts/generate_portfolio_samples.py
```

---

## ✅ QUICKEST METHOD

**Easiest way from Windows PowerShell:**

```powershell
wsl bash -c "cd ~/Recon-automation-Bug-bounty-stack && python3 scripts/generate_portfolio_samples.py"
```

**This will:**
1. Open WSL
2. Navigate to project
3. Run portfolio generator
4. Create 3 PDFs in `output/portfolio_samples/`

---

## 📁 WHERE TO FIND SAMPLES

**After generation, samples will be in:**
```
\\wsl$\Ubuntu\home\ubuntu\Recon-automation-Bug-bounty-stack\output\portfolio_samples\
```

**Files:**
- `upwork_sample1.pdf` (E-commerce)
- `upwork_sample2.pdf` (SaaS Platform)
- `upwork_sample3.pdf` (API)

---

## 🚀 NEXT STEPS

**After generating:**

1. **Locate PDFs** in `output/portfolio_samples/`
2. **Upload to Upwork:**
   - Go to Portfolio section
   - Click "Add a project"
   - Upload each PDF
   - Add description
   - Tag appropriately

---

**Try the WSL command above - it should work! 🎯**

