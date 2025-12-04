<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# 🤖 Automation Quick Start

**Complete automation for First Dollar Plan**

---

## ⚡ Quick Commands

### **1. View Dashboard**
```bash
./scripts/first_dollar_cli.sh dashboard
# OR
python3 scripts/automate_first_dollar.py --action dashboard
```

### **2. Generate Portfolio Samples**
```bash
./scripts/first_dollar_cli.sh portfolio
# OR
python3 scripts/generate_portfolio_samples.py
```

### **3. Generate Proposal**
```bash
./scripts/first_dollar_cli.sh proposal "Client Name" 300 "Job description"
```

### **4. Complete Workflow (Win → Scan → Deliver)**
```bash
./scripts/first_dollar_cli.sh workflow "Client Name" domain.com 300
```

---

## 🎯 Complete Workflow Example

### **Step 1: Setup (One Time)**
```bash
# Generate portfolio samples
./scripts/first_dollar_cli.sh portfolio

# Check status
./scripts/first_dollar_cli.sh dashboard
```

### **Step 2: Generate Proposals**
```bash
# Single proposal
./scripts/first_dollar_cli.sh proposal "Acme Corp" 300 "Urgent security scan needed"

# Proposals saved to: output/first_dollar_automation/proposals/
# Copy and paste into Upwork
```

### **Step 3: When You Win**
```bash
# Complete automated workflow
./scripts/first_dollar_cli.sh workflow "Acme Corp" acme.com 300

# This automatically:
# 1. Tracks project won
# 2. Runs security scan
# 3. Generates professional report
# 4. Tracks delivery
# 5. Provides delivery message
```

---

## 📊 All Commands

```bash
# Dashboard
./scripts/first_dollar_cli.sh dashboard

# Generate proposal
./scripts/first_dollar_cli.sh proposal "Client" 300 "Description"

# Track project won
./scripts/first_dollar_cli.sh won "Client" 300 "domain.com"

# Run scan
./scripts/first_dollar_cli.sh scan "Client" "domain.com"

# Mark delivered
./scripts/first_dollar_cli.sh deliver "Client"

# Complete workflow
./scripts/first_dollar_cli.sh workflow "Client" domain.com 300

# Generate portfolio
./scripts/first_dollar_cli.sh portfolio
```

---

## 📁 Files Created

- `scripts/automate_first_dollar.py` - Main automation script
- `scripts/first_dollar_cli.sh` - CLI wrapper
- `scripts/generate_portfolio_samples.py` - Portfolio generator
- `scripts/quick_client_workflow.py` - Complete workflow
- `output/first_dollar_automation/tracking.json` - All tracking data
- `output/first_dollar_automation/proposals/` - Generated proposals

---

**Everything is automated! Execute the plan efficiently. 🚀💰**

