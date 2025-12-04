<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# 🤖 First Dollar Plan Automation Guide

**Complete automation system for executing the quickest path to first dollar**

---

## 🚀 Quick Start

### **1. Check Dashboard**
```bash
./scripts/first_dollar_cli.sh dashboard
```

### **2. Generate Portfolio Samples**
```bash
./scripts/first_dollar_cli.sh portfolio
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

## 📋 Automation Features

### **1. Proposal Generation**
- Generate proposals from templates
- Save to file for easy copy-paste
- Track all applications

**Usage:**
```bash
# Single proposal
./scripts/first_dollar_cli.sh proposal "Acme Corp" 300 "Urgent security scan"

# Batch proposals (from JSON file)
./scripts/first_dollar_cli.sh batch jobs.json
```

**Jobs JSON Format:**
```json
[
  {
    "client_name": "Acme Corp",
    "job_description": "Need urgent security scan",
    "price": 300
  },
  {
    "client_name": "Tech Startup",
    "job_description": "ASAP security assessment",
    "price": 400
  }
]
```

---

### **2. Project Tracking**
- Track won projects
- Monitor revenue
- Track delivery status

**Usage:**
```bash
# Track project won
./scripts/first_dollar_cli.sh won "Acme Corp" 300 "acme.com"

# Mark as delivered
./scripts/first_dollar_cli.sh deliver "Acme Corp"
```

---

### **3. Complete Workflow**
- Automated scan execution
- Report generation
- Delivery tracking

**Usage:**
```bash
./scripts/first_dollar_cli.sh workflow "Acme Corp" acme.com 300
```

This automatically:
1. Tracks project won
2. Runs security scan
3. Generates professional report
4. Tracks delivery
5. Provides delivery message template

---

### **4. Portfolio Generation**
- Generate 3 sample reports
- Ready for Upwork upload

**Usage:**
```bash
./scripts/first_dollar_cli.sh portfolio
```

---

## 📊 Dashboard

View all stats and progress:
```bash
./scripts/first_dollar_cli.sh dashboard
```

Shows:
- Profile setup status
- Applications sent
- Projects won
- Total revenue
- Recent applications
- Active projects

---

## 🔄 Complete Workflow Example

### **Step 1: Setup (One Time)**
```bash
# Generate portfolio samples
./scripts/first_dollar_cli.sh portfolio

# Check profile setup
./scripts/first_dollar_cli.sh check-profile
```

### **Step 2: Apply to Projects**
```bash
# Generate proposal for job
./scripts/first_dollar_cli.sh proposal "Client Name" 300 "Urgent security scan needed"

# Copy proposal from output/proposals/
# Paste into Upwork
```

### **Step 3: When You Win**
```bash
# Complete workflow (scan + report + track)
./scripts/first_dollar_cli.sh workflow "Client Name" domain.com 300

# Follow instructions to deliver
```

---

## 📁 File Structure

```
output/
└── first_dollar_automation/
    ├── tracking.json          # All tracking data
    ├── proposals/              # Generated proposals
    │   ├── 20241115_143022_Client_Name.txt
    │   └── ...
    └── dashboard.html         # Visual dashboard (coming soon)
```

---

## 🎯 Python API Usage

### **Direct Python Usage:**
```python
from scripts.automate_first_dollar import FirstDollarAutomation

automation = FirstDollarAutomation()

# Generate proposal
proposal = automation.generate_proposal("Client Name", "Job description", 300)
filepath = automation.save_proposal(proposal, "Client Name")

# Track project won
automation.track_project_won("Client Name", 300, "domain.com")

# Run scan
automation.run_scan("domain.com", "Client Name")

# Generate report
automation.generate_report("Client Name", "domain.com")

# Show dashboard
automation.show_dashboard()
```

---

## ✅ Integration with Existing System

All automation integrates with:
- `run_pipeline.py` - For scanning
- `scripts/generate_report.py` - For report generation
- Existing output structure

---

## 🚀 Quick Commands Reference

```bash
# Dashboard
./scripts/first_dollar_cli.sh dashboard

# Generate proposal
./scripts/first_dollar_cli.sh proposal "Client" 300 "Description"

# Track project won
./scripts/first_dollar_cli.sh won "Client" 300 "domain.com"

# Complete workflow
./scripts/first_dollar_cli.sh workflow "Client" domain.com 300

# Generate portfolio
./scripts/first_dollar_cli.sh portfolio
```

---

## 📊 Tracking Data

All data is stored in `output/first_dollar_automation/tracking.json`:

```json
{
  "profile_setup": true,
  "applications_sent": 15,
  "projects_won": 3,
  "revenue": 900,
  "applications": [...],
  "projects": [...]
}
```

---

**Automation ready! Execute the plan efficiently. 🚀💰**

