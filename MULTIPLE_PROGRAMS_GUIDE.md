<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# 🎯 WORKING ON MULTIPLE BUG BOUNTY PROGRAMS
## Stop Getting Stuck in Rapyd-Only Mode

---

## 🔍 WHY EVERYTHING FEELS LIKE RAPYD

**You've been working almost exclusively on Rapyd:**

```
Your current state:
├── rapyd/     ← 107 items, 57 in findings/ (HEAVILY WORKED)
├── bolt/      ← 29 items (some work)
├── paypal/    ← 1 item (barely touched)
├── shopify/   ← 1 item (barely touched)
├── stripe/    ← 1 item (barely touched)
└── square/    ← 1 item (barely touched)
```

**Your alias:**
```bash
alias rapyd="cd ~/Recon-automation-Bug-bounty-stack/programs/rapyd/findings"
```

This **only** goes to Rapyd, so when you use it, you're always in Rapyd context.

---

## ✅ SOLUTION: SET UP MULTI-PROGRAM WORKFLOW

### **Option 1: Create Aliases for Each Program**

```bash
# Edit your ~/.bashrc
nano ~/.bashrc

# Add these lines at the end:

# Bug Bounty Program Aliases
alias bb="cd ~/Recon-automation-Bug-bounty-stack"
alias programs="cd ~/Recon-automation-Bug-bounty-stack/programs"

# Individual programs
alias rapyd="cd ~/Recon-automation-Bug-bounty-stack/programs/rapyd"
alias shopify="cd ~/Recon-automation-Bug-bounty-stack/programs/shopify"
alias paypal="cd ~/Recon-automation-Bug-bounty-stack/programs/paypal"
alias stripe="cd ~/Recon-automation-Bug-bounty-stack/programs/stripe"
alias square="cd ~/Recon-automation-Bug-bounty-stack/programs/square"
alias bolt="cd ~/Recon-automation-Bug-bounty-stack/programs/bolt"

# Findings directories (if you want quick access to findings)
alias rapyd-findings="cd ~/Recon-automation-Bug-bounty-stack/programs/rapyd/findings"
alias shopify-findings="cd ~/Recon-automation-Bug-bounty-stack/programs/shopify/findings"
alias paypal-findings="cd ~/Recon-automation-Bug-bounty-stack/programs/paypal/findings"

# Save and reload
source ~/.bashrc
```

**Usage:**
```bash
shopify           # Goes to Shopify program
paypal            # Goes to PayPal program
rapyd-findings    # Goes to Rapyd findings
bb                # Goes to repo root
programs          # Lists all programs
```

---

### **Option 2: Use the Program Selector Script**

**Make it executable (in WSL terminal):**
```bash
cd ~/Recon-automation-Bug-bounty-stack
chmod +x select_program.sh
```

**Usage:**
```bash
# From anywhere:
~/Recon-automation-Bug-bounty-stack/select_program.sh

# Or create alias:
alias choose="~/Recon-automation-Bug-bounty-stack/select_program.sh"

# Then just type:
choose
```

**You'll see:**
```
🎯 BUG BOUNTY PROGRAM SELECTOR
Available programs:
  1. rapyd
  2. shopify
  3. paypal
  4. stripe
  5. square
  6. bolt
  0. Cancel

Select program (1-6):
```

---

### **Option 3: Function-Based Switcher**

```bash
# Add to ~/.bashrc

bbselect() {
    case $1 in
        rapyd|r)
            cd ~/Recon-automation-Bug-bounty-stack/programs/rapyd
            ;;
        shopify|s)
            cd ~/Recon-automation-Bug-bounty-stack/programs/shopify
            ;;
        paypal|p)
            cd ~/Recon-automation-Bug-bounty-stack/programs/paypal
            ;;
        stripe|st)
            cd ~/Recon-automation-Bug-bounty-stack/programs/stripe
            ;;
        square|sq)
            cd ~/Recon-automation-Bug-bounty-stack/programs/square
            ;;
        bolt|b)
            cd ~/Recon-automation-Bug-bounty-stack/programs/bolt
            ;;
        *)
            echo "Usage: bbselect [rapyd|shopify|paypal|stripe|square|bolt]"
            echo "Shortcuts: r, s, p, st, sq, b"
            ;;
    esac
    pwd
    ls
}

# Reload
source ~/.bashrc
```

**Usage:**
```bash
bbselect shopify    # Go to Shopify
bbselect s          # Shortcut for Shopify
bbselect paypal     # Go to PayPal
bbselect r          # Go to Rapyd
```

---

## 🚀 HOW TO START WORKING ON NEW PROGRAMS

### **When Starting a New Program:**

```bash
# 1. Go to programs directory
cd ~/Recon-automation-Bug-bounty-stack/programs

# 2. Choose a program (e.g., Shopify)
cd shopify

# 3. Create necessary directories
mkdir -p findings
mkdir -p recon
mkdir -p exploits
mkdir -p reports

# 4. Copy template files from Rapyd (optional)
cp ../rapyd/TESTING_CHECKLIST.md ./
cp ../rapyd/BUG_SUBMISSION_TEMPLATE.md ./

# 5. Create program-specific config
cat > config.yaml << 'EOF'
program: shopify
platform: hackerone
scope:
  - "*.shopify.com"
  - "*.myshopify.com"
out_of_scope:
  - "*.shopifyapps.com"
EOF

# 6. Start testing
```

---

## 📋 RECOMMENDED WORKFLOW

### **1. Morning Routine - Choose Your Target**

```bash
# Option A: Use alias
shopify           # Today I'm testing Shopify

# Option B: Use selector
choose            # Interactive menu

# Option C: Use function
bbselect shopify  # Quick switch
```

### **2. Do Your Research**

```bash
# You're now in the program directory
pwd
# Output: ~/Recon-automation-Bug-bounty-stack/programs/shopify

# Run recon
subfinder -d shopify.com > recon/subdomains.txt
httpx -l recon/subdomains.txt -o recon/live_hosts.txt

# Test endpoints
nuclei -l recon/live_hosts.txt -o findings/nuclei_results.txt
```

### **3. Document Findings**

```bash
# Create finding document
cd findings
nano FINDING_001_SQL_INJECTION.md
```

### **4. Switch Programs**

```bash
# Done with Shopify for today, switch to PayPal
bbselect paypal

# Or
paypal
```

---

## 🎯 YOUR RAPYD SITUATION IS ACTUALLY GOOD

**You've done extensive work on Rapyd:**
- 57 files in findings/
- IDOR testing scripts
- Evidence capture automation
- Bug reports
- Testing documentation

**This is EXACTLY how you should work on a program!**

**Now replicate this depth for other programs:**
1. Pick a new program (Shopify, PayPal, etc.)
2. Do thorough reconnaissance
3. Test systematically
4. Document everything
5. Build custom tooling (like you did for Rapyd)

---

## 💡 RECOMMENDED NEXT STEPS

### **This Week:**

**Day 1-2: Set Up Shopify**
```bash
cd ~/Recon-automation-Bug-bounty-stack/programs/shopify
mkdir -p findings recon exploits reports
cp ../rapyd/TESTING_CHECKLIST.md ./
# Start testing Shopify
```

**Day 3-4: Set Up PayPal**
```bash
cd ~/Recon-automation-Bug-bounty-stack/programs/paypal
mkdir -p findings recon exploits reports
# Start testing PayPal
```

**Day 5-7: Rotate Between Programs**
```bash
# Morning: Shopify testing
shopify
# Find 1-2 bugs

# Afternoon: PayPal testing
paypal
# Find 1-2 bugs

# Evening: Rapyd (you know it well)
rapyd
# Clean up existing findings
```

---

## 📊 TRACK YOUR PROGRESS

Create a tracking file:

```bash
# In repo root
cat > PROGRAMS_STATUS.md << 'EOF'
# Bug Bounty Programs Status

## Active Programs

### Rapyd ⭐⭐⭐⭐⭐ (Primary)
- Findings: 57 documented
- Focus: IDOR vulnerabilities
- Status: Actively testing
- Next: Submit current findings

### Shopify ⭐ (Starting)
- Findings: 0
- Focus: E-commerce logic flaws
- Status: Setting up
- Next: Initial reconnaissance

### PayPal ⭐ (Starting)
- Findings: 0
- Focus: Payment logic
- Status: Setting up
- Next: Initial reconnaissance

### Stripe (Not Started)
### Square (Not Started)
### Bolt ⭐⭐ (Some work)

## This Week's Goals
- [ ] Submit 1 Rapyd finding
- [ ] Find 1 Shopify bug
- [ ] Find 1 PayPal bug
- [ ] Set up Stripe environment

## This Month's Goals
- [ ] 5 Rapyd findings submitted
- [ ] 3 Shopify findings
- [ ] 3 PayPal findings
- [ ] 2 Stripe findings
EOF
```

**Update it weekly:**
```bash
nano PROGRAMS_STATUS.md
```

---

## ✅ SUMMARY

**Why everything feels like Rapyd:**
- You've been working almost exclusively on Rapyd (good depth!)
- Your alias only goes to Rapyd
- Other programs aren't set up yet

**Solutions:**
1. ✅ Create aliases for all programs
2. ✅ Use program selector script
3. ✅ Set up other programs properly
4. ✅ Rotate between programs daily/weekly

**Next actions:**
```bash
# 1. Set up aliases (5 minutes)
nano ~/.bashrc
# Add program aliases
source ~/.bashrc

# 2. Choose a new program (today)
shopify

# 3. Set it up like Rapyd
mkdir -p findings recon exploits reports

# 4. Start testing
# Find bugs in multiple programs, not just Rapyd
```

**Your Rapyd work is excellent. Now replicate that thoroughness across multiple programs to maximize your bug bounty earnings!** 🎯💰

---

**TIP:** The best bug bounty hunters work on 3-5 programs simultaneously, rotating based on:
- New assets added to programs
- Program updates
- Your energy/focus
- What's working (where you're finding bugs)

Don't put all your eggs in one basket (even if it's a good basket like Rapyd).
