<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# 🎲 RANDOM PROGRAM SELECTOR - SETUP GUIDE
## Stop Getting Stuck on Rapyd - Work on Random Programs

---

## 🎯 WHAT THIS DOES

**Automatically picks a RANDOM bug bounty program for you to work on.**

**Features:**
- ✅ True randomness - picks any program
- ✅ Smart anti-repeat - won't pick same program twice in a row
- ✅ Tracks history - see what you worked on recently
- ✅ Auto-setup - creates necessary directories
- ✅ One command - instant random program selection

**No more Rapyd-only tunnel vision!**

---

## 🚀 QUICK SETUP (2 minutes)

### **Step 1: Make Scripts Executable**

```bash
cd ~/Recon-automation-Bug-bounty-stack

# Make both scripts executable
chmod +x random_program.sh
chmod +x smart_program_selector.sh
```

---

### **Step 2: Add Aliases to Your Shell**

```bash
# Edit your shell config
nano ~/.bashrc

# Add these lines at the end:

# ============================================
# BUG BOUNTY RANDOM PROGRAM SELECTOR
# ============================================

# Pick any random program (pure random)
alias random="~/Recon-automation-Bug-bounty-stack/random_program.sh"

# Pick random program (smart - no repeats)
alias hunt="~/Recon-automation-Bug-bounty-stack/smart_program_selector.sh"

# Still want manual control? Keep these too:
alias bb="cd ~/Recon-automation-Bug-bounty-stack"
alias rapyd="cd ~/Recon-automation-Bug-bounty-stack/programs/rapyd"
alias shopify="cd ~/Recon-automation-Bug-bounty-stack/programs/shopify"
alias paypal="cd ~/Recon-automation-Bug-bounty-stack/programs/paypal"
alias stripe="cd ~/Recon-automation-Bug-bounty-stack/programs/stripe"

# Save and exit (Ctrl+X, then Y, then Enter)

# Reload your shell config
source ~/.bashrc
```

---

## 🎮 USAGE

### **Method 1: Smart Random (Recommended)**

```bash
hunt
```

**Output:**
```
🎲 SMART PROGRAM SELECTOR
============================================

📋 All programs: rapyd shopify paypal stripe square bolt

❌ Excluded (last program): rapyd

🎯 TODAY'S PROGRAM: shopify
📁 Directory: /home/ubuntu/Recon-automation-Bug-bounty-stack/programs/shopify

✅ Ready to hunt bugs in: shopify
```

**Features:**
- Won't repeat last program
- Tracks history
- Auto-creates directories
- Shows recent work history

---

### **Method 2: Pure Random**

```bash
random
```

**Output:**
```
🎲 RANDOM PROGRAM SELECTOR
============================================

📋 Available programs: rapyd shopify paypal stripe square bolt

🎯 TODAY'S PROGRAM: paypal
📁 Directory: /home/ubuntu/Recon-automation-Bug-bounty-stack/programs/paypal

✅ Ready to hunt bugs in: paypal
```

**Features:**
- Completely random
- Could pick any program (including last one)
- Simple and fast

---

### **Method 3: Manual Selection (When You Want Control)**

```bash
# Go directly to a specific program
shopify
paypal
rapyd
stripe
```

---

## 📊 EXAMPLE DAILY WORKFLOW

### **Every Morning:**

```bash
# Start your day with a random program
hunt

# Output (example):
# 🎯 TODAY'S PROGRAM: stripe
# ✅ Ready to hunt bugs in: stripe

# You're now in: ~/Recon-automation-Bug-bounty-stack/programs/stripe
pwd
# /home/ubuntu/Recon-automation-Bug-bounty-stack/programs/stripe

# Do your work
subfinder -d stripe.com > recon/subdomains.txt
httpx -l recon/subdomains.txt -o recon/live.txt
nuclei -l recon/live.txt -o findings/nuclei_$(date +%Y%m%d).txt

# Find bugs, document, submit
```

### **After Lunch:**

```bash
# Want to switch? Pick another random program
hunt

# Output (example):
# ❌ Excluded (last program): stripe
# 🎯 TODAY'S PROGRAM: shopify

# Now working on Shopify
```

### **End of Day:**

```bash
# Check what you worked on today
cat ~/.program_history | tail -5

# Output:
# stripe,2025-11-04-09:30:00
# shopify,2025-11-04-13:45:00
# paypal,2025-11-04-16:20:00
```

---

## 🎯 WEEKLY ROTATION EXAMPLE

**Week 1:**
```
Monday:    hunt → shopify
Tuesday:   hunt → paypal
Wednesday: hunt → stripe
Thursday:  hunt → square
Friday:    hunt → bolt
Weekend:   rapyd (manual - finish up work)
```

**Automatically forces you to diversify!**

---

## 🔥 ADVANCED: WEIGHTED RANDOMNESS

If you want certain programs to appear more often, edit the smart selector:

```bash
nano ~/Recon-automation-Bug-bounty-stack/smart_program_selector.sh

# Find this section:
# Pick a random program (excluding last one)
random_index=$((RANDOM % ${#available_programs[@]}))
selected="${available_programs[$random_index]}"

# Replace with weighted selection:
# Create weighted list (programs appear multiple times based on priority)
weighted_programs=()
for prog in "${available_programs[@]}"; do
    case $prog in
        shopify)
            # Add Shopify 3 times (3x more likely)
            weighted_programs+=("$prog" "$prog" "$prog")
            ;;
        paypal)
            # Add PayPal 2 times (2x more likely)
            weighted_programs+=("$prog" "$prog")
            ;;
        rapyd)
            # Add Rapyd 1 time (normal probability)
            weighted_programs+=("$prog")
            ;;
        *)
            # Others appear once (normal)
            weighted_programs+=("$prog")
            ;;
    esac
done

random_index=$((RANDOM % ${#weighted_programs[@]}))
selected="${weighted_programs[$random_index]}"
```

---

## 📈 BENEFITS OF RANDOM SELECTION

### **More Bugs:**
- More programs = more attack surface
- Different tech stacks = different vulnerabilities
- Less competition on smaller programs

### **Better Learning:**
- Exposure to different technologies
- Learn new vulnerability patterns
- Build diverse skillset

### **More Income:**
- Not dependent on one program
- Multiple revenue streams
- Less risk if one program closes

### **Less Burnout:**
- Variety keeps it interesting
- No tunnel vision on one program
- Fresh perspective daily

---

## 🎲 RANDOMNESS STATISTICS

**With 7 programs and smart selector:**

```
Probability each day:
- Program you worked on yesterday: 0% (excluded)
- Each other program: ~16.7% (1/6)

Over 7 days (using smart selector):
- You'll work on 7 different programs
- Perfect diversification!

Over 30 days:
- Each program: ~4-5 times
- Balanced coverage
- No Rapyd-only tunnel vision
```

---

## 🛠️ TROUBLESHOOTING

### **"Command not found: hunt"**

```bash
# Reload your shell config
source ~/.bashrc

# Or restart your terminal
```

### **"Permission denied"**

```bash
cd ~/Recon-automation-Bug-bounty-stack
chmod +x random_program.sh
chmod +x smart_program_selector.sh
```

### **"No programs found"**

```bash
# Check if programs directory exists
ls ~/Recon-automation-Bug-bounty-stack/programs/

# Should show: rapyd, shopify, paypal, stripe, etc.
```

### **Want to clear history and start fresh?**

```bash
rm ~/.program_history
```

---

## 📋 SUMMARY

**Two Scripts Created:**

1. **random_program.sh** - Pure random selection
   - Use with: `random`
   - Picks any program randomly
   
2. **smart_program_selector.sh** - Smart random selection
   - Use with: `hunt`
   - Excludes last program (forces variety)
   - Tracks history
   - **Recommended for daily use**

**Setup:**
```bash
# 1. Make executable
chmod +x random_program.sh smart_program_selector.sh

# 2. Add to ~/.bashrc
alias hunt="~/Recon-automation-Bug-bounty-stack/smart_program_selector.sh"
alias random="~/Recon-automation-Bug-bounty-stack/random_program.sh"

# 3. Reload
source ~/.bashrc

# 4. Use it
hunt
```

**Daily workflow:**
```bash
# Every morning:
hunt           # Pick random program
# Work on it
# Find bugs
# Document
# Submit

# Repeat tomorrow with a DIFFERENT program
```

---

**NO MORE RAPYD-ONLY MODE. AUTOMATIC PROGRAM DIVERSIFICATION. MORE BUGS. MORE MONEY.** 🎲🎯💰

---

## 🎯 NEXT STEPS

**Right now:**
```bash
cd ~/Recon-automation-Bug-bounty-stack
chmod +x random_program.sh smart_program_selector.sh
nano ~/.bashrc
# Add aliases
source ~/.bashrc
hunt
```

**Start finding bugs in random programs instead of just Rapyd!**
