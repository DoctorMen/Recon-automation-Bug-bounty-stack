<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# 🚀 VIBE CODING - Quick Start Guide
### Get Started in 30 Seconds

---

## ⚡ INSTANT START

### 1. Run Vibe Command System
```bash
cd ~/Recon-automation-Bug-bounty-stack
python3 VIBE_COMMAND_SYSTEM.py
```

### 2. Try Your First Command
```
vibe> scan example.com quickly
```

### 3. See Results
```
vibe> what did you find?
```

**That's it!** You're now vibe coding. 🎵

---

## 💬 COMMON COMMANDS (Just Type These)

### Scanning
```
scan all targets
scan example.com
scan example.com quickly
scan example.com aggressively
find vulnerabilities in example.com
recon example.com
```

### Target Management
```
add target example.com
show targets
what targets do I have
```

### Results
```
show results
what did you find
generate report
```

### Control
```
run pipeline
stop everything
what's happening
status
```

### Help
```
help
what can you do
```

---

## 🎯 EXAMPLE SESSION

```bash
$ python3 VIBE_COMMAND_SYSTEM.py

vibe> add target example.com
➕ Vibe Command: Adding target 'example.com'
✅ Added 'example.com' to targets.txt

vibe> scan it quickly
⚡ Vibe Command: Quick scan of 'example.com'
🚀 Running fast recon (subdomain enumeration + httpx)
✅ Quick scan started

vibe> what's happening?
⏳ Status: Scans are currently running

vibe> show results
📊 Recent findings:
  📄 subdomains_example.com.txt (15KB)
  📄 http_results.txt (45KB)

vibe> exit
👋 Goodbye!
```

---

## 🔥 ONE-LINER MODE

Run commands without entering interactive mode:

```bash
# Quick scan
python3 VIBE_COMMAND_SYSTEM.py "scan example.com quickly"

# Check status
python3 VIBE_COMMAND_SYSTEM.py "what's happening"

# Show results
python3 VIBE_COMMAND_SYSTEM.py "show results"
```

---

## 💡 PRO TIPS

### Tip 1: Make an Alias
```bash
# Add to ~/.bashrc or ~/.zshrc
alias vibe="python3 ~/Recon-automation-Bug-bounty-stack/VIBE_COMMAND_SYSTEM.py"

# Then use anywhere:
$ vibe "scan all"
```

### Tip 2: Natural Language
You don't need exact syntax. These all work:
- "scan example.com"
- "scan example.com quickly"
- "quick scan example.com"
- "run a quick scan on example.com"

### Tip 3: Get Help Anytime
```
vibe> help
# Shows all available commands
```

---

## 🎮 WHAT YOU CAN SAY

The vibe system understands natural language. Just describe what you want:

✅ "scan all targets"  
✅ "find vulnerabilities in example.com"  
✅ "run a quick recon on target.com"  
✅ "show me what you found"  
✅ "what's happening right now"  
✅ "add target example.com"  
✅ "generate a report"  
✅ "stop everything"  

**If it doesn't understand, it will suggest alternatives!**

---

## 🚀 NEXT STEPS

1. ✅ **Try it now** - Run your first vibe command
2. 📖 **Read the full guide** - See `VIBE_CODING_EXPLAINED.md`
3. 🎯 **Customize it** - Add your own command patterns
4. 💰 **Find more bugs** - Spend less time on commands, more on hunting

---

**Welcome to vibe coding!** 🎵  
*Where your tools speak your language.*

**Copyright © 2025 DoctorMen. All Rights Reserved.**
