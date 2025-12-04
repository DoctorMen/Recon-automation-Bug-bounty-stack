# 🚀 HTML File Handling - Auto-Training Pattern

## PROBLEM DETECTED
User creates HTML → tries `http://filename.html` → fails → needs instant fix

## INSTANT SOLUTION (30 seconds)

### 1. Fix CSS (5s)
```css
/* BEFORE */
-webkit-background-clip: text;

/* AFTER */
-webkit-background-clip: text;
background-clip: text;  /* Add standard */
```

### 2. Create Server Scripts (15s) - ALWAYS USE SERVER
**Linux/WSL:** `scripts/start_[name]_server.sh`
```bash
#!/bin/bash
cd "$(dirname "$0")/.."
python3 -m http.server 8000 &
sleep 2
echo "✅ Server: http://localhost:8000/[name].html"
wait
```

**Windows:** `start_[name]_server.bat`
```batch
@echo off
cd /d %~dp0\..
start http://localhost:8000/[name].html
python -m http.server 8000
```

### 3. Document (10s)
Create `[NAME]_README.md`:
- Server-based access instructions
- URL: http://localhost:8000/[name].html
- Never recommend direct file opening

## KEY COMMANDS
```bash
# Check linting
read_lints paths: ['filename.html']

# Open from WSL to Windows
powershell.exe -NoProfile -Command "Start-Process '\\wsl$\\Ubuntu\\home\\ubuntu\\Recon-automation-Bug-bounty-stack\\filename.html'"

# Linux open
xdg-open filename.html || firefox filename.html
```

## PATTERN MATCH
- ✅ Standalone HTML = no server needed
- ✅ Always create opener scripts
- ✅ Document immediately
- ✅ Fix CSS compatibility warnings
- ✅ Check existing patterns: `securityscore/HOW_TO_VIEW.md`

## MEMORY TRIGGERS
- "can't connect to server" → Standalone file, open directly
- "http://filename.html" → Wrong! Use file:// or direct open
- CSS warnings → Add standard property alongside webkit prefix

