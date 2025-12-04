# HTML File Handling - Quick Reference

## Pattern Recognition

**When user creates/edits HTML file:**
1. ✅ Check if it's standalone (embedded CSS/JS)
2. ✅ Fix CSS compatibility warnings (`background-clip` alongside `-webkit-background-clip`)
3. ✅ Create helper scripts for opening
4. ✅ Document how to open (no server needed if standalone)

## Common Issues & Instant Fixes

### Issue: "Can't connect to server at filename.html"
**Root Cause**: User trying `http://filename.html` instead of opening file directly
**Instant Fix**: 
- Windows: Double-click file or `start filename.html`
- WSL: `powershell.exe -NoProfile -Command "Start-Process '\\wsl$\\Ubuntu\\home\\ubuntu\\Recon-automation-Bug-bounty-stack\\filename.html'"`
- Linux: `xdg-open filename.html`

### Issue: CSS warnings about webkit prefixes
**Instant Fix**: Add standard property alongside webkit:
```css
-webkit-background-clip: text;
background-clip: text;  /* Add this */
```

### Issue: File location confusion
**Instant Fix**: Always check `pwd` and provide full path options

## Standard Workflow (30 seconds)

1. **Create/fix HTML** → Ensure standalone (embedded styles)
2. **Fix linting** → Add standard CSS properties
3. **Create opener script** → `scripts/open_[name].sh` and `open_[name].bat`
4. **Document** → Add to README or create `[NAME]_README.md`
5. **Test** → Verify it opens correctly

## Templates

### Helper Script (Linux/WSL)
```bash
#!/bin/bash
FILE="filename.html"
FULL_PATH="$(pwd)/$FILE"
if command -v powershell.exe &> /dev/null; then
    powershell.exe -NoProfile -Command "Start-Process '\\\\wsl$\\Ubuntu\\home\\ubuntu\\Recon-automation-Bug-bounty-stack\\$FILE'"
else
    xdg-open "$FILE" || firefox "$FILE"
fi
```

### Helper Script (Windows)
```batch
@echo off
cd /d %~dp0\..
start filename.html
pause
```

### Documentation Template
```markdown
# Filename.html - Quick Start

## Open Directly (No Server Needed!)
- Windows: Double-click `filename.html`
- WSL: `powershell.exe -NoProfile -Command "Start-Process '\\wsl$\\Ubuntu\\home\\ubuntu\\Recon-automation-Bug-bounty-stack\\filename.html'"`
- Linux: `xdg-open filename.html`

✅ Standalone - all CSS/JS embedded
✅ Works offline
✅ No dependencies
```

## Key Commands Cheat Sheet

```bash
# Check if file exists
ls -la filename.html

# Get full path
realpath filename.html  # Linux
pwd  # Current directory

# Open from WSL to Windows
powershell.exe -NoProfile -Command "Start-Process '\\wsl$\\Ubuntu\\home\\ubuntu\\Recon-automation-Bug-bounty-stack\\filename.html'"

# Start local server (if needed)
python3 -m http.server 8000
# Then: http://localhost:8000/filename.html

# Check linting
read_lints paths: ['filename.html']
```

## Remember

- ✅ Standalone HTML = no server needed
- ✅ Always create opener scripts
- ✅ Document immediately
- ✅ Fix CSS compatibility warnings
- ✅ Provide multiple access methods (Windows/WSL/Linux)
- ✅ Check existing patterns in codebase first

