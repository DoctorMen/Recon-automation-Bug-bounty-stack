# Auto-Fix HTML Files - Quick Checklist

## When HTML file is created/edited:

### Step 1: Fix CSS (5 seconds)
- [ ] Check for `-webkit-` prefixes without standard properties
- [ ] Add standard property: `background-clip` alongside `-webkit-background-clip`

### Step 2: Create Server Scripts (10 seconds)
- [ ] Create `scripts/start_[name]_server.sh` for Linux/WSL
- [ ] Create `start_[name]_server.bat` for Windows
- [ ] Make shell script executable (if possible)

### Step 3: Document (5 seconds)
- [ ] Create `[NAME]_README.md` with SERVER instructions
- [ ] Always document: http://localhost:8000/[name].html
- [ ] NEVER recommend direct file opening

### Step 4: Verify (10 seconds)
- [ ] Check linting: `read_lints paths: ['filename.html']`
- [ ] Test server script works
- [ ] Document server URL

**Total: ~30 seconds**

## Important Rules
- ✅ ALWAYS use Python HTTP server (port 8000)
- ✅ NEVER recommend direct file opening
- ✅ Match pattern: securityscore/start.sh
- ✅ URL format: http://localhost:8000/[filename].html

