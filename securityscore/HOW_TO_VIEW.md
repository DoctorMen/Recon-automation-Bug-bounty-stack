<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# SecurityScore - How to View

## Option 1: Open Directly in Browser (NO SERVER NEEDED!)

The `standalone.html` file works **without any server**! Just:

1. **Right-click** on `standalone.html` in your file explorer
2. **Select "Open with"** → Choose your browser (Chrome, Firefox, Edge)
3. **Done!** It will work immediately

Or drag and drop the file into your browser window.

## Option 2: Use Local Server

If you want to use a server, run:

```bash
cd securityscore
python3 -m http.server 8000
```

Then open: `http://localhost:8000/standalone.html`

## Option 3: Quick Test

**Windows:**
- Double-click `standalone.html`
- Or right-click → Open with → Browser

**Linux/WSL:**
```bash
cd securityscore
xdg-open standalone.html
# or
firefox standalone.html
# or
google-chrome standalone.html
```

## Why It Works Standalone

The HTML file is completely self-contained:
- ✅ All CSS is embedded
- ✅ All JavaScript is embedded
- ✅ No external dependencies
- ✅ No backend required for demo

**Just open the file directly in your browser!**

