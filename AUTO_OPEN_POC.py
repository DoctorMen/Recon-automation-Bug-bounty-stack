#!/usr/bin/env python3
"""
AUTO OPEN POC - IMMEDIATE BROWSER TESTING
=========================================
Automatically open the GitLab clickjacking PoC in browser.

Purpose: Test the vulnerability immediately in your browser
Action: Auto-launch the most recent PoC file
Goal: Verify GitLab loads in iframe for screenshot evidence

Copyright (c) 2025 DoctorMen
"""

import os
import webbrowser
import glob
from datetime import datetime

def auto_open_latest_poc():
    """Find and open the latest GitLab PoC file"""
    
    print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║          AUTO OPEN POC - IMMEDIATE BROWSER TESTING                    ║
║          Launch Latest PoC | Verify Vulnerability | Take Screenshot   ║
╚══════════════════════════════════════════════════════════════════════╝

🎯 ACTION: Auto-opening latest GitLab PoC in browser
📊 EXPECTED: GitLab loads in iframe with alert message
💰 NEXT: Check scope and submit if working
    """)
    
    # Find the latest GitLab PoC file
    poc_files = glob.glob("gitlab_clickjacking_test_*.html")
    
    if not poc_files:
        # Try the original file
        original_poc = "clickjacking_poc_gitlab_com.html"
        if os.path.exists(original_poc):
            poc_files = [original_poc]
        else:
            print(f"❌ No PoC files found!")
            return False
    
    # Get the most recent file
    latest_poc = max(poc_files, key=os.path.getctime)
    
    print(f"📁 LATEST POC FILE: {latest_poc}")
    
    # Open in browser
    try:
        file_path = os.path.abspath(latest_poc)
        webbrowser.open(f"file://{file_path}")
        print(f"🌐 AUTO-OPENING: {latest_poc}")
        print(f"📱 Check your browser - the PoC should open automatically!")
        
        print(f"""
🎯 WHAT TO LOOK FOR:
   ✅ SUCCESS: GitLab visible in iframe with alert popup
   ✅ EVIDENCE: Take screenshot of working PoC
   ✅ NEXT STEP: Check GitLab HackerOne scope for clickjacking
   
❌ IF FAILED: 
   • Error message about X-Frame-Options
   • Blank iframe or blocked content
   • Need to pivot to different target
        """)
        
        return latest_poc
        
    except Exception as e:
        print(f"❌ Could not auto-open: {e}")
        print(f"🔍 Please open manually: {latest_poc}")
        return latest_poc

def main():
    """Execute auto-open PoC"""
    
    print("""
🎯 AUTO OPEN POC - IMMEDIATE BROWSER TESTING
=========================================

✅ PURPOSE: Test GitLab clickjacking in your browser now
✅ ACTION: Auto-launch latest PoC file
✅ GOAL: Verify vulnerability for screenshot evidence

Let's test this immediately!
    """)
    
    result = auto_open_latest_poc()
    
    if result:
        print(f"""
✅ POC LAUNCHED SUCCESSFULLY

File: {result}
Status: Check your browser now!

🎯 NEXT STEPS:
   1. Verify GitLab loads in iframe
   2. Take screenshot if working
   3. Check GitLab HackerOne scope
   4. Submit finding immediately

💰 POTENTIAL BOUNTY: $500-1,500 if valid!
        """)
    else:
        print(f"""
❌ FAILED TO LAUNCH POC

Check your files and try again.
        """)

if __name__ == "__main__":
    main()
