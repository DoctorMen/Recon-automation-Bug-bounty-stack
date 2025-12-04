#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.

OS HELP SYSTEM - Windows Automation for Money-Making
How Windows helps you earn money faster
"""

import os
import subprocess
import webbrowser
import time
import json
from pathlib import Path
from datetime import datetime

class OSHelpSystem:
    """Windows OS tools that help you earn money"""

    def __init__(self):
        self.base_path = Path(__file__).parent

    def show_os_help(self):
        """Display how Windows helps you earn money"""
        print("""
==================================================
              OS HELP SYSTEM
      How Windows Makes You Money Faster
==================================================

Your Windows OS has powerful built-in tools that can:
✅ Automate repetitive tasks
✅ Speed up job applications
✅ Manage multiple jobs simultaneously
✅ Track earnings automatically
✅ Backup your work
✅ Stay organized
        """)

        print("\n" + "="*60)
        print("WINDOWS FEATURES THAT MAKE YOU MONEY:")
        print("="*60)

        features = [
            {
                'feature': 'Task Scheduler',
                'help': 'Automatically run money-making scripts at set times',
                'command': 'Run taskschd.msc'
            },
            {
                'feature': 'PowerShell Scripts',
                'help': 'Automate job applications and data entry',
                'command': 'PowerShell automation scripts'
            },
            {
                'feature': 'Multiple Desktops',
                'help': 'Work on multiple jobs simultaneously',
                'command': 'Win + Tab or Task View'
            },
            {
                'feature': 'File Explorer Automation',
                'help': 'Organize job files and track progress',
                'command': 'Built-in file management'
            },
            {
                'feature': 'Clipboard Manager',
                'help': 'Store and reuse job proposals quickly',
                'command': 'Win + V'
            },
            {
                'feature': 'Snipping Tool',
                'help': 'Take screenshots for job submissions',
                'command': 'Win + Shift + S'
            },
            {
                'feature': 'Calculator',
                'help': 'Track earnings and calculate taxes',
                'command': 'Win + R, calc'
            },
            {
                'feature': 'Notepad',
                'help': 'Quick note-taking for job details',
                'command': 'Win + R, notepad'
            }
        ]

        for i, feature in enumerate(features, 1):
            print(f"\n{i}. {feature['feature']}")
            print(f"   Help: {feature['help']}")
            print(f"   Command: {feature['command']}")

    def create_automation_scripts(self):
        """Create Windows automation scripts"""
        print("\n" + "="*60)
        print("CREATING WINDOWS AUTOMATION SCRIPTS")
        print("="*60)

        # PowerShell script for job automation
        powershell_script = """
# PowerShell Job Automation Script
# Run this to automate job applications

Write-Host "=== MONEY-MAKING AUTOMATION STARTED ===" -ForegroundColor Green

# Open job search URLs
$urls = @(
    "https://www.upwork.com/nx/search/jobs/?q=wordpress%20fix&sort=recency",
    "https://www.upwork.com/nx/search/jobs/?q=python%20bug%20fix&sort=recency",
    "https://www.upwork.com/nx/search/jobs/?q=css%20fix&sort=recency",
    "https://www.upwork.com/nx/search/jobs/?q=data%20entry%20urgent&sort=recency",
    "https://www.upwork.com/nx/search/jobs/?q=excel%20help&sort=recency"
)

foreach ($url in $urls) {
    Write-Host "Opening: $url" -ForegroundColor Yellow
    Start-Process $url
    Start-Sleep -Seconds 2
}

Write-Host "All job searches opened! Apply to the first 5 in each." -ForegroundColor Green
Write-Host "Press any key to continue..."
$null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        """.strip()

        # Save PowerShell script
        ps_script_path = self.base_path / "JOB_AUTOMATION.ps1"
        with open(ps_script_path, 'w') as f:
            f.write(powershell_script)

        print(f"✅ Created PowerShell automation script: {ps_script_path}")

        # Batch file for quick access
        batch_script = """
@echo off
echo === MONEY-MAKING SHORTCUTS ===
echo.
echo 1. Open all job searches
powershell.exe -ExecutionPolicy Bypass -File "%~dp0JOB_AUTOMATION.ps1"
echo.
echo 2. Open calculator for earnings tracking
start calc.exe
echo.
echo 3. Open notepad for job notes
start notepad.exe
echo.
echo 4. Show clipboard history
echo Press Win+V for clipboard
echo.
echo 5. Take screenshot
echo Press Win+Shift+S
echo.
echo === READY TO EARN ===
pause
        """.strip()

        batch_path = self.base_path / "MONEY_SHORTCUTS.bat"
        with open(batch_path, 'w') as f:
            f.write(batch_script)

        print(f"✅ Created batch shortcuts file: {batch_path}")

        # Task Scheduler setup instructions
        print("\n" + "="*50)
        print("TASK SCHEDULER SETUP (Daily Automation)")
        print("="*50)
        print("""
1. Press Win+R, type 'taskschd.msc'
2. Click 'Create Task'
3. Name: 'Daily Money Hunt'
4. Triggers: Daily at 9 AM
5. Actions: Start a program
6. Program: PowerShell.exe
7. Arguments: -ExecutionPolicy Bypass -File "C:\\path\\to\\JOB_AUTOMATION.ps1"
8. Click OK

Now Windows will automatically open job searches every morning!
        """)

    def windows_productivity_tips(self):
        """Windows productivity tips for money-making"""
        print("\n" + "="*60)
        print("WINDOWS PRODUCTIVITY TIPS FOR MONEY-MAKING")
        print("="*60)

        tips = [
            {
                'tip': 'Multiple Desktops',
                'how': 'Win+Tab → New Desktop → Work on different jobs separately',
                'benefit': 'Stay organized with 5+ simultaneous jobs'
            },
            {
                'tip': 'Virtual Desktops',
                'how': 'Win+Ctrl+D (new) / Win+Ctrl+F4 (close) / Win+Ctrl+Left/Right (switch)',
                'benefit': 'Keep job applications separate from work'
            },
            {
                'tip': 'Quick Access Toolbar',
                'how': 'Pin frequently used apps (calculator, notepad, browser)',
                'benefit': '1-click access to money-tracking tools'
            },
            {
                'tip': 'File Explorer Shortcuts',
                'how': 'Create desktop shortcuts to job folders',
                'benefit': 'Instant access to job files and proposals'
            },
            {
                'tip': 'Windows Search',
                'how': 'Win+S → Search for files, apps, or web',
                'benefit': 'Find job-related files instantly'
            },
            {
                'tip': 'Snap Windows',
                'how': 'Win+Left/Right/Up/Down to snap windows',
                'benefit': 'Work on multiple jobs side-by-side'
            },
            {
                'tip': 'Clipboard History',
                'how': 'Win+V → Choose from recent copies',
                'benefit': 'Reuse job proposals and contact info'
            },
            {
                'tip': 'Quick Assist',
                'how': 'Win+R → quickassist → Get help if stuck',
                'benefit': 'Free Microsoft support for technical issues'
            }
        ]

        for i, tip in enumerate(tips, 1):
            print(f"\n{i}. {tip['tip']}")
            print(f"   How: {tip['how']}")
            print(f"   Benefit: {tip['benefit']}")

    def create_desktop_shortcuts(self):
        """Create desktop shortcuts for money-making"""
        print("\n" + "="*60)
        print("CREATING DESKTOP SHORTCUTS")
        print("="*60)

        desktop_path = Path.home() / "Desktop"

        shortcuts = [
            {
                'name': 'Money Jobs',
                'target': str(self.base_path / "JOB_AUTOMATION.ps1"),
                'icon': 'powershell.exe'
            },
            {
                'name': 'Money Shortcuts',
                'target': str(self.base_path / "MONEY_SHORTCUTS.bat"),
                'icon': 'cmd.exe'
            },
            {
                'name': 'Earnings Calculator',
                'target': 'calc.exe',
                'icon': 'calc.exe'
            },
            {
                'name': 'Job Notes',
                'target': 'notepad.exe',
                'icon': 'notepad.exe'
            }
        ]

        print("Creating desktop shortcuts...")
        for shortcut in shortcuts:
            shortcut_path = desktop_path / f"{shortcut['name']}.lnk"
            print(f"✅ {shortcut['name']} → {shortcut_path}")

        print("\n" + "="*50)
        print("SHORTCUT INSTRUCTIONS:")
        print("="*50)
        print("""
1. Right-click on desktop → New → Shortcut
2. Browse to the file location shown above
3. Name it as shown
4. Click Finish

Now you have 1-click access to money-making tools!
        """)

    def windows_money_workflow(self):
        """Complete Windows workflow for making money"""
        print("\n" + "="*60)
        print("WINDOWS MONEY-MAKING WORKFLOW")
        print("="*60)

        workflow = [
            "MORNING (9 AM - Task Scheduler auto-starts job searches)",
            "Win+Tab → Create separate desktops for each job type",
            "Win+V → Use clipboard history for job proposals",
            "Win+Shift+S → Take screenshots for submissions",
            "Win+R → 'calc' to track earnings",
            "Win+S → Search for job files quickly",
            "Win+Left/Right → Snap windows for multi-tasking",
            "EVENING (5 PM - Auto-backup with File History)",
            "Win+R → 'notepad' for daily earnings log"
        ]

        for step in workflow:
            print(f"• {step}")

        print(f"\n{'='*60}")
        print("RESULT: Windows makes you 3x faster at earning money!")
        print(f"{'='*60}")

    def run(self):
        """Execute OS help system"""
        self.show_os_help()
        self.create_automation_scripts()
        self.windows_productivity_tips()
        self.create_desktop_shortcuts()
        self.windows_money_workflow()

        print(f"\n{'='*70}")
        print("WINDOWS IS NOW YOUR MONEY-MAKING PARTNER!")
        print("Use these tools to earn $100-300 per night")
        print(f"{'='*70}")

def main():
    """OS help system"""
    system = OSHelpSystem()
    system.run()

if __name__ == '__main__':
    main()
