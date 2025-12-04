#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.

CASH TONIGHT - Real Money Tonight System
Upwork Quick Jobs for Immediate Payment
"""

import webbrowser
import time
from datetime import datetime
from pathlib import Path

class CashTonight:
    """Get paid TONIGHT system"""
    
    def __init__(self):
        self.base_path = Path(__file__).parent
        
        # Quick jobs that pay TONIGHT
        self.jobs = [
            {
                'title': 'WordPress Error Fix',
                'skill': 'WordPress',
                'time': '2-3 hours',
                'pay': '$50-150',
                'url': 'https://www.upwork.com/nx/search/jobs/?q=wordpress%20fix&per_page=50&sort=recency',
                'proposal': """I can fix your WordPress error immediately. I have 7+ years experience with WordPress and can resolve plugin conflicts, theme issues, database errors, white screen of death, login problems, and PHP errors.

I'm available RIGHT NOW and can complete within 2-3 hours. Let me know the specific error and I'll fix it immediately.

Ready to start immediately - just message me with details."""
            },
            {
                'title': 'Python Bug Fix',
                'skill': 'Python',
                'time': '1-2 hours',
                'pay': '$40-100',
                'url': 'https://www.upwork.com/nx/search/jobs/?q=python%20bug%20fix&per_page=50&sort=recency',
                'proposal': """I can fix your Python script bug right now. Expert in debugging Python errors, logic fixes, import issues, API integration problems, data processing bugs, and web scraping fixes.

Available immediately and can complete within 1-2 hours. Send me the error and code, I'll fix it now.

Ready to start immediately."""
            },
            {
                'title': 'CSS Styling Fixes',
                'skill': 'CSS/HTML',
                'time': '1-2 hours',
                'pay': '$30-80',
                'url': 'https://www.upwork.com/nx/search/jobs/?q=css%20fix&per_page=50&sort=recency',
                'proposal': """I can fix your CSS/HTML styling issues immediately. Expert in responsive design fixes, layout problems, cross-browser compatibility, mobile responsiveness, Bootstrap/Custom CSS, and WordPress styling.

Available now, can complete within 1-2 hours. Show me the issue and I'll fix it immediately.

Ready to start right away."""
            },
            {
                'title': 'Data Entry Task',
                'skill': 'Data Entry',
                'time': '2-4 hours',
                'pay': '$25-60',
                'url': 'https://www.upwork.com/nx/search/jobs/?q=data%20entry%20urgent&per_page=50&sort=recency',
                'proposal': """I can complete your data entry task immediately. I'm fast and accurate (60+ WPM), available right now, can work 2-4 hours continuously, detail oriented, experienced with Excel/Google Sheets, and reliable and communicative.

Ready to start immediately and work until completion. Send the task details and I'll begin now."""
            },
            {
                'title': 'Excel Help',
                'skill': 'Excel',
                'time': '1 hour',
                'pay': '$30-75',
                'url': 'https://www.upwork.com/nx/search/jobs/?q=excel%20help&per_page=50&sort=recency',
                'proposal': """I can fix your Excel formula problems immediately. Expert in complex formulas (VLOOKUP, INDEX/MATCH, Pivot Tables), data analysis, automation with macros, chart creation, data cleaning, and report generation.

Available now and can solve within 1 hour. Send me your spreadsheet and requirements.

Ready to help immediately."""
            }
        ]
    
    def show_jobs(self):
        """Display job options"""
        print("""
==================================================
              CASH TONIGHT SYSTEM
          Real Upwork Jobs - Same Day Payment
          
  Start IMMEDIATELY - Get paid TONIGHT
  No experience required - Work from anywhere
==================================================
        """)
        
        print(f"\nTONIGHT'S QUICK JOBS (Payment in 2-6 hours):\n")
        
        for i, job in enumerate(self.jobs, 1):
            print(f"{i}. {job['title']}")
            print(f"   Pay: {job['pay']}")
            print(f"   Time: {job['time']}")
            print(f"   Immediate start: YES")
            print()
    
    def open_jobs(self):
        """Open all job searches"""
        print("\nOPENING JOB SEARCHES...")
        print("These are the MOST RECENT jobs - apply NOW!\n")
        
        for job in self.jobs:
            print(f"Opening {job['skill']} jobs...")
            webbrowser.open(job['url'])
            time.sleep(1)
        
        print("\nAll job searches opened!")
        print("TIP: Apply to the FIRST 5 jobs in each category")
    
    def show_proposals(self):
        """Display ready proposals"""
        print("\nYOUR PROPOSALS ARE READY:")
        print("Copy and paste these for instant applications:\n")
        
        for job in self.jobs:
            print(f"--- {job['title']} ---")
            print(job['proposal'])
            print("\n" + "="*60 + "\n")
    
    def emergency_cash(self):
        """Ultra-fast cash plan"""
        print("""
EMERGENCY CASH PLAN - GET MONEY IN 2 HOURS:

1. DATA ENTRY JOBS (Fastest to get)
   - Pay: $25-60 per job
   - Time: 2 hours
   - Apply to 10 NOW

2. EXCEL HELP (Quick fixes)
   - Pay: $30-75 per job
   - Time: 1 hour
   - Apply to 10 NOW

3. WORDPRESS FIXES (High demand)
   - Pay: $50-150 per job
   - Time: 2-3 hours
   - Apply to 10 NOW

ULTRA FAST STRATEGY:
- Apply to 30 jobs in 30 minutes
- Respond to messages instantly
- Start work immediately
- Complete within 2-4 hours
- Get paid tonight

MINIMUM GUARANTEED: $100-300 TONIGHT
        """)
    
    def complete_strategy(self):
        """Complete strategy guide"""
        print("""
TONIGHT'S MONEY-MAKING STRATEGY:

STEP 1: Apply to 20 Jobs (30 minutes)
- Open all search URLs
- Apply to first 5 jobs in each category
- Use the ready proposals
- Mention "Available immediately"

STEP 2: Respond to Messages (1-2 hours)
- When clients message, respond within 5 minutes
- Say "I can start right now"
- Ask for specific details
- Confirm you can complete tonight

STEP 3: Complete the Work (2-4 hours)
- Start immediately once hired
- Communicate progress
- Deliver on time
- Request payment release

STEP 4: Get Paid TONIGHT (2-6 hours)
- Most clients release payment same day
- Upwork processes immediately
- Money in your account tonight

EXPECTED RESULTS:
- 20 applications = 2-5 responses
- 2-5 responses = 1-2 jobs
- 1-2 jobs = $100-300 TONIGHT
        """)
    
    def run(self):
        """Execute the system"""
        self.show_jobs()
        
        print("\nChoose your path:")
        print("1. Open job searches + get proposals")
        print("2. Emergency cash plan (2 hours)")
        print("3. Full strategy guide")
        
        choice = input("\nEnter choice (1-3): ").strip()
        
        if choice == '1':
            self.open_jobs()
            self.show_proposals()
        elif choice == '2':
            self.emergency_cash()
            self.open_jobs()
        else:
            self.complete_strategy()
            self.open_jobs()
            self.show_proposals()
        
        print(f"\n{'='*70}")
        print("READY TO EARN TONIGHT!")
        print("Apply NOW and get paid in 2-6 hours")
        print(f"{'='*70}")

def main():
    """Get paid tonight system"""
    system = CashTonight()
    system.run()

if __name__ == '__main__':
    main()
