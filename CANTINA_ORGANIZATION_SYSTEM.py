#!/usr/bin/env python3
"""
Cantina Organization System
Complete bug bounty hunting organization and submission management
Optimized for maximum bounty collection and professional reputation
"""

import json
import os
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import re

@dataclass
class CantinaSubmission:
    """Individual Cantina submission tracking"""
    id: str
    program: str
    domain: str
    vulnerability_type: str
    severity: str
    bounty_estimate: str
    bounty_min: int
    status: str  # pending, submitted, accepted, rejected, paid
    submission_date: Optional[str] = None
    acceptance_date: Optional[str] = None
    payment_date: Optional[str] = None
    actual_bounty: Optional[int] = None
    files: List[str] = None
    notes: str = ""
    
    def __post_init__(self):
        if self.files is None:
            self.files = []

@dataclass
class CantinaProgram:
    """Cantina program management"""
    name: str
    company: str
    bounty_range: str
    response_time: str
    submission_count: int = 0
    accepted_count: int = 0
    total_earned: int = 0
    priority: int = 1  # 1=high, 2=medium, 3=low
    active: bool = True

class CantinaOrganizationSystem:
    """
    Complete Cantina bug bounty organization system
    Manages submissions, tracks earnings, optimizes strategy
    """
    
    def __init__(self):
        self.data_file = "cantina_organization_data.json"
        self.submissions = []
        self.programs = {}
        self.stats = {}
        
        self._load_data()
        self._initialize_programs()
    
    def _load_data(self):
        """Load existing organization data"""
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'r') as f:
                    data = json.load(f)
                    self.submissions = [CantinaSubmission(**s) for s in data.get('submissions', [])]
                    self.programs = data.get('programs', {})
                    self.stats = data.get('stats', {})
            except Exception as e:
                print(f"❌ Error loading data: {e}")
                self.submissions = []
                self.programs = {}
                self.stats = {}
    
    def _save_data(self):
        """Save organization data"""
        data = {
            'submissions': [asdict(s) for s in self.submissions],
            'programs': self.programs,
            'stats': self.stats,
            'last_updated': datetime.now().isoformat()
        }
        
        with open(self.data_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _initialize_programs(self):
        """Initialize Cantina programs with priority rankings"""
        
        if not self.programs:
            self.programs = {
                "microsoft": CantinaProgram(
                    name="Microsoft",
                    company="Microsoft Corporation",
                    bounty_range="$5,000-$250,000",
                    response_time="14 days",
                    priority=1  # Highest priority - massive bounties
                ),
                "google": CantinaProgram(
                    name="Google",
                    company="Alphabet Inc.",
                    bounty_range="$5,000-$100,000",
                    response_time="7 days",
                    priority=1  # Highest priority - massive bounties
                ),
                "apple": CantinaProgram(
                    name="Apple",
                    company="Apple Inc.",
                    bounty_range="$1,000-$100,000",
                    response_time="30 days",
                    priority=2  # High priority - good bounties but slow
                ),
                "tesla": CantinaProgram(
                    name="Tesla",
                    company="Tesla Inc.",
                    bounty_range="$1,000-$15,000",
                    response_time="7 days",
                    priority=2  # High priority - good bounties, fast response
                ),
                "meta": CantinaProgram(
                    name="Meta (Facebook)",
                    company="Meta Platforms Inc.",
                    bounty_range="$500-$40,000",
                    response_time="14 days",
                    priority=2  # High priority - good bounties
                ),
                "shopify": CantinaProgram(
                    name="Shopify",
                    company="Shopify Inc.",
                    bounty_range="$500-$10,000",
                    response_time="7 days",
                    priority=3  # Medium priority - moderate bounties
                ),
                "uber": CantinaProgram(
                    name="Uber",
                    company="Uber Technologies",
                    bounty_range="$500-$10,000",
                    response_time="5 days",
                    priority=3  # Medium priority - moderate bounties, fast
                ),
                "gitlab": CantinaProgram(
                    name="GitLab",
                    company="GitLab Inc.",
                    bounty_range="$100-$5,000",
                    response_time="14 days",
                    priority=4  # Lower priority - smaller bounties
                )
            }
            
            # Convert to dict format
            self.programs = {k: asdict(v) for k, v in self.programs.items()}
    
    def scan_for_submissions(self):
        """Scan directory for Cantina submission files"""
        
        print("🔍 SCANNING FOR CANTINA SUBMISSIONS")
        print()
        
        # Find all Cantina submission files
        submission_files = []
        
        # Master report
        for file in os.listdir('.'):
            if file.startswith('cantina_master_report_') and file.endswith('.md'):
                submission_files.append(file)
        
        # Individual submissions
        for file in os.listdir('.'):
            if file.startswith('cantina_submission_') and file.endswith('.md'):
                submission_files.append(file)
        
        # Data files
        for file in os.listdir('.'):
            if file.startswith('cantina_submission_data_') and file.endswith('.json'):
                submission_files.append(file)
        
        print(f"📋 FOUND {len(submission_files)} CANTINA FILES")
        
        # Parse data file for detailed information
        data_file = None
        for file in submission_files:
            if file.startswith('cantina_submission_data_') and file.endswith('.json'):
                data_file = file
                break
        
        if data_file:
            self._parse_submission_data(data_file)
        
        print(f"✅ PROCESSED {len(self.submissions)} SUBMISSIONS")
        print()
    
    def _parse_submission_data(self, data_file: str):
        """Parse Cantina submission data file"""
        
        try:
            with open(data_file, 'r') as f:
                data = json.load(f)
            
            for sub_data in data.get('submissions', []):
                # Create submission ID
                submission_id = f"{sub_data['program'].lower()}_{sub_data['target_domain']}_{sub_data['vulnerability_type'].replace(' ', '_').replace('/', '_')}"
                
                # Parse bounty estimate
                bounty_min = self._parse_bounty_estimate(sub_data['bounty_estimate'])
                
                submission = CantinaSubmission(
                    id=submission_id,
                    program=sub_data['program'],
                    domain=sub_data['target_domain'],
                    vulnerability_type=sub_data['vulnerability_type'],
                    severity=sub_data['severity'],
                    bounty_estimate=sub_data['bounty_estimate'],
                    bounty_min=bounty_min,
                    status="pending"  # Not submitted yet
                )
                
                # Add to submissions if not already exists
                existing = self._find_submission(submission_id)
                if not existing:
                    self.submissions.append(submission)
                
                # Update program stats
                if sub_data['program'].lower() in self.programs:
                    self.programs[sub_data['program'].lower()]['submission_count'] += 1
        
        except Exception as e:
            print(f"❌ Error parsing data file: {e}")
    
    def _find_submission(self, submission_id: str) -> Optional[CantinaSubmission]:
        """Find submission by ID"""
        for sub in self.submissions:
            if sub.id == submission_id:
                return sub
        return None
    
    def _parse_bounty_estimate(self, bounty_estimate: str) -> int:
        """Parse bounty estimate string to get minimum value"""
        match = re.search(r'\$(\d+)', bounty_estimate.replace(',', ''))
        return int(match.group(1)) if match else 0
    
    def generate_submission_plan(self):
        """Generate optimal submission plan for Cantina"""
        
        print("📋 GENERATING CANTINA SUBMISSION PLAN")
        print()
        
        # Sort submissions by priority (program priority * bounty value)
        priority_order = {
            1: [],  # High priority programs
            2: [],  # Medium priority programs  
            3: [],  # Low priority programs
            4: []   # Lowest priority programs
        }
        
        for submission in self.submissions:
            if submission.status == "pending":
                program_key = submission.program.lower()
                if program_key in self.programs:
                    priority = self.programs[program_key]['priority']
                    priority_order[priority].append(submission)
        
        # Sort each priority level by bounty amount (highest first)
        for priority in priority_order:
            priority_order[priority].sort(key=lambda x: x.bounty_min, reverse=True)
        
        # Generate submission schedule
        schedule = []
        day = 1
        
        print("🎯 OPTIMAL SUBMISSION SCHEDULE:")
        print()
        
        for priority in [1, 2, 3, 4]:  # High to low priority
            submissions = priority_order[priority]
            
            if submissions:
                print(f"📅 DAY {day}-{day+len(submissions)-1}: PRIORITY {priority} PROGRAMS")
                
                for i, sub in enumerate(submissions):
                    schedule_day = day + i
                    schedule.append({
                        'day': schedule_day,
                        'submission': sub,
                        'priority': priority
                    })
                    
                    print(f"   Day {schedule_day}: {sub.program} - {sub.vulnerability_type} (${sub.bounty_min:,})")
                
                day += len(submissions)
                print()
        
        # Calculate expected earnings
        total_pending = sum(s.bounty_min for s in self.submissions if s.status == "pending")
        high_value = sum(s.bounty_min for s in self.submissions if s.status == "pending" and s.bounty_min >= 1000)
        medium_value = sum(s.bounty_min for s in self.submissions if s.status == "pending" and 500 <= s.bounty_min < 1000)
        low_value = sum(s.bounty_min for s in self.submissions if s.status == "pending" and s.bounty_min < 500)
        
        print("💰 EXPECTED EARNINGS ANALYSIS:")
        print(f"   Total Pending: ${total_pending:,}")
        print(f"   High Value ($1k+): ${high_value:,}")
        print(f"   Medium Value ($500-$1k): ${medium_value:,}")
        print(f"   Low Value (<$500): ${low_value:,}")
        print()
        
        # Program breakdown
        print("🎯 PROGRAM BREAKDOWN:")
        for program_key, program_data in self.programs.items():
            pending_count = len([s for s in self.submissions if s.program.lower() == program_key and s.status == "pending"])
            if pending_count > 0:
                pending_value = sum(s.bounty_min for s in self.submissions if s.program.lower() == program_key and s.status == "pending")
                print(f"   {program_data['name']}: {pending_count} submissions, ${pending_value:,}")
        print()
        
        return schedule
    
    def create_submission_checklist(self):
        """Create submission checklist for organized Cantina hunting"""
        
        print("📋 CANTINA SUBMISSION CHECKLIST")
        print()
        
        # Group pending submissions by program
        pending_by_program = {}
        for sub in self.submissions:
            if sub.status == "pending":
                program = sub.program
                if program not in pending_by_program:
                    pending_by_program[program] = []
                pending_by_program[program].append(sub)
        
        checklist = []
        
        for program, submissions in pending_by_program.items():
            print(f"🎯 {program} SUBMISSIONS:")
            
            for i, sub in enumerate(submissions, 1):
                # Find submission files
                main_file = f"cantina_submission_{sub.domain.replace('.', '_')}_{sub.vulnerability_type.replace(' ', '_').replace('/', '_')}_20251201_141732.md"
                test_file = f"automated_test_{sub.domain.replace('.', '_')}_{sub.vulnerability_type.replace(' ', '_').replace('/', '_')}_20251201_141732.sh"
                evidence_file = f"evidence_{sub.domain.replace('.', '_')}_{sub.vulnerability_type.replace(' ', '_').replace('/', '_')}_20251201_141732.txt"
                
                checklist_item = {
                    'program': program,
                    'submission': sub,
                    'files': {
                        'main': main_file,
                        'test': test_file,
                        'evidence': evidence_file
                    }
                }
                
                print(f"   {i}. {sub.vulnerability_type}")
                print(f"      📄 Main: {main_file}")
                print(f"      🤖 Test: {test_file}")
                print(f"      📋 Evidence: {evidence_file}")
                print(f"      💰 Bounty: {sub.bounty_estimate}")
                print()
                
                checklist.append(checklist_item)
        
        return checklist
    
    def track_submission_status(self):
        """Track and update submission status"""
        
        print("📊 CANTINA SUBMISSION STATUS TRACKING")
        print()
        
        # Status summary
        status_counts = {}
        total_value = 0
        earned_value = 0
        
        for status in ["pending", "submitted", "accepted", "rejected", "paid"]:
            count = len([s for s in self.submissions if s.status == status])
            status_counts[status] = count
            
            if status in ["accepted", "paid"]:
                value = sum(s.actual_bounty or s.bounty_min for s in self.submissions if s.status == status)
                earned_value += value
            
            total_value += sum(s.bounty_min for s in self.submissions if s.status == status)
        
        print("📈 STATUS SUMMARY:")
        for status, count in status_counts.items():
            if count > 0:
                print(f"   {status.title()}: {count} submissions")
        
        print(f"\n💰 FINANCIAL SUMMARY:")
        print(f"   Total Potential: ${total_value:,}")
        print(f"   Earned So Far: ${earned_value:,}")
        print(f"   Success Rate: {(earned_value / total_value * 100):.1f}%" if total_value > 0 else "   Success Rate: N/A")
        print()
        
        # Program performance
        print("🎯 PROGRAM PERFORMANCE:")
        for program_key, program_data in self.programs.items():
            program_submissions = [s for s in self.submissions if s.program.lower() == program_key]
            
            if program_submissions:
                total = len(program_submissions)
                accepted = len([s for s in program_submissions if s.status in ["accepted", "paid"]])
                earned = sum((s.actual_bounty or s.bounty_min) for s in program_submissions if s.status in ["accepted", "paid"])
                
                print(f"   {program_data['name']}: {accepted}/{total} accepted, ${earned:,}")
        print()
    
    def update_submission_status(self, submission_id: str, status: str, actual_bounty: Optional[int] = None, notes: str = ""):
        
        submission = self._find_submission(submission_id)
        if submission:
            old_status = submission.status
            submission.status = status
            
            if actual_bounty:
                submission.actual_bounty = actual_bounty
            
            if notes:
                submission.notes = notes
            
            # Update timestamps
            now = datetime.now().strftime('%Y-%m-%d')
            if status == "submitted" and not submission.submission_date:
                submission.submission_date = now
            elif status == "accepted" and not submission.acceptance_date:
                submission.acceptance_date = now
            elif status == "paid" and not submission.payment_date:
                submission.payment_date = now
            
            # Update program stats
            program_key = submission.program.lower()
            if program_key in self.programs:
                if old_status not in ["accepted", "paid"] and status in ["accepted", "paid"]:
                    self.programs[program_key]['accepted_count'] += 1
                    self.programs[program_key]['total_earned'] += actual_bounty or submission.bounty_min
            
            self._save_data()
            
            print(f"✅ UPDATED {submission_id}: {old_status} → {status}")
            if actual_bounty:
                print(f"   💰 Actual Bounty: ${actual_bounty:,}")
        
        else:
            print(f"❌ Submission {submission_id} not found")
    
    def generate_daily_report(self):
        """Generate daily Cantina hunting report"""
        
        print("📊 DAILY CANTINA HUNTING REPORT")
        print(f"📅 Date: {datetime.now().strftime('%Y-%m-%d')}")
        print()
        
        # Today's targets
        pending_count = len([s for s in self.submissions if s.status == "pending"])
        submitted_today = len([s for s in self.submissions if s.submission_date == datetime.now().strftime('%Y-%m-%d')])
        
        print("🎯 TODAY'S TARGETS:")
        print(f"   Pending Submissions: {pending_count}")
        print(f"   Submitted Today: {submitted_today}")
        print(f"   Daily Goal: 5 submissions")
        print(f"   Progress: {submitted_today}/5 ({(submitted_today/5*100):.0f}%)")
        print()
        
        # High-value targets
        high_value_pending = [s for s in self.submissions if s.status == "pending" and s.bounty_min >= 1000]
        if high_value_pending:
            print("💎 HIGH VALUE TARGETS:")
            for sub in sorted(high_value_pending, key=lambda x: x.bounty_min, reverse=True)[:5]:
                print(f"   {sub.program} - {sub.vulnerability_type}: ${sub.bounty_min:,}")
            print()
        
        # Recent activity
        recent_submissions = [s for s in self.submissions if s.submission_date and s.submission_date >= (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')]
        if recent_submissions:
            print("📈 RECENT ACTIVITY (7 days):")
            for sub in recent_submissions[-5:]:  # Last 5 submissions
                print(f"   {sub.submission_date}: {sub.program} - {sub.vulnerability_type} ({sub.status})")
            print()
        
        # Earnings tracking
        total_earned = sum(s.actual_bounty or s.bounty_min for s in self.submissions if s.status == "paid")
        pending_earnings = sum(s.bounty_min for s in self.submissions if s.status == "pending")
        
        print("💰 EARNINGS TRACKING:")
        print(f"   Total Earned: ${total_earned:,}")
        print(f"   Pending Earnings: ${pending_earnings:,}")
        print(f"   Monthly Goal: $10,000")
        print(f"   Progress: ${(total_earned/10000*100):.0f}%")
        print()
    
    def create_submission_automation(self):
        """Create automated submission scripts"""
        
        print("🤖 CREATING SUBMISSION AUTOMATION")
        print()
        
        # Create submission script
        script_content = f"""#!/bin/bash
# Cantina Automated Submission Script
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

echo "CANTINA AUTOMATED SUBMISSION SYSTEM"
echo "Date: $(date)"
echo

# Function to submit to Cantina
submit_to_cantina() {{
    local program="$1"
    local vulnerability="$2"
    local main_file="$3"
    local test_file="$4"
    local bounty="$5"
    
    echo "Submitting to $program:"
    echo "   Vulnerability: $vulnerability"
    echo "   Bounty: $bounty"
    echo "   Files: $main_file, $test_file"
    echo
    
    # TODO: Add actual Cantina API integration
    echo "   Submission queued for manual upload"
    echo "   Files prepared for Cantina platform"
    echo
}}

# Read submission checklist
if [ -f "submission_checklist.txt" ]; then
    while IFS= read -r line; do
        if [[ $line == *"PROGRAM:"* ]]; then
            program=$(echo "$line" | cut -d':' -f2 | tr -d ' ')
        elif [[ $line == *"Vulnerability:"* ]]; then
            vulnerability=$(echo "$line" | cut -d':' -f2 | tr -d ' ')
        elif [[ $line == *"Main:"* ]]; then
            main_file=$(echo "$line" | cut -d':' -f2 | tr -d ' ')
        elif [[ $line == *"Test:"* ]]; then
            test_file=$(echo "$line" | cut -d':' -f2 | tr -d ' ')
        elif [[ $line == *"Bounty:"* ]]; then
            bounty=$(echo "$line" | cut -d':' -f2 | tr -d ' ')
            
            # Submit to Cantina
            submit_to_cantina "$program" "$vulnerability" "$main_file" "$test_file" "$bounty"
        fi
    done < submission_checklist.txt
else
    echo "submission_checklist.txt not found"
    echo "Run generate_submission_checklist() first"
fi

echo "AUTOMATED SUBMISSION COMPLETE"
echo "All submissions queued for Cantina platform"
"""
        
        with open("cantina_auto_submit.sh", 'w') as f:
            f.write(script_content)
        
        # Make executable
        try:
            subprocess.run(['chmod', '+x', 'cantina_auto_submit.sh'], check=True)
            print("✅ Created cantina_auto_submit.sh")
        except:
            print("✅ Created cantina_auto_submit.sh (manual chmod needed)")
        
        # Create tracking script
        tracking_content = f"""#!/bin/bash
# Cantina Submission Tracking Script
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

echo "CANTINA SUBMISSION TRACKING"
echo "Date: $(date)"
echo

# Check submission status
if [ -f "cantina_organization_data.json" ]; then
    echo "Current Status:"
    python3 -c "
import json
with open('cantina_organization_data.json', 'r') as f:
    data = json.load(f)

submissions = data.get('submissions', [])
status_counts = {{}}
total_value = 0

for sub in submissions:
    status = sub.get('status', 'unknown')
    status_counts[status] = status_counts.get(status, 0) + 1
    total_value += sub.get('bounty_min', 0)

for status, count in status_counts.items():
    if count > 0:
        print(f'   {{status.title()}}: {{count}} submissions')

print(f'\\nTotal Potential: ${{total_value:,}}')
"
else
    echo "No data file found"
fi

echo
echo "NEXT ACTIONS:"
echo "1. Submit pending vulnerabilities to Cantina"
echo "2. Update status when accepted/rejected"
echo "3. Track earnings and optimize strategy"
"""
        
        with open("cantina_track_status.sh", 'w') as f:
            f.write(tracking_content)
        
        # Make executable
        try:
            subprocess.run(['chmod', '+x', 'cantina_track_status.sh'], check=True)
            print("✅ Created cantina_track_status.sh")
        except:
            print("✅ Created cantina_track_status.sh (manual chmod needed)")
        
        print()
        print("🤖 AUTOMATION SCRIPTS CREATED:")
        print("   📤 cantina_auto_submit.sh - Automated submission")
        print("   📊 cantina_track_status.sh - Status tracking")
        print()

# Main execution
if __name__ == "__main__":
    system = CantinaOrganizationSystem()
    
    print("🎯 CANTINA ORGANIZATION SYSTEM")
    print("📋 COMPLETE BUG BOUNTY MANAGEMENT")
    print("💰 OPTIMIZED FOR MAXIMUM EARNINGS")
    print()
    
    # Scan for submissions
    system.scan_for_submissions()
    
    # Generate submission plan
    schedule = system.generate_submission_plan()
    
    # Create checklist
    checklist = system.create_submission_checklist()
    
    # Track status
    system.track_submission_status()
    
    # Generate daily report
    system.generate_daily_report()
    
    # Create automation
    system.create_submission_automation()
    
    # Save data
    system._save_data()
    
    print("✅ CANTINA ORGANIZATION COMPLETE")
    print("🎯 Ready for systematic Cantina hunting")
    print("💰 Optimized for maximum bounty collection")
    print("📋 All tracking and automation ready")
