#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
# -*- coding: utf-8 -*-
"""
Automated First Dollar Plan Execution
Automates the quickest path to first dollar workflow
"""

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
import argparse

# Fix Windows encoding
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

class FirstDollarAutomation:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.output_dir = self.base_dir / "output" / "first_dollar_automation"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.tracking_file = self.output_dir / "tracking.json"
        self.proposals_dir = self.output_dir / "proposals"
        self.proposals_dir.mkdir(exist_ok=True)
        
        self.load_tracking()
    
    def load_tracking(self):
        """Load tracking data"""
        if self.tracking_file.exists():
            with open(self.tracking_file, 'r') as f:
                self.tracking = json.load(f)
        else:
            self.tracking = {
                "profile_setup": False,
                "applications_sent": 0,
                "projects_won": 0,
                "revenue": 0,
                "applications": [],
                "projects": []
            }
    
    def save_tracking(self):
        """Save tracking data"""
        with open(self.tracking_file, 'w') as f:
            json.dump(self.tracking, f, indent=2)
    
    def check_profile_setup(self):
        """Check if profile setup is complete"""
        checklist = {
            "Profile created": False,
            "Portfolio samples uploaded": False,
            "Skills added": False,
            "Availability set": False
        }
        
        print("\n📋 Profile Setup Checklist:")
        print("=" * 50)
        for item, status in checklist.items():
            status_icon = "✅" if status else "☐"
            print(f"{status_icon} {item}")
        
        if all(checklist.values()):
            self.tracking["profile_setup"] = True
            print("\n✅ Profile setup complete!")
        else:
            print("\n⚠️  Complete profile setup before proceeding")
            print("\n📝 Quick Setup Guide:")
            print("1. Go to Upwork.com")
            print("2. Use headline: 'Enterprise Security Scanner | 2-Hour Vulnerability Reports | $200-$500'")
            print("3. Set hourly rate: $75/hour")
            print("4. Add skills: Security Testing, Vulnerability Assessment, Penetration Testing")
            print("5. Generate portfolio samples (run: python3 scripts/generate_portfolio_samples.py)")
        
        return all(checklist.values())
    
    def generate_proposal(self, client_name, job_description, price=300, template_type="emergency"):
        """Generate proposal from template"""
        templates = {
            "emergency": """Subject: 2-Hour Security Scan - Results Today

Hi {client_name},

I see you need a security assessment urgently. I specialize in fast, comprehensive security scans using enterprise automation tools.

What I'll deliver in 2 hours:
✅ Complete vulnerability scan (100+ security checks)
✅ Professional report with security score
✅ Critical issues flagged immediately
✅ Step-by-step fix instructions
✅ 30-day support included

My automated system scans 80-240x faster than manual methods, so I can deliver results today - perfect for urgent situations.

Fixed Price: ${price}
Timeline: 2 hours from start
Guarantee: Full refund if not satisfied

Ready to secure your business today?

Best regards,
[Your Name]"""
        }
        
        template = templates.get(template_type, templates["emergency"])
        proposal = template.format(client_name=client_name, price=price)
        
        # Add specific detail from job description if provided
        if job_description:
            # Extract key concern (simple keyword matching)
            keywords = ["urgent", "ASAP", "emergency", "today", "immediate", "quick"]
            for keyword in keywords:
                if keyword.lower() in job_description.lower():
                    proposal = proposal.replace(
                        "I see you need a security assessment urgently.",
                        f"I see you need a security assessment urgently - I understand you need results {keyword.lower()}."
                    )
                    break
        
        return proposal
    
    def save_proposal(self, proposal, client_name, job_id=None):
        """Save proposal to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{client_name.replace(' ', '_')}.txt"
        filepath = self.proposals_dir / filename
        
        with open(filepath, 'w') as f:
            f.write(proposal)
        
        # Track application
        application = {
            "timestamp": timestamp,
            "client_name": client_name,
            "job_id": job_id,
            "proposal_file": str(filepath),
            "status": "sent"
        }
        
        self.tracking["applications"].append(application)
        self.tracking["applications_sent"] += 1
        self.save_tracking()
        
        return filepath
    
    def generate_proposals_batch(self, jobs_file=None):
        """Generate proposals for multiple jobs"""
        if jobs_file and os.path.exists(jobs_file):
            with open(jobs_file, 'r') as f:
                jobs = json.load(f)
        else:
            print("\n📝 Manual Job Entry Mode")
            print("Enter job details (press Enter with empty client name to finish):")
            jobs = []
            while True:
                client_name = input("\nClient Name: ").strip()
                if not client_name:
                    break
                job_description = input("Job Description (brief): ").strip()
                price = input("Price ($200-$500, default 300): ").strip() or "300"
                jobs.append({
                    "client_name": client_name,
                    "job_description": job_description,
                    "price": int(price)
                })
        
        print(f"\n🚀 Generating {len(jobs)} proposals...")
        
        for i, job in enumerate(jobs, 1):
            print(f"\n[{i}/{len(jobs)}] Generating proposal for {job['client_name']}...")
            proposal = self.generate_proposal(
                job['client_name'],
                job.get('job_description', ''),
                job.get('price', 300)
            )
            
            filepath = self.save_proposal(proposal, job['client_name'])
            print(f"✅ Saved: {filepath}")
            print("\n" + "="*50)
            print(proposal)
            print("="*50)
        
        print(f"\n✅ Generated {len(jobs)} proposals!")
        print(f"📊 Total applications sent: {self.tracking['applications_sent']}")
    
    def track_project_won(self, client_name, amount, domain=None):
        """Track won project"""
        project = {
            "timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"),
            "client_name": client_name,
            "amount": amount,
            "domain": domain,
            "status": "won",
            "delivered": False
        }
        
        self.tracking["projects"].append(project)
        self.tracking["projects_won"] += 1
        self.tracking["revenue"] += amount
        self.save_tracking()
        
        print(f"\n🎉 Project won: {client_name} - ${amount}")
        print(f"💰 Total revenue: ${self.tracking['revenue']}")
        
        # Generate scan command
        if domain:
            print(f"\n🚀 Ready to scan? Run:")
            print(f"python3 run_pipeline.py --target {domain} --output output/{client_name.replace(' ', '_')}")
    
    def track_delivery(self, client_name):
        """Track project delivery"""
        for project in self.tracking["projects"]:
            if project["client_name"] == client_name and not project.get("delivered"):
                project["delivered"] = True
                project["delivered_at"] = datetime.now().strftime("%Y%m%d_%H%M%S")
                self.save_tracking()
                print(f"✅ Marked {client_name} as delivered")
                return
        print(f"⚠️  Project not found: {client_name}")
    
    def generate_report(self, client_name, domain):
        """Generate client report"""
        output_dir = self.base_dir / "output" / client_name.replace(" ", "_")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        cmd = [
            "python3",
            "scripts/generate_report.py",
            "--format", "professional",
            "--client-name", client_name,
            "--output", str(output_dir / "report.pdf")
        ]
        
        print(f"\n📊 Generating report for {client_name}...")
        print(f"Command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(cmd, cwd=self.base_dir, check=True)
            print(f"✅ Report generated: {output_dir / 'report.pdf'}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Error generating report: {e}")
            return False
    
    def run_scan(self, domain, client_name):
        """Run security scan for client"""
        output_dir = self.base_dir / "output" / client_name.replace(" ", "_")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        cmd = [
            "python3",
            "run_pipeline.py",
            "--target", domain,
            "--output", str(output_dir)
        ]
        
        print(f"\n🔍 Running scan for {domain}...")
        print(f"Command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(cmd, cwd=self.base_dir, check=True)
            print(f"✅ Scan complete: {output_dir}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Error running scan: {e}")
            return False
    
    def show_dashboard(self):
        """Show automation dashboard"""
        print("\n" + "="*60)
        print("🚀 FIRST DOLLAR AUTOMATION DASHBOARD")
        print("="*60)
        
        print(f"\n📊 Stats:")
        print(f"  Profile Setup: {'✅' if self.tracking['profile_setup'] else '☐'}")
        print(f"  Applications Sent: {self.tracking['applications_sent']}")
        print(f"  Projects Won: {self.tracking['projects_won']}")
        print(f"  Total Revenue: ${self.tracking['revenue']}")
        
        if self.tracking['applications']:
            print(f"\n📝 Recent Applications ({len(self.tracking['applications'])}):")
            for app in self.tracking['applications'][-5:]:
                print(f"  • {app['client_name']} - {app['timestamp']}")
        
        if self.tracking['projects']:
            print(f"\n💼 Active Projects ({len(self.tracking['projects'])}):")
            for project in self.tracking['projects']:
                status = "✅ Delivered" if project.get('delivered') else "⏳ In Progress"
                print(f"  • {project['client_name']} - ${project['amount']} - {status}")
        
        print("\n" + "="*60)


def main():
    parser = argparse.ArgumentParser(description="Automate First Dollar Plan")
    parser.add_argument("--action", choices=["dashboard", "proposal", "batch", "won", "deliver", "scan", "report", "check-profile"], 
                       default="dashboard", help="Action to perform")
    parser.add_argument("--client", help="Client name")
    parser.add_argument("--domain", help="Domain to scan")
    parser.add_argument("--amount", type=int, help="Project amount")
    parser.add_argument("--price", type=int, default=300, help="Proposal price")
    parser.add_argument("--jobs-file", help="JSON file with jobs list")
    parser.add_argument("--description", help="Job description")
    
    args = parser.parse_args()
    
    automation = FirstDollarAutomation()
    
    if args.action == "dashboard":
        automation.show_dashboard()
    
    elif args.action == "check-profile":
        automation.check_profile_setup()
    
    elif args.action == "proposal":
        if not args.client:
            print("❌ --client required")
            sys.exit(1)
        proposal = automation.generate_proposal(args.client, args.description or "", args.price)
        filepath = automation.save_proposal(proposal, args.client)
        print(f"\n✅ Proposal saved: {filepath}")
        print("\n" + "="*50)
        print(proposal)
        print("="*50)
    
    elif args.action == "batch":
        automation.generate_proposals_batch(args.jobs_file)
    
    elif args.action == "won":
        if not args.client or not args.amount:
            print("❌ --client and --amount required")
            sys.exit(1)
        automation.track_project_won(args.client, args.amount, args.domain)
    
    elif args.action == "deliver":
        if not args.client:
            print("❌ --client required")
            sys.exit(1)
        automation.track_delivery(args.client)
    
    elif args.action == "scan":
        if not args.domain or not args.client:
            print("❌ --domain and --client required")
            sys.exit(1)
        automation.run_scan(args.domain, args.client)
    
    elif args.action == "report":
        if not args.client or not args.domain:
            print("❌ --client and --domain required")
            sys.exit(1)
        automation.generate_report(args.client, args.domain)


if __name__ == "__main__":
    main()

