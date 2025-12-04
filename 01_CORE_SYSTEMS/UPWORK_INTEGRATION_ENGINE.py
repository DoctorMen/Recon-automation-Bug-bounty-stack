#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
# -*- coding: utf-8 -*-
"""
UPWORK INTEGRATION ENGINE
Real backend for ParallelProfit™ 3D Dashboard

This system:
1. Connects to Upwork API (RSS feeds + scraping)
2. Discovers jobs matching your skills
3. Generates AI-powered proposals
4. Tracks applications and wins
5. Calculates real revenue metrics

Author: DoctorMen
Status: Production Ready
"""

import json
import sys
import time
import requests
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import feedparser
import re
from urllib.parse import quote_plus

# Fix encoding for Windows
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')

class UpworkIntegrationEngine:
    """
    Real Upwork integration for ParallelProfit™
    """
    
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.data_dir = self.base_dir / "output" / "upwork_data"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Load configuration
        self.config = self.load_config()
        
        # Initialize metrics
        self.metrics = {
            "jobs_discovered": 0,
            "proposals_generated": 0,
            "applications_sent": 0,
            "jobs_won": 0,
            "revenue_earned": 0,
            "win_rate": 0.0,
            "last_updated": datetime.now().isoformat()
        }
        
        # Load existing metrics if available
        self.load_metrics()
        
        print("🚀 UPWORK INTEGRATION ENGINE INITIALIZED")
        print(f"📁 Data directory: {self.data_dir}")
    
    def load_config(self) -> Dict:
        """Load or create configuration"""
        config_file = self.base_dir / "config" / "upwork_config.json"
        config_file.parent.mkdir(parents=True, exist_ok=True)
        
        if config_file.exists():
            with open(config_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        else:
            # Default configuration
            default_config = {
                "skills": [
                    "python",
                    "automation",
                    "web scraping",
                    "api integration",
                    "security testing",
                    "penetration testing",
                    "bug bounty",
                    "vulnerability assessment"
                ],
                "hourly_rate_min": 50,
                "hourly_rate_max": 150,
                "job_types": ["hourly", "fixed"],
                "experience_levels": ["intermediate", "expert"],
                "min_budget": 500,
                "proposal_template": "professional",
                "auto_apply": False,  # Safety: manual approval required
                "max_proposals_per_day": 10
            }
            
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(default_config, f, indent=2)
            
            print(f"✅ Created default config: {config_file}")
            return default_config
    
    def load_metrics(self):
        """Load existing metrics"""
        metrics_file = self.data_dir / "metrics.json"
        if metrics_file.exists():
            with open(metrics_file, 'r', encoding='utf-8') as f:
                self.metrics = json.load(f)
            print(f"📊 Loaded existing metrics: {self.metrics['jobs_discovered']} jobs discovered")
    
    def save_metrics(self):
        """Save metrics to file"""
        self.metrics['last_updated'] = datetime.now().isoformat()
        metrics_file = self.data_dir / "metrics.json"
        with open(metrics_file, 'w', encoding='utf-8') as f:
            json.dump(self.metrics, f, indent=2)
    
    def discover_jobs(self) -> List[Dict]:
        """
        Discover jobs from Upwork RSS feeds
        Upwork provides public RSS feeds for job searches
        """
        print("\n🔍 DISCOVERING JOBS...")
        
        jobs = []
        
        # Upwork RSS feed URLs (public, no API key needed)
        for skill in self.config['skills'][:3]:  # Limit to top 3 skills
            rss_url = f"https://www.upwork.com/ab/feed/jobs/rss?q={quote_plus(skill)}&sort=recency"
            
            try:
                print(f"  Fetching: {skill}...")
                feed = feedparser.parse(rss_url)
                
                for entry in feed.entries[:5]:  # Top 5 per skill
                    job = self.parse_job_entry(entry, skill)
                    if job and self.matches_criteria(job):
                        jobs.append(job)
                        print(f"    ✅ Found: {job['title'][:50]}...")
                
                time.sleep(2)  # Rate limiting
                
            except Exception as e:
                print(f"    ❌ Error fetching {skill}: {str(e)}")
        
        # Save discovered jobs
        jobs_file = self.data_dir / f"jobs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(jobs_file, 'w', encoding='utf-8') as f:
            json.dump(jobs, f, indent=2)
        
        # Update metrics
        self.metrics['jobs_discovered'] += len(jobs)
        self.save_metrics()
        
        print(f"\n✅ Discovered {len(jobs)} matching jobs")
        return jobs
    
    def parse_job_entry(self, entry, skill: str) -> Optional[Dict]:
        """Parse RSS feed entry into job dict"""
        try:
            # Extract budget from description
            budget = self.extract_budget(entry.get('summary', ''))
            
            job = {
                "id": entry.get('id', ''),
                "title": entry.get('title', ''),
                "description": entry.get('summary', ''),
                "url": entry.get('link', ''),
                "posted": entry.get('published', ''),
                "skill_matched": skill,
                "budget": budget,
                "discovered_at": datetime.now().isoformat()
            }
            
            return job
        except Exception as e:
            print(f"    ⚠️ Error parsing entry: {str(e)}")
            return None
    
    def extract_budget(self, description: str) -> Optional[int]:
        """Extract budget from job description"""
        # Look for common budget patterns
        patterns = [
            r'\$(\d+(?:,\d{3})*(?:\.\d{2})?)',  # $1,000 or $1000.00
            r'(\d+(?:,\d{3})*)\s*(?:USD|dollars)',  # 1000 USD
            r'Budget:\s*\$?(\d+(?:,\d{3})*)',  # Budget: $1000
        ]
        
        for pattern in patterns:
            match = re.search(pattern, description)
            if match:
                budget_str = match.group(1).replace(',', '')
                try:
                    return int(float(budget_str))
                except:
                    pass
        
        return None
    
    def matches_criteria(self, job: Dict) -> bool:
        """Check if job matches our criteria"""
        # Check budget
        if job.get('budget'):
            if job['budget'] < self.config['min_budget']:
                return False
        
        # Check for red flags in description
        description_lower = job['description'].lower()
        red_flags = ['free', 'unpaid', 'volunteer', 'no budget', 'test project']
        if any(flag in description_lower for flag in red_flags):
            return False
        
        return True
    
    def generate_proposal(self, job: Dict) -> Dict:
        """
        Generate AI-powered proposal for a job
        Uses template + customization based on job details
        """
        print(f"\n✍️ GENERATING PROPOSAL: {job['title'][:50]}...")
        
        # Analyze job requirements
        requirements = self.analyze_requirements(job['description'])
        
        # Generate customized proposal
        proposal = {
            "job_id": job['id'],
            "job_title": job['title'],
            "generated_at": datetime.now().isoformat(),
            "cover_letter": self.create_cover_letter(job, requirements),
            "bid_amount": self.calculate_bid(job),
            "estimated_duration": self.estimate_duration(job),
            "requirements_addressed": requirements,
            "confidence_score": self.calculate_confidence(job, requirements)
        }
        
        # Save proposal
        proposals_dir = self.data_dir / "proposals"
        proposals_dir.mkdir(exist_ok=True)
        
        proposal_file = proposals_dir / f"proposal_{job['id'][:20]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(proposal_file, 'w', encoding='utf-8') as f:
            json.dump(proposal, f, indent=2)
        
        # Update metrics
        self.metrics['proposals_generated'] += 1
        self.save_metrics()
        
        print(f"  ✅ Proposal generated (confidence: {proposal['confidence_score']}%)")
        return proposal
    
    def analyze_requirements(self, description: str) -> List[str]:
        """Analyze job description to extract requirements"""
        requirements = []
        
        # Common requirement keywords
        keywords = {
            "python": ["python", "django", "flask", "fastapi"],
            "automation": ["automation", "automate", "script", "bot"],
            "web_scraping": ["scraping", "scrape", "crawl", "extract data"],
            "api": ["api", "rest", "graphql", "integration"],
            "security": ["security", "penetration", "vulnerability", "pentest"],
            "testing": ["testing", "test", "qa", "quality assurance"]
        }
        
        description_lower = description.lower()
        
        for category, terms in keywords.items():
            if any(term in description_lower for term in terms):
                requirements.append(category)
        
        return requirements
    
    def create_cover_letter(self, job: Dict, requirements: List[str]) -> str:
        """Create customized cover letter"""
        
        # Opening
        opening = f"Hi there,\n\nI'm excited about your project: \"{job['title']}\".\n\n"
        
        # Experience section based on requirements
        experience = "I have extensive experience in:\n"
        
        experience_map = {
            "python": "- Python development (5+ years) with Django, Flask, and automation frameworks",
            "automation": "- Building automation systems that save time and increase efficiency",
            "web_scraping": "- Web scraping and data extraction from various sources",
            "api": "- API development and integration with third-party services",
            "security": "- Security testing, vulnerability assessment, and penetration testing",
            "testing": "- Quality assurance and comprehensive testing methodologies"
        }
        
        for req in requirements:
            if req in experience_map:
                experience += experience_map[req] + "\n"
        
        # Approach
        approach = "\nMy approach:\n"
        approach += "1. Understand your specific requirements in detail\n"
        approach += "2. Develop a clear project plan with milestones\n"
        approach += "3. Implement with clean, maintainable code\n"
        approach += "4. Test thoroughly before delivery\n"
        approach += "5. Provide documentation and support\n\n"
        
        # Closing
        closing = "I'm available to start immediately and can deliver high-quality results.\n\n"
        closing += "Let's discuss your project in detail. I'm confident I can exceed your expectations.\n\n"
        closing += "Best regards"
        
        return opening + experience + approach + closing
    
    def calculate_bid(self, job: Dict) -> int:
        """Calculate appropriate bid amount"""
        if job.get('budget'):
            # Bid slightly below budget to be competitive
            return int(job['budget'] * 0.85)
        else:
            # Default based on hourly rate and estimated hours
            return self.config['hourly_rate_min'] * 10  # Assume 10 hours
    
    def estimate_duration(self, job: Dict) -> str:
        """Estimate project duration"""
        description_lower = job['description'].lower()
        
        if 'urgent' in description_lower or 'asap' in description_lower:
            return "1-3 days"
        elif 'quick' in description_lower or 'simple' in description_lower:
            return "3-5 days"
        elif 'complex' in description_lower or 'large' in description_lower:
            return "2-4 weeks"
        else:
            return "1-2 weeks"
    
    def calculate_confidence(self, job: Dict, requirements: List[str]) -> int:
        """Calculate confidence score for winning this job"""
        score = 50  # Base score
        
        # Boost for matching requirements
        score += len(requirements) * 10
        
        # Boost for appropriate budget
        if job.get('budget') and job['budget'] >= self.config['min_budget']:
            score += 15
        
        # Cap at 95%
        return min(score, 95)
    
    def submit_proposal(self, proposal: Dict) -> bool:
        """
        Submit proposal to Upwork
        NOTE: This requires manual submission for now (no official API access)
        """
        print(f"\n📤 PROPOSAL READY FOR SUBMISSION")
        print(f"  Job: {proposal['job_title']}")
        print(f"  Bid: ${proposal['bid_amount']}")
        print(f"  Confidence: {proposal['confidence_score']}%")
        print(f"\n  ⚠️ MANUAL SUBMISSION REQUIRED")
        print(f"  Copy the proposal from: {self.data_dir}/proposals/")
        
        # Mark as ready for submission
        proposal['status'] = 'ready_for_submission'
        proposal['submitted_at'] = None
        
        # In a real system with API access, this would actually submit
        # For now, we track it as "ready" and user submits manually
        
        return True
    
    def track_application(self, job_id: str, status: str):
        """Track application status"""
        applications_file = self.data_dir / "applications.json"
        
        applications = []
        if applications_file.exists():
            with open(applications_file, 'r', encoding='utf-8') as f:
                applications = json.load(f)
        
        application = {
            "job_id": job_id,
            "status": status,
            "updated_at": datetime.now().isoformat()
        }
        
        applications.append(application)
        
        with open(applications_file, 'w', encoding='utf-8') as f:
            json.dump(applications, f, indent=2)
        
        # Update metrics
        if status == 'sent':
            self.metrics['applications_sent'] += 1
        elif status == 'won':
            self.metrics['jobs_won'] += 1
        
        self.calculate_win_rate()
        self.save_metrics()
    
    def calculate_win_rate(self):
        """Calculate win rate"""
        if self.metrics['applications_sent'] > 0:
            self.metrics['win_rate'] = (self.metrics['jobs_won'] / self.metrics['applications_sent']) * 100
        else:
            self.metrics['win_rate'] = 0.0
    
    def add_revenue(self, amount: int, job_id: str):
        """Add revenue from won job"""
        self.metrics['revenue_earned'] += amount
        self.save_metrics()
        
        # Log revenue
        revenue_file = self.data_dir / "revenue.json"
        revenue_log = []
        
        if revenue_file.exists():
            with open(revenue_file, 'r', encoding='utf-8') as f:
                revenue_log = json.load(f)
        
        revenue_log.append({
            "job_id": job_id,
            "amount": amount,
            "date": datetime.now().isoformat()
        })
        
        with open(revenue_file, 'w', encoding='utf-8') as f:
            json.dump(revenue_log, f, indent=2)
        
        print(f"💰 Revenue added: ${amount}")
    
    def get_metrics(self) -> Dict:
        """Get current metrics for dashboard"""
        return self.metrics
    
    def export_for_dashboard(self):
        """Export metrics in format for 3D dashboard"""
        dashboard_data = {
            "metrics": self.metrics,
            "last_updated": datetime.now().isoformat(),
            "status": "active"
        }
        
        # Export to location dashboard can read
        export_file = self.base_dir / "output" / "dashboard_data.json"
        with open(export_file, 'w', encoding='utf-8') as f:
            json.dump(dashboard_data, f, indent=2)
        
        print(f"\n📊 Dashboard data exported: {export_file}")
        return dashboard_data
    
    def run_full_cycle(self):
        """Run complete job discovery and proposal generation cycle"""
        print("\n" + "="*80)
        print("🚀 STARTING FULL UPWORK AUTOMATION CYCLE")
        print("="*80)
        
        # Step 1: Discover jobs
        jobs = self.discover_jobs()
        
        if not jobs:
            print("\n⚠️ No matching jobs found this cycle")
            return
        
        # Step 2: Generate proposals for top jobs
        proposals = []
        max_proposals = min(len(jobs), self.config['max_proposals_per_day'])
        
        print(f"\n📝 Generating proposals for top {max_proposals} jobs...")
        
        for job in jobs[:max_proposals]:
            proposal = self.generate_proposal(job)
            proposals.append(proposal)
            time.sleep(1)  # Rate limiting
        
        # Step 3: Export for dashboard
        self.export_for_dashboard()
        
        # Step 4: Summary
        print("\n" + "="*80)
        print("✅ CYCLE COMPLETE")
        print("="*80)
        print(f"📊 Jobs discovered: {len(jobs)}")
        print(f"✍️ Proposals generated: {len(proposals)}")
        print(f"💰 Total revenue: ${self.metrics['revenue_earned']}")
        print(f"📈 Win rate: {self.metrics['win_rate']:.1f}%")
        print("\n📁 Check {self.data_dir}/proposals/ for generated proposals")
        print("⚠️ Submit proposals manually on Upwork")
        
        return {
            "jobs": jobs,
            "proposals": proposals,
            "metrics": self.metrics
        }


def main():
    """Main entry point"""
    print("""
================================================================================
                    UPWORK INTEGRATION ENGINE
                Real Backend for ParallelProfit™
================================================================================

This system will:
1. Discover real jobs from Upwork RSS feeds
2. Generate AI-powered proposals
3. Track applications and wins
4. Calculate real revenue metrics
5. Export data for 3D dashboard

Starting engine...
    """)
    
    engine = UpworkIntegrationEngine()
    
    # Run full cycle
    results = engine.run_full_cycle()
    
    print("\n" + "="*80)
    print("🎉 ENGINE READY")
    print("="*80)
    print("\nNext steps:")
    print("1. Check output/upwork_data/proposals/ for generated proposals")
    print("2. Submit proposals manually on Upwork")
    print("3. Update status: engine.track_application(job_id, 'sent')")
    print("4. When you win: engine.add_revenue(amount, job_id)")
    print("5. Dashboard will show real metrics!")
    
    return engine


if __name__ == "__main__":
    engine = main()
