#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
🚀 ACTIVE MONEY MAKER - Real-time Upwork Job Hunter
Finds jobs RIGHT NOW and generates ready-to-submit proposals
"""

import json
import requests
from datetime import datetime
from pathlib import Path
from bs4 import BeautifulSoup
import time

class ActiveMoneyMaker:
    """Real-time job discovery and proposal generation"""
    
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.output_dir = self.base_dir / "output" / "active_jobs"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Upwork RSS feeds (public, no auth needed)
        self.upwork_rss_feeds = [
            "https://www.upwork.com/ab/feed/jobs/rss?q=security+scan&sort=recency",
            "https://www.upwork.com/ab/feed/jobs/rss?q=vulnerability+assessment&sort=recency",
            "https://www.upwork.com/ab/feed/jobs/rss?q=penetration+testing&sort=recency",
            "https://www.upwork.com/ab/feed/jobs/rss?q=security+audit&sort=recency"
        ]
        
        self.log("💰 Active Money Maker Started")
    
    def log(self, msg):
        """Log with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {msg}")
    
    def fetch_upwork_jobs(self):
        """Fetch latest Upwork jobs from RSS feeds"""
        self.log("🔍 Scanning Upwork for NEW jobs...")
        
        all_jobs = []
        
        for feed_url in self.upwork_rss_feeds:
            try:
                self.log(f"  → Checking: {feed_url.split('q=')[1].split('&')[0]}")
                
                # Fetch RSS feed
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                response = requests.get(feed_url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    # Parse RSS
                    soup = BeautifulSoup(response.content, 'xml')
                    items = soup.find_all('item')
                    
                    for item in items[:5]:  # Top 5 from each feed
                        job = {
                            'title': item.find('title').text if item.find('title') else 'Unknown',
                            'link': item.find('link').text if item.find('link') else '',
                            'description': item.find('description').text if item.find('description') else '',
                            'pubDate': item.find('pubDate').text if item.find('pubDate') else '',
                            'source': 'upwork'
                        }
                        
                        # Extract budget if available
                        desc = job['description'].lower()
                        if 'budget' in desc or '$' in desc:
                            # Try to extract budget
                            import re
                            budget_match = re.search(r'\$(\d+)', desc)
                            if budget_match:
                                job['budget'] = int(budget_match.group(1))
                            else:
                                job['budget'] = 300  # Default
                        else:
                            job['budget'] = 300
                        
                        # Check if urgent
                        urgent_keywords = ['urgent', 'asap', 'immediately', 'today', 'now', 'emergency']
                        job['urgent'] = any(kw in job['title'].lower() or kw in desc for kw in urgent_keywords)
                        
                        all_jobs.append(job)
                    
                    self.log(f"  ✅ Found {len(items[:5])} jobs")
                else:
                    self.log(f"  ⚠️  Feed unavailable (status {response.status_code})")
                    
            except Exception as e:
                self.log(f"  ⚠️  Error: {str(e)[:50]}")
        
        # Remove duplicates
        unique_jobs = []
        seen_links = set()
        for job in all_jobs:
            if job['link'] not in seen_links:
                unique_jobs.append(job)
                seen_links.add(job['link'])
        
        self.log(f"✅ Total unique jobs found: {len(unique_jobs)}")
        return unique_jobs
    
    def generate_proposal(self, job):
        """Generate custom proposal for job"""
        title = job['title']
        budget = job.get('budget', 300)
        urgent = job.get('urgent', False)
        
        # Calculate optimal price
        if urgent:
            price = int(budget * 0.85)  # 85% for urgent
        else:
            price = int(budget * 0.75)  # 75% for normal
        
        # Ensure minimum
        if price < 200:
            price = 200
        
        # Generate proposal
        proposal = f"""Subject: 2-Hour Security Scan - Available NOW

Hi there,

I see you need {title.lower()}. I specialize in fast, comprehensive security assessments using enterprise automation.

✅ What You Get:
• Complete vulnerability scan (100+ automated checks)
• Professional PDF report with security score
• Critical issues flagged immediately
• Step-by-step remediation guide
• 30-day support included

✅ Why Choose Me:
• 2-hour delivery (vs 5-7 days competitors)
• 80x faster automation (enterprise tools)
• Available NOW - can start immediately
• Fixed price - no surprises

Fixed Price: ${price}
Timeline: 2 hours from start
Guarantee: Full refund if not satisfied

Ready to secure your system today?

Best regards,
[Your Name]
Security Automation Specialist
"""
        
        return proposal, price
    
    def save_opportunities(self, jobs):
        """Save job opportunities with proposals"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save jobs data
        jobs_file = self.output_dir / f"jobs_{timestamp}.json"
        with open(jobs_file, 'w', encoding='utf-8') as f:
            json.dump(jobs, f, indent=2)
        
        self.log(f"💾 Saved jobs to: {jobs_file}")
        
        # Generate proposals for each
        proposals_dir = self.output_dir / f"proposals_{timestamp}"
        proposals_dir.mkdir(exist_ok=True)
        
        summary = []
        
        for idx, job in enumerate(jobs, 1):
            proposal, price = self.generate_proposal(job)
            
            # Save proposal
            proposal_file = proposals_dir / f"proposal_{idx}.txt"
            with open(proposal_file, 'w', encoding='utf-8') as f:
                f.write(f"JOB: {job['title']}\n")
                f.write(f"LINK: {job['link']}\n")
                f.write(f"BUDGET: ${job.get('budget', 300)}\n")
                f.write(f"YOUR PRICE: ${price}\n")
                f.write(f"URGENT: {'YES ⚡' if job.get('urgent') else 'No'}\n")
                f.write(f"\n{'='*60}\n\n")
                f.write(proposal)
            
            summary.append({
                'job': job['title'][:50],
                'link': job['link'],
                'your_price': price,
                'urgent': job.get('urgent', False),
                'proposal_file': str(proposal_file)
            })
        
        # Save summary
        summary_file = self.output_dir / f"APPLY_NOW_{timestamp}.md"
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write(f"# 🚀 APPLY TO THESE JOBS NOW\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**Total Opportunities:** {len(jobs)}\n\n")
            f.write(f"---\n\n")
            
            for idx, item in enumerate(summary, 1):
                urgent_flag = " ⚡ URGENT" if item['urgent'] else ""
                f.write(f"## Job {idx}{urgent_flag}\n\n")
                f.write(f"**Title:** {item['job']}\n\n")
                f.write(f"**Your Price:** ${item['your_price']}\n\n")
                f.write(f"**Link:** {item['link']}\n\n")
                f.write(f"**Proposal:** `{item['proposal_file']}`\n\n")
                f.write(f"---\n\n")
        
        self.log(f"📋 Summary saved to: {summary_file}")
        self.log(f"✅ {len(jobs)} proposals ready in: {proposals_dir}")
        
        return summary_file
    
    def run(self):
        """Main execution"""
        self.log("="*60)
        self.log("🚀 FINDING MONEY-MAKING OPPORTUNITIES NOW")
        self.log("="*60)
        
        # Fetch jobs
        jobs = self.fetch_upwork_jobs()
        
        if not jobs:
            self.log("⚠️  No jobs found. Upwork RSS may be unavailable.")
            self.log("💡 Manual action: Go to upwork.com/jobs and search 'security scan'")
            return
        
        # Save opportunities
        summary_file = self.save_opportunities(jobs)
        
        self.log("="*60)
        self.log("✅ READY TO MAKE MONEY")
        self.log("="*60)
        self.log(f"\n📋 Next Steps:")
        self.log(f"1. Open: {summary_file}")
        self.log(f"2. Click each job link")
        self.log(f"3. Copy-paste the proposal")
        self.log(f"4. Submit application")
        self.log(f"\n⏱️  Time: 2-3 minutes per job")
        self.log(f"💰 Potential: ${sum(j.get('budget', 300) for j in jobs[:10])}")
        
        return summary_file

if __name__ == "__main__":
    maker = ActiveMoneyMaker()
    maker.run()
