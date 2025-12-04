#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
# -*- coding: utf-8 -*-
"""
Complete Money-Making Toolkit
Every practical tool to maximize earnings TODAY
"""

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

class MoneyMakingToolkit:
    """
    Every tool needed to make money faster and more efficiently
    """
    
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.output_dir = self.base_dir / "output"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    # TOOL 1: SMART PROPOSAL GENERATOR
    def generate_optimized_proposal(self, job_details: Dict) -> str:
        """
        Generate proposal optimized for highest win rate
        Based on job budget, urgency, client history
        """
        budget = job_details.get("budget", 300)
        is_urgent = any(word in job_details.get("title", "").lower() 
                       for word in ["urgent", "asap", "emergency", "today"])
        client_verified = job_details.get("payment_verified", True)
        
        # Price optimization
        if is_urgent:
            suggested_price = min(budget * 0.8, budget - 50)  # Slightly under budget
        else:
            suggested_price = budget * 0.75  # More competitive
        
        # Proposal template selection
        if is_urgent:
            template = self._urgent_template(job_details, suggested_price)
        else:
            template = self._standard_template(job_details, suggested_price)
        
        return template
    
    def _urgent_template(self, job: Dict, price: float) -> str:
        """Urgent job template (highest win rate)"""
        return f"""Subject: Available NOW - 2-Hour Delivery

Hi {job.get('client_name', 'there')},

I'm a military veteran specializing in security automation. I can start YOUR project immediately.

What I'll deliver in 2 hours:
✅ Complete vulnerability scan (100+ automated checks)
✅ Professional report with security score
✅ Critical issues flagged immediately  
✅ Step-by-step fix instructions
✅ 30-day support included

My military background = reliability + discipline + on-time delivery guaranteed.

Fixed Price: ${price:.0f}
Start Time: Immediately upon hire
Delivery: 2 hours from start

I'm online now and ready. Let's secure your system today.

Best,
[Your Name]
U.S. Military Veteran | Security Automation Specialist"""
    
    def _standard_template(self, job: Dict, price: float) -> str:
        """Standard job template"""
        return f"""Subject: Military Veteran - 2-Hour Security Scan

Hi {job.get('client_name', 'there')},

I'm a military veteran who transitioned into cybersecurity through years of intensive study and automation system training.

What I'll deliver:
✅ Complete vulnerability assessment (100+ checks)
✅ Exploitability verification (proof vulnerabilities are real)
✅ Professional report (executive + technical)
✅ Remediation roadmap
✅ 30-day support

My military background provides discipline, reliability, and mission-oriented approach. Your project will be delivered on time, every time.

Fixed Price: ${price:.0f}
Timeline: 2 hours from start
Guarantee: Full refund if not satisfied

Ready to start. Can deliver today.

Best,
[Your Name]
U.S. Military Veteran | Security Automation Specialist"""
    
    # TOOL 2: WIN RATE TRACKER
    def track_application(self, job_id: str, details: Dict):
        """Track every application to measure win rates"""
        tracker_file = self.output_dir / "application_tracker.json"
        
        if tracker_file.exists():
            with open(tracker_file, 'r') as f:
                data = json.load(f)
        else:
            data = {"applications": [], "stats": {}}
        
        data["applications"].append({
            "job_id": job_id,
            "timestamp": datetime.now().isoformat(),
            "budget": details.get("budget"),
            "is_urgent": details.get("is_urgent", False),
            "status": "submitted"
        })
        
        with open(tracker_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"✅ Application tracked: {job_id}")
        return data
    
    def update_application_status(self, job_id: str, status: str, revenue: float = 0):
        """Update when you win/lose"""
        tracker_file = self.output_dir / "application_tracker.json"
        
        with open(tracker_file, 'r') as f:
            data = json.load(f)
        
        for app in data["applications"]:
            if app["job_id"] == job_id:
                app["status"] = status
                app["revenue"] = revenue
                app["updated"] = datetime.now().isoformat()
        
        # Calculate win rate
        total = len(data["applications"])
        wins = sum(1 for app in data["applications"] if app["status"] == "won")
        data["stats"]["win_rate"] = f"{(wins/total*100):.1f}%" if total > 0 else "0%"
        data["stats"]["total_revenue"] = sum(app.get("revenue", 0) for app in data["applications"])
        
        with open(tracker_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"📊 Win Rate: {data['stats']['win_rate']}")
        print(f"💰 Total Revenue: ${data['stats']['total_revenue']:.0f}")
    
    # TOOL 3: PRICE OPTIMIZER
    def suggest_optimal_price(self, job_budget: float, urgency: str, client_history: Dict) -> Dict:
        """Suggest best price to win while maximizing revenue"""
        
        base_price = job_budget * 0.75  # Start at 75% of budget
        
        # Adjust for urgency
        if urgency == "extreme":  # ASAP, emergency, today
            price = base_price * 1.1  # Can charge MORE for urgent
        elif urgency == "high":  # urgent, fast
            price = base_price
        else:
            price = base_price * 0.9  # Competitive for normal jobs
        
        # Adjust for client quality
        if client_history.get("payment_verified") and client_history.get("reviews_count", 0) > 10:
            price = price * 1.05  # Quality clients pay more
        
        # Adjust for your review count
        your_reviews = client_history.get("your_reviews", 0)
        if your_reviews > 10:
            price = price * 1.1  # You can charge more with reviews
        elif your_reviews > 5:
            price = price * 1.05
        
        return {
            "suggested_price": round(price, 0),
            "min_price": round(price * 0.9, 0),
            "max_price": round(price * 1.2, 0),
            "reasoning": f"Based on {urgency} urgency, client quality, and your profile strength"
        }
    
    # TOOL 4: FOLLOW-UP AUTOMATION
    def generate_follow_up_messages(self, days_since_application: int) -> Optional[str]:
        """Auto-generate follow-up messages to increase win rate"""
        
        if days_since_application == 1:
            return """Hi [Client],

Just following up on my proposal for your security scan project. I'm still available to start immediately and can deliver in 2 hours.

Happy to answer any questions!

Best,
[Your Name]"""
        
        elif days_since_application == 3:
            return """Hi [Client],

Wanted to check if you had any questions about the security scan. I've completed similar projects for [X] clients with great results.

Still available and ready to start today.

Best,
[Your Name]"""
        
        return None
    
    # TOOL 5: CLIENT VALUE SCORER
    def score_client_value(self, client_data: Dict) -> Dict:
        """Score clients to prioritize high-value opportunities"""
        score = 0
        flags = []
        
        # Payment verified
        if client_data.get("payment_verified"):
            score += 20
            flags.append("✅ Payment verified")
        else:
            flags.append("⚠️ Payment NOT verified")
        
        # Spending history
        spent = client_data.get("total_spent", 0)
        if spent > 10000:
            score += 30
            flags.append("✅ High spender ($10K+)")
        elif spent > 1000:
            score += 20
            flags.append("✅ Good spender ($1K+)")
        elif spent == 0:
            score += 5
            flags.append("⚠️ New client (no history)")
        
        # Reviews
        rating = client_data.get("rating", 0)
        if rating >= 4.8:
            score += 20
            flags.append("✅ Excellent rating (4.8+)")
        elif rating >= 4.0:
            score += 10
            flags.append("✅ Good rating (4.0+)")
        else:
            flags.append("⚠️ Low rating")
        
        # Hire rate
        hire_rate = client_data.get("hire_rate", 0)
        if hire_rate >= 75:
            score += 20
            flags.append("✅ High hire rate (75%+)")
        elif hire_rate >= 50:
            score += 10
            flags.append("✅ Good hire rate (50%+)")
        else:
            flags.append("⚠️ Low hire rate")
        
        # Active jobs
        active = client_data.get("active_jobs", 0)
        if active > 5:
            score += 10
            flags.append("✅ Very active client")
        
        # Overall assessment
        if score >= 80:
            assessment = "🎯 PRIORITY - High value client"
        elif score >= 60:
            assessment = "✅ GOOD - Apply confidently"
        elif score >= 40:
            assessment = "⚠️ MODERATE - Proceed with caution"
        else:
            assessment = "❌ SKIP - Low value/high risk"
        
        return {
            "score": score,
            "assessment": assessment,
            "flags": flags,
            "recommend_apply": score >= 40
        }
    
    # TOOL 6: REVENUE MAXIMIZER
    def calculate_daily_earning_potential(self) -> Dict:
        """Calculate how much you can earn today"""
        
        # Based on your current capabilities
        hours_available = 8  # Work day
        scan_time = 2  # Hours per scan
        max_scans_per_day = hours_available / scan_time  # 4 scans
        
        avg_price_low = 200
        avg_price_high = 500
        
        # Conservative estimate (50% win rate after 10+ reviews)
        applications_needed_low = 20
        expected_wins_low = 2
        
        # Optimistic estimate (30% win rate with good proposals)
        applications_needed_high = 10
        expected_wins_high = 3
        
        return {
            "max_scans_per_day": max_scans_per_day,
            "conservative": {
                "applications_needed": applications_needed_low,
                "expected_wins": expected_wins_low,
                "revenue_low": expected_wins_low * avg_price_low,
                "revenue_high": expected_wins_low * avg_price_high,
                "time_required": "20 applications (40 min) + 2 scans (4 hours) = 4.67 hours"
            },
            "optimistic": {
                "applications_needed": applications_needed_high,
                "expected_wins": expected_wins_high,
                "revenue_low": expected_wins_high * avg_price_low,
                "revenue_high": expected_wins_high * avg_price_high,
                "time_required": "10 applications (20 min) + 3 scans (6 hours) = 6.33 hours"
            },
            "today_target": {
                "min_revenue": expected_wins_low * avg_price_low,
                "max_revenue": expected_wins_high * avg_price_high,
                "applications_to_send": 10,
                "expected_result": "$400-$1,500"
            }
        }
    
    # TOOL 7: QUICK PROPOSAL GENERATOR (Screenshot-based)
    def extract_job_from_screenshot_text(self, ocr_text: str) -> Dict:
        """Extract job details from screenshot OCR text"""
        import re
        
        details = {}
        
        # Extract budget
        budget_match = re.search(r'\$(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)', ocr_text)
        if budget_match:
            details["budget"] = float(budget_match.group(1).replace(',', ''))
        
        # Detect urgency
        urgent_keywords = ["urgent", "asap", "emergency", "immediately", "today", "now"]
        details["is_urgent"] = any(word in ocr_text.lower() for word in urgent_keywords)
        
        # Extract title (usually first line or near "title")
        lines = ocr_text.split('\n')
        details["title"] = lines[0] if lines else "Security Scan Project"
        
        # Detect payment verified
        details["payment_verified"] = "payment verified" in ocr_text.lower()
        
        return details
    
    # TOOL 8: DASHBOARD GENERATOR
    def generate_money_dashboard(self) -> str:
        """Show current earnings, applications, win rate"""
        tracker_file = self.output_dir / "application_tracker.json"
        
        if not tracker_file.exists():
            return "📊 No applications tracked yet. Start applying!"
        
        with open(tracker_file, 'r') as f:
            data = json.load(f)
        
        stats = data.get("stats", {})
        apps = data.get("applications", [])
        
        # Today's stats
        today = datetime.now().date()
        today_apps = [a for a in apps if datetime.fromisoformat(a["timestamp"]).date() == today]
        today_wins = [a for a in today_apps if a.get("status") == "won"]
        today_revenue = sum(a.get("revenue", 0) for a in today_wins)
        
        # This week
        week_start = today - timedelta(days=today.weekday())
        week_apps = [a for a in apps if datetime.fromisoformat(a["timestamp"]).date() >= week_start]
        week_wins = [a for a in week_apps if a.get("status") == "won"]
        week_revenue = sum(a.get("revenue", 0) for a in week_wins)
        
        dashboard = f"""
{'='*60}
💰 MONEY-MAKING DASHBOARD
{'='*60}

📅 TODAY:
  • Applications: {len(today_apps)}
  • Wins: {len(today_wins)}
  • Revenue: ${today_revenue:.0f}

📅 THIS WEEK:
  • Applications: {len(week_apps)}
  • Wins: {len(week_wins)}
  • Revenue: ${week_revenue:.0f}

📊 ALL TIME:
  • Total Applications: {len(apps)}
  • Win Rate: {stats.get('win_rate', 'N/A')}
  • Total Revenue: ${stats.get('total_revenue', 0):.0f}

🎯 NEXT ACTIONS:
  • Need {10 - len(today_apps)} more applications today (target: 10)
  • Expected earnings today: ${len(today_apps) * 0.3 * 350:.0f}

{'='*60}
"""
        return dashboard


def main():
    """CLI interface"""
    import sys
    
    toolkit = MoneyMakingToolkit()
    
    if len(sys.argv) < 2:
        print("💰 Money-Making Toolkit Commands:")
        print("  proposal <job_id> <budget> <urgent>  - Generate optimized proposal")
        print("  price <budget> <urgency> - Get optimal price suggestion")
        print("  score <client_data_json> - Score client value")
        print("  potential - Calculate daily earning potential")
        print("  dashboard - Show earnings dashboard")
        print("  track <job_id> <budget> - Track application")
        print("  won <job_id> <revenue> - Mark as won")
        return
    
    command = sys.argv[1]
    
    if command == "proposal":
        job_details = {
            "job_id": sys.argv[2] if len(sys.argv) > 2 else "job1",
            "budget": float(sys.argv[3]) if len(sys.argv) > 3 else 300,
            "is_urgent": sys.argv[4].lower() == "true" if len(sys.argv) > 4 else False,
            "client_name": "there"
        }
        proposal = toolkit.generate_optimized_proposal(job_details)
        print(proposal)
    
    elif command == "price":
        budget = float(sys.argv[2]) if len(sys.argv) > 2 else 300
        urgency = sys.argv[3] if len(sys.argv) > 3 else "normal"
        result = toolkit.suggest_optimal_price(budget, urgency, {})
        print(json.dumps(result, indent=2))
    
    elif command == "potential":
        result = toolkit.calculate_daily_earning_potential()
        print(json.dumps(result, indent=2))
    
    elif command == "dashboard":
        print(toolkit.generate_money_dashboard())
    
    elif command == "track":
        job_id = sys.argv[2] if len(sys.argv) > 2 else "job1"
        budget = float(sys.argv[3]) if len(sys.argv) > 3 else 300
        toolkit.track_application(job_id, {"budget": budget})
    
    elif command == "won":
        job_id = sys.argv[2] if len(sys.argv) > 2 else "job1"
        revenue = float(sys.argv[3]) if len(sys.argv) > 3 else 300
        toolkit.update_application_status(job_id, "won", revenue)


if __name__ == "__main__":
    main()

