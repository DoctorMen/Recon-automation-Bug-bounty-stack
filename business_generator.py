#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
BUSINESS GENERATOR - Automated Business Launch System
Turns your Master System documentation into executable businesses

Usage:
    python3 business_generator.py --business security_scanning
    python3 business_generator.py --business knowledge_audit
    python3 business_generator.py --business vibe_coding
    python3 business_generator.py --list  # Show all available businesses
"""

import os
import sys
import json
import argparse
from datetime import datetime
from pathlib import Path

class BusinessGenerator:
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.output_dir = self.base_dir / "generated_businesses"
        self.output_dir.mkdir(exist_ok=True)
        
        # Business templates from your Master System
        self.businesses = {
            "security_scanning": {
                "name": "Security Scanning Service",
                "description": "Automated security scans for clients",
                "revenue_potential": "$2K-$10K/month",
                "time_to_launch": "2 hours",
                "platforms": ["Upwork", "Fiverr", "Direct"],
                "setup_time": "2 hours"
            },
            "knowledge_audit": {
                "name": "Knowledge Debt Consulting",
                "description": "Help companies organize documentation",
                "revenue_potential": "$5K-$50K/month",
                "time_to_launch": "1 hour",
                "platforms": ["LinkedIn", "Direct", "Consulting"],
                "setup_time": "1 hour"
            },
            "vibe_coding": {
                "name": "Vibe Coding Consulting",
                "description": "Teach developers AI-assisted development",
                "revenue_potential": "$3K-$20K/month",
                "time_to_launch": "30 minutes",
                "platforms": ["Email", "Reddit", "Twitter"],
                "setup_time": "30 minutes"
            },
            "proposal_writing": {
                "name": "Proposal Writing Service",
                "description": "Write winning proposals for freelancers",
                "revenue_potential": "$1K-$5K/month",
                "time_to_launch": "1 hour",
                "platforms": ["Upwork", "Reddit", "Twitter"],
                "setup_time": "1 hour"
            },
            "automation_consulting": {
                "name": "Automation Consulting",
                "description": "Help businesses automate workflows",
                "revenue_potential": "$5K-$30K/month",
                "time_to_launch": "2 hours",
                "platforms": ["LinkedIn", "Direct", "Referral"],
                "setup_time": "2 hours"
            }
        }
    
    def list_businesses(self):
        """List all available businesses"""
        print("\n" + "="*60)
        print("🚀 AVAILABLE BUSINESSES TO GENERATE")
        print("="*60 + "\n")
        
        for biz_id, biz in self.businesses.items():
            print(f"Business ID: {biz_id}")
            print(f"Name: {biz['name']}")
            print(f"Description: {biz['description']}")
            print(f"Revenue Potential: {biz['revenue_potential']}")
            print(f"Launch Time: {biz['time_to_launch']}")
            print(f"Platforms: {', '.join(biz['platforms'])}")
            print("-" * 60 + "\n")
    
    def generate_business(self, business_id):
        """Generate complete business setup"""
        if business_id not in self.businesses:
            print(f"❌ Error: Business '{business_id}' not found")
            print("Run with --list to see available businesses")
            return False
        
        biz = self.businesses[business_id]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        biz_dir = self.output_dir / f"{business_id}_{timestamp}"
        biz_dir.mkdir(exist_ok=True)
        
        print("\n" + "="*60)
        print(f"🚀 GENERATING: {biz['name']}")
        print("="*60 + "\n")
        
        # Generate all necessary files
        self._generate_overview(biz_dir, business_id, biz)
        self._generate_action_plan(biz_dir, business_id, biz)
        self._generate_proposals(biz_dir, business_id, biz)
        self._generate_tracking(biz_dir, business_id, biz)
        self._generate_ai_prompts(biz_dir, business_id, biz)
        
        print(f"\n✅ Business generated successfully!")
        print(f"📁 Location: {biz_dir}")
        print(f"\n🎯 Next Steps:")
        print(f"   1. Open: {biz_dir}/ACTION_PLAN.md")
        print(f"   2. Follow the checklist (takes {biz['setup_time']})")
        print(f"   3. Start making money!")
        print(f"\n💰 Revenue Potential: {biz['revenue_potential']}\n")
        
        return True
    
    def _generate_overview(self, biz_dir, biz_id, biz):
        """Generate business overview document"""
        content = f"""# {biz['name']} - Business Overview

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Business ID:** {biz_id}
**Status:** Ready to Launch

---

## 📊 Business Summary

**Description:** {biz['description']}
**Revenue Potential:** {biz['revenue_potential']}
**Time to Launch:** {biz['time_to_launch']}
**Platforms:** {', '.join(biz['platforms'])}

---

## 🎯 Value Proposition

### What You Offer:
"""
        
        # Add business-specific value props
        if biz_id == "security_scanning":
            content += """
- Professional security scans in 2-4 hours (vs 1-2 days competitors)
- 100+ automated security checks (Nuclei, OWASP Top 10)
- Military veteran credibility (trust factor)
- Same-day delivery with professional PDF report
- 30-day support included
"""
        elif biz_id == "knowledge_audit":
            content += """
- Documentation audit in 2 hours (identify "knowledge debt")
- Clear action plan to cut docs by 50-70%
- Implementation guidance
- ROI: 20-30% productivity increase for their team
- Based on personal experience (credibility)
"""
        elif biz_id == "vibe_coding":
            content += """
- 1-hour crash course in AI-assisted development
- Learn Cursor, ChatGPT, Claude for coding
- Reduce development time by 50-80%
- Get actual working code during session
- Learn patterns you can reuse forever
"""
        elif biz_id == "proposal_writing":
            content += """
- Professional proposals written in 30 minutes
- Proven templates with 15-25% win rate
- Customized to job requirements
- Price optimization included
- Guaranteed delivery in 24 hours
"""
        elif biz_id == "automation_consulting":
            content += """
- Identify automation opportunities (save 10-20 hours/week)
- Build custom automation scripts
- AI-powered workflow optimization
- Training on how to maintain systems
- ROI: 10-20x return on investment
"""
        
        content += """
---

## 💰 Pricing Strategy

### Tier 1: Entry (Quick Win)
- **Price:** $200-$500
- **Delivery:** 2-4 hours
- **Target:** First 10 clients (build reviews)

### Tier 2: Standard (Sustainable)
- **Price:** $500-$1,500
- **Delivery:** 1-2 days
- **Target:** Months 2-3 (recurring base)

### Tier 3: Premium (High Value)
- **Price:** $1,500-$5,000
- **Delivery:** 1 week
- **Target:** Month 4+ (established reputation)

---

## 📈 Revenue Projections

### Month 1: $2,000-$5,000
- 10-20 applications
- 2-5 clients won
- Average: $400-$1,000 per client
- Focus: Get reviews

### Month 2-3: $5,000-$15,000
- 20-40 applications
- 10-20 clients
- Average: $500-$1,500 per client
- Focus: Recurring clients

### Month 4-6: $10,000-$30,000
- Established reputation
- 20-40 clients
- 30% recurring revenue
- Focus: Premium pricing

---

## 🎯 Success Metrics

Track these weekly:
- [ ] Applications submitted
- [ ] Response rate
- [ ] Win rate
- [ ] Average project value
- [ ] Client satisfaction
- [ ] Referral rate

---

## 🚀 Ready to Launch?

Open: ACTION_PLAN.md for step-by-step execution plan.
"""
        
        with open(biz_dir / "OVERVIEW.md", "w") as f:
            f.write(content)
    
    def _generate_action_plan(self, biz_dir, biz_id, biz):
        """Generate actionable launch plan"""
        content = f"""# {biz['name']} - Action Plan

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

---

## ⚡ QUICK LAUNCH (Next {biz['setup_time']})

### ✅ PHASE 1: Setup (30 minutes)

"""
        
        # Platform-specific setup
        if "Upwork" in biz['platforms']:
            content += """
**Upwork Setup:**
- [ ] Create/update profile
- [ ] Add portfolio samples
- [ ] Write service description
- [ ] Set hourly rate ($50-$150)
"""
        
        if "Fiverr" in biz['platforms']:
            content += """
**Fiverr Setup:**
- [ ] Create seller account
- [ ] Create 2-3 gigs
- [ ] Add express delivery option
- [ ] Upload gig images
"""
        
        if "LinkedIn" in biz['platforms']:
            content += """
**LinkedIn Setup:**
- [ ] Update profile with new service
- [ ] Write launch post (see PROPOSALS.md)
- [ ] Join 3-5 relevant groups
- [ ] Prepare to DM 20 connections
"""
        
        content += """
---

### ✅ PHASE 2: First Outreach (30-60 minutes)

"""
        
        # Business-specific outreach
        if biz_id == "security_scanning":
            content += """
**Upwork Applications:**
- [ ] Search: "urgent security scan"
- [ ] Search: "penetration test needed ASAP"
- [ ] Search: "website vulnerability check"
- [ ] Apply to 10 jobs (use PROPOSALS.md templates)
- [ ] Price: $200-$400 for urgent work

**Fiverr Gigs:**
- [ ] Gig 1: "Website Security Scan - 4 Hour Delivery" ($200)
- [ ] Gig 2: "WordPress Security Audit" ($150)
- [ ] Gig 3: "URGENT Security Check - 2 Hour Rush" ($300)
"""
        
        elif biz_id == "knowledge_audit":
            content += """
**LinkedIn Post:**
- [ ] Write post about your documentation problem (see PROPOSALS.md)
- [ ] Post in 3-5 relevant groups
- [ ] Tag 10 connections who might need this

**Direct Outreach:**
- [ ] DM 20 founders/CTOs with personalized message
- [ ] Offer free 15-min audit (hook)
- [ ] Follow up within 24 hours

**Email Campaign:**
- [ ] Email 10 past clients/contacts
- [ ] Offer: "Free documentation audit - 15 minutes"
"""
        
        elif biz_id == "vibe_coding":
            content += """
**Email Outreach:**
- [ ] Email 10 developer friends/contacts
- [ ] Offer: "1-hour AI coding crash course - $100"
- [ ] Include: "You'll write actual code during session"

**Reddit/Discord:**
- [ ] Post in r/learnprogramming (offer consultation)
- [ ] Post in r/Cursor (share your experience)
- [ ] Post in dev Discord servers

**Twitter/X:**
- [ ] Tweet about your vibe coding results
- [ ] Share code examples
- [ ] Offer paid consulting in bio
"""
        
        content += """
---

### ✅ PHASE 3: First Client (2-48 hours)

**When You Get First Response:**
- [ ] Respond within 5-15 minutes (critical!)
- [ ] Ask clarifying questions
- [ ] Send custom proposal (use templates)
- [ ] Close the deal fast

**Delivery Checklist:**
- [ ] Over-deliver on promises
- [ ] Communicate proactively
- [ ] Deliver early if possible
- [ ] Ask for review immediately
- [ ] Request referral if happy

---

## 📋 DAILY CHECKLIST (After Launch)

**Morning (30 minutes):**
- [ ] Check all platforms for messages
- [ ] Respond to any inquiries
- [ ] Apply to 5-10 new opportunities

**Afternoon (1 hour):**
- [ ] Deliver on active projects
- [ ] Follow up with prospects
- [ ] Update tracking spreadsheet

**Evening (30 minutes):**
- [ ] Post on relevant platforms
- [ ] Engage with potential clients
- [ ] Plan tomorrow's outreach

---

## 🎯 WEEK 1 GOALS

- [ ] 20-40 applications/outreach completed
- [ ] 5-10 responses received
- [ ] 1-3 clients won
- [ ] $500-$2,000 revenue generated
- [ ] 1-3 positive reviews obtained

---

## 💡 SUCCESS TIPS

1. **Speed Wins:** Respond within 15 minutes to inquiries
2. **Over-Deliver:** Give more than promised
3. **Ask for Reviews:** Immediately after delivery
4. **Follow Up:** Don't let leads go cold
5. **Track Everything:** Use TRACKING.md template

---

## 🚨 COMMON MISTAKES TO AVOID

❌ Applying to too many wrong jobs (quality > quantity)
❌ Pricing too low out of desperation (value your time)
❌ Not following up on responses (money left on table)
❌ Delivering late (kills reputation fast)
❌ Not asking for reviews (social proof is everything)

---

## 🚀 NEXT STEPS

1. Complete Phase 1 setup (30 min)
2. Start Phase 2 outreach (60 min)
3. Monitor for responses (check every 2 hours)
4. Win first client (deliver excellently)
5. Build to 10 clients (then scale)

**First $1,000 is 2-7 days away. Execute!**
"""
        
        with open(biz_dir / "ACTION_PLAN.md", "w") as f:
            f.write(content)
    
    def _generate_proposals(self, biz_dir, biz_id, biz):
        """Generate proposal templates"""
        content = f"""# {biz['name']} - Proposal Templates

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

---

## 📝 COPY-PASTE READY PROPOSALS

"""
        
        if biz_id == "security_scanning":
            content += """
### Template 1: Upwork Security Scan ($200-$400)

```
Hi [Client Name],

I can help you with this security assessment immediately.

As a military veteran turned cybersecurity professional, I provide:

✅ Complete security scan (100+ automated checks)
✅ 2-4 hour delivery (not days)
✅ Professional PDF report with remediation steps
✅ OWASP Top 10, CVEs, misconfigurations covered
✅ 30-day support included

For your [specific requirement]:
• Timeline: 2-4 hours from start to delivery
• Price: $[300-400]
• Deliverables: Full scan + report + support

I'm available to start immediately. Shall we begin?

Best regards,
[Your Name]
Military Veteran | Security Automation Specialist
```

### Template 2: Fiverr Security Gig Description

```
🛡️ PROFESSIONAL WEBSITE SECURITY SCAN - 4 HOUR DELIVERY

Military veteran security professional with automated scanning system.

WHAT YOU GET:
✅ 100+ security checks (Nuclei templates)
✅ OWASP Top 10 vulnerability assessment
✅ CVE detection and analysis
✅ Professional PDF report
✅ Step-by-step remediation guide
✅ 30-day support

DELIVERY: 2-4 hours (Express: 1-2 hours available)

WHY CHOOSE ME:
• Military-grade discipline and attention to detail
• Automated scanning system (fast + thorough)
• Professional reporting (client-ready)
• Available 24/7 for urgent requests

ORDER NOW for same-day security assessment!
```

### Template 3: LinkedIn Post (Knowledge Debt Angle)

```
🔒 Is your website secure? Most companies don't know.

I offer rapid security assessments using automated scanning:
• 100+ security checks in 2-4 hours
• Professional report with clear remediation steps
• Military veteran reliability

Perfect for:
• Startups launching products
• Companies without security team
• Pre-compliance audits

DM me for free quick check (5 minutes). 
Full scan: $300-$500 same-day delivery.

#cybersecurity #websecurity #startups
```
"""
        
        elif biz_id == "knowledge_audit":
            content += """
### Template 1: LinkedIn Post

```
I had 4,000+ lines of documentation for my business.

The problem? I couldn't find anything. Execution slowed to a crawl.

Last week I cut it to 500 lines that actually get used.

Result: Productivity tripled overnight.

This is called "Knowledge Debt" - when the cost of maintaining 
knowledge exceeds its value.

If you have:
• 100+ Notion pages nobody reads
• Confluence docs from 2019
• "Complete guides" that confuse more than help

You might have it too.

I'm offering free 15-minute documentation audits this week.

I'll analyze your docs and show you exactly what to cut/keep/reorganize.

DM me if interested. Limited spots available.

#productivity #documentation #startup #knowledgemanagement
```

### Template 2: Direct Outreach Email

```
Subject: Quick question about your documentation

Hi [Name],

I noticed [your company/team] has been growing rapidly. 
Quick question: How's your internal documentation holding up?

I ask because I just went through this myself. Built 4,000+ 
lines of docs that became impossible to navigate. Productivity 
tanked.

Cut it to 500 lines last week. Team productivity up 30%+.

I'm offering free 15-minute documentation audits. I'll show 
you what to cut, what to keep, and how to organize for actual use.

Interested? Takes 15 minutes on a call.

Best,
[Your Name]

P.S. If it's valuable, happy to do full cleanup for $500-$2,000 
(depending on size). But let's start with the free audit.
```

### Template 3: Paid Service Proposal

```
Hi [Name],

Based on our 15-minute audit, here's what I can do:

KNOWLEDGE DEBT CLEANUP SERVICE

What you get:
✅ Complete documentation audit
✅ Identify 50-70% that can be cut/consolidated
✅ Reorganize remaining docs for findability
✅ Create "just-in-time" documentation system
✅ Train your team on new system

Typical Results:
• 30-50% productivity increase
• Onboarding time cut in half
• Team can find what they need in <1 minute
• Less time documenting, more time executing

Investment:
• Small team (10-50 docs): $500-$1,500
• Medium (50-200 docs): $1,500-$5,000
• Large (200+ docs): $5,000-$15,000

Timeline: 1-2 weeks for full implementation

ROI: If we save your team 5 hours/week total, that's 
$10K-$50K/year value (depending on team size).

Interested in moving forward?

Best,
[Your Name]
```
"""
        
        elif biz_id == "vibe_coding":
            content += """
### Template 1: Developer Email Outreach

```
Subject: I automated 90% of my coding with AI - want to learn?

Hi [Name],

Quick message: I just automated 90% of my development workflow 
using AI (Cursor + ChatGPT + Claude).

Results:
• Project that took 40 hours → now takes 6 hours
• 80% less debugging time
• Write production-ready code 10x faster

I'm offering 1-hour crash courses for developers who want to 
learn the system ($100/hour).

In one hour you'll:
• Write actual working code with AI
• Learn the prompts that actually work
• Get templates you can reuse forever
• See 5-10x productivity increase

Interested? Let me know and I'll send a calendar link.

Best,
[Your Name]

P.S. This isn't theory - we'll build something real during 
the session. You'll leave with working code.
```

### Template 2: Reddit Post (r/learnprogramming)

```
Title: I automated my entire dev workflow with AI - AMA

I spent the last 3 months learning how to use AI (Cursor, ChatGPT, 
Claude) for actual development work.

Results:
• Went from 40 hour/week coding to 15 hours/week
• Same output, way less time
• Less debugging, more building
• 80% of my code is AI-generated (then I review/fix)

Common questions I get:
"Doesn't AI write bad code?" → Yes, if you don't guide it properly
"Won't this make me a worse developer?" → No, you learn FASTER
"What's the best tool?" → Cursor for coding, ChatGPT for architecture

I'm offering paid consultations ($100/hour) where I'll teach you 
the exact system I use. We'll write actual code together.

DM me if interested. Happy to answer questions here too.
```

### Template 3: LinkedIn Paid Consultation Offer

```
🤖 I automated 90% of my development work with AI.

Here's what changed:
• 40 hour projects → 6 hours
• Less time debugging
• More time building features customers want

The tools: Cursor, ChatGPT, Claude

The secret: Knowing how to guide AI to write production code.

I'm offering 1-hour crash courses for developers:
• We build something real together
• You learn the prompts that work
• You get templates to reuse
• $100/hour investment

Result: 5-10x faster development immediately.

DM me if interested. 5 spots available this week.

#ai #development #productivity #cursor
```
"""
        
        content += """
---

## 💡 CUSTOMIZATION GUIDE

### How to Customize These Templates:

1. **Client Name:** Always use their actual name
2. **Specific Requirement:** Reference their exact need
3. **Price:** Adjust based on urgency and complexity
4. **Timeline:** Be realistic about delivery
5. **Your Name:** Add your actual credentials

### Winning Elements to Keep:

✅ Specific deliverables (not vague promises)
✅ Clear timeline (creates urgency)
✅ Social proof (military veteran, results)
✅ Risk reversal (support, guarantees)
✅ Fast response time (competitive advantage)

---

## 🎯 USAGE TIPS

1. **Copy-Paste:** Don't rewrite from scratch
2. **Customize:** Change bracketed sections only
3. **Test Prices:** Start mid-range, adjust based on response
4. **Track Results:** Note which templates win most
5. **Iterate:** Improve based on feedback

**These templates have 15-25% win rates when used correctly.**
"""
        
        with open(biz_dir / "PROPOSALS.md", "w") as f:
            f.write(content)
    
    def _generate_tracking(self, biz_dir, biz_id, biz):
        """Generate tracking template"""
        content = """# Business Tracking Template

**Generated:** """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """

---

## 📊 WEEKLY TRACKING

### Week 1: [Date Range]

**Applications/Outreach:**
- Submitted: ___
- Responses: ___
- Win rate: ___%

**Revenue:**
- Clients won: ___
- Total revenue: $___
- Average per client: $___

**Reviews:**
- Positive: ___
- 5-star: ___
- Testimonials: ___

**Notes:**
- What worked:
- What didn't:
- Adjust for next week:

---

## 💰 MONTHLY REVENUE TRACKER

| Date | Client | Service | Amount | Status | Review |
|------|--------|---------|---------|--------|--------|
| 2025-01-01 | Client A | Security Scan | $300 | Paid | ⭐⭐⭐⭐⭐ |
| | | | | | |

**Monthly Total:** $___

**Recurring Revenue:** $___

**New Clients:** ___

**Repeat Clients:** ___

---

## 🎯 KPI DASHBOARD

**Win Rate:** __% (Target: 15-25%)
**Avg Project Value:** $__ (Target: Increasing)
**Response Rate:** __% (Target: 30-50%)
**Client Satisfaction:** __/5 (Target: 4.5+)
**Recurring %:** __% (Target: 30%+)

---

## 📈 GROWTH METRICS

**Month 1:**
- Revenue: $___
- Clients: ___
- Reviews: ___

**Month 2:**
- Revenue: $___
- Clients: ___
- Reviews: ___

**Month 3:**
- Revenue: $___
- Clients: ___
- Reviews: ___

**Growth Rate:** ___%

---

## 🔄 CONTINUOUS IMPROVEMENT

### What's Working:
1.
2.
3.

### What's Not Working:
1.
2.
3.

### Changes to Make:
1.
2.
3.

---

## 💡 NOTES & LEARNINGS

Date | Learning | Action Taken
-----|----------|-------------
     |          |

---

**Update this weekly. Track everything. Optimize constantly.**
"""
        
        with open(biz_dir / "TRACKING.md", "w") as f:
            f.write(content)
    
    def _generate_ai_prompts(self, biz_dir, biz_id, biz):
        """Generate AI prompts for ongoing use"""
        content = f"""# AI Prompts for {biz['name']}

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

---

## 🤖 CURSOR/CHATGPT PROMPTS FOR THIS BUSINESS

### Prompt 1: Generate Custom Proposal

```
I need a proposal for [PLATFORM] targeting this job:

[PASTE JOB DESCRIPTION]

My service: {biz['description']}
My pricing: $[AMOUNT]
My advantage: [military veteran / fast delivery / proven results]

Generate a winning proposal that:
1. References their specific needs
2. Highlights my competitive advantages
3. Includes clear deliverables and timeline
4. Ends with clear call-to-action

Make it 200-300 words, professional but personable.
```

### Prompt 2: Improve Existing Proposal

```
Here's my proposal that didn't win:

[PASTE PROPOSAL]

The job was:
[PASTE JOB DESCRIPTION]

Analyze why this might not have won and rewrite it to be more compelling.
Focus on specific client needs and clear value proposition.
```

### Prompt 3: Generate Marketing Copy

```
I need marketing copy for [PLATFORM] promoting my service.

Service: {biz['description']}
Target audience: [WHO]
Key benefit: [MAIN VALUE]
Pricing: $[AMOUNT]

Generate:
1. Attention-grabbing headline
2. 3-5 bullet points of benefits
3. Social proof element
4. Clear call-to-action

Keep it under 150 words, punchy and benefit-focused.
```

### Prompt 4: Handle Client Objection

```
A potential client said:

"[PASTE OBJECTION]"

My service: {biz['description']}
Context: [SITUATION]

Help me write a response that:
1. Acknowledges their concern
2. Addresses the objection directly
3. Provides social proof or guarantee
4. Moves them toward hiring

Keep it 100-150 words, professional and reassuring.
```

### Prompt 5: Create Follow-Up Message

```
I sent a proposal [TIME] ago and haven't heard back.

Original proposal was for: [SERVICE]
Price: $[AMOUNT]
Client's main need: [NEED]

Write a follow-up message that:
1. Reminds them of the proposal
2. Adds new value (insight, tip, or bonus)
3. Creates urgency without being pushy
4. Makes it easy to respond

Keep it under 100 words, friendly and helpful.
```

### Prompt 6: Optimize Pricing

```
I've completed [NUMBER] projects in this business:

Service: {biz['description']}
Current price: $[CURRENT]
Win rate: [X]%
Client feedback: [SUMMARY]
Time per project: [HOURS]

Should I raise my prices? If so, to what amount and why?
Give me the math and psychology behind the recommendation.
```

### Prompt 7: Generate Content Ideas

```
I want to create content marketing for this business:

Service: {biz['description']}
Target audience: [WHO]
Platforms: [WHERE]

Generate 10 content ideas that would:
1. Demonstrate expertise
2. Attract potential clients
3. Be easy to create quickly
4. Provide real value

Format: Mix of posts, tips, case studies, how-tos.
```

### Prompt 8: Improve Service Delivery

```
I just delivered this service:

Client: [NAME]
Service: {biz['description']}
What I did: [SUMMARY]
Time taken: [HOURS]
Client feedback: [IF ANY]

How can I:
1. Deliver faster (automate more)
2. Deliver better (higher quality)
3. Charge more (added value)
4. Create recurring revenue (ongoing service)

Give specific actionable recommendations.
```

---

## 💡 HOW TO USE THESE PROMPTS

### In Cursor:
1. Open Cursor
2. Start chat (Cmd/Ctrl + L)
3. Copy-paste prompt
4. Replace [BRACKETED] sections with your specifics
5. Get AI-generated response
6. Refine if needed

### In ChatGPT/Claude:
1. Open new chat
2. Paste prompt
3. Fill in details
4. Get response
5. Copy to your platform

---

## 🎯 PROMPT LIBRARY EXPANSION

As you work, add new prompts here that you find useful:

### Custom Prompt 1: [Your Title]
```
[Your prompt]
```

### Custom Prompt 2: [Your Title]
```
[Your prompt]
```

---

**Save this file. Use these prompts daily. Never start from scratch again.**
"""
        
        with open(biz_dir / "AI_PROMPTS.md", "w") as f:
            f.write(content)

def main():
    parser = argparse.ArgumentParser(
        description="Generate ready-to-launch businesses from your Master System"
    )
    parser.add_argument(
        "--business",
        type=str,
        help="Business ID to generate (e.g., security_scanning)"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all available businesses"
    )
    
    args = parser.parse_args()
    
    generator = BusinessGenerator()
    
    if args.list:
        generator.list_businesses()
    elif args.business:
        generator.generate_business(args.business)
    else:
        print("\nUsage:")
        print("  python3 business_generator.py --list")
        print("  python3 business_generator.py --business security_scanning")
        print("\nRun with --list to see all available businesses\n")

if __name__ == "__main__":
    main()




