#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
# -*- coding: utf-8 -*-
"""
AI PROPOSAL GENERATOR
Advanced proposal generation using AI techniques

This generates highly customized, winning proposals for Upwork jobs.

Author: DoctorMen
Status: Production Ready
"""

import json
import sys
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List

# Fix encoding for Windows
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')

class AIProposalGenerator:
    """
    AI-powered proposal generator
    """
    
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        
        # Load templates
        self.templates = self.load_templates()
        
        # Skill database
        self.skills_db = {
            "python": {
                "experience": "5+ years of Python development",
                "frameworks": ["Django", "Flask", "FastAPI", "Scrapy"],
                "projects": "Built 50+ automation scripts and web applications",
                "certifications": "Python Expert"
            },
            "automation": {
                "experience": "Expert in building automation systems",
                "tools": ["Selenium", "Playwright", "BeautifulSoup", "Requests"],
                "projects": "Automated 100+ repetitive tasks saving 1000+ hours",
                "roi": "Average 80% time savings for clients"
            },
            "web_scraping": {
                "experience": "Advanced web scraping and data extraction",
                "tools": ["Scrapy", "BeautifulSoup", "Selenium", "Puppeteer"],
                "projects": "Scraped data from 200+ websites",
                "compliance": "Always respect robots.txt and rate limits"
            },
            "api": {
                "experience": "API development and integration specialist",
                "types": ["REST", "GraphQL", "WebSocket", "gRPC"],
                "projects": "Integrated 50+ third-party APIs",
                "documentation": "Comprehensive API documentation included"
            },
            "security": {
                "experience": "Security testing and vulnerability assessment",
                "methodologies": ["OWASP Top 10", "Penetration Testing", "Code Review"],
                "tools": ["Burp Suite", "OWASP ZAP", "Metasploit", "Nmap"],
                "certifications": "Security+ equivalent knowledge"
            }
        }
    
    def load_templates(self) -> Dict:
        """Load proposal templates"""
        return {
            "professional": {
                "tone": "professional",
                "length": "medium",
                "style": "direct"
            },
            "friendly": {
                "tone": "friendly",
                "length": "short",
                "style": "conversational"
            },
            "detailed": {
                "tone": "professional",
                "length": "long",
                "style": "comprehensive"
            }
        }
    
    def analyze_job(self, job: Dict) -> Dict:
        """Deep analysis of job requirements"""
        description = job.get('description', '').lower()
        title = job.get('title', '').lower()
        
        analysis = {
            "primary_skills": [],
            "secondary_skills": [],
            "complexity": "medium",
            "urgency": "normal",
            "budget_type": "unknown",
            "client_type": "unknown",
            "pain_points": [],
            "success_criteria": []
        }
        
        # Detect primary skills
        skill_keywords = {
            "python": ["python", "django", "flask", "fastapi"],
            "automation": ["automation", "automate", "bot", "script"],
            "web_scraping": ["scraping", "scrape", "crawl", "extract"],
            "api": ["api", "rest", "integration", "endpoint"],
            "security": ["security", "pentest", "vulnerability", "hack"],
            "data": ["data", "database", "sql", "mongodb"],
            "frontend": ["frontend", "react", "vue", "angular"],
            "backend": ["backend", "server", "node", "express"]
        }
        
        for skill, keywords in skill_keywords.items():
            if any(kw in description or kw in title for kw in keywords):
                analysis["primary_skills"].append(skill)
        
        # Detect complexity
        complexity_indicators = {
            "simple": ["simple", "basic", "easy", "quick"],
            "medium": ["moderate", "standard", "typical"],
            "complex": ["complex", "advanced", "sophisticated", "enterprise"]
        }
        
        for level, indicators in complexity_indicators.items():
            if any(ind in description for ind in indicators):
                analysis["complexity"] = level
                break
        
        # Detect urgency
        if any(word in description for word in ["urgent", "asap", "immediately", "rush"]):
            analysis["urgency"] = "high"
        elif any(word in description for word in ["flexible", "no rush", "long-term"]):
            analysis["urgency"] = "low"
        
        # Detect pain points
        pain_indicators = [
            ("time", "need to save time"),
            ("manual", "tired of manual work"),
            ("scale", "need to scale operations"),
            ("data", "need better data"),
            ("security", "concerned about security")
        ]
        
        for indicator, pain in pain_indicators:
            if indicator in description:
                analysis["pain_points"].append(pain)
        
        return analysis
    
    def generate_opening(self, job: Dict, analysis: Dict) -> str:
        """Generate compelling opening"""
        title = job.get('title', 'your project')
        
        openings = [
            f"Hi! I'm excited about \"{title}\" and confident I can deliver exactly what you need.",
            f"Hello! Your project \"{title}\" aligns perfectly with my expertise.",
            f"Hi there! I've read your requirements for \"{title}\" and I'm ready to start immediately.",
        ]
        
        # Choose based on urgency
        if analysis['urgency'] == 'high':
            return openings[2]
        else:
            return openings[0]
    
    def generate_experience_section(self, analysis: Dict) -> str:
        """Generate experience section based on required skills"""
        section = "\n**My Relevant Experience:**\n\n"
        
        for skill in analysis['primary_skills'][:3]:  # Top 3 skills
            if skill in self.skills_db:
                skill_info = self.skills_db[skill]
                section += f"✅ **{skill.replace('_', ' ').title()}:** {skill_info['experience']}\n"
                section += f"   - {skill_info['projects']}\n"
        
        return section
    
    def generate_approach(self, job: Dict, analysis: Dict) -> str:
        """Generate project approach"""
        approach = "\n**My Approach:**\n\n"
        
        if analysis['complexity'] == 'simple':
            approach += "1. Quick requirements review (30 min)\n"
            approach += "2. Rapid development with best practices\n"
            approach += "3. Testing and delivery (same day possible)\n"
        elif analysis['complexity'] == 'complex':
            approach += "1. Detailed requirements analysis and planning\n"
            approach += "2. Architecture design and approval\n"
            approach += "3. Iterative development with regular updates\n"
            approach += "4. Comprehensive testing and QA\n"
            approach += "5. Documentation and knowledge transfer\n"
        else:
            approach += "1. Clarify requirements and scope\n"
            approach += "2. Create development plan with milestones\n"
            approach += "3. Build with clean, maintainable code\n"
            approach += "4. Test thoroughly before delivery\n"
            approach += "5. Provide documentation and support\n"
        
        return approach
    
    def generate_value_proposition(self, analysis: Dict) -> str:
        """Generate unique value proposition"""
        value = "\n**Why Choose Me:**\n\n"
        
        value += "✅ **Fast Delivery:** I work efficiently and meet deadlines\n"
        value += "✅ **Quality Code:** Clean, documented, maintainable code\n"
        value += "✅ **Communication:** Regular updates and quick responses\n"
        value += "✅ **Support:** Post-delivery support included\n"
        
        if analysis['urgency'] == 'high':
            value += "✅ **Availability:** Can start immediately and work urgently\n"
        
        return value
    
    def generate_closing(self, analysis: Dict) -> str:
        """Generate strong closing"""
        if analysis['urgency'] == 'high':
            closing = "\nI'm available to start RIGHT NOW and can deliver quickly without compromising quality.\n\n"
        else:
            closing = "\nI'm available to start this week and excited to discuss your project in detail.\n\n"
        
        closing += "Let's chat about your specific requirements. I'm confident I can exceed your expectations.\n\n"
        closing += "Best regards"
        
        return closing
    
    def calculate_bid(self, job: Dict, analysis: Dict) -> int:
        """Smart bid calculation"""
        base_bid = 500  # Minimum bid
        
        # Adjust for complexity
        complexity_multiplier = {
            "simple": 1.0,
            "medium": 1.5,
            "complex": 2.5
        }
        
        bid = base_bid * complexity_multiplier.get(analysis['complexity'], 1.5)
        
        # Adjust for urgency
        if analysis['urgency'] == 'high':
            bid *= 1.3  # 30% premium for urgent work
        
        # Check job budget
        if job.get('budget'):
            # Bid 85% of budget to be competitive
            budget_bid = int(job['budget'] * 0.85)
            bid = min(bid, budget_bid)
        
        return int(bid)
    
    def generate_proposal(self, job: Dict, template: str = "professional") -> Dict:
        """Generate complete AI-powered proposal"""
        print(f"\n🤖 GENERATING AI PROPOSAL...")
        print(f"   Job: {job.get('title', 'Unknown')[:50]}...")
        
        # Analyze job
        analysis = self.analyze_job(job)
        print(f"   Skills detected: {', '.join(analysis['primary_skills'])}")
        print(f"   Complexity: {analysis['complexity']}")
        print(f"   Urgency: {analysis['urgency']}")
        
        # Generate sections
        opening = self.generate_opening(job, analysis)
        experience = self.generate_experience_section(analysis)
        approach = self.generate_approach(job, analysis)
        value = self.generate_value_proposition(analysis)
        closing = self.generate_closing(analysis)
        
        # Combine into full proposal
        cover_letter = opening + experience + approach + value + closing
        
        # Calculate bid
        bid_amount = self.calculate_bid(job, analysis)
        
        # Estimate duration
        duration_map = {
            "simple": "1-3 days",
            "medium": "1-2 weeks",
            "complex": "2-4 weeks"
        }
        estimated_duration = duration_map.get(analysis['complexity'], "1-2 weeks")
        
        # Calculate confidence score
        confidence = 60  # Base
        confidence += len(analysis['primary_skills']) * 10  # +10 per skill match
        confidence = min(confidence, 95)  # Cap at 95%
        
        proposal = {
            "job_id": job.get('id', ''),
            "job_title": job.get('title', ''),
            "generated_at": datetime.now().isoformat(),
            "cover_letter": cover_letter,
            "bid_amount": bid_amount,
            "estimated_duration": estimated_duration,
            "analysis": analysis,
            "confidence_score": confidence,
            "template_used": template
        }
        
        print(f"   ✅ Proposal generated!")
        print(f"   💰 Bid: ${bid_amount}")
        print(f"   ⏱️ Duration: {estimated_duration}")
        print(f"   📊 Confidence: {confidence}%")
        
        return proposal
    
    def save_proposal(self, proposal: Dict):
        """Save proposal to file"""
        proposals_dir = self.base_dir / "output" / "upwork_data" / "proposals"
        proposals_dir.mkdir(parents=True, exist_ok=True)
        
        filename = f"proposal_{proposal['job_id'][:20]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = proposals_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(proposal, f, indent=2)
        
        # Also save as text for easy copying
        text_file = filepath.with_suffix('.txt')
        with open(text_file, 'w', encoding='utf-8') as f:
            f.write(f"JOB: {proposal['job_title']}\n")
            f.write(f"BID: ${proposal['bid_amount']}\n")
            f.write(f"DURATION: {proposal['estimated_duration']}\n")
            f.write(f"CONFIDENCE: {proposal['confidence_score']}%\n")
            f.write("\n" + "="*80 + "\n")
            f.write("COVER LETTER:\n")
            f.write("="*80 + "\n\n")
            f.write(proposal['cover_letter'])
        
        print(f"\n💾 Proposal saved:")
        print(f"   JSON: {filepath}")
        print(f"   Text: {text_file}")
        
        return filepath


def main():
    """Test the AI proposal generator"""
    print("""
================================================================================
                    AI PROPOSAL GENERATOR
                Advanced Upwork Proposal Generation
================================================================================
    """)
    
    generator = AIProposalGenerator()
    
    # Test with sample job
    sample_job = {
        "id": "test_job_123",
        "title": "Python Automation Script for Web Scraping",
        "description": """
        I need a Python developer to create an automation script that scrapes 
        product data from an e-commerce website. The script should:
        - Extract product names, prices, and descriptions
        - Handle pagination automatically
        - Save data to CSV format
        - Run daily via cron job
        
        This is urgent and I need it completed within 3 days.
        Budget: $800
        """,
        "budget": 800,
        "url": "https://upwork.com/jobs/test"
    }
    
    # Generate proposal
    proposal = generator.generate_proposal(sample_job)
    
    # Save proposal
    generator.save_proposal(proposal)
    
    print("\n" + "="*80)
    print("✅ AI PROPOSAL GENERATOR READY")
    print("="*80)
    print("\nGenerated proposal with:")
    print(f"  - Customized cover letter")
    print(f"  - Smart bid calculation (${proposal['bid_amount']})")
    print(f"  - Realistic timeline ({proposal['estimated_duration']})")
    print(f"  - {proposal['confidence_score']}% confidence score")


if __name__ == "__main__":
    main()
