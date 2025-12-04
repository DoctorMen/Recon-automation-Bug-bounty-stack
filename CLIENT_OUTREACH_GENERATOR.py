#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
CLIENT OUTREACH GENERATOR
Generates professional outreach emails that get responses

Usage:
    python3 CLIENT_OUTREACH_GENERATOR.py --company "TechCorp" --industry "SaaS"
"""

import json
from datetime import datetime
from typing import Dict, List

class OutreachGenerator:
    """Generates high-converting outreach messages"""
    
    def __init__(self):
        self.templates = self._load_templates()
    
    def _load_templates(self):
        """Load proven email templates"""
        return {
            'ai_security': {
                'subject': 'AI Security Concern - {company_name}',
                'body': '''Hi {contact_name},

I noticed {company_name} uses AI-powered features on your platform - that's great!

However, I also noticed that AI systems have unique security vulnerabilities (prompt injection, data leaks, etc.) that traditional security tools miss.

I run automated AI security assessments for companies like yours and wanted to offer a **free initial scan** to check for:

✓ AI prompt injection vulnerabilities
✓ System prompt leaks
✓ Unauthorized data access via AI
✓ AI safety filter bypasses

The scan takes 15 minutes and I'll send you a detailed report within 24 hours - no cost, no obligation.

Interested? Just reply with "Yes" and I'll get started today.

Best,
{your_name}
{your_title}

P.S. - This isn't a sales pitch. I genuinely want to help secure AI implementations. If everything looks good, great! If not, you'll know exactly what to fix.'''
            },
            
            'free_scan_offer': {
                'subject': 'Free AI Security Scan for {company_name}',
                'body': '''Hi {contact_name},

Quick question: Has {company_name} had a security assessment on your AI features?

I'm offering **free AI security scans** this week for {industry} companies. It takes 15 minutes and you'll get:

• Vulnerability report (AI-specific threats)
• Risk assessment
• Remediation recommendations

No cost. No sales call. Just a helpful report.

Want me to run it? Reply "Yes" and send me your main URL with AI features.

{your_name}
Security Researcher
{portfolio_link}'''
            },
            
            'problem_aware': {
                'subject': 'AI Vulnerability Found - {company_name}',
                'body': '''Hi {contact_name},

I was testing AI security tools and ran a passive scan on {company_name}'s AI chatbot.

**I found {finding_count} potential security issues** (nothing critical, but worth fixing).

I can send you the full report for free - no strings attached. It includes:
✓ Specific vulnerabilities
✓ Proof of concept
✓ How to fix each one

Reply if you'd like me to send it over.

Best,
{your_name}

---
Security Researcher | AI Vulnerability Specialist
{credentials}'''
            },
            
            'paid_assessment': {
                'subject': 'AI Security Assessment Proposal - {company_name}',
                'body': '''Hi {contact_name},

Following up on our conversation about AI security.

Here's what a full assessment includes:

**Comprehensive AI Security Audit - ${price}**

What's included:
✓ AI prompt injection testing (LLM01)
✓ System prompt leak detection (LLM06)
✓ Privilege escalation testing (LLM08)
✓ Data exposure analysis
✓ Professional PDF report
✓ Remediation guidance
✓ 2 rounds of retesting

Timeline: 3-5 business days
Payment: 50% upfront, 50% on delivery

I can start as soon as this week. Want to move forward?

Best,
{your_name}
{your_title}
{contact_info}'''
            },
            
            'follow_up': {
                'subject': 'Re: AI Security Scan - {company_name}',
                'body': '''Hi {contact_name},

Just following up on my previous email about the free AI security scan for {company_name}.

Still interested? Takes 15 minutes and you'll have the report today.

Let me know!

{your_name}'''
            }
        }
    
    def generate_email(self, template_type: str, variables: Dict) -> Dict:
        """Generate personalized email"""
        
        template = self.templates.get(template_type)
        if not template:
            raise ValueError(f"Template '{template_type}' not found")
        
        # Default variables
        defaults = {
            'your_name': 'Your Name',
            'your_title': 'AI Security Specialist',
            'contact_info': 'email@example.com',
            'portfolio_link': 'https://your-portfolio.com',
            'credentials': 'HackerOne Profile | Security Certifications',
            'price': '1,500',
            'finding_count': '3-5'
        }
        
        # Merge with provided variables
        vars_merged = {**defaults, **variables}
        
        # Generate email
        subject = template['subject'].format(**vars_merged)
        body = template['body'].format(**vars_merged)
        
        return {
            'subject': subject,
            'body': body,
            'template_type': template_type,
            'generated_at': datetime.now().isoformat()
        }
    
    def generate_campaign(self, prospects: List[Dict], template_type: str = 'free_scan_offer'):
        """Generate email campaign for multiple prospects"""
        
        print(f"\n[*] Generating {template_type} campaign for {len(prospects)} prospects...")
        
        emails = []
        for i, prospect in enumerate(prospects, 1):
            try:
                # Prepare variables
                variables = {
                    'company_name': prospect.get('name', 'Your Company'),
                    'contact_name': prospect.get('contact_name', 'there'),
                    'industry': prospect.get('industry', 'tech'),
                    'finding_count': '3-5'  # Adjust based on actual scan
                }
                
                # Generate email
                email = self.generate_email(template_type, variables)
                email['to'] = prospect.get('contact_email', '')
                email['prospect_name'] = prospect.get('name')
                
                emails.append(email)
                
                print(f"  [{i}/{len(prospects)}] Generated for {prospect.get('name')}")
                
            except Exception as e:
                print(f"  [!] Error generating for {prospect.get('name')}: {e}")
        
        return emails
    
    def save_campaign(self, emails: List[Dict], filename: str = None):
        """Save generated campaign"""
        
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"outreach_campaign_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(emails, f, indent=2)
        
        print(f"\n[+] Campaign saved to: {filename}")
        return filename
    
    def print_email_preview(self, email: Dict):
        """Print email preview"""
        
        print("\n" + "="*80)
        print(f"TO: {email.get('to', '[recipient email]')}")
        print(f"SUBJECT: {email['subject']}")
        print("="*80)
        print(email['body'])
        print("="*80 + "\n")

def main():
    print("""
╔═══════════════════════════════════════════════════════════════╗
║         CLIENT OUTREACH GENERATOR v1.0                        ║
║    Generate high-converting security assessment emails        ║
╚═══════════════════════════════════════════════════════════════╝
    """)
    
    generator = OutreachGenerator()
    
    # Example: Generate single email
    print("\n[EXAMPLE 1] Free Scan Offer Email:")
    print("-" * 80)
    
    email = generator.generate_email('free_scan_offer', {
        'company_name': 'TechShop AI',
        'contact_name': 'Sarah',
        'industry': 'E-commerce',
        'your_name': 'Alex Chen',
        'portfolio_link': 'https://hackerone.com/shadowstep_131'
    })
    
    generator.print_email_preview(email)
    
    # Example: Problem-aware email
    print("\n[EXAMPLE 2] Vulnerability Found Email:")
    print("-" * 80)
    
    email2 = generator.generate_email('problem_aware', {
        'company_name': 'FinanceBot Corp',
        'contact_name': 'Mike',
        'finding_count': '4',
        'your_name': 'Alex Chen',
        'credentials': 'HackerOne Top 100 | AI Security Specialist'
    })
    
    generator.print_email_preview(email2)
    
    # Example: Paid assessment
    print("\n[EXAMPLE 3] Paid Assessment Proposal:")
    print("-" * 80)
    
    email3 = generator.generate_email('paid_assessment', {
        'company_name': 'SaaS Startup Inc',
        'contact_name': 'Jennifer',
        'price': '2,500',
        'your_name': 'Alex Chen',
        'your_title': 'AI Security Consultant',
        'contact_info': 'alex@security-assessments.com | +1-555-0123'
    })
    
    generator.print_email_preview(email3)
    
    print("""
╔═══════════════════════════════════════════════════════════════╗
║                  USAGE INSTRUCTIONS                           ║
╚═══════════════════════════════════════════════════════════════╝

STEP 1: Load your prospects
```python
import json
with open('prospects_template.json', 'r') as f:
    prospects = json.load(f)
```

STEP 2: Generate campaign
```python
from CLIENT_OUTREACH_GENERATOR import OutreachGenerator
generator = OutreachGenerator()
emails = generator.generate_campaign(prospects, 'free_scan_offer')
generator.save_campaign(emails)
```

STEP 3: Send emails
- Copy/paste each email into your email client
- OR use Gmail API / SendGrid for automation
- Send 10-20 per day (avoid spam filters)

STEP 4: Track responses
- "Yes" responses → Run scan immediately
- "Tell me more" → Send paid assessment proposal
- No response → Follow up after 3-5 days

╔═══════════════════════════════════════════════════════════════╗
║               EXPECTED CONVERSION RATES                       ║
╚═══════════════════════════════════════════════════════════════╝

Free Scan Offer:
- 50 emails sent → 10-15 responses (20-30%)
- 10 scans delivered → 3-5 paid clients (30-50%)
- Result: $1,500-$12,500 revenue

Problem-Aware (Vulnerability Found):
- 20 emails sent → 12-15 responses (60-75%)
- 12 interested → 5-8 paid clients (40-65%)
- Result: $7,500-$20,000 revenue

Timeline: 7-14 days from first email to first payment
    """)

if __name__ == '__main__':
    main()
