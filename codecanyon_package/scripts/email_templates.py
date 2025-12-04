#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Email Templates for Client Communication
Professional email templates for payment confirmation, report delivery, and upsells
"""

from datetime import datetime
from typing import Optional


def payment_confirmation_email(
    client_name: str,
    business_name: str,
    amount: float,
    scan_id: str,
    your_name: str = "Security Scan Team",
    your_email: str = "",
    your_phone: str = ""
) -> str:
    """Generate payment confirmation email"""
    
    subject = f"Payment Received - Security Scan Started for {business_name}"
    
    body = f"""Subject: {subject}

Hi {client_name},

Payment received - thank you!

I've started the security scan for {business_name} right now.

You'll receive:
✓ Complete security report
✓ List of all vulnerabilities found  
✓ Step-by-step fix instructions
✓ Security score and recommendations

Delivery: Within 2 hours

If you have any questions, just reply to this email.

Thank you for taking your website security seriously!

Best regards,
{your_name}
{your_email}
{your_phone}

──────────────────────────────────
Security Scan Services
Emergency Security Scans
──────────────────────────────────
"""
    
    return body


def report_delivery_email(
    client_name: str,
    business_name: str,
    scan_id: str,
    report_path: str,
    security_score: int,
    critical_count: int,
    high_count: int,
    your_name: str = "Security Scan Team",
    your_email: str = "",
    your_phone: str = "",
    paypal_link: str = ""
) -> str:
    """Generate report delivery email"""
    
    urgency = "URGENT" if critical_count > 0 or high_count > 0 else "IMPORTANT"
    
    subject = f"{urgency}: Security Scan Results - {business_name}"
    
    body = f"""Subject: {subject}

Hi {client_name},

Your security scan is complete.

══════════════════════════════════════════════
SCAN RESULTS SUMMARY
══════════════════════════════════════════════

Security Score: {security_score}/10

"""

    if critical_count > 0:
        body += f"🔴 CRITICAL: {critical_count} issue(s) requiring immediate attention\n"
    if high_count > 0:
        body += f"🟠 HIGH: {high_count} issue(s) requiring prompt action\n"

    body += f"""
══════════════════════════════════════════════

Your complete security report is attached.

NEXT STEPS:

1. Review the report immediately
2. Fix critical issues ASAP (within 24 hours)
3. Address high priority issues (within 48-72 hours)
4. Reply to this email with any questions

MONTHLY MONITORING SERVICE:

If you want monthly security monitoring to catch issues like this before hackers do, I offer that for $500/month. 

Benefits:
✓ Monthly security scans
✓ Immediate alerts when new vulnerabilities are found
✓ Peace of mind knowing your site is monitored
✓ Priority support for fixing issues

Reply YES if you'd like to set up monthly monitoring.

Thank you for taking security seriously!

Best regards,
{your_name}
{your_email}
{your_phone}

──────────────────────────────────
Security Scan Services
Report attached: {report_path}
──────────────────────────────────
"""
    
    return body


def monthly_service_upsell_email(
    client_name: str,
    business_name: str,
    your_name: str = "Security Scan Team",
    your_email: str = "",
    your_phone: str = "",
    paypal_link: str = ""
) -> str:
    """Generate monthly service upsell email"""
    
    subject = f"Monthly Security Monitoring for {business_name}"
    
    body = f"""Subject: {subject}

Hi {client_name},

Based on your recent security scan, I wanted to offer you monthly security monitoring.

Your competitors are probably already doing this - it's essential for protecting your business online.

══════════════════════════════════════════════
MONTHLY SECURITY MONITORING
══════════════════════════════════════════════

Price: $500/month

What You Get:
✓ Monthly comprehensive security scans
✓ Immediate alerts when new vulnerabilities are found
✓ Detailed reports with fix instructions
✓ Priority support for questions
✓ Peace of mind knowing your site is monitored

Why This Matters:

- New vulnerabilities appear constantly
- Hackers scan websites daily looking for weaknesses
- Your competitors are monitoring their sites
- Prevention is cheaper than recovery from a hack

Cost of NOT monitoring:
- Data breach: $10,000+ in legal fees
- Website downtime: $500-$2,000 per day
- Customer trust: Priceless

$500/month to prevent that = Worth it.

══════════════════════════════════════════════

READY TO GET STARTED?

Reply YES and I'll:
1. Set up recurring monthly billing via PayPal
2. Schedule your first monthly scan
3. Send you the monitoring agreement

Or call me at {your_phone} to discuss.

No pressure - just wanted to make sure you knew this option was available.

Best regards,
{your_name}
{your_email}
{your_phone}

──────────────────────────────────
Security Scan Services
Monthly Security Monitoring
──────────────────────────────────
"""
    
    return body


def follow_up_call_script(
    client_name: str,
    critical_issue: str = ""
) -> str:
    """Generate follow-up call script"""
    
    script = f"""
══════════════════════════════════════════════
FOLLOW-UP CALL SCRIPT
══════════════════════════════════════════════

Hi {client_name}, this is [Your Name]. Did you get my security report?

[Wait for their response - usually they'll be worried]

Yeah, I found {critical_issue if critical_issue else "some security issues"} that need attention. Want me to walk you through the fix real quick?

[Spend 2-3 mins explaining the main issue]

So here's what I recommend: I offer monthly security monitoring for $500/month. 

I scan your site every month and catch these issues before hackers do. Your competitors are probably doing this already.

Want to try it for a month? If you don't like it, just cancel.

[Handle objections]

If YES:
Perfect! I'll send you a quick agreement and set up auto-billing through PayPal. Your first official monthly scan will be on [date 30 days from now].

══════════════════════════════════════════════
"""
    
    return script


def save_email_template(template_type: str, content: str, output_dir: Optional[str] = None):
    """Save email template to file"""
    from pathlib import Path
    
    if not output_dir:
        output_dir = Path(__file__).parent.parent / "client_data" / "email_templates"
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    filename = f"{template_type}_{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt"
    filepath = output_path / filename
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    
    return filepath


def main():
    """Example usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate email templates")
    parser.add_argument("--type", required=True, choices=["payment", "report", "upsell", "call"],
                       help="Template type")
    parser.add_argument("--client-name", required=True, help="Client name")
    parser.add_argument("--business-name", required=True, help="Business name")
    parser.add_argument("--amount", type=float, help="Payment amount")
    parser.add_argument("--scan-id", help="Scan ID")
    parser.add_argument("--security-score", type=int, help="Security score")
    parser.add_argument("--critical", type=int, default=0, help="Critical count")
    parser.add_argument("--high", type=int, default=0, help="High count")
    parser.add_argument("--your-name", default="Security Scan Team", help="Your name")
    parser.add_argument("--your-email", default="", help="Your email")
    parser.add_argument("--your-phone", default="", help="Your phone")
    
    args = parser.parse_args()
    
    if args.type == "payment":
        email = payment_confirmation_email(
            client_name=args.client_name,
            business_name=args.business_name,
            amount=args.amount or 200.0,
            scan_id=args.scan_id or "ES-000000",
            your_name=args.your_name,
            your_email=args.your_email,
            your_phone=args.your_phone
        )
    elif args.type == "report":
        email = report_delivery_email(
            client_name=args.client_name,
            business_name=args.business_name,
            scan_id=args.scan_id or "ES-000000",
            report_path="report.md",
            security_score=args.security_score or 7,
            critical_count=args.critical,
            high_count=args.high,
            your_name=args.your_name,
            your_email=args.your_email,
            your_phone=args.your_phone
        )
    elif args.type == "upsell":
        email = monthly_service_upsell_email(
            client_name=args.client_name,
            business_name=args.business_name,
            your_name=args.your_name,
            your_email=args.your_email,
            your_phone=args.your_phone
        )
    elif args.type == "call":
        email = follow_up_call_script(
            client_name=args.client_name,
            critical_issue="a critical security issue"
        )
    
    print(email)
    
    # Optionally save
    save_email_template(args.type, email)
    print(f"\n✅ Template saved to client_data/email_templates/")


if __name__ == "__main__":
    main()

