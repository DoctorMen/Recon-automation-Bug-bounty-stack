#!/usr/bin/env python3
"""
Instant Submission Helper
Helps you submit bugs immediately and get paid fast
"""

import json
from pathlib import Path
from typing import Dict, List, Any

class InstantSubmissionHelper:
    """
    Helps submit bugs instantly without vouchers
    Provides direct submission methods for fast payout
    """
    
    # Instant submission methods (no vouchers needed)
    INSTANT_SUBMISSION_METHODS = {
        "open_bug_bounty": {
            "platform": "Open Bug Bounty",
            "url": "https://www.openbugbounty.org",
            "signup_required": False,
            "submission_method": "Web form",
            "payout_time": "24-48 hours after validation",
            "payout_method": "Direct crypto to wallet",
            "validation_time": "Fast (24-48 hours)",
            "best_for": "Web vulnerabilities on any crypto site"
        },
        "direct_email": {
            "platforms": {
                "kraken": {
                    "email": "security@kraken.com",
                    "payout": "Bitcoin (direct to wallet)",
                    "validation": "3-5 days",
                    "max_reward": "$100,000",
                    "requirements": "Kraken account (free to create)"
                },
                "byte_federal": {
                    "email": "security@bytefederal.com",
                    "payout": "Crypto or Fiat",
                    "validation": "5-7 days",
                    "max_reward": "$20,000",
                    "requirements": "None"
                }
            },
            "best_for": "Critical bugs, bypass platforms"
        },
        "github_direct": {
            "platforms": {
                "clearpool": {
                    "url": "https://github.com/clearpool-finance",
                    "method": "GitHub Discussions",
                    "payout": "USDC or CPOOL tokens",
                    "validation": "3-5 days",
                    "requirements": "GitHub account (free)"
                }
            },
            "best_for": "Open source crypto projects"
        }
    }
    
    # Fast payout programs
    FAST_PAYOUT_PROGRAMS = {
        "open_bug_bounty": {
            "name": "Open Bug Bounty",
            "payout_time": "24-48 hours",
            "signup": False,
            "method": "Instant web submission"
        },
        "kraken": {
            "name": "Kraken",
            "payout_time": "3-5 days",
            "signup": False,
            "method": "Direct email (security@kraken.com)"
        },
        "byte_federal": {
            "name": "Byte Federal",
            "payout_time": "5-7 days",
            "signup": False,
            "method": "Direct email (security@bytefederal.com)"
        },
        "clearpool": {
            "name": "Clearpool",
            "payout_time": "3-5 days",
            "signup": False,
            "method": "GitHub Discussions"
        }
    }
    
    @staticmethod
    def generate_submission_template(finding: Dict[str, Any], method: str = "open_bug_bounty") -> str:
        """Generate submission-ready report"""
        if method == "open_bug_bounty":
            return InstantSubmissionHelper._generate_open_bug_bounty_template(finding)
        elif method == "direct_email":
            return InstantSubmissionHelper._generate_email_template(finding)
        elif method == "github":
            return InstantSubmissionHelper._generate_github_template(finding)
        else:
            return json.dumps(finding, indent=2)
    
    @staticmethod
    def _generate_open_bug_bounty_template(finding: Dict[str, Any]) -> str:
        """Generate Open Bug Bounty submission template"""
        template = f"""
# Vulnerability Report - Open Bug Bounty

## Target Website
{finding.get('url', 'N/A')}

## Vulnerability Type
{finding.get('type', 'N/A')}

## Severity
{finding.get('severity', 'N/A')}

## Description
{finding.get('description', 'N/A')}

## Steps to Reproduce
1. Navigate to: {finding.get('url', 'N/A')}
2. {finding.get('steps', 'Follow vulnerability exploitation steps')}
3. Observe: {finding.get('impact', 'Vulnerability impact')}

## Proof of Concept
{finding.get('proof', 'Proof of concept here')}

## Impact
{finding.get('impact', 'Security impact description')}

## Remediation
{finding.get('recommendation', 'Recommended fix')}

---
Submitted via Open Bug Bounty (https://www.openbugbounty.org)
"""
        return template
    
    @staticmethod
    def _generate_email_template(finding: Dict[str, Any]) -> str:
        """Generate direct email submission template"""
        template = f"""
Subject: Security Vulnerability Report - {finding.get('type', 'Vulnerability')}

Dear Security Team,

I have discovered a security vulnerability on {finding.get('url', 'your platform')}.

VULNERABILITY DETAILS:
- Type: {finding.get('type', 'N/A')}
- Severity: {finding.get('severity', 'N/A')}
- URL: {finding.get('url', 'N/A')}
- Description: {finding.get('description', 'N/A')}

STEPS TO REPRODUCE:
{finding.get('steps', 'Detailed steps here')}

PROOF OF CONCEPT:
{finding.get('proof', 'Proof here')}

IMPACT:
{finding.get('impact', 'Security impact')}

REMEDIATION:
{finding.get('recommendation', 'Recommended fix')}

I have followed responsible disclosure practices and have not exploited this vulnerability beyond what is necessary to demonstrate the issue.

Best regards,
[Your Name]
[Your Email]
"""
        return template
    
    @staticmethod
    def _generate_github_template(finding: Dict[str, Any]) -> str:
        """Generate GitHub submission template"""
        template = f"""## Security Vulnerability Report

**Target**: {finding.get('url', 'N/A')}
**Type**: {finding.get('type', 'N/A')}
**Severity**: {finding.get('severity', 'N/A')}

### Description
{finding.get('description', 'N/A')}

### Steps to Reproduce
{finding.get('steps', 'Detailed steps here')}

### Proof of Concept
```
{finding.get('proof', 'Proof here')}
```

### Impact
{finding.get('impact', 'Security impact')}

### Remediation
{finding.get('recommendation', 'Recommended fix')}
"""
        return template
    
    @staticmethod
    def _get_instant_submission_instructions(finding: Dict[str, Any]) -> str:
        """Get instant submission instructions for a finding"""
        submission_info = InstantSubmissionHelper.get_fastest_submission_method(finding)
        
        instructions = f"""
### 🚀 Fastest Submission Method: {submission_info['method'].upper()}

**Platform**: {submission_info['platform']}  
**Payout Time**: {submission_info['payout_time']}  
**Signup Required**: {'❌ NO' if submission_info.get('method') == 'open_bug_bounty' else '✅ Yes (free)'}

### Submission Steps:

"""
        
        if submission_info['method'] == 'open_bug_bounty':
            instructions += """1. Go to: https://www.openbugbounty.org
2. Click "Submit Report"
3. Fill out the form with your findings
4. Submit immediately (no signup needed!)
5. Get paid 24-48 hours after validation

**NO VOUCHER NEEDED - Submit right now!**
"""
        elif submission_info['method'] == 'direct_email':
            email = submission_info.get('email', 'security@target.com')
            instructions += f"""1. Email: {email}
2. Subject: Security Vulnerability Report - {finding.get('type', 'Vulnerability')}
3. Attach your report (template below)
4. Send immediately
5. Get paid {submission_info['payout_time']} after validation

**NO PLATFORM NEEDED - Email directly!**

### Email Template:
```
{InstantSubmissionHelper._generate_email_template(finding)}
```
"""
        elif submission_info['method'] == 'github':
            url = submission_info.get('url', 'https://github.com')
            instructions += f"""1. Go to: {url}
2. Open Discussions
3. Create new discussion with your report
4. Submit immediately
5. Get paid {submission_info['payout_time']} after validation

**NO SIGNUP NEEDED - Submit via GitHub!**
"""
        
        return instructions
    
    @staticmethod
    def get_fastest_submission_method(finding: Dict[str, Any]) -> Dict[str, Any]:
        """Get fastest submission method for a finding"""
        url = finding.get('url', '')
        
        # Check if target matches known programs
        if 'kraken.com' in url.lower():
            return {
                "method": "direct_email",
                "platform": "kraken",
                "email": "security@kraken.com",
                "payout_time": "3-5 days",
                "template": InstantSubmissionHelper._generate_email_template(finding)
            }
        elif 'bytefederal.com' in url.lower():
            return {
                "method": "direct_email",
                "platform": "byte_federal",
                "email": "security@bytefederal.com",
                "payout_time": "5-7 days",
                "template": InstantSubmissionHelper._generate_email_template(finding)
            }
        elif 'clearpool' in url.lower():
            return {
                "method": "github",
                "platform": "clearpool",
                "url": "https://github.com/clearpool-finance",
                "payout_time": "3-5 days",
                "template": InstantSubmissionHelper._generate_github_template(finding)
            }
        else:
            # Default to Open Bug Bounty (fastest, no signup)
            return {
                "method": "open_bug_bounty",
                "platform": "Open Bug Bounty",
                "url": "https://www.openbugbounty.org",
                "payout_time": "24-48 hours",
                "template": InstantSubmissionHelper._generate_open_bug_bounty_template(finding)
            }

