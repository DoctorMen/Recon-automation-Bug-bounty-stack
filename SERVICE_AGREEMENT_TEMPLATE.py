#!/usr/bin/env python3
"""
SERVICE AGREEMENT TEMPLATE - LEGAL CLIENT CONTRACTS
==================================================
Professional service agreement for security audit consulting.

Legal: Simple 1-page engagement letter covering all essential terms
Usage: Customize for each client before accepting payment
Protection: Limits liability, defines scope, payment terms

Copyright (c) 2025 DoctorMen
"""

import json
from datetime import datetime, timedelta
from typing import Dict, Any

class ServiceAgreementTemplate:
    """Generate professional service agreements for security consulting"""
    
    def __init__(self):
        self.agreement_template = {
            "title": "Professional Security Audit Services Agreement",
            "parties": {
                "provider": "Alpine Security Consulting LLC",
                "client": "[CLIENT BUSINESS NAME]"
            },
            "services": {
                "description": "Professional Website Security Audit",
                "scope": "External security assessment of client's website and online infrastructure",
                "deliverables": [
                    "Comprehensive security vulnerability assessment",
                    "Professional security audit report with executive summary",
                    "Detailed remediation recommendations",
                    "30-day follow-up consultation"
                ],
                "exclusions": [
                    "Internal network testing",
                    "Social engineering assessments",
                    "Physical security assessments",
                    "Source code review"
                ]
            },
            "timeline": {
                "start_date": "[START DATE]",
                "delivery_date": "[DELIVERY DATE - within 48 hours]",
                "consultation_period": "30 days from delivery"
            },
            "payment": {
                "total_fee": "$997.00",
                "payment_schedule": [
                    "50% due upon signing ($498.50)",
                    "50% due upon report delivery ($498.50)"
                ],
                "payment_methods": ["Bank transfer", "Business check", "PayPal Business"],
                "late_payment": "1.5% per month on overdue amounts"
            },
            "liability": {
                "limitation": "Liability limited to fees paid for services",
                "no_guarantee": "No guarantee of complete security or zero vulnerabilities",
                "client_responsibility": "Client responsible for implementing remediation",
                "indemnification": "Client indemnifies provider against third-party claims"
            },
            "confidentiality": {
                "duration": "5 years from agreement date",
                "scope": "All client information and assessment results",
                "exceptions": "Legal requirements, court orders, or with client consent"
            },
            "termination": {
                "by_client": "48 hours written notice, payment for services rendered",
                "by_provider": "Material breach of agreement, 24 hours written notice",
                "effect": "Payment for all services performed up to termination date"
            }
        }
    
    def generate_service_agreement(self, client_name: str, client_email: str, target_website: str) -> Dict[str, Any]:
        """Generate customized service agreement for specific client"""
        
        print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║          SERVICE AGREEMENT TEMPLATE - LEGAL CLIENT CONTRACTS           ║
║          Professional Protection | Scope Definition | Payment Terms     ║
╚══════════════════════════════════════════════════════════════════════╝

🎯 CLIENT: {client_name}
📧 EMAIL: {client_email}
🌐 TARGET: {target_website}
💰 FEE: $997.00
        """)
        
        # Customize agreement for client
        customized_agreement = self.agreement_template.copy()
        customized_agreement["parties"]["client"] = client_name
        customized_agreement["client_contact"] = {
            "email": client_email,
            "website": target_website
        }
        
        # Add dates
        today = datetime.now()
        start_date = today.strftime("%B %d, %Y")
        delivery_date = (today + timedelta(days=2)).strftime("%B %d, %Y")
        
        customized_agreement["timeline"]["start_date"] = start_date
        customized_agreement["timeline"]["delivery_date"] = delivery_date
        customized_agreement["agreement_date"] = start_date
        
        # Add signature blocks
        signatures = {
            "provider_signature": "_________________________",
            "provider_name": "Alpine Security Consulting LLC",
            "provider_date": start_date,
            "client_signature": "_________________________",
            "client_name": client_name,
            "client_date": start_date
        }
        
        # Generate agreement text
        agreement_text = self._create_agreement_document(customized_agreement, signatures)
        customized_agreement["full_text"] = agreement_text
        customized_agreement["signatures"] = signatures
        
        # Save agreement
        filename = f"service_agreement_{client_name.replace(' ', '_').lower()}_{int(datetime.now().timestamp())}.json"
        with open(filename, 'w') as f:
            json.dump(customized_agreement, f, indent=2)
        
        # Also save as text file for easy printing
        text_filename = filename.replace('.json', '.txt')
        with open(text_filename, 'w') as f:
            f.write(agreement_text)
        
        self._print_agreement_summary(customized_agreement, filename, text_filename)
        
        return customized_agreement
    
    def _create_agreement_document(self, agreement: Dict, signatures: Dict) -> str:
        """Create formatted agreement document text"""
        
        document = f"""
{agreement['title'].upper()}
{'=' * len(agreement['title'])}

AGREEMENT DATE: {agreement['agreement_date']}

PARTIES:
Provider: {agreement['parties']['provider']}
Client: {agreement['parties']['client']}

SERVICES:
{agreement['services']['description']}

Scope of Work:
{agreement['services']['scope']}

Deliverables:
"""
        
        for deliverable in agreement['services']['deliverables']:
            document += f"• {deliverable}\n"
        
        document += f"""
Exclusions:
"""
        
        for exclusion in agreement['services']['exclusions']:
            document += f"• {exclusion}\n"
        
        document += f"""
TIMELINE:
Start Date: {agreement['timeline']['start_date']}
Delivery Date: {agreement['timeline']['delivery_date']}
Consultation Period: {agreement['timeline']['consultation_period']}

PAYMENT TERMS:
Total Fee: {agreement['payment']['total_fee']}
Payment Schedule:
"""
        
        for payment in agreement['payment']['payment_schedule']:
            document += f"• {payment}\n"
        
        document += f"""
Payment Methods: {', '.join(agreement['payment']['payment_methods'])}
Late Payment: {agreement['payment']['late_payment']}

LIABILITY LIMITATION:
{agreement['liability']['limitation']}
{agreement['liability']['no_guarantee']}
{agreement['liability']['client_responsibility']}
{agreement['liability']['indemnification']}

CONFIDENTIALITY:
Duration: {agreement['confidentiality']['duration']}
Scope: {agreement['confidentiality']['scope']}
Exceptions: {agreement['confidentiality']['exceptions']}

TERMINATION:
By Client: {agreement['termination']['by_client']}
By Provider: {agreement['termination']['by_provider']}
Effect: {agreement['termination']['effect']}

SIGNATURES:

PROVIDER:
{signatures['provider_signature']}
{signatures['provider_name']}
Date: {signatures['provider_date']}

CLIENT:
{signatures['client_signature']}
{signatures['client_name']}
Date: {signatures['client_date']}

GOVERNING LAW:
This agreement shall be governed by the laws of the State of Wyoming.
Any disputes shall be resolved through binding arbitration.

ENTIRE AGREEMENT:
This document represents the entire agreement between the parties
and supersedes all prior discussions and understandings.
        """
        
        return document
    
    def _print_agreement_summary(self, agreement: Dict, json_file: str, text_file: str):
        """Print agreement generation summary"""
        
        print(f"""
{'='*70}
📋 SERVICE AGREEMENT GENERATION COMPLETE
{'='*70}

📄 AGREEMENT DETAILS:
   Client: {agreement['parties']['client']}
   Service: {agreement['services']['description']}
   Fee: {agreement['payment']['total_fee']}
   Timeline: {agreement['timeline']['delivery_date']}
   Start Date: {agreement['timeline']['start_date']}

📁 FILES CREATED:
   JSON Data: {json_file}
   Printable: {text_file}

🔒 LEGAL PROTECTIONS INCLUDED:
   ✅ Scope definition (prevents scope creep)
   ✅ Payment terms (ensures timely payment)
   ✅ Liability limitation (protects your business)
   ✅ Confidentiality clause (protects client data)
   ✅ Termination terms (defines exit process)
   ✅ Governing law (Wyoming LLC friendly)

💡 USAGE INSTRUCTIONS:
   1. Send text file to client for review
   2. Client signs and returns
   3. Collect 50% upfront payment
   4. Begin security audit services
   5. Deliver report and collect final payment

🎯 READY FOR CLIENT ENGAGEMENT - LEGALLY PROTECTED!

This service agreement provides essential legal protection
while maintaining professional standards for client relationships.
        """)

def main():
    """Execute service agreement generation demonstration"""
    
    print("""
📋 SERVICE AGREEMENT TEMPLATE - LEGAL CLIENT CONTRACTS
==================================================

✅ LEGAL: Professional 1-page engagement letter
✅ PROTECTION: Limits liability, defines scope, payment terms
✅ READY: Customizable for each client
✅ COMPLIANT: Suitable for Wyoming LLC operations

This essential legal document enables safe client engagement.
    """)
    
    generator = ServiceAgreementTemplate()
    
    # Demonstrate with sample client
    sample_client = "Example Restaurant LLC"
    sample_email = "owner@examplerestaurant.com"
    sample_website = "examplerestaurant.com"
    
    agreement = generator.generate_service_agreement(sample_client, sample_email, sample_website)
    
    print(f"""
✅ SERVICE AGREEMENT CAPABILITY CONFIRMED

You now have:
- Professional service agreement template
- Legal protection for client engagements
- Clear scope and payment terms
- Wyoming LLC compliant documentation

🎯 READY TO SIGN FIRST CLIENT - LEGALLY PROTECTED!
    """)

if __name__ == "__main__":
    main()
