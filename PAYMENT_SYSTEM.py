#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
PAYMENT COLLECTION SYSTEM
Generate invoices and track payments - Get paid BEFORE work

Usage:
    python3 PAYMENT_SYSTEM.py --client "TechCorp" --service "AI Security Audit" --price 1500
"""

import json
from datetime import datetime, timedelta
from typing import Dict

class PaymentSystem:
    """Manage invoices and payment tracking"""
    
    def __init__(self):
        self.invoices = []
        self.load_invoices()
    
    def load_invoices(self):
        """Load existing invoices"""
        try:
            with open('invoices.json', 'r') as f:
                self.invoices = json.load(f)
        except FileNotFoundError:
            self.invoices = []
    
    def save_invoices(self):
        """Save invoices to file"""
        with open('invoices.json', 'w') as f:
            json.dump(self.invoices, f, indent=2)
    
    def create_invoice(self, client_name: str, service: str, price: float, 
                      payment_terms: str = "Due upon receipt") -> Dict:
        """Create professional invoice"""
        
        invoice_number = f"INV-{datetime.now().strftime('%Y%m%d')}-{len(self.invoices) + 1:03d}"
        
        invoice = {
            'invoice_number': invoice_number,
            'client_name': client_name,
            'service': service,
            'price': price,
            'payment_terms': payment_terms,
            'status': 'UNPAID',
            'created_date': datetime.now().isoformat(),
            'due_date': (datetime.now() + timedelta(days=0)).isoformat(),  # Due immediately
            'paid_date': None,
            'payment_method': None
        }
        
        self.invoices.append(invoice)
        self.save_invoices()
        
        return invoice
    
    def generate_invoice_text(self, invoice: Dict, your_details: Dict) -> str:
        """Generate invoice text for email"""
        
        template = f"""
╔═══════════════════════════════════════════════════════════════╗
║                         INVOICE                               ║
╚═══════════════════════════════════════════════════════════════╝

Invoice #: {invoice['invoice_number']}
Date: {datetime.fromisoformat(invoice['created_date']).strftime('%B %d, %Y')}

BILL TO:
{invoice['client_name']}

FROM:
{your_details.get('name', 'Your Name')}
{your_details.get('business_name', 'Security Consulting')}
{your_details.get('email', 'your@email.com')}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SERVICE DESCRIPTION                                         AMOUNT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{invoice['service']:<55} ${invoice['price']:,.2f}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

                                                TOTAL: ${invoice['price']:,.2f}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PAYMENT TERMS: {invoice['payment_terms']}

PAYMENT METHODS:
{self._format_payment_methods(your_details.get('payment_methods', {}))}

IMPORTANT: Work begins upon payment receipt.
Please reply with payment confirmation to start your assessment.

Thank you for your business!
{your_details.get('name', 'Your Name')}
{your_details.get('email', 'your@email.com')}
"""
        return template
    
    def _format_payment_methods(self, methods: Dict) -> str:
        """Format payment method details"""
        formatted = []
        
        if methods.get('paypal'):
            formatted.append(f"• PayPal: {methods['paypal']}")
        if methods.get('venmo'):
            formatted.append(f"• Venmo: @{methods['venmo']}")
        if methods.get('crypto'):
            formatted.append(f"• Bitcoin: {methods['crypto']}")
        if methods.get('bank'):
            formatted.append("• Bank Transfer: (Details provided upon request)")
        if methods.get('stripe'):
            formatted.append(f"• Credit Card: {methods['stripe']}")
        
        if not formatted:
            formatted.append("• PayPal / Venmo / Crypto accepted")
        
        return "\n".join(formatted)
    
    def mark_paid(self, invoice_number: str, payment_method: str = "PayPal"):
        """Mark invoice as paid"""
        for invoice in self.invoices:
            if invoice['invoice_number'] == invoice_number:
                invoice['status'] = 'PAID'
                invoice['paid_date'] = datetime.now().isoformat()
                invoice['payment_method'] = payment_method
                self.save_invoices()
                return True
        return False
    
    def get_unpaid_invoices(self):
        """Get all unpaid invoices"""
        return [inv for inv in self.invoices if inv['status'] == 'UNPAID']
    
    def get_revenue_stats(self):
        """Calculate revenue statistics"""
        total_invoiced = sum(inv['price'] for inv in self.invoices)
        total_paid = sum(inv['price'] for inv in self.invoices if inv['status'] == 'PAID')
        total_unpaid = sum(inv['price'] for inv in self.invoices if inv['status'] == 'UNPAID')
        
        return {
            'total_invoiced': total_invoiced,
            'total_paid': total_paid,
            'total_unpaid': total_unpaid,
            'invoice_count': len(self.invoices),
            'paid_count': len([inv for inv in self.invoices if inv['status'] == 'PAID']),
            'unpaid_count': len([inv for inv in self.invoices if inv['status'] == 'UNPAID'])
        }

def main():
    print("""
╔═══════════════════════════════════════════════════════════════╗
║              PAYMENT COLLECTION SYSTEM                        ║
║           Get Paid BEFORE You Work                            ║
╚═══════════════════════════════════════════════════════════════╝
    """)
    
    payment_system = PaymentSystem()
    
    # Your business details
    your_details = {
        'name': 'Alex Chen',
        'business_name': 'ShadowStep Security Consulting',
        'email': 'alex@shadowstep-security.com',
        'payment_methods': {
            'paypal': 'alex@shadowstep-security.com',
            'venmo': 'shadowstep-security',
            'crypto': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
            'stripe': 'https://buy.stripe.com/your-payment-link'
        }
    }
    
    # Example: Create invoice
    print("\n[EXAMPLE] Creating Invoice...")
    invoice = payment_system.create_invoice(
        client_name="TechShop AI Inc.",
        service="AI Security Assessment - Comprehensive",
        price=2500.00,
        payment_terms="50% upfront ($1,250), 50% on delivery"
    )
    
    print(f"✓ Invoice created: {invoice['invoice_number']}")
    
    # Generate invoice text
    print("\n" + "="*80)
    print("INVOICE TEXT (Copy and paste into email):")
    print("="*80)
    invoice_text = payment_system.generate_invoice_text(invoice, your_details)
    print(invoice_text)
    
    # Revenue stats
    stats = payment_system.get_revenue_stats()
    print("\n" + "="*80)
    print("REVENUE DASHBOARD")
    print("="*80)
    print(f"Total Invoiced: ${stats['total_invoiced']:,.2f}")
    print(f"Total Paid: ${stats['total_paid']:,.2f}")
    print(f"Total Unpaid: ${stats['total_unpaid']:,.2f}")
    print(f"\nInvoices: {stats['invoice_count']} total ({stats['paid_count']} paid, {stats['unpaid_count']} unpaid)")
    
    print("""

╔═══════════════════════════════════════════════════════════════╗
║                    PAYMENT WORKFLOW                           ║
╚═══════════════════════════════════════════════════════════════╝

STEP 1: Client agrees to assessment
  → Send invoice immediately
  → "I'll send over the invoice. Work starts as soon as payment clears!"

STEP 2: Send invoice
  → Use template above
  → Include all payment methods
  → Clear payment terms

STEP 3: Wait for payment
  → Check PayPal/Venmo/bank daily
  → DO NOT START WORK until paid
  → Follow up after 24-48 hours if no payment

STEP 4: Payment received
  → Mark invoice as paid
  → Start work immediately
  → Send "Payment received, starting assessment now" email

STEP 5: Deliver results
  → Generate report with ONE_CLICK_ASSESSMENT.py
  → Send professional PDF
  → Ask for testimonial/referral

╔═══════════════════════════════════════════════════════════════╗
║                   PRICING STRATEGY                            ║
╚═══════════════════════════════════════════════════════════════╝

AI Security Audit (Basic):
  Price: $500-750
  Time: 1-2 hours
  Deliverable: JSON report + recommendations

AI Security Audit (Comprehensive):
  Price: $1,500-2,500
  Time: 3-5 hours
  Deliverable: Professional PDF + detailed remediation

Full Stack Assessment (Web + AI):
  Price: $3,000-5,000
  Time: 6-10 hours
  Deliverable: Complete security audit + retest

Retainer (Monthly):
  Price: $997-2,997/month
  Deliverable: Continuous monitoring + monthly scans

╔═══════════════════════════════════════════════════════════════╗
║              PROTECT YOURSELF - PAYMENT FIRST                 ║
╚═══════════════════════════════════════════════════════════════╝

NEVER start work without payment because:
  ❌ Client might disappear after you deliver
  ❌ Client might dispute value
  ❌ Client might claim "didn't find anything"
  ❌ You lose leverage once work is done

ALWAYS get paid first because:
  ✅ You're guaranteed payment
  ✅ Client is committed
  ✅ You control delivery timeline
  ✅ Professional business practice

If client hesitates:
  "I require 50% upfront to begin work. This is standard practice
   for security assessments. I can start as soon as payment clears!"

If client pushes back:
  "I understand. How about this: $500 upfront for initial scan,
   then remaining $1,000 only if you want the full report?"

REMEMBER: Your time is valuable. Get paid first, deliver value,
collect testimonial, move to next client.
    """)

if __name__ == '__main__':
    main()
