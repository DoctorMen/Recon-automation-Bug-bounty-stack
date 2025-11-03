#!/usr/bin/env python3
"""
Client Intake Form
Simple script to collect client information and start scan workflow
"""

import sys
from pathlib import Path

# Import client scan workflow
sys.path.insert(0, str(Path(__file__).parent))
from quick_client_scan import process_client_scan


def collect_client_info() -> dict:
    """Collect client information interactively"""
    
    print("=" * 80)
    print("CLIENT INTAKE FORM")
    print("=" * 80)
    print("\nPlease provide the following information:\n")
    
    client_name = input("Business Name: ").strip()
    if not client_name:
        print("Error: Business name required")
        sys.exit(1)
    
    contact_name = input("Contact Name: ").strip()
    if not contact_name:
        print("Error: Contact name required")
        sys.exit(1)
    
    email = input("Email Address: ").strip()
    if not email or "@" not in email:
        print("Error: Valid email address required")
        sys.exit(1)
    
    phone = input("Phone Number: ").strip()
    if not phone:
        print("Error: Phone number required")
        sys.exit(1)
    
    website = input("Website URL (e.g., https://example.com): ").strip()
    if not website:
        print("Error: Website URL required")
        sys.exit(1)
    
    # Add http:// if no scheme
    if not website.startswith(("http://", "https://")):
        website = "https://" + website
    
    amount_str = input("Payment Amount ($200 default): ").strip()
    amount = float(amount_str) if amount_str else 200.0
    
    payment_method = input("Payment Method (PayPal/Venmo/Zelle) [PayPal]: ").strip()
    if not payment_method:
        payment_method = "PayPal"
    
    print("\n" + "=" * 80)
    print("CONFIRMATION")
    print("=" * 80)
    print(f"\nBusiness: {client_name}")
    print(f"Contact: {contact_name}")
    print(f"Email: {email}")
    print(f"Phone: {phone}")
    print(f"Website: {website}")
    print(f"Amount: ${amount}")
    print(f"Payment: {payment_method}\n")
    
    confirm = input("Start scan? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("Cancelled.")
        sys.exit(0)
    
    return {
        "client_name": client_name,
        "contact_name": contact_name,
        "email": email,
        "phone": phone,
        "website": website,
        "amount": amount,
        "payment_method": payment_method
    }


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Client Intake Form")
    parser.add_argument("--interactive", action="store_true", help="Interactive mode")
    parser.add_argument("--client-name", help="Business name")
    parser.add_argument("--contact", help="Contact name")
    parser.add_argument("--email", help="Email address")
    parser.add_argument("--phone", help="Phone number")
    parser.add_argument("--website", help="Website URL")
    parser.add_argument("--amount", type=float, default=200.0, help="Payment amount")
    parser.add_argument("--payment-method", default="PayPal", help="Payment method")
    
    args = parser.parse_args()
    
    if args.interactive or not all([args.client_name, args.contact, args.email, args.phone, args.website]):
        # Interactive mode
        info = collect_client_info()
    else:
        # Command line mode
        info = {
            "client_name": args.client_name,
            "contact_name": args.contact,
            "email": args.email,
            "phone": args.phone,
            "website": args.website,
            "amount": args.amount,
            "payment_method": args.payment_method
        }
    
    # Process client scan
    result = process_client_scan(**info)
    
    if result["success"]:
        print("\n✅ Client intake and scan completed!")
        print(f"\nReport ready: {result['report_path']}")
        print(f"Send report to: {info['email']}")
    else:
        print(f"\n❌ Error: {result.get('error', 'Unknown error')}")
        sys.exit(1)


if __name__ == "__main__":
    main()

