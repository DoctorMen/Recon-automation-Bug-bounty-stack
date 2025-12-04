#!/usr/bin/env python3
"""
GDPR Authorization Creator
Creates GDPR-compliant authorization files for European operations

Copyright © 2025 DoctorMen. All Rights Reserved.
"""

import sys
import argparse
from LEGAL_AUTHORIZATION_SYSTEM_GDPR import GDPRLegalAuthorizationShield

def main():
    parser = argparse.ArgumentParser(
        description="Create GDPR-compliant authorization template for security testing",
        epilog="Example: python3 CREATE_GDPR_AUTHORIZATION.py --target example.com --client 'Client Corp' --country France"
    )
    
    parser.add_argument("--target", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("--client", required=True, help="Client company name")
    parser.add_argument("--country", required=False, default="", help="EU Member State (e.g., France, Germany, Netherlands)")
    
    args = parser.parse_args()
    
    print("="*70)
    print("🇪🇺 GDPR-COMPLIANT AUTHORIZATION CREATOR")
    print("="*70)
    print(f"\nTarget: {args.target}")
    print(f"Client: {args.client}")
    print(f"EU Member State: {args.country if args.country else 'Not specified'}")
    print()
    
    # Create authorization template
    shield = GDPRLegalAuthorizationShield()
    filename = shield.create_gdpr_authorization_template(
        target=args.target,
        client_name=args.client,
        eu_member_state=args.country
    )
    
    print("\n" + "="*70)
    print("✅ GDPR AUTHORIZATION TEMPLATE CREATED")
    print("="*70)
    
    print(f"\n📁 File: {filename}")
    print("\n⚠️  CRITICAL NEXT STEPS:")
    print("\n1️⃣  COMPLETE DPIA (Data Protection Impact Assessment)")
    print("   python3 CREATE_DPIA_TEMPLATE.py --target", args.target)
    
    print("\n2️⃣  EDIT AUTHORIZATION FILE")
    print(f"   nano {filename}")
    print("   Required edits:")
    print("   - Fill in authorized_by name and email")
    print("   - Add emergency contact phone")
    print("   - Review and update scope array")
    print("   - Verify GDPR lawful basis (consent, contract, etc.)")
    print("   - Add Data Controller information")
    print("   - Add DPO contact (if applicable)")
    print("   - Specify data categories")
    print("   - Set retention period (max 7 years)")
    print("   - Review cross-border transfer settings")
    print("   - Update NIS2 fields if critical entity")
    
    print("\n3️⃣  GET CLIENT SIGNATURE")
    print("   - Send authorization to client")
    print("   - Obtain signature (electronic or wet signature)")
    print("   - Add signature_date to file")
    print("   - Calculate SHA256 hash of signed document")
    print("   - Add signature_hash to file")
    
    print("\n4️⃣  VERIFY GDPR COMPLIANCE")
    print(f"   python3 VERIFY_GDPR_COMPLIANCE.py {filename}")
    
    print("\n5️⃣  RUN AUTHORIZED SCAN")
    print(f"   python3 SENTINEL_AGENT.py {args.target} --tier basic --gdpr")
    
    print("\n" + "="*70)
    print("📚 GDPR COMPLIANCE RESOURCES")
    print("="*70)
    print("\n🇪🇺 GDPR Information:")
    print("   https://gdpr.eu/")
    print("   https://ec.europa.eu/info/law/law-topic/data-protection")
    
    print("\n🛡️ NIS2 Directive:")
    print("   https://digital-strategy.ec.europa.eu/en/policies/nis2-directive")
    
    print("\n📋 Data Protection Authorities (DPAs):")
    print("   France (CNIL): https://www.cnil.fr/")
    print("   Germany (BfDI): https://www.bfdi.bund.de/")
    print("   Netherlands (AP): https://autoriteitpersoonsgegevens.nl/")
    print("   EU-wide list: https://edpb.europa.eu/about-edpb/about-edpb/members_en")
    
    print("\n⚖️  LEGAL NOTICE:")
    print("   This tool creates templates only. You are responsible for:")
    print("   - Obtaining proper legal authorization")
    print("   - Ensuring GDPR compliance")
    print("   - Consulting with legal counsel")
    print("   - Complying with national laws in EU member states")
    print("   - Registering with relevant data protection authorities")
    print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        sys.exit(1)
