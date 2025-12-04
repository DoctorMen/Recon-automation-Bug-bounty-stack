#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
🛡️ INSURANCE INFORMATION MANAGEMENT
Track professional liability insurance for legal compliance

LEGAL REQUIREMENT: Maintain $1M-$2M liability insurance for security testing
"""

import os
import sys
import json
from datetime import datetime, timedelta
from pathlib import Path

class InsuranceManager:
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.safety_db = self.project_root / "data" / "safety"
        self.safety_db.mkdir(parents=True, exist_ok=True)
        self.insurance_db = self.safety_db / "insurance_status.json"
    
    def setup_insurance(self, 
                       provider: str,
                       policy_number: str,
                       coverage_amount: int,
                       expiry_date: str):
        """
        Setup insurance information
        
        Args:
            provider: Insurance provider name (e.g., "Hiscox", "Coalition")
            policy_number: Your policy number
            coverage_amount: Coverage amount in dollars (e.g., 1000000 for $1M)
            expiry_date: Expiry date in YYYY-MM-DD format
        """
        
        try:
            expiry = datetime.fromisoformat(expiry_date)
        except:
            print("❌ Error: Expiry date must be in YYYY-MM-DD format")
            return
        
        days_until_expiry = (expiry - datetime.now()).days
        
        if days_until_expiry < 0:
            status = "EXPIRED"
        elif days_until_expiry < 30:
            status = "EXPIRING_SOON"
        else:
            status = "ACTIVE"
        
        insurance_data = {
            "status": status,
            "provider": provider,
            "policy_number": policy_number,
            "coverage_amount": coverage_amount,
            "expiry_date": expiry_date,
            "last_updated": datetime.now().isoformat(),
            "alerts": {
                "expiry_notification_30d": days_until_expiry < 30,
                "expiry_notification_7d": days_until_expiry < 7
            }
        }
        
        with open(self.insurance_db, 'w') as f:
            json.dump(insurance_data, f, indent=2)
        
        print("✅ Insurance information updated!")
        print(f"\nProvider: {provider}")
        print(f"Policy Number: {policy_number}")
        print(f"Coverage: ${coverage_amount:,}")
        print(f"Expires: {expiry_date}")
        print(f"Status: {status}")
        
        if days_until_expiry < 30:
            print(f"\n⚠️  WARNING: Insurance expires in {days_until_expiry} days!")
            print("   Please renew your policy soon.")
    
    def check_insurance(self):
        """Check current insurance status"""
        if not self.insurance_db.exists():
            print("❌ Insurance information not configured")
            print("\nSetup with:")
            print("python3 scripts/setup_insurance_info.py \\")
            print("  --provider 'Hiscox' \\")
            print("  --policy 'POL123456' \\")
            print("  --coverage 1000000 \\")
            print("  --expiry '2025-12-31'")
            return
        
        with open(self.insurance_db, 'r') as f:
            data = json.load(f)
        
        status = data.get("status", "UNKNOWN")
        provider = data.get("provider", "")
        coverage = data.get("coverage_amount", 0)
        expiry_date = data.get("expiry_date", "")
        
        print("\n" + "="*70)
        print("🛡️  INSURANCE STATUS")
        print("="*70)
        
        status_symbol = {
            "ACTIVE": "✅",
            "EXPIRING_SOON": "⚠️",
            "EXPIRED": "❌",
            "NOT_CONFIGURED": "❌"
        }.get(status, "❓")
        
        print(f"\n{status_symbol} Status: {status}")
        print(f"Provider: {provider}")
        print(f"Coverage: ${coverage:,}")
        print(f"Expires: {expiry_date}")
        
        if status == "EXPIRING_SOON":
            try:
                expiry = datetime.fromisoformat(expiry_date)
                days_remaining = (expiry - datetime.now()).days
                print(f"\n⚠️  WARNING: Expires in {days_remaining} days")
                print("   Schedule renewal immediately")
            except:
                pass
        elif status == "EXPIRED":
            print("\n❌ CRITICAL: Insurance EXPIRED")
            print("   Security testing should be paused until renewed")
            print("   Update with: python3 scripts/setup_insurance_info.py --update")
        
        print("="*70 + "\n")
    
    def insurance_recommendations(self):
        """Show insurance recommendations"""
        print("\n" + "="*70)
        print("💡 INSURANCE RECOMMENDATIONS FOR SECURITY PROFESSIONALS")
        print("="*70 + "\n")
        
        print("REQUIRED COVERAGE:")
        print("1. Cyber Liability Insurance")
        print("   - Minimum: $1M-$2M coverage")
        print("   - Covers: Data breaches, privacy violations, unauthorized access")
        print("   - Annual cost: $1,000-$3,000")
        print()
        
        print("2. Professional Liability (E&O)")
        print("   - Minimum: $1M-$2M coverage")
        print("   - Covers: Professional mistakes, missed vulnerabilities")
        print("   - Annual cost: $800-$2,500")
        print()
        
        print("3. General Business Liability")
        print("   - Minimum: $1M coverage")
        print("   - Covers: General business operations")
        print("   - Annual cost: $500-$1,500")
        print()
        
        print("RECOMMENDED PROVIDERS:")
        print("- Hiscox (hiscox.com)")
        print("- Coalition (thecoalition.com)")
        print("- Chubb (chubb.com)")
        print("- Travelers (travelers.com)")
        print("- Hartford (thehartford.com)")
        print()
        
        print("IMPORTANT NOTES:")
        print("✓ Shop around for best rates")
        print("✓ Read policy exclusions carefully")
        print("✓ Ensure coverage includes security testing")
        print("✓ Update coverage as revenue grows")
        print("✓ Set renewal reminders (30 days in advance)")
        print("="*70 + "\n")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Manage insurance information")
    parser.add_argument("--provider", help="Insurance provider name")
    parser.add_argument("--policy", help="Policy number")
    parser.add_argument("--coverage", type=int, help="Coverage amount (e.g., 1000000)")
    parser.add_argument("--expiry", help="Expiry date (YYYY-MM-DD)")
    parser.add_argument("--check", action="store_true", help="Check current status")
    parser.add_argument("--recommendations", action="store_true", help="Show recommendations")
    
    args = parser.parse_args()
    
    manager = InsuranceManager()
    
    if args.check:
        manager.check_insurance()
        return
    
    if args.recommendations:
        manager.insurance_recommendations()
        return
    
    if all([args.provider, args.policy, args.coverage, args.expiry]):
        manager.setup_insurance(
            provider=args.provider,
            policy_number=args.policy,
            coverage_amount=args.coverage,
            expiry_date=args.expiry
        )
    else:
        print("Insurance Information Management")
        print("\nUsage:")
        print("  python3 scripts/setup_insurance_info.py \\")
        print("    --provider 'Hiscox' \\")
        print("    --policy 'POL123456' \\")
        print("    --coverage 1000000 \\")
        print("    --expiry '2025-12-31'")
        print("\nOther commands:")
        print("  --check              Check current insurance status")
        print("  --recommendations    Show insurance recommendations")


if __name__ == "__main__":
    main()

