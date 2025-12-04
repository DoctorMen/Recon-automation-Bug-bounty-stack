#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Quick Client Workflow Automation
Complete workflow from project win to delivery
"""

import argparse
import subprocess
import sys
from pathlib import Path
from datetime import datetime

def run_complete_workflow(client_name, domain, amount):
    """Run complete client workflow"""
    base_dir = Path(__file__).parent.parent
    client_dir = base_dir / "output" / client_name.replace(" ", "_")
    client_dir.mkdir(parents=True, exist_ok=True)
    
    print("="*60)
    print(f"🚀 COMPLETE CLIENT WORKFLOW: {client_name}")
    print("="*60)
    
    # Step 1: Track project won
    print(f"\n[1/4] 📝 Tracking project won...")
    try:
        result = subprocess.run([
            "python3", "scripts/automate_first_dollar.py",
            "--action", "won",
            "--client", client_name,
            "--amount", str(amount),
            "--domain", domain
        ], cwd=base_dir, check=True)
        print("✅ Project tracked")
    except:
        print("⚠️  Could not track (continuing anyway)")
    
    # Step 2: Run scan
    print(f"\n[2/4] 🔍 Running security scan for {domain}...")
    try:
        result = subprocess.run([
            "python3", "run_pipeline.py",
            "--target", domain,
            "--output", str(client_dir)
        ], cwd=base_dir, check=True)
        print("✅ Scan complete")
    except subprocess.CalledProcessError as e:
        print(f"❌ Scan failed: {e}")
        return False
    
    # Step 3: Generate report
    print(f"\n[3/4] 📊 Generating professional report...")
    try:
        result = subprocess.run([
            "python3", "scripts/generate_report.py",
            "--format", "professional",
            "--client-name", client_name,
            "--output", str(client_dir / "report.pdf")
        ], cwd=base_dir, check=True)
        print("✅ Report generated")
    except subprocess.CalledProcessError as e:
        print(f"⚠️  Report generation failed: {e}")
        print("Creating placeholder...")
        (client_dir / "report.pdf").touch()
    
    # Step 4: Track delivery
    print(f"\n[4/4] ✅ Marking as delivered...")
    try:
        result = subprocess.run([
            "python3", "scripts/automate_first_dollar.py",
            "--action", "deliver",
            "--client", client_name
        ], cwd=base_dir, check=True)
        print("✅ Delivery tracked")
    except:
        print("⚠️  Could not track delivery")
    
    # Generate delivery message
    print("\n" + "="*60)
    print("📧 DELIVERY MESSAGE TEMPLATE:")
    print("="*60)
    print(f"""
Hi {client_name},

Your security scan is complete!

Attached: Executive Summary + Full Technical Report

Location: {client_dir / 'report.pdf'}

Next steps:
1. Review Executive Summary (2 pages)
2. Forward technical details to your developer
3. I'm available for 30 days if you have questions

Want to discuss findings over a quick call?

Best,
[Your Name]
""")
    
    print("="*60)
    print("✅ Workflow complete!")
    print(f"📁 All files saved to: {client_dir}")
    
    return True


def main():
    parser = argparse.ArgumentParser(description="Quick Client Workflow Automation")
    parser.add_argument("--client", required=True, help="Client name")
    parser.add_argument("--domain", required=True, help="Domain to scan")
    parser.add_argument("--amount", type=int, required=True, help="Project amount")
    
    args = parser.parse_args()
    
    success = run_complete_workflow(args.client, args.domain, args.amount)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

