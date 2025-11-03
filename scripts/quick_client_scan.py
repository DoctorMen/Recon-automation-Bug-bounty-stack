#!/usr/bin/env python3
"""
Quick Client Scan
Automated workflow for scanning a single client website and generating report
"""

import json
import sys
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional

# Paths
SCRIPT_DIR = Path(__file__).parent
REPO_ROOT = SCRIPT_DIR.parent
OUTPUT_DIR = REPO_ROOT / "output"
CLIENT_DATA_DIR = REPO_ROOT / "client_data"

# Import client tracking and report generator
sys.path.insert(0, str(SCRIPT_DIR))
from client_tracking import add_client, add_scan, add_payment, get_client_stats
from client_report_generator import generate_report_from_scan_results


def run_scan_for_client(website_url: str, client_output_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Run quick scan for a client website"""
    
    if not client_output_dir:
        # Create client-specific output directory
        safe_domain = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in website_url)
        client_output_dir = OUTPUT_DIR / f"client_{safe_domain}_{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    
    client_output_dir.mkdir(parents=True, exist_ok=True)
    
    # Create temporary targets.txt
    targets_file = client_output_dir / "targets.txt"
    with open(targets_file, "w", encoding="utf-8") as f:
        f.write(website_url + "\n")
    
    # Save original targets.txt
    original_targets = REPO_ROOT / "targets.txt"
    targets_backup = None
    if original_targets.exists():
        targets_backup = REPO_ROOT / "targets.txt.backup"
        import shutil
        shutil.copy(original_targets, targets_backup)
    
    # Temporarily replace targets.txt
    import shutil
    shutil.copy(targets_file, original_targets)
    
    try:
        # Run immediate ROI hunter (fastest scan)
        print(f"Running security scan for {website_url}...")
        print("This may take 5-15 minutes...")
        
        roi_script = SCRIPT_DIR / "immediate_roi_hunter.py"
        result = subprocess.run(
            [sys.executable, str(roi_script)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=1800  # 30 minutes max
        )
        
        if result.returncode != 0:
            print(f"Warning: Scan completed with errors: {result.stderr}")
        
        # Find scan results
        findings_files = [
            OUTPUT_DIR / "triage.json",
            OUTPUT_DIR / "nuclei-findings.json",
            OUTPUT_DIR / "immediate_roi" / "high_roi_findings.json"
        ]
        
        findings = []
        for findings_file in findings_files:
            if findings_file.exists():
                try:
                    with open(findings_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            findings.extend(data)
                        elif isinstance(data, dict):
                            findings.append(data)
                except Exception as e:
                    print(f"Warning: Could not read {findings_file}: {e}")
        
        # Count by severity
        critical_count = sum(1 for f in findings if f.get("info", {}).get("severity", "").lower() == "critical")
        high_count = sum(1 for f in findings if f.get("info", {}).get("severity", "").lower() == "high")
        medium_count = sum(1 for f in findings if f.get("info", {}).get("severity", "").lower() == "medium")
        low_count = sum(1 for f in findings if f.get("info", {}).get("severity", "").lower() == "low")
        
        # Calculate security score
        security_score = 10 - (critical_count * 3 + high_count * 2 + medium_count * 1 + low_count * 0.5)
        security_score = max(0, min(10, int(security_score)))
        
        return {
            "success": True,
            "findings": findings,
            "findings_count": len(findings),
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "security_score": security_score,
            "output_dir": client_output_dir
        }
    
    finally:
        # Restore original targets.txt
        if targets_backup and targets_backup.exists():
            import shutil
            shutil.copy(targets_backup, original_targets)
            targets_backup.unlink()


def process_client_scan(
    client_name: str,
    contact_name: str,
    email: str,
    phone: str,
    website: str,
    amount: float = 200.0,
    payment_method: str = "PayPal"
) -> Dict[str, Any]:
    """Complete client scan workflow"""
    
    print("=" * 80)
    print("CLIENT SCAN WORKFLOW")
    print("=" * 80)
    print(f"\nClient: {client_name}")
    print(f"Website: {website}")
    print(f"Payment: ${amount} via {payment_method}\n")
    
    # Step 1: Add client to tracking
    print("[*] Adding client to tracking system...")
    client_id = add_client(
        business_name=client_name,
        contact_name=contact_name,
        email=email,
        phone=phone,
        website=website
    )
    print(f"✅ Client ID: {client_id}\n")
    
    # Step 2: Run scan
    print("[*] Running security scan...")
    scan_results = run_scan_for_client(website)
    
    if not scan_results["success"]:
        return {
            "success": False,
            "error": "Scan failed",
            "client_id": client_id
        }
    
    print(f"✅ Scan complete: {scan_results['findings_count']} findings")
    print(f"   Security Score: {scan_results['security_score']}/10\n")
    
    # Step 3: Generate client report
    print("[*] Generating professional report...")
    report_path = generate_report_from_scan_results(
        client_name=client_name,
        client_email=email,
        website_url=website
    )
    print(f"✅ Report generated: {report_path}\n")
    
    # Step 4: Add scan record
    print("[*] Recording scan...")
    scan_id = add_scan(
        client_id=client_id,
        website=website,
        scan_type="emergency",
        findings_count=scan_results["findings_count"],
        critical_count=scan_results["critical_count"],
        high_count=scan_results["high_count"],
        medium_count=scan_results["medium_count"],
        low_count=scan_results["low_count"],
        security_score=scan_results["security_score"],
        report_path=str(report_path)
    )
    print(f"✅ Scan ID: {scan_id}\n")
    
    # Step 5: Record payment
    print("[*] Recording payment...")
    payment_id = add_payment(
        client_id=client_id,
        scan_id=scan_id,
        amount=amount,
        payment_method=payment_method,
        payment_type="emergency_scan"
    )
    print(f"✅ Payment ID: {payment_id}\n")
    
    print("=" * 80)
    print("SCAN COMPLETE!")
    print("=" * 80)
    print(f"\nReport: {report_path}")
    print(f"Client ID: {client_id}")
    print(f"Scan ID: {scan_id}")
    print(f"Payment ID: {payment_id}\n")
    
    return {
        "success": True,
        "client_id": client_id,
        "scan_id": scan_id,
        "payment_id": payment_id,
        "report_path": report_path,
        "scan_results": scan_results
    }


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Quick Client Scan Workflow")
    parser.add_argument("--client-name", required=True, help="Business name")
    parser.add_argument("--contact", required=True, help="Contact name")
    parser.add_argument("--email", required=True, help="Email address")
    parser.add_argument("--phone", required=True, help="Phone number")
    parser.add_argument("--website", required=True, help="Website URL")
    parser.add_argument("--amount", type=float, default=200.0, help="Payment amount")
    parser.add_argument("--payment-method", default="PayPal", help="Payment method")
    
    args = parser.parse_args()
    
    result = process_client_scan(
        client_name=args.client_name,
        contact_name=args.contact,
        email=args.email,
        phone=args.phone,
        website=args.website,
        amount=args.amount,
        payment_method=args.payment_method
    )
    
    if result["success"]:
        print("\n✅ Client scan workflow completed successfully!")
        print(f"\nNext steps:")
        print(f"1. Email report to {args.email}")
        print(f"2. Follow up in 2 hours to discuss monthly service")
        print(f"3. Track in client system: python3 scripts/client_tracking.py summary")
    else:
        print(f"\n❌ Error: {result.get('error', 'Unknown error')}")
        sys.exit(1)


if __name__ == "__main__":
    main()

