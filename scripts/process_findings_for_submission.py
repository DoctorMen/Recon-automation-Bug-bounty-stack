#!/usr/bin/env python3
"""
Complete Bug Processing Pipeline
Verifies, filters duplicates, generates reports, prioritizes high-value bugs
"""

import json
import sys
from pathlib import Path
from typing import List, Dict, Any

# Add scripts directory to path
SCRIPT_DIR = Path(__file__).parent
REPO_ROOT = SCRIPT_DIR.parent
sys.path.insert(0, str(SCRIPT_DIR))

from bug_verifier import BugVerifier
from advanced_duplicate_filter import AdvancedDuplicateFilter
from high_quality_report_generator import HighQualityReportGenerator

def process_findings(input_file: Path, output_dir: Path):
    """Process findings: verify, filter, prioritize, generate reports"""
    print("=" * 80)
    print("🔍 PROCESSING FINDINGS FOR SUBMISSION")
    print("=" * 80)
    print()
    
    # Load findings
    print(f"[*] Loading findings from: {input_file}")
    with open(input_file) as f:
        findings = json.load(f)
    
    print(f"[*] Original findings: {len(findings)}")
    print()
    
    # Step 1: Verify findings
    print("[*] Step 1: Verifying findings...")
    verifier = BugVerifier()
    verified = verifier.verify_all(findings)
    print(f"    Verified: {len(verified)}/{len(findings)}")
    print()
    
    # Step 2: Filter duplicates
    print("[*] Step 2: Filtering duplicates...")
    duplicate_filter = AdvancedDuplicateFilter()
    unique = duplicate_filter.filter_duplicates(verified)
    print(f"    Unique: {len(unique)}/{len(verified)}")
    print()
    
    # Step 3: Consolidate similar
    print("[*] Step 3: Consolidating similar bugs...")
    consolidated = duplicate_filter.consolidate_similar(unique)
    print(f"    Consolidated: {len(consolidated)}/{len(unique)}")
    print()
    
    # Step 4: Prioritize high-value
    print("[*] Step 4: Prioritizing high-value bugs...")
    prioritized = duplicate_filter.prioritize_high_value(consolidated)
    
    high_value = [f for f in prioritized if f.get("value", 0) >= 3000 or f.get("verification", {}).get("impact") == "high"]
    medium_value = [f for f in prioritized if 1000 <= f.get("value", 0) < 3000 or f.get("verification", {}).get("impact") == "medium"]
    low_value = [f for f in prioritized if f.get("value", 0) < 1000]
    
    print(f"    High-value: {len(high_value)}")
    print(f"    Medium-value: {len(medium_value)}")
    print(f"    Low-value: {len(low_value)}")
    print()
    
    # Step 5: Generate reports
    print("[*] Step 5: Generating high-quality reports...")
    report_generator = HighQualityReportGenerator(output_dir)
    reports_generated = report_generator.generate_all_reports(prioritized)
    print(f"    Reports generated: {reports_generated}")
    print()
    
    # Save processed findings
    processed_file = output_dir / "processed_findings.json"
    with open(processed_file, 'w') as f:
        json.dump({
            "original_count": len(findings),
            "verified_count": len(verified),
            "unique_count": len(unique),
            "consolidated_count": len(consolidated),
            "high_value_count": len(high_value),
            "medium_value_count": len(medium_value),
            "low_value_count": len(low_value),
            "high_value": high_value,
            "medium_value": medium_value,
            "low_value": low_value,
            "all_findings": prioritized
        }, f, indent=2)
    
    # Summary
    print("=" * 80)
    print("✅ PROCESSING COMPLETE")
    print("=" * 80)
    print()
    print(f"Original findings: {len(findings)}")
    print(f"Verified: {len(verified)}")
    print(f"Unique: {len(unique)}")
    print(f"Consolidated: {len(consolidated)}")
    print(f"High-value: {len(high_value)}")
    print(f"Medium-value: {len(medium_value)}")
    print(f"Low-value: {len(low_value)}")
    print()
    print(f"High-value findings: ${sum(f.get('value', 0) for f in high_value):,}")
    print(f"Medium-value findings: ${sum(f.get('value', 0) for f in medium_value):,}")
    print(f"Low-value findings: ${sum(f.get('value', 0) for f in low_value):,}")
    print(f"Total estimated value: ${sum(f.get('value', 0) for f in prioritized):,}")
    print()
    print(f"Reports saved to: {output_dir / 'submission_reports'}")
    print(f"Processed findings saved to: {processed_file}")
    print("=" * 80)

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Process findings for submission")
    parser.add_argument("--input", type=str, help="Input findings JSON file")
    parser.add_argument("--output", type=str, help="Output directory")
    
    args = parser.parse_args()
    
    # Default: Process demo findings
    if not args.input:
        # Find latest findings
        demo_dir = REPO_ROOT / "output" / "top_0.1_demo"
        if demo_dir.exists():
            # Combine all findings
            all_findings = []
            for target_dir in demo_dir.iterdir():
                if target_dir.is_dir():
                    findings_file = target_dir / "exploitation" / "confirmed_vulnerabilities.json"
                    if findings_file.exists():
                        with open(findings_file) as f:
                            findings = json.load(f)
                            all_findings.extend(findings)
            
            if all_findings:
                input_file = demo_dir / "all_findings.json"
                with open(input_file, 'w') as f:
                    json.dump(all_findings, f, indent=2)
                
                output_dir = demo_dir / "processed"
                process_findings(input_file, output_dir)
            else:
                print("❌ No findings found")
        else:
            print("❌ Demo directory not found")
    else:
        input_file = Path(args.input)
        output_dir = Path(args.output) if args.output else input_file.parent / "processed"
        process_findings(input_file, output_dir)

if __name__ == "__main__":
    main()

