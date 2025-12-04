#!/usr/bin/env python3
"""
EXTRACT FINDINGS - Pull real results from MCP database
======================================================
Extracts production findings and creates submission packages.

Copyright (c) 2025 DoctorMen
"""

import sqlite3
import json
from datetime import datetime

def extract_findings():
    """Extract findings from MCP database"""
    
    conn = sqlite3.connect("mcp_orchestrator.db")
    cursor = conn.cursor()
    
    # Get all findings
    cursor.execute("""
        SELECT * FROM findings 
        ORDER BY bounty_estimate DESC
    """)
    
    findings = []
    for row in cursor.fetchall():
        finding = {
            "id": row[0],
            "target": row[1],
            "agent_type": row[2],
            "vulnerability_type": row[3],
            "severity": row[4],
            "confidence": row[5],
            "evidence": json.loads(row[6]),
            "exploit_potential": row[7],
            "bounty_estimate": row[8],
            "status": row[9],
            "created_at": row[10]
        }
        findings.append(finding)
    
    conn.close()
    
    return findings

def create_submission_package(findings, filename):
    """Create professional submission package"""
    
    # Group by target
    targets = {}
    for f in findings:
        target = f["target"]
        if target not in targets:
            targets[target] = []
        targets[target].append(f)
    
    submission = {
        "scan_metadata": {
            "orchestrator": "Production MCP Orchestrator",
            "scan_date": datetime.now().isoformat(),
            "total_targets": len(targets),
            "total_findings": len(findings),
            "total_bounty_potential": sum(f["bounty_estimate"] for f in findings)
        },
        "executive_summary": {
            "high_value_targets": [],
            "critical_findings": [],
            "submission_readiness": "PRODUCTION_READY"
        },
        "target_analysis": {}
    }
    
    for target, target_findings in targets.items():
        total_bounty = sum(f["bounty_estimate"] for f in target_findings)
        high_value_count = len([f for f in target_findings if f["bounty_estimate"] >= 1000])
        
        target_analysis = {
            "target": target,
            "total_findings": len(target_findings),
            "high_value_findings": high_value_count,
            "estimated_bounty": total_bounty,
            "findings": []
        }
        
        for f in target_findings:
            if f["bounty_estimate"] >= 100:  # Only include findings worth submitting
                finding_detail = {
                    "vulnerability_type": f["vulnerability_type"],
                    "severity": f["severity"],
                    "confidence": f["confidence"],
                    "bounty_estimate": f["bounty_estimate"],
                    "evidence": f["evidence"],
                    "exploit_potential": f["exploit_potential"],
                    "discovered_by": "MCP Orchestrator",
                    "verification_status": "READY_FOR_TRIAGE"
                }
                target_analysis["findings"].append(finding_detail)
                
                # Track high-value findings
                if f["bounty_estimate"] >= 1000:
                    submission["executive_summary"]["high_value_targets"].append({
                        "target": target,
                        "finding": f["vulnerability_type"],
                        "bounty": f["bounty_estimate"]
                    })
        
        submission["target_analysis"][target] = target_analysis
    
    # Save submission package
    with open(filename, 'w') as f:
        json.dump(submission, f, indent=2)
    
    return submission

def main():
    """Extract and package findings"""
    
    print("🔍 EXTRACTING PRODUCTION FINDINGS FROM MCP DATABASE")
    print("="*60)
    
    findings = extract_findings()
    
    print(f"📊 Total findings extracted: {len(findings)}")
    
    # Show summary by target
    targets = {}
    for f in findings:
        target = f["target"]
        if target not in targets:
            targets[target] = {"count": 0, "bounty": 0}
        targets[target]["count"] += 1
        targets[target]["bounty"] += f["bounty_estimate"]
    
    print(f"\n🎯 FINDINGS BY TARGET:")
    for target, data in sorted(targets.items(), key=lambda x: x[1]["bounty"], reverse=True):
        print(f"   📍 {target}: {data['count']} findings, ${data['bounty']:,.0f} potential")
    
    # Create submission package
    submission_file = f"cantina_submission_package_{int(datetime.now().timestamp())}.json"
    submission = create_submission_package(findings, submission_file)
    
    print(f"\n💾 SUBMISSION PACKAGE CREATED: {submission_file}")
    print(f"📊 Package Summary:")
    print(f"   🎯 Targets: {submission['scan_metadata']['total_targets']}")
    print(f"   🔍 Findings: {submission['scan_metadata']['total_findings']}")
    print(f"   💰 Total Potential: ${submission['scan_metadata']['total_bounty_potential']:,.0f}")
    
    # Show top findings
    high_value = [f for f in findings if f["bounty_estimate"] >= 1000]
    if high_value:
        print(f"\n🏆 HIGH-VALUE FINDINGS READY FOR SUBMISSION:")
        for i, f in enumerate(sorted(high_value, key=lambda x: x["bounty_estimate"], reverse=True), 1):
            print(f"   [{i}] {f['target']} - {f['vulnerability_type']}: ${f['bounty_estimate']:,.0f}")
    
    print(f"\n✅ READY FOR CANTINA TRIAGE SUBMISSION")
    print(f"📋 Use {submission_file} for professional bounty submission")

if __name__ == "__main__":
    main()
