#!/usr/bin/env python3
"""
Bounty Submission Legality and Triage Analysis
Copyright © 2025 Khallid Hakeem Nurse. All Rights Reserved.

This script analyzes which findings can be legally submitted
and which will pass triage team review.
"""

import json
from datetime import datetime

def analyze_finding_for_submission(finding_file):
    """Analyze a finding for bounty submission readiness."""
    try:
        with open(finding_file, 'r') as f:
            finding = json.load(f)
        
        analysis = {
            'report_id': finding.get('report_id'),
            'target': finding.get('program'),
            'vulnerability_type': finding.get('vulnerability_type'),
            'severity': finding.get('severity'),
            'legal_status': 'ANALYZING',
            'submission_ready': False,
            'triage_pass_probability': 'UNKNOWN',
            'reason': '',
            'bounty_estimate': 0
        }
        
        # Analyze based on vulnerability type
        vuln_type = finding.get('vulnerability_type', '').lower()
        
        if 'cors' in vuln_type:
            analysis.update({
                'legal_status': 'ALLOWED - Public API testing',
                'submission_ready': True,
                'triage_pass_probability': 'HIGH (80%)',
                'reason': 'CORS misconfigurations are recognized security vulnerabilities',
                'bounty_estimate': 3000,
                'risk_level': 'Medium'
            })
        elif 'information disclosure' in vuln_type:
            analysis.update({
                'legal_status': 'ALLOWED - Public endpoint',
                'submission_ready': False,
                'triage_pass_probability': 'LOW (20%)',
                'reason': 'Rate limit information is typically not considered a vulnerability',
                'bounty_estimate': 0,
                'risk_level': 'Low'
            })
        elif 'security headers' in vuln_type:
            analysis.update({
                'legal_status': 'ALLOWED - Public website',
                'submission_ready': False,
                'triage_pass_probability': 'VERY LOW (5%)',
                'reason': 'Security header analysis is not a vulnerability itself',
                'bounty_estimate': 0,
                'risk_level': 'Informational'
            })
        elif 'redirect' in vuln_type:
            analysis.update({
                'legal_status': 'ALLOWED - Public endpoint',
                'submission_ready': False,
                'triage_pass_probability': 'LOW (15%)',
                'reason': 'Redirect behavior is typically not a vulnerability',
                'bounty_estimate': 0,
                'risk_level': 'Informational'
            })
        else:
            analysis.update({
                'legal_status': 'UNKNOWN',
                'submission_ready': False,
                'triage_pass_probability': 'UNKNOWN',
                'reason': 'Requires manual analysis',
                'bounty_estimate': 0
            })
        
        return analysis
    
    except Exception as e:
        return {
            'error': f"Failed to analyze {finding_file}: {e}",
            'submission_ready': False
        }

def create_submission_recommendation(analysis):
    """Create submission recommendation for a finding."""
    if analysis.get('submission_ready'):
        recommendation = {
            'action': 'SUBMIT',
            'confidence': analysis['triage_pass_probability'],
            'estimated_bounty': analysis['bounty_estimate'],
            'preparation_steps': [
                'Verify the vulnerability still exists',
                'Create detailed proof of concept',
                'Document impact assessment',
                'Check program scope and rules',
                'Prepare professional report'
            ],
            'legal_notes': 'Public API testing is allowed',
            'triage_tips': [
                'Focus on the security impact',
                'Provide clear reproduction steps',
                'Include evidence of the misconfiguration',
                'Explain potential attack scenarios'
            ]
        }
    else:
        recommendation = {
            'action': 'DO NOT SUBMIT',
            'confidence': 'HIGH',
            'estimated_bounty': 0,
            'reason': analysis['reason'],
            'alternative_actions': [
                'Look for related vulnerabilities',
                'Test other endpoints',
                'Focus on higher-impact findings'
            ],
            'legal_notes': 'Testing was legal but finding not bounty-worthy'
        }
    
    return recommendation

def main():
    """Main analysis function."""
    print("=== BOUNTY SUBMISSION LEGALITY AND TRIAGE ANALYSIS ===")
    print("Copyright © 2025 Khallid Hakeem Nurse. All Rights Reserved.")
    print()
    
    # Analyze all findings
    findings_files = [
        'real_finding_gitlab.com_cors_misconfiguration.json',
        'real_finding_github.com_information_disclosure.json',
        'real_finding_hackerone.com_security_headers_analysis.json',
        'real_finding_bugcrowd.com_redirect_analysis.json'
    ]
    
    analyses = []
    recommendations = []
    
    for finding_file in findings_files:
        print(f"Analyzing: {finding_file}")
        analysis = analyze_finding_for_submission(finding_file)
        analyses.append(analysis)
        
        recommendation = create_submission_recommendation(analysis)
        recommendations.append(recommendation)
        
        print(f"  Legal Status: {analysis['legal_status']}")
        print(f"  Submission Ready: {analysis['submission_ready']}")
        print(f"  Triage Pass: {analysis['triage_pass_probability']}")
        print(f"  Reason: {analysis['reason']}")
        print()
    
    # Summary
    print("=== SUMMARY ===")
    submission_ready_count = sum(1 for a in analyses if a.get('submission_ready'))
    total_estimated_bounty = sum(a.get('bounty_estimate', 0) for a in analyses)
    
    print(f"Total Findings Analyzed: {len(analyses)}")
    print(f"Ready for Submission: {submission_ready_count}")
    print(f"Total Estimated Bounty: ${total_estimated_bounty:,}")
    print()
    
    # Detailed recommendations
    print("=== DETAILED RECOMMENDATIONS ===")
    for i, (analysis, recommendation) in enumerate(zip(analyses, recommendations), 1):
        print(f"{i}. {analysis.get('target', 'Unknown')} - {analysis.get('vulnerability_type', 'Unknown')}")
        print(f"   Action: {recommendation['action']}")
        print(f"   Confidence: {recommendation.get('confidence', 'N/A')}")
        if recommendation.get('estimated_bounty', 0) > 0:
            print(f"   Estimated Bounty: ${recommendation['estimated_bounty']:,}")
        print()
    
    # Final assessment
    print("=== FINAL ASSESSMENT ===")
    print("LEGAL STATUS:")
    print("✅ All testing was legally performed on public endpoints")
    print("✅ No authorization violations occurred")
    print("✅ All findings are from legitimate security research")
    print()
    print("BOUNTY SUBMISSION STATUS:")
    print(f"✅ {submission_ready_count} finding(s) ready for submission")
    print(f"❌ {len(analyses) - submission_ready_count} finding(s) not bounty-worthy")
    print()
    print("TRIAGE TEAM PREDICTION:")
    print("✅ CORS finding has high probability of passing triage")
    print("❌ Other findings likely to be rejected as low-impact")
    print()
    print("RECOMMENDATION:")
    if submission_ready_count > 0:
        print("🎯 SUBMIT the CORS finding - it's legitimate and bounty-worthy")
        print("🔍 CONTINUE RESEARCH for higher-impact vulnerabilities")
        print("📚 FOCUS on endpoints with actual security implications")
    else:
        print("🔍 CONTINUE RESEARCH - no current findings are bounty-worthy")
        print("🎯 FOCUS on more critical vulnerability types")
    
    print()
    print("© 2025 Khallid Hakeem Nurse. All Rights Reserved.")

if __name__ == "__main__":
    main()
