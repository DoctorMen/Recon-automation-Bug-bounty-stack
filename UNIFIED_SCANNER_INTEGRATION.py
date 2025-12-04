#!/usr/bin/env python3
"""
UNIFIED SCANNER INTEGRATION
===========================
Integrates QUANTUM_ACCELERATOR_V2 with existing pipeline:
- run_pipeline.py (main orchestrator)
- SENTINEL_AGENT.py (security assessment)
- LEGAL_AUTHORIZATION_SYSTEM.py (mandatory authorization)

This creates a unified scanning system that:
1. Uses real tools (Nuclei, Slither, HTTPX, etc.)
2. Enforces mandatory authorization
3. Stores findings in SQLite database
4. Generates evidence-based reports
5. NO auto-submit - requires manual approval

Copyright (c) 2025 DoctorMen
"""

import sys
import os
import json
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('unified_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Import existing systems
try:
    from LEGAL_AUTHORIZATION_SYSTEM import LegalAuthorizationShield
    LEGAL_SHIELD_AVAILABLE = True
except ImportError:
    logger.warning("Legal Authorization Shield not found - will use V2 internal checker")
    LEGAL_SHIELD_AVAILABLE = False

try:
    from QUANTUM_ACCELERATOR_V2 import (
        QuantumAcceleratorV2, 
        Database, 
        Finding, 
        Severity,
        ToolRunner,
        SubmissionHelper
    )
    ACCELERATOR_V2_AVAILABLE = True
except ImportError:
    logger.error("QUANTUM_ACCELERATOR_V2 not found!")
    ACCELERATOR_V2_AVAILABLE = False

try:
    from SENTINEL_AGENT import SentinelAgent
    SENTINEL_AVAILABLE = True
except ImportError:
    logger.warning("SENTINEL_AGENT not found - will use V2 scanner only")
    SENTINEL_AVAILABLE = False


class UnifiedScanner:
    """
    Unified scanning system that integrates all components:
    - QUANTUM_ACCELERATOR_V2 (real tool integration)
    - SENTINEL_AGENT (security assessment)
    - LEGAL_AUTHORIZATION_SYSTEM (mandatory authorization)
    - run_pipeline.py (orchestration)
    """
    
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.db = Database() if ACCELERATOR_V2_AVAILABLE else None
        
        # Initialize legal shield
        if LEGAL_SHIELD_AVAILABLE:
            self.shield = LegalAuthorizationShield()
        else:
            from QUANTUM_ACCELERATOR_V2 import AuthorizationChecker
            self.shield = AuthorizationChecker()
        
        # Initialize accelerator
        if ACCELERATOR_V2_AVAILABLE:
            self.accelerator = QuantumAcceleratorV2(dry_run=dry_run)
        else:
            self.accelerator = None
        
        logger.info("Unified Scanner initialized")
        logger.info(f"  Legal Shield: {'✅' if LEGAL_SHIELD_AVAILABLE else '⚠️ V2 internal'}")
        logger.info(f"  Accelerator V2: {'✅' if ACCELERATOR_V2_AVAILABLE else '❌'}")
        logger.info(f"  SENTINEL Agent: {'✅' if SENTINEL_AVAILABLE else '❌'}")
        logger.info(f"  Dry Run: {dry_run}")
    
    def check_authorization(self, target: str) -> Tuple[bool, str, Dict]:
        """Check authorization using available shield"""
        if LEGAL_SHIELD_AVAILABLE:
            return self.shield.check_authorization(target)
        elif ACCELERATOR_V2_AVAILABLE:
            return self.shield.check_authorization(target)
        else:
            logger.error("No authorization system available!")
            return False, "No authorization system available", {}
    
    def scan_target(self, target: str, scan_type: str = "comprehensive",
                   program: str = None) -> Dict:
        """
        Run comprehensive scan on authorized target.
        
        Args:
            target: Domain or contract path to scan
            scan_type: "web", "smart_contract", or "comprehensive"
            program: Bug bounty program name for submission prep
        
        Returns:
            Dict with all findings and reports
        """
        print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║                    UNIFIED SCANNER - PRODUCTION                      ║
║              Real Tools | Real Findings | No Auto-Submit             ║
╚══════════════════════════════════════════════════════════════════════╝
        """)
        
        # STEP 1: Authorization check (MANDATORY)
        print("⚖️  Step 1: Legal Authorization Check")
        print("=" * 60)
        
        authorized, reason, auth_data = self.check_authorization(target)
        
        if not authorized:
            print(f"\n❌ SCAN BLOCKED: {reason}")
            print(f"\n⚠️  LEGAL REQUIREMENT: Written authorization required")
            print(f"   Create authorization file:")
            print(f"   python3 CREATE_AUTHORIZATION.py --target {target} --client 'CLIENT_NAME'")
            return {"error": reason, "authorized": False}
        
        print(f"✅ Authorization valid for: {target}")
        print(f"   Client: {auth_data.get('client_name', 'Unknown')}")
        print(f"   Scope: {auth_data.get('scope', [])}")
        print(f"   Valid until: {auth_data.get('end_date', 'Unknown')}")
        
        results = {
            "target": target,
            "scan_type": scan_type,
            "program": program,
            "authorized": True,
            "auth_data": auth_data,
            "start_time": datetime.now().isoformat(),
            "findings": [],
            "reports": []
        }
        
        # STEP 2: Run QUANTUM_ACCELERATOR_V2 scans
        if ACCELERATOR_V2_AVAILABLE:
            print("\n🔬 Step 2: QUANTUM_ACCELERATOR_V2 Scan")
            print("=" * 60)
            
            if scan_type in ["web", "comprehensive"]:
                print("   Running web vulnerability scans...")
                web_findings = self.accelerator.scan_target(target, "web")
                results["findings"].extend([self._finding_to_dict(f) for f in web_findings])
                print(f"   ✅ Found {len(web_findings)} web vulnerabilities")
            
            if scan_type in ["smart_contract", "comprehensive"]:
                print("   Running smart contract analysis...")
                contract_findings = self.accelerator.scan_target(target, "smart_contract")
                results["findings"].extend([self._finding_to_dict(f) for f in contract_findings])
                print(f"   ✅ Found {len(contract_findings)} contract issues")
        
        # STEP 3: Run SENTINEL_AGENT assessment
        if SENTINEL_AVAILABLE and scan_type in ["web", "comprehensive"]:
            print("\n🛡️  Step 3: SENTINEL Agent Assessment")
            print("=" * 60)
            
            try:
                # SENTINEL already checks authorization internally
                agent = SentinelAgent(
                    target=target,
                    tier="comprehensive" if scan_type == "comprehensive" else "basic",
                    output_dir="./assessments"
                )
                
                if not self.dry_run:
                    sentinel_report = agent.run_assessment()
                    if sentinel_report:
                        results["sentinel_report"] = sentinel_report
                        # Convert SENTINEL findings to unified format
                        for finding in sentinel_report.get("findings", []):
                            results["findings"].append({
                                "source": "sentinel",
                                "title": finding.get("title", "Unknown"),
                                "severity": finding.get("severity", "info"),
                                "category": finding.get("category", "unknown"),
                                "details": finding.get("details", ""),
                                "recommendation": finding.get("recommendation", "")
                            })
                        print(f"   ✅ SENTINEL found {len(sentinel_report.get('findings', []))} issues")
                else:
                    print("   [DRY RUN] Would run SENTINEL assessment")
            except Exception as e:
                logger.error(f"SENTINEL error: {e}")
                print(f"   ⚠️ SENTINEL error: {e}")
        
        # STEP 4: Deduplicate and prioritize findings
        print("\n📊 Step 4: Finding Analysis")
        print("=" * 60)
        
        unique_findings = self._deduplicate_findings(results["findings"])
        results["findings"] = unique_findings
        results["findings_by_severity"] = self._group_by_severity(unique_findings)
        
        print(f"   Total unique findings: {len(unique_findings)}")
        for severity, findings in results["findings_by_severity"].items():
            if findings:
                print(f"   - {severity.upper()}: {len(findings)}")
        
        # STEP 5: Prepare submission packages (if program specified)
        if program and unique_findings:
            print(f"\n📋 Step 5: Submission Preparation for {program}")
            print("=" * 60)
            
            submissions = self._prepare_submissions(unique_findings, program)
            results["submissions"] = submissions
            
            print(f"   Prepared {len(submissions)} submission packages")
            print("   ⚠️  MANUAL REVIEW REQUIRED before submitting!")
            
            # Generate report files
            for i, submission in enumerate(submissions[:5]):  # Top 5
                report_file = f"submission_{i+1}_{submission['finding_id'][:8]}.md"
                self._write_submission_report(submission, report_file)
                results["reports"].append(report_file)
                print(f"   📄 Generated: {report_file}")
        
        # STEP 6: Save results
        results["end_time"] = datetime.now().isoformat()
        results_file = f"unified_scan_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"\n💾 Results saved: {results_file}")
        
        # Summary
        self._print_summary(results)
        
        return results
    
    def _finding_to_dict(self, finding) -> Dict:
        """Convert Finding object to dictionary"""
        if hasattr(finding, '__dict__'):
            d = finding.__dict__.copy()
            if hasattr(finding, 'severity') and hasattr(finding.severity, 'value'):
                d['severity'] = finding.severity.value
            return d
        return finding
    
    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """Remove duplicate findings based on title and target"""
        seen = set()
        unique = []
        
        for finding in findings:
            key = f"{finding.get('title', '')}:{finding.get('target', '')}"
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        
        return unique
    
    def _group_by_severity(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Group findings by severity"""
        groups = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": []
        }
        
        for finding in findings:
            severity = finding.get("severity", "info").lower()
            if severity in groups:
                groups[severity].append(finding)
            else:
                groups["info"].append(finding)
        
        return groups
    
    def _prepare_submissions(self, findings: List[Dict], program: str) -> List[Dict]:
        """Prepare submission packages for manual review"""
        submissions = []
        
        # Sort by severity (critical first)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings, 
            key=lambda f: severity_order.get(f.get("severity", "info").lower(), 5)
        )
        
        for finding in sorted_findings:
            severity = finding.get("severity", "info").lower()
            
            # Only prepare submissions for medium+ severity
            if severity in ["critical", "high", "medium"]:
                submission = {
                    "finding_id": finding.get("id", f"finding_{len(submissions)+1}"),
                    "program": program,
                    "prepared_at": datetime.now().isoformat(),
                    "status": "PENDING_HUMAN_APPROVAL",
                    "auto_submit": False,  # NEVER auto-submit
                    "requires_approval": True,
                    "title": finding.get("title", "Unknown Vulnerability"),
                    "severity": severity,
                    "description": finding.get("description", finding.get("details", "")),
                    "evidence": finding.get("evidence", finding.get("raw_output", "")),
                    "reproduction_steps": finding.get("reproduction_steps", []),
                    "impact": finding.get("impact", ""),
                    "remediation": finding.get("remediation", finding.get("recommendation", "")),
                    "tool_source": finding.get("tool_source", finding.get("source", "unknown")),
                    "confidence": finding.get("confidence", 0.5)
                }
                
                # Get historical acceptance rate if available
                if self.db:
                    rate = self.db.get_acceptance_rate(finding.get("vulnerability_type"))
                    if rate > 0:
                        submission["historical_acceptance_rate"] = f"{rate * 100:.1f}%"
                    else:
                        submission["historical_acceptance_rate"] = "No historical data"
                
                submissions.append(submission)
        
        return submissions
    
    def _write_submission_report(self, submission: Dict, filename: str):
        """Write submission report to file"""
        report = f"""# {submission['title']}

## Summary
**Severity:** {submission['severity'].upper()}  
**Program:** {submission['program']}  
**Status:** {submission['status']}  
**Tool Source:** {submission['tool_source']}  
**Confidence:** {submission.get('confidence', 'N/A')}  

## Description
{submission.get('description', 'No description available')}

## Evidence
```
{submission.get('evidence', 'No evidence captured')[:2000]}
```

## Reproduction Steps
{chr(10).join(f'{i+1}. {step}' for i, step in enumerate(submission.get('reproduction_steps', ['No steps provided'])))}

## Impact
{submission.get('impact', 'Impact not specified')}

## Remediation
{submission.get('remediation', 'No remediation provided')}

---

**⚠️ MANUAL REVIEW REQUIRED**  
This submission was prepared automatically but requires human approval before submitting.

**Historical Acceptance Rate:** {submission.get('historical_acceptance_rate', 'No data')}

*Generated by Unified Scanner*  
*Timestamp: {submission['prepared_at']}*
"""
        
        with open(filename, 'w') as f:
            f.write(report)
    
    def _print_summary(self, results: Dict):
        """Print scan summary"""
        print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║                         SCAN COMPLETE                                ║
╚══════════════════════════════════════════════════════════════════════╝

🎯 Target: {results['target']}
📋 Scan Type: {results['scan_type']}
⏱️  Duration: {self._calculate_duration(results)}

📊 FINDINGS SUMMARY:
""")
        
        for severity, findings in results.get("findings_by_severity", {}).items():
            if findings:
                print(f"   {severity.upper()}: {len(findings)}")
        
        print(f"\n   Total: {len(results.get('findings', []))}")
        
        if results.get("submissions"):
            print(f"""
📋 SUBMISSIONS PREPARED: {len(results['submissions'])}
   ⚠️  MANUAL REVIEW REQUIRED before submitting!
   
   Generated reports:""")
            for report in results.get("reports", []):
                print(f"   - {report}")
        
        print(f"""
💾 Full results: unified_scan_*.json

NEXT STEPS:
1. Review generated submission reports
2. Verify findings manually
3. Submit to {results.get('program', 'bug bounty platform')} after approval
""")
    
    def _calculate_duration(self, results: Dict) -> str:
        """Calculate scan duration"""
        try:
            start = datetime.fromisoformat(results["start_time"])
            end = datetime.fromisoformat(results["end_time"])
            duration = (end - start).total_seconds()
            minutes = int(duration // 60)
            seconds = int(duration % 60)
            return f"{minutes}m {seconds}s"
        except:
            return "Unknown"


def integrate_with_pipeline():
    """
    Integration hook for run_pipeline.py
    
    Add this to run_pipeline.py after the existing agents:
    
    # Agent 6: Unified Scanner (Quantum Accelerator V2)
    log("")
    log(">>> Starting Agent 6: Unified Scanner")
    from UNIFIED_SCANNER_INTEGRATION import UnifiedScanner
    scanner = UnifiedScanner()
    for target in targets:
        scanner.scan_target(target, scan_type="comprehensive")
    """
    print("""
INTEGRATION INSTRUCTIONS FOR run_pipeline.py
============================================

Add the following code after Agent 5 (Report Writer) in run_pipeline.py:

```python
# Agent 6: Unified Scanner (Quantum Accelerator V2)
log("")
log(">>> Starting Agent 6: Unified Scanner")
if RESUME and is_stage_complete("unified_scan"):
    log("Skipping unified scan (already complete)")
else:
    try:
        from UNIFIED_SCANNER_INTEGRATION import UnifiedScanner
        scanner = UnifiedScanner()
        for target in targets:
            scanner.scan_target(target, scan_type="comprehensive")
        mark_stage_complete("unified_scan")
    except Exception as e:
        log(f"WARNING: Unified scanner failed: {e}")
```

This will:
1. Run after all existing agents
2. Use real tools (Nuclei, Slither, etc.)
3. Store findings in SQLite database
4. Generate submission reports for manual review
5. Respect all authorization requirements
""")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Unified Scanner - Production Ready")
    parser.add_argument("target", nargs="?", help="Target to scan")
    parser.add_argument("--scan-type", choices=["web", "smart_contract", "comprehensive"], 
                       default="comprehensive")
    parser.add_argument("--program", help="Bug bounty program name")
    parser.add_argument("--dry-run", action="store_true", help="Don't execute actual scans")
    parser.add_argument("--integrate", action="store_true", help="Show pipeline integration instructions")
    
    args = parser.parse_args()
    
    if args.integrate:
        integrate_with_pipeline()
        return
    
    if not args.target:
        parser.print_help()
        return
    
    scanner = UnifiedScanner(dry_run=args.dry_run)
    results = scanner.scan_target(
        args.target, 
        scan_type=args.scan_type,
        program=args.program
    )
    
    if results.get("error"):
        sys.exit(1)


if __name__ == "__main__":
    main()
