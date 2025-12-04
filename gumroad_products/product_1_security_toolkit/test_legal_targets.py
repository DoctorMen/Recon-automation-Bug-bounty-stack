#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Legal Bug Bounty Test - Automated Power Demo
Tests smart pipeline on legal, authorized targets from public bug bounty programs
"""

import os
import sys
import time
import json
from datetime import datetime
from pathlib import Path

# Check if smart_pipeline is available
try:
    from smart_pipeline import SmartPipeline
except ImportError:
    print("Error: smart_pipeline.py not found")
    print("Make sure you're in the correct directory")
    sys.exit(1)


class LegalTargetTest:
    """Test smart pipeline on legal bug bounty targets"""
    
    # VERIFIED PUBLIC BUG BOUNTY PROGRAMS (as of 2024)
    # Always verify current status before testing
    LEGAL_TARGETS = {
        "tier1_high_value": [
            {
                "name": "HackerOne Platform",
                "domain": "hackerone.com",
                "program_url": "https://hackerone.com/security",
                "avg_bounty": "$500-$5000",
                "triage_speed": "Fast (2-5 days)",
                "notes": "Well-established, good payouts"
            }
        ],
        "tier2_practice": [
            {
                "name": "PortSwigger Web Security Academy",
                "domain": "portswigger.net",
                "program_url": "https://portswigger.net/web-security",
                "avg_bounty": "Learning only",
                "triage_speed": "N/A",
                "notes": "Perfect for testing, no real vulns"
            }
        ]
    }
    
    def __init__(self):
        self.results = {
            "test_date": datetime.now().isoformat(),
            "speed_tests": [],
            "learning_tests": [],
            "findings": []
        }
        self.report_file = Path("output/legal_test_report.json")
        self.report_file.parent.mkdir(parents=True, exist_ok=True)
    
    def show_legal_targets(self):
        """Display list of legal targets"""
        print("\n" + "="*60)
        print("LEGAL BUG BOUNTY TARGETS")
        print("="*60 + "\n")
        
        print("These targets have PUBLIC bug bounty programs that")
        print("EXPLICITLY AUTHORIZE security testing.\n")
        
        for tier, targets in self.LEGAL_TARGETS.items():
            print(f"\n{'='*60}")
            print(f"{tier.upper().replace('_', ' ')}")
            print(f"{'='*60}\n")
            
            for i, target in enumerate(targets, 1):
                print(f"{i}. {target['name']}")
                print(f"   Domain: {target['domain']}")
                print(f"   Program: {target['program_url']}")
                print(f"   Avg Bounty: {target['avg_bounty']}")
                print(f"   Triage: {target['triage_speed']}")
                print(f"   Notes: {target['notes']}\n")
        
        print("="*60)
        print("⚠️  ALWAYS verify program status before testing!")
        print("="*60 + "\n")
    
    def verify_authorization(self, domain: str) -> bool:
        """Verify user has read and understood authorization requirements"""
        print(f"\n{'='*60}")
        print(f"AUTHORIZATION CHECK: {domain}")
        print(f"{'='*60}\n")
        
        print("Before testing, you MUST confirm:")
        print("1. This domain has a PUBLIC bug bounty program")
        print("2. You have read the program's policy")
        print("3. Your testing is within the defined scope")
        print("4. You will follow responsible disclosure\n")
        
        response = input("Have you verified all of the above? (yes/no): ").strip().lower()
        
        if response != "yes":
            print("\n❌ Authorization not confirmed. Test cancelled.")
            print("Please verify authorization before testing.\n")
            return False
        
        print("\n✅ Authorization confirmed. Proceeding with test...\n")
        return True
    
    def run_speed_test(self, target: str, goal: str = "balanced"):
        """Run speed test comparing traditional vs smart pipeline"""
        print(f"\n{'='*60}")
        print(f"SPEED TEST: {target}")
        print(f"{'='*60}\n")
        
        if not self.verify_authorization(target):
            return None
        
        print("🚀 Starting Smart Pipeline scan...\n")
        
        pipeline = SmartPipeline(use_learning=True, use_agents=True)
        
        start_time = time.time()
        
        try:
            result = pipeline.scan(target, workflow="recon", optimization_goal=goal)
            duration = time.time() - start_time
            
            test_result = {
                "target": target,
                "method": "smart_pipeline",
                "duration_seconds": duration,
                "duration_minutes": round(duration / 60, 1),
                "goal": goal,
                "timestamp": datetime.now().isoformat(),
                "success": True
            }
            
            self.results["speed_tests"].append(test_result)
            
            print(f"\n✅ Speed Test Complete!")
            print(f"   Duration: {test_result['duration_minutes']} minutes")
            print(f"   Goal: {goal}")
            
            return test_result
            
        except Exception as e:
            print(f"\n❌ Speed test failed: {e}")
            return None
    
    def run_learning_test(self, target: str, iterations: int = 3):
        """Run multiple scans to demonstrate learning"""
        print(f"\n{'='*60}")
        print(f"LEARNING TEST: {target} ({iterations} iterations)")
        print(f"{'='*60}\n")
        
        if not self.verify_authorization(target):
            return None
        
        pipeline = SmartPipeline(use_learning=True, use_agents=True)
        durations = []
        
        for i in range(1, iterations + 1):
            print(f"\n[Iteration {i}/{iterations}]")
            print("-" * 60)
            
            start_time = time.time()
            
            try:
                result = pipeline.scan(target, workflow="recon", optimization_goal="balanced")
                duration = time.time() - start_time
                durations.append(duration)
                
                print(f"✓ Scan {i} completed in {duration/60:.1f} minutes")
                
                # Show improvement
                if i > 1:
                    improvement = ((durations[0] - duration) / durations[0]) * 100
                    print(f"  Improvement vs first scan: {improvement:.1f}%")
                
                time.sleep(2)  # Brief pause between scans
                
            except Exception as e:
                print(f"✗ Scan {i} failed: {e}")
                continue
        
        if durations:
            test_result = {
                "target": target,
                "iterations": iterations,
                "durations_minutes": [round(d/60, 1) for d in durations],
                "first_scan": round(durations[0]/60, 1),
                "last_scan": round(durations[-1]/60, 1),
                "improvement_percent": round(((durations[0] - durations[-1]) / durations[0]) * 100, 1),
                "timestamp": datetime.now().isoformat()
            }
            
            self.results["learning_tests"].append(test_result)
            
            print(f"\n{'='*60}")
            print("LEARNING TEST RESULTS")
            print(f"{'='*60}")
            print(f"First scan: {test_result['first_scan']} minutes")
            print(f"Last scan: {test_result['last_scan']} minutes")
            print(f"Improvement: {test_result['improvement_percent']}%")
            print(f"{'='*60}\n")
            
            return test_result
        
        return None
    
    def analyze_findings(self):
        """Analyze findings from output directory"""
        print(f"\n{'='*60}")
        print("ANALYZING FINDINGS")
        print(f"{'='*60}\n")
        
        triage_file = Path("output/triage.json")
        
        if not triage_file.exists():
            print("No triage.json found. Run a scan first.\n")
            return None
        
        try:
            with open(triage_file, 'r') as f:
                findings = json.load(f)
            
            if not findings:
                print("No findings in triage.json\n")
                return None
            
            # Count by severity
            severity_counts = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
            
            for finding in findings:
                severity = finding.get('info', {}).get('severity', 'unknown').lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            print("Findings Summary:")
            print(f"  Critical: {severity_counts['critical']}")
            print(f"  High: {severity_counts['high']}")
            print(f"  Medium: {severity_counts['medium']}")
            print(f"  Low: {severity_counts['low']}")
            print(f"  Info: {severity_counts['info']}")
            print(f"  Total: {sum(severity_counts.values())}\n")
            
            # Estimate value
            estimated_value = (
                severity_counts['critical'] * 3000 +
                severity_counts['high'] * 1000 +
                severity_counts['medium'] * 300 +
                severity_counts['low'] * 100
            )
            
            print(f"Estimated Value (if all valid): ${estimated_value:,}\n")
            
            self.results["findings"] = {
                "severity_counts": severity_counts,
                "total": sum(severity_counts.values()),
                "estimated_value": estimated_value,
                "timestamp": datetime.now().isoformat()
            }
            
            return self.results["findings"]
            
        except Exception as e:
            print(f"Error analyzing findings: {e}\n")
            return None
    
    def generate_report(self):
        """Generate final test report"""
        print(f"\n{'='*60}")
        print("GENERATING TEST REPORT")
        print(f"{'='*60}\n")
        
        # Save JSON report
        with open(self.report_file, 'w') as f:
            json.dump(self.results, indent=2, fp=f)
        
        print(f"✓ Report saved to: {self.report_file}\n")
        
        # Print summary
        print("="*60)
        print("TEST SUMMARY")
        print("="*60 + "\n")
        
        if self.results["speed_tests"]:
            print(f"Speed Tests: {len(self.results['speed_tests'])}")
            avg_duration = sum(t["duration_minutes"] for t in self.results["speed_tests"]) / len(self.results["speed_tests"])
            print(f"Average Scan Time: {avg_duration:.1f} minutes\n")
        
        if self.results["learning_tests"]:
            print(f"Learning Tests: {len(self.results['learning_tests'])}")
            for test in self.results["learning_tests"]:
                print(f"  Target: {test['target']}")
                print(f"  Improvement: {test['improvement_percent']}%\n")
        
        if self.results.get("findings"):
            findings = self.results["findings"]
            print(f"Findings: {findings['total']}")
            print(f"Estimated Value: ${findings['estimated_value']:,}\n")
        
        print("="*60 + "\n")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Legal Bug Bounty Test - Smart Pipeline Power Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show legal targets
  python3 test_legal_targets.py --list
  
  # Run speed test
  python3 test_legal_targets.py --speed example.com
  
  # Run learning test (3 iterations)
  python3 test_legal_targets.py --learning example.com
  
  # Analyze findings
  python3 test_legal_targets.py --analyze
        """
    )
    
    parser.add_argument('--list', action='store_true',
                       help='List legal bug bounty targets')
    parser.add_argument('--speed', metavar='TARGET',
                       help='Run speed test on target')
    parser.add_argument('--learning', metavar='TARGET',
                       help='Run learning test on target')
    parser.add_argument('--analyze', action='store_true',
                       help='Analyze findings from last scan')
    parser.add_argument('--iterations', type=int, default=3,
                       help='Number of iterations for learning test')
    
    args = parser.parse_args()
    
    tester = LegalTargetTest()
    
    if args.list:
        tester.show_legal_targets()
    
    elif args.speed:
        tester.run_speed_test(args.speed)
        tester.generate_report()
    
    elif args.learning:
        tester.run_learning_test(args.learning, args.iterations)
        tester.generate_report()
    
    elif args.analyze:
        tester.analyze_findings()
        tester.generate_report()
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
