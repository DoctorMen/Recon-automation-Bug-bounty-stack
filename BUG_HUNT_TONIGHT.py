#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.

BUG HUNT TONIGHT - Ethical Bug Bounty Hunting on Authorized Programs
Safe, legal, 2-click workflow to find bugs and earn money tonight.

LEGAL: All programs here have PUBLIC bug bounty programs = AUTHORIZED
ETHICAL: Responsible disclosure, no harm, follow rules
PROFITABLE: High-value targets with proven payouts
"""

import subprocess
import random
from datetime import datetime
import json
from pathlib import Path

class BugHuntTonight:
    """2-click bug hunting on authorized programs"""
    
    def __init__(self):
        self.base_path = Path(__file__).parent
        
        # AUTHORIZED programs with public bug bounty programs
        # These are LEGAL to test - they explicitly invite security researchers
        self.authorized_programs = {
            'hackerone': {
                'shopify.com': {'min_payout': 500, 'avg_payout': 2500, 'difficulty': 'medium'},
                'github.com': {'min_payout': 500, 'avg_payout': 3000, 'difficulty': 'hard'},
                'mozilla.org': {'min_payout': 500, 'avg_payout': 2000, 'difficulty': 'medium'},
                'dropbox.com': {'min_payout': 250, 'avg_payout': 1500, 'difficulty': 'medium'},
                'yelp.com': {'min_payout': 100, 'avg_payout': 800, 'difficulty': 'easy'},
            },
            'bugcrowd': {
                'atlassian.com': {'min_payout': 500, 'avg_payout': 2000, 'difficulty': 'medium'},
                'sony.com': {'min_payout': 100, 'avg_payout': 1000, 'difficulty': 'easy'},
            },
            'public_programs': {
                'google.com': {'min_payout': 100, 'avg_payout': 5000, 'difficulty': 'very_hard'},
                'facebook.com': {'min_payout': 500, 'avg_payout': 2500, 'difficulty': 'hard'},
                'linkedin.com': {'min_payout': 100, 'avg_payout': 1000, 'difficulty': 'medium'},
            }
        }
        
        # High-value vulnerability types to focus on
        self.high_value_vulns = [
            'subdomain-takeover',  # Easy to find, $500-2000
            'api-misconfig',       # Common, $250-1500
            'auth-bypass',         # Medium difficulty, $1000-5000
            'ssrf',                # High value, $500-3000
            'xxe',                 # Less competition, $500-2000
        ]
    
    def select_tonight_target(self):
        """Select the best target for tonight based on difficulty and payout"""
        print("🎯 Selecting tonight's target...")
        print("\n💡 Strategy: Medium difficulty + High payout + Less competition")
        
        # Filter for medium difficulty, good payout
        good_targets = []
        for platform, programs in self.authorized_programs.items():
            for domain, info in programs.items():
                if info['difficulty'] in ['easy', 'medium'] and info['avg_payout'] >= 1000:
                    good_targets.append({
                        'domain': domain,
                        'platform': platform,
                        'payout': info['avg_payout'],
                        'difficulty': info['difficulty']
                    })
        
        # Sort by payout/difficulty ratio
        good_targets.sort(key=lambda x: x['payout'], reverse=True)
        
        print(f"\n✅ Top {len(good_targets)} authorized targets tonight:\n")
        for i, target in enumerate(good_targets[:5], 1):
            print(f"{i}. {target['domain']:20s} | ${target['payout']:4d} avg | {target['difficulty']:10s} | {target['platform']}")
        
        # Return top 3 for parallel hunting
        return [t['domain'] for t in good_targets[:3]]
    
    def hunt(self, targets=None):
        """Execute the bug hunt"""
        if targets is None:
            targets = self.select_tonight_target()
        
        print(f"\n🚀 STARTING BUG HUNT - {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        print("="*70)
        
        for target in targets:
            print(f"\n🎯 Target: {target}")
            print("📋 Legal Status: AUTHORIZED (Public Bug Bounty Program)")
            print("🔍 Focus: High-value, low-competition vulnerabilities")
            print("\nPhase 1: Reconnaissance...")
            
            # Create targets file
            targets_file = self.base_path / "hunt_tonight.txt"
            with open(targets_file, 'w') as f:
                f.write(target + '\n')
            
            # Run quick recon
            print("  - Subdomain enumeration")
            print("  - Service discovery")
            print("  - Technology fingerprinting")
            
            cmd = [
                'python3',
                str(self.base_path / 'run_recon.py'),
                '--target', target,
                '--output', str(self.base_path / f'output/hunt_{target.split(".")[0]}')
            ]
            
            try:
                print(f"\n⚙️  Running: {' '.join(cmd)}")
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)  # 30 min max
                
                if result.returncode == 0:
                    print("✅ Recon complete!")
                    print("\nPhase 2: Vulnerability scanning...")
                    
                    # Run nuclei with high-value templates
                    nuclei_cmd = [
                        'python3',
                        str(self.base_path / 'run_nuclei.py'),
                        '--target', target,
                        '--templates', 'takeovers,misconfiguration,cves',
                        '--severity', 'medium,high,critical'
                    ]
                    
                    print(f"⚙️  Running: {' '.join(nuclei_cmd)}")
                    nuclei_result = subprocess.run(nuclei_cmd, capture_output=True, text=True, timeout=1800)
                    
                    if nuclei_result.returncode == 0:
                        print("✅ Vulnerability scan complete!")
                        print("\n📊 Checking results...")
                        self.analyze_findings(target)
                    else:
                        print(f"⚠️  Nuclei scan had issues: {nuclei_result.stderr[:200]}")
                else:
                    print(f"⚠️  Recon had issues: {result.stderr[:200]}")
                    
            except subprocess.TimeoutExpired:
                print("⏰ Scan timeout (30 min) - moving to next target")
            except Exception as e:
                print(f"❌ Error: {e}")
        
        print("\n" + "="*70)
        print("🎉 BUG HUNT COMPLETE!")
        print("\n📋 Next steps:")
        print("1. Review findings: cat output/hunt_*/nuclei_results.txt")
        print("2. Manual verification: Confirm findings are real")
        print("3. Submit: See SUBMIT_NOW.md for quick submission guide")
        print("\n💰 Expected timeline: 2-4 hours for full verification + submission")
    
    def analyze_findings(self, target):
        """Quick analysis of findings"""
        output_dir = self.base_path / f'output/hunt_{target.split(".")[0]}'
        
        if not output_dir.exists():
            print("⚠️  Output directory not found")
            return
        
        # Look for nuclei results
        nuclei_file = output_dir / 'nuclei_results.txt'
        if nuclei_file.exists():
            with open(nuclei_file, 'r') as f:
                findings = f.readlines()
            
            if findings:
                print(f"\n🎯 FINDINGS: {len(findings)} potential vulnerabilities!")
                print("\n🔍 Top findings:")
                for i, finding in enumerate(findings[:5], 1):
                    print(f"  {i}. {finding.strip()[:100]}")
                
                print("\n💰 POTENTIAL VALUE:")
                print(f"  - If 1 valid finding: $250-$2000")
                print(f"  - If 2-3 valid findings: $500-$4000")
                print(f"  - If critical finding: $1000-$10000")
                
                print("\n⚠️  IMPORTANT: Manual verification required!")
                print("  - Confirm it's a real vulnerability")
                print("  - Check scope (is this asset in-scope?)")
                print("  - Verify impact")
                print("  - Check for duplicates")
            else:
                print("\n📋 No automated findings. Try:")
                print("  - Manual testing (auth bypass, logic flaws)")
                print("  - API endpoint analysis")
                print("  - JavaScript file review")
        else:
            print("⚠️  Nuclei results not found")

def main():
    """2-Click Bug Hunt"""
    print("""
╔══════════════════════════════════════════════════════════════╗
║                  BUG HUNT TONIGHT 🎯                         ║
║          Ethical Bug Bounty Hunting System                   ║
║                                                               ║
║  ✅ LEGAL: Only authorized bug bounty programs               ║
║  ✅ ETHICAL: Responsible disclosure                          ║
║  ✅ PROFITABLE: Focus on high-value targets                  ║
║                                                               ║
║  Copyright © 2025 DoctorMen. All Rights Reserved.           ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    hunter = BugHuntTonight()
    
    print("\n🎯 TONIGHT'S MISSION: Find 1-3 valid bugs and submit")
    print("⏰ TIME: 2-4 hours (scanning + verification)")
    print("💰 VALUE: $250-2000 per valid finding")
    print("\n" + "="*70 + "\n")
    
    # Execute hunt
    hunter.hunt()

if __name__ == '__main__':
    main()
