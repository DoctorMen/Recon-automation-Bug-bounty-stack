#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
# -*- coding: utf-8 -*-
"""
PARALLELPROFIT™ MASTER SYSTEM
Complete automation: Discover → Generate → Track → Earn

This is the master orchestrator that runs the entire ParallelProfit system.

Author: DoctorMen
Status: Production Ready
"""

import json
import sys
import time
from pathlib import Path
from datetime import datetime

# Import our systems
sys.path.insert(0, str(Path(__file__).parent))

try:
    from UPWORK_INTEGRATION_ENGINE import UpworkIntegrationEngine
    from AI_PROPOSAL_GENERATOR import AIProposalGenerator
    from DASHBOARD_CONNECTOR import DashboardConnector
except ImportError as e:
    print(f"WARNING: Import error: {e}")
    print("Make sure all system files are in the same directory")
    sys.exit(1)

# Fix encoding for Windows
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')

class ParallelProfitMaster:
    """
    Master orchestrator for ParallelProfit™ system
    """
    
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        
        print("🚀 Initializing ParallelProfit™ Master System...")
        
        # Initialize subsystems
        self.upwork_engine = UpworkIntegrationEngine()
        self.ai_generator = AIProposalGenerator()
        self.dashboard = DashboardConnector()
        
        print("✅ All systems initialized")
    
    def run_discovery(self):
        """Run job discovery"""
        print("\n" + "="*80)
        print("🔍 PHASE 1: JOB DISCOVERY")
        print("="*80)
        
        jobs = self.upwork_engine.discover_jobs()
        
        print(f"\n✅ Discovered {len(jobs)} matching jobs")
        return jobs
    
    def run_proposal_generation(self, jobs):
        """Generate AI proposals for jobs"""
        print("\n" + "="*80)
        print("🤖 PHASE 2: AI PROPOSAL GENERATION")
        print("="*80)
        
        proposals = []
        
        for i, job in enumerate(jobs[:5], 1):  # Top 5 jobs
            print(f"\n[{i}/{min(len(jobs), 5)}] Processing: {job['title'][:50]}...")
            
            # Generate AI proposal
            proposal = self.ai_generator.generate_proposal(job)
            
            # Save proposal
            self.ai_generator.save_proposal(proposal)
            
            proposals.append(proposal)
            
            # Rate limiting
            time.sleep(2)
        
        print(f"\n✅ Generated {len(proposals)} AI-powered proposals")
        return proposals
    
    def update_dashboard(self):
        """Update 3D dashboard with real data"""
        print("\n" + "="*80)
        print("📊 PHASE 3: DASHBOARD UPDATE")
        print("="*80)
        
        self.dashboard.update_dashboard()
        
        print("\n✅ Dashboard updated with real metrics")
    
    def show_summary(self):
        """Show execution summary"""
        metrics = self.upwork_engine.get_metrics()
        
        print("\n" + "="*80)
        print("📊 PARALLELPROFIT™ SUMMARY")
        print("="*80)
        print(f"\n💼 Jobs Discovered: {metrics['jobs_discovered']}")
        print(f"✍️ Proposals Generated: {metrics['proposals_generated']}")
        print(f"📤 Applications Sent: {metrics['applications_sent']}")
        print(f"🏆 Jobs Won: {metrics['jobs_won']}")
        print(f"💰 Revenue Earned: ${metrics['revenue_earned']}")
        print(f"📈 Win Rate: {metrics['win_rate']:.1f}%")
        
        print("\n" + "="*80)
        print("📁 OUTPUT LOCATIONS")
        print("="*80)
        print(f"\n📊 Metrics: output/upwork_data/metrics.json")
        print(f"✍️ Proposals: output/upwork_data/proposals/")
        print(f"📈 Dashboard: output/dashboard_data.json")
        
        print("\n" + "="*80)
        print("🎯 NEXT STEPS")
        print("="*80)
        print("\n1. Review proposals in output/upwork_data/proposals/")
        print("2. Submit top proposals manually on Upwork")
        print("3. Track submissions:")
        print("   python -c \"from UPWORK_INTEGRATION_ENGINE import UpworkIntegrationEngine; e = UpworkIntegrationEngine(); e.track_application('job_id', 'sent')\"")
        print("4. When you win a job:")
        print("   python -c \"from UPWORK_INTEGRATION_ENGINE import UpworkIntegrationEngine; e = UpworkIntegrationEngine(); e.add_revenue(amount, 'job_id')\"")
        print("5. Open 3D dashboard to see real metrics!")
    
    def run_full_cycle(self):
        """Run complete automation cycle"""
        print("""
================================================================================
                        PARALLELPROFIT™ MASTER
                    Complete Upwork Automation System
================================================================================

Starting full automation cycle:
1. Discover jobs from Upwork
2. Generate AI-powered proposals
3. Update 3D dashboard with real data

Let's make money! 💰
        """)
        
        start_time = time.time()
        
        try:
            # Phase 1: Discovery
            jobs = self.run_discovery()
            
            if not jobs:
                print("\n⚠️ No matching jobs found this cycle")
                print("Try adjusting your skills in config/upwork_config.json")
                return
            
            # Phase 2: Proposal Generation
            proposals = self.run_proposal_generation(jobs)
            
            # Phase 3: Dashboard Update
            self.update_dashboard()
            
            # Summary
            duration = time.time() - start_time
            
            print("\n" + "="*80)
            print("✅ CYCLE COMPLETE")
            print("="*80)
            print(f"\n⏱️ Duration: {duration:.1f} seconds")
            print(f"📊 Jobs processed: {len(jobs)}")
            print(f"✍️ Proposals generated: {len(proposals)}")
            
            self.show_summary()
            
            return {
                "jobs": jobs,
                "proposals": proposals,
                "duration": duration
            }
            
        except Exception as e:
            print(f"\n❌ Error during cycle: {str(e)}")
            import traceback
            traceback.print_exc()
            return None
    
    def run_continuous(self, hours: int = 24):
        """Run continuously for specified hours"""
        print(f"\n🔄 Starting continuous operation for {hours} hours...")
        print("Press Ctrl+C to stop\n")
        
        end_time = time.time() + (hours * 3600)
        cycle_count = 0
        
        try:
            while time.time() < end_time:
                cycle_count += 1
                print(f"\n{'='*80}")
                print(f"🔄 CYCLE #{cycle_count}")
                print(f"{'='*80}")
                
                # Run full cycle
                self.run_full_cycle()
                
                # Wait before next cycle (4 hours)
                wait_time = 4 * 3600
                remaining = end_time - time.time()
                
                if remaining < wait_time:
                    print(f"\n⏰ Less than 4 hours remaining, stopping...")
                    break
                
                print(f"\n⏰ Waiting 4 hours before next cycle...")
                print(f"   Next cycle at: {datetime.fromtimestamp(time.time() + wait_time).strftime('%H:%M:%S')}")
                
                time.sleep(wait_time)
        
        except KeyboardInterrupt:
            print("\n\n⚠️ Stopped by user")
        
        print(f"\n✅ Completed {cycle_count} cycles")
        self.show_summary()


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='ParallelProfit™ Master System')
    parser.add_argument('--continuous', type=int, metavar='HOURS',
                       help='Run continuously for specified hours')
    parser.add_argument('--discover-only', action='store_true',
                       help='Only discover jobs, no proposals')
    parser.add_argument('--dashboard-only', action='store_true',
                       help='Only update dashboard')
    
    args = parser.parse_args()
    
    # Initialize master system
    master = ParallelProfitMaster()
    
    if args.dashboard_only:
        # Just update dashboard
        master.update_dashboard()
        master.show_summary()
    
    elif args.discover_only:
        # Just discover jobs
        master.run_discovery()
    
    elif args.continuous:
        # Run continuously
        master.run_continuous(args.continuous)
    
    else:
        # Run single cycle
        master.run_full_cycle()
    
    print("\n" + "="*80)
    print("🎉 PARALLELPROFIT™ MASTER COMPLETE")
    print("="*80)
    print("\nYour 3D dashboard now shows REAL data!")
    print("Check output/upwork_data/proposals/ for generated proposals")
    print("\n💰 Go submit those proposals and make money! 🚀")


if __name__ == "__main__":
    main()
