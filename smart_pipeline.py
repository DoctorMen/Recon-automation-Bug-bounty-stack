#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Smart Pipeline - Integrated ML Learning + 10-Agent Parallelization
Combines self-learning optimization with multi-agent execution
"""

import os
import sys
import time
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict

# Import our new systems
try:
    from ml_learning_engine import LearningEngine
    from agent_swarm import AgentSwarm
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Make sure ml_learning_engine.py and agent_swarm.py are in the same directory")
    sys.exit(1)


class SmartPipeline:
    """
    Intelligent pipeline that:
    1. Learns from past executions
    2. Predicts performance
    3. Optimizes settings automatically
    4. Executes with 10-agent parallelization
    """
    
    def __init__(self, use_learning: bool = True, use_agents: bool = True):
        self.use_learning = use_learning
        self.use_agents = use_agents
        
        if use_learning:
            self.learning_engine = LearningEngine()
        
        if use_agents:
            self.swarm = AgentSwarm()
    
    def scan(self, target: str, workflow: str = "full", optimization_goal: str = "balanced"):
        """
        Run intelligent scan with learning and parallelization
        
        Args:
            target: Target domain
            workflow: 'full', 'recon', or 'vuln'
            optimization_goal: 'speed', 'accuracy', or 'balanced'
        """
        
        print(f"\n{'='*60}")
        print(f"🧠 SMART PIPELINE - AI-Optimized Bug Bounty Automation")
        print(f"{'='*60}\n")
        
        print(f"🎯 Target: {target}")
        print(f"📋 Workflow: {workflow}")
        print(f"🎛️  Optimization: {optimization_goal}\n")
        
        # Phase 1: Prediction (if learning enabled)
        if self.use_learning:
            print("📊 PHASE 1: Analyzing Historical Data\n")
            prediction = self.learning_engine.predict_execution("run_pipeline", target)
            
            print(f"⏱️  Predicted Duration: {prediction['estimated_duration_human']}")
            print(f"🔍 Expected Findings:")
            for severity, count in prediction['predicted_findings'].items():
                print(f"   • {severity.capitalize()}: {count}")
            print(f"📈 Confidence: {int(prediction['confidence']*100)}%\n")
            
            # Get optimized settings
            settings = self.learning_engine.suggest_settings(
                "run_pipeline", target, optimization_goal
            )
            print(f"⚙️  Optimized Settings:")
            for key, value in settings.items():
                print(f"   • {key}: {value}")
            print()
            
            # Apply settings to environment
            for key, value in settings.items():
                os.environ[key] = str(value)
        
        # Phase 2: Execution (if agents enabled)
        start_time = time.time()
        execution_id = None
        
        if self.use_agents:
            print(f"🚀 PHASE 2: Launching 10-Agent Swarm\n")
            
            self.swarm.start()
            self.swarm.parallel_scan(target, workflow)
            self.swarm.wait_for_completion()
            
            results = self.swarm.get_results()
            self.swarm.stop()
            
            duration = time.time() - start_time
            
            print(f"\n✅ SCAN COMPLETED in {duration:.1f}s ({duration/60:.1f} minutes)\n")
            
            # Parse results
            stats = results['stats']
            print(f"📊 Task Statistics:")
            print(f"   • Completed: {stats['completed']}")
            print(f"   • Failed: {stats['failed']}")
            print(f"   • Success Rate: {stats['completed']/(stats['completed']+stats['failed'])*100:.1f}%\n")
        
        else:
            # Fallback to traditional execution
            print(f"🔧 PHASE 2: Running Traditional Pipeline\n")
            import subprocess
            
            cmd = f"python3 run_pipeline.py"
            result = subprocess.run(cmd, shell=True)
            
            duration = time.time() - start_time
            success = result.returncode == 0
            
            results = {
                "return_code": result.returncode,
                "duration": duration
            }
        
        # Phase 3: Learning (record execution)
        if self.use_learning:
            print(f"🧠 PHASE 3: Recording Learning Data\n")
            
            # Parse actual results from output files
            findings = self._count_findings()
            
            execution_id = self.learning_engine.history.log_execution(
                command="smart_pipeline",
                target=target,
                settings=settings if self.use_learning else {},
                duration=duration,
                success=stats['completed'] > 0 if self.use_agents else success,
                results=findings
            )
            
            print(f"✓ Execution logged: {execution_id}")
            print(f"✓ Learning data updated\n")
        
        # Print learning stats
        if self.use_learning:
            stats = self.learning_engine.get_learning_stats()
            print(f"📈 Learning Progress:")
            print(f"   • Total Executions: {stats['total_executions']}")
            print(f"   • Success Rate: {stats['success_rate']*100:.1f}%")
            print(f"   • Targets Scanned: {stats['targets_scanned']}")
            print(f"   • Learning Active: {'✓' if stats['learning_active'] else '✗'}\n")
        
        print(f"{'='*60}")
        print(f"✅ SMART PIPELINE COMPLETE")
        print(f"{'='*60}\n")
        
        if execution_id:
            print(f"💬 Rate this scan: python3 smart_pipeline.py feedback --execution-id {execution_id} --rating [1-5]\n")
        
        return {
            "execution_id": execution_id,
            "duration": duration,
            "target": target,
            "workflow": workflow
        }
    
    def _count_findings(self) -> Dict[str, int]:
        """Count findings from output files"""
        findings = {
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "total_count": 0
        }
        
        # Try to parse triage.json if it exists
        triage_file = Path("output/triage.json")
        if triage_file.exists():
            try:
                with open(triage_file, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for finding in data:
                            severity = finding.get('info', {}).get('severity', 'unknown').lower()
                            findings[f"{severity}_count"] = findings.get(f"{severity}_count", 0) + 1
                            findings["total_count"] += 1
            except Exception as e:
                print(f"Warning: Could not parse triage.json: {e}")
        
        return findings
    
    def show_stats(self):
        """Show learning statistics"""
        if not self.use_learning:
            print("Learning engine not enabled")
            return
        
        stats = self.learning_engine.get_learning_stats()
        
        print(f"\n📊 LEARNING ENGINE STATISTICS\n")
        print(f"Total Executions: {stats['total_executions']}")
        print(f"Successful: {stats['successful_executions']}")
        print(f"Success Rate: {stats['success_rate']*100:.1f}%")
        print(f"Avg Duration: {stats['avg_duration_seconds']/60:.1f} minutes")
        print(f"Unique Targets: {stats['targets_scanned']}")
        print(f"Learning Active: {'✓' if stats['learning_active'] else '✗'}\n")
    
    def record_feedback(self, execution_id: str, rating: int, comment: str = ""):
        """Record user feedback"""
        if not self.use_learning:
            print("Learning engine not enabled")
            return
        
        self.learning_engine.record_feedback(execution_id, comment, rating)
        print(f"✓ Feedback recorded for execution {execution_id}")


def main():
    parser = argparse.ArgumentParser(
        description="Smart Pipeline - ML Learning + 10-Agent Parallelization",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fast scan with learning and agents
  python3 smart_pipeline.py scan example.com --goal speed
  
  # Accurate scan with full workflow
  python3 smart_pipeline.py scan example.com --goal accuracy --workflow full
  
  # Show learning statistics
  python3 smart_pipeline.py stats
  
  # Provide feedback
  python3 smart_pipeline.py feedback --execution-id abc123 --rating 5
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run intelligent scan')
    scan_parser.add_argument('target', help='Target domain')
    scan_parser.add_argument('--workflow', choices=['full', 'recon', 'vuln'],
                            default='full', help='Scan workflow')
    scan_parser.add_argument('--goal', choices=['speed', 'accuracy', 'balanced'],
                            default='balanced', help='Optimization goal')
    scan_parser.add_argument('--no-learning', action='store_true',
                            help='Disable learning engine')
    scan_parser.add_argument('--no-agents', action='store_true',
                            help='Disable agent parallelization')
    
    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Show learning statistics')
    
    # Feedback command
    feedback_parser = subparsers.add_parser('feedback', help='Record feedback')
    feedback_parser.add_argument('--execution-id', required=True, help='Execution ID')
    feedback_parser.add_argument('--rating', type=int, choices=[1,2,3,4,5],
                                required=True, help='Rating (1-5)')
    feedback_parser.add_argument('--comment', default='', help='Optional comment')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Create smart pipeline
    if args.command == 'scan':
        pipeline = SmartPipeline(
            use_learning=not args.no_learning,
            use_agents=not args.no_agents
        )
        pipeline.scan(args.target, args.workflow, args.goal)
    
    elif args.command == 'stats':
        pipeline = SmartPipeline()
        pipeline.show_stats()
    
    elif args.command == 'feedback':
        pipeline = SmartPipeline()
        pipeline.record_feedback(args.execution_id, args.rating, args.comment)


if __name__ == "__main__":
    main()
