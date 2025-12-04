#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Unified Runner for Agentic System
Single entry point for all agentic capabilities
"""

import asyncio
import argparse
import json
import sys
import logging
from pathlib import Path
from typing import List

# Import all agentic components
from agentic_core import AgenticOrchestrator, TaskPriority
from agentic_recon_agents import create_all_agents
from agentic_coordinator import (
    run_complete_agentic_system,
    SelfImprovingCoordinator,
    CollaborativeAgentNetwork,
    AutoScalingCoordinator
)
from agentic_learning import ContinuousLearningSystem
from agentic_monitoring import create_monitoring_system
from agentic_integration import run_unified_pipeline

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('output/agentic.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class AgenticSystemRunner:
    """
    Unified runner for agentic system
    """
    
    def __init__(self, config: dict):
        self.config = config
        self.output_dir = Path("output")
        self.output_dir.mkdir(exist_ok=True)
        
    async def run(self, targets: List[str], pipeline_type: str, mode: str = "agentic"):
        """Run agentic system with specified configuration"""
        
        logger.info("=" * 80)
        logger.info("🤖 AGENTIC RECONNAISSANCE SYSTEM")
        logger.info("=" * 80)
        logger.info(f"Targets: {len(targets)}")
        logger.info(f"Pipeline: {pipeline_type}")
        logger.info(f"Mode: {mode}")
        logger.info(f"Configuration: {json.dumps(self.config, indent=2)}")
        logger.info("=" * 80)
        
        # Create monitoring system if enabled
        if self.config.get('monitoring', {}).get('enabled', True):
            monitor = create_monitoring_system()
            dashboard = monitor['dashboard']
            
            # Start continuous dashboard updates
            dashboard_task = asyncio.create_task(
                dashboard.continuous_dashboard_update(
                    "output/dashboard.json",
                    interval_seconds=self.config.get('monitoring', {}).get('dashboard_update_interval', 5)
                )
            )
            logger.info("✅ Monitoring system started")
        
        # Load learning state if enabled
        if self.config.get('learning', {}).get('enabled', True):
            learner = ContinuousLearningSystem()
            learning_file = Path("learning_state.json")
            if learning_file.exists():
                learner.load_state(str(learning_file))
                logger.info("✅ Learning state loaded")
            else:
                logger.info("ℹ️  No previous learning state found - starting fresh")
        
        # Run based on mode
        result = None
        
        try:
            if mode == "agentic":
                result = await run_complete_agentic_system(targets, pipeline_type)
            elif mode == "legacy" or mode == "hybrid":
                result = await run_unified_pipeline(targets, mode, pipeline_type)
            else:
                raise ValueError(f"Unknown mode: {mode}")
            
            logger.info("=" * 80)
            logger.info("✅ EXECUTION COMPLETE")
            logger.info("=" * 80)
            
            # Save results
            result_file = self.output_dir / "agentic_result.json"
            with open(result_file, 'w') as f:
                json.dump(result, f, indent=2)
            
            logger.info(f"📄 Results saved to: {result_file}")
            
            # Save learning state if enabled
            if self.config.get('learning', {}).get('enabled', True):
                learner.save_state("learning_state.json")
                logger.info("💾 Learning state saved")
            
            # Print summary
            self._print_summary(result)
            
        except Exception as e:
            logger.error(f"❌ Execution failed: {e}", exc_info=True)
            raise
        
        finally:
            # Cleanup
            if self.config.get('monitoring', {}).get('enabled', True):
                dashboard_task.cancel()
        
        return result
    
    def _print_summary(self, result: dict):
        """Print execution summary"""
        print("\n" + "=" * 80)
        print("📊 EXECUTION SUMMARY")
        print("=" * 80)
        
        if isinstance(result, dict):
            if 'targets_processed' in result:
                print(f"Targets Processed: {result['targets_processed']}")
            
            if 'system_metrics' in result:
                metrics = result['system_metrics']['metrics']
                print(f"Total Tasks: {metrics.get('total_tasks', 0)}")
                print(f"Completed: {metrics.get('completed_tasks', 0)}")
                print(f"Failed: {metrics.get('failed_tasks', 0)}")
                print(f"Execution Time: {metrics.get('total_execution_time', 0):.2f}s")
            
            if 'learning_insights' in result:
                insights = result['learning_insights']
                print(f"\nLearning Progress:")
                print(f"  Patterns Learned: {insights.get('patterns_learned', 0)}")
                print(f"  Optimization Rules: {insights.get('optimization_rules', 0)}")
                print(f"  Workflow History: {insights.get('workflow_history', 0)}")
        
        print("=" * 80)
        print("\n📂 Output Files:")
        print("  • output/agentic_result.json - Complete results")
        print("  • output/dashboard.json - Real-time metrics")
        print("  • learning_state.json - Learning progress")
        print("  • output/agentic.log - Detailed logs")
        print()


def load_config(config_file: str = None) -> dict:
    """Load configuration from file or use defaults"""
    default_config = {
        "orchestrator": {
            "max_concurrent_tasks": 10,
            "task_timeout": 300,
            "retry_attempts": 3
        },
        "learning": {
            "enabled": True,
            "learning_rate": 0.1,
            "exploration_rate": 0.3
        },
        "monitoring": {
            "enabled": True,
            "metrics_retention_seconds": 3600,
            "dashboard_update_interval": 5
        },
        "distributed": {
            "enabled": False,
            "num_partitions": 16
        }
    }
    
    if config_file and Path(config_file).exists():
        with open(config_file, 'r') as f:
            user_config = json.load(f)
        
        # Merge configs (user config overrides defaults)
        for key, value in user_config.items():
            if isinstance(value, dict) and key in default_config:
                default_config[key].update(value)
            else:
                default_config[key] = value
    
    return default_config


def load_targets(target_args: List[str], target_file: str = None) -> List[str]:
    """Load targets from arguments or file"""
    targets = list(target_args) if target_args else []
    
    if target_file:
        target_path = Path(target_file)
        if target_path.exists():
            with open(target_path, 'r') as f:
                file_targets = [line.strip() for line in f if line.strip()]
                targets.extend(file_targets)
        else:
            logger.warning(f"Target file not found: {target_file}")
    
    # Remove duplicates while preserving order
    seen = set()
    unique_targets = []
    for target in targets:
        if target not in seen:
            seen.add(target)
            unique_targets.append(target)
    
    return unique_targets


async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="🤖 Advanced Agentic Reconnaissance System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single target
  python3 run_agentic_system.py example.com

  # Multiple targets
  python3 run_agentic_system.py example.com test.com demo.com

  # From file
  python3 run_agentic_system.py --target-file targets.txt

  # Different pipelines
  python3 run_agentic_system.py example.com --pipeline quick_scan
  python3 run_agentic_system.py example.com --pipeline deep_discovery
  python3 run_agentic_system.py example.com --pipeline focused_vuln

  # Hybrid mode (gradual migration)
  python3 run_agentic_system.py --target-file targets.txt --mode hybrid

  # Custom configuration
  python3 run_agentic_system.py example.com --config my_config.json

For detailed documentation, see: AGENTIC_SYSTEM_COMPLETE.md
        """
    )
    
    parser.add_argument(
        'targets',
        nargs='*',
        help="Target domains (space-separated)"
    )
    
    parser.add_argument(
        '--target-file', '-f',
        help="File containing targets (one per line)"
    )
    
    parser.add_argument(
        '--pipeline', '-p',
        choices=['full_recon', 'quick_scan', 'deep_discovery', 'focused_vuln'],
        default='full_recon',
        help="Pipeline type to execute (default: full_recon)"
    )
    
    parser.add_argument(
        '--mode', '-m',
        choices=['agentic', 'legacy', 'hybrid'],
        default='agentic',
        help="Execution mode (default: agentic)"
    )
    
    parser.add_argument(
        '--config', '-c',
        help="Configuration file (JSON)"
    )
    
    parser.add_argument(
        '--no-learning',
        action='store_true',
        help="Disable learning system"
    )
    
    parser.add_argument(
        '--no-monitoring',
        action='store_true',
        help="Disable monitoring system"
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help="Verbose output"
    )
    
    args = parser.parse_args()
    
    # Adjust log level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Load configuration
    config = load_config(args.config)
    
    # Override config with flags
    if args.no_learning:
        config['learning']['enabled'] = False
    if args.no_monitoring:
        config['monitoring']['enabled'] = False
    
    # Load targets
    targets = load_targets(args.targets, args.target_file)
    
    if not targets:
        parser.print_help()
        print("\n❌ Error: No targets specified")
        print("   Use: python3 run_agentic_system.py example.com")
        print("   Or:  python3 run_agentic_system.py --target-file targets.txt")
        sys.exit(1)
    
    # Create runner and execute
    runner = AgenticSystemRunner(config)
    
    try:
        result = await runner.run(targets, args.pipeline, args.mode)
        sys.exit(0)
    except KeyboardInterrupt:
        logger.info("\n⚠️  Interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"\n❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
