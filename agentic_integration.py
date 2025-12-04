#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Integration layer between agentic system and existing pipeline
Provides backward compatibility and gradual migration path
"""

import asyncio
import subprocess
from pathlib import Path
from typing import List, Dict, Any
import logging

from agentic_core import Task, TaskPriority
from agentic_coordinator import run_complete_agentic_system
from agentic_recon_agents import create_all_agents

logger = logging.getLogger(__name__)


class LegacyPipelineAdapter:
    """
    Adapts existing shell-based pipeline to agentic system
    Allows gradual migration while maintaining compatibility
    """
    
    def __init__(self):
        self.output_dir = Path("output")
        self.scripts_dir = Path("scripts")
        
    async def run_legacy_stage(self, stage_name: str, target: str) -> Dict[str, Any]:
        """Run a legacy shell script stage"""
        script_map = {
            'recon': 'run_recon.sh',
            'httpx': 'run_httpx.sh',
            'nuclei': 'run_nuclei.sh',
            'process': 'post_scan_processor.sh'
        }
        
        script = self.scripts_dir / script_map.get(stage_name, f"{stage_name}.sh")
        
        if not script.exists():
            logger.warning(f"Legacy script not found: {script}")
            return {'success': False, 'error': 'Script not found'}
        
        try:
            # Run legacy script
            proc = await asyncio.create_subprocess_exec(
                'bash', str(script), target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.scripts_dir.parent
            )
            
            stdout, stderr = await proc.communicate()
            
            return {
                'success': proc.returncode == 0,
                'stdout': stdout.decode(),
                'stderr': stderr.decode(),
                'returncode': proc.returncode
            }
            
        except Exception as e:
            logger.error(f"Legacy stage error: {e}")
            return {'success': False, 'error': str(e)}
    
    def migrate_existing_results(self) -> List[str]:
        """Find existing scan results to process"""
        targets = []
        
        if self.output_dir.exists():
            for target_dir in self.output_dir.iterdir():
                if target_dir.is_dir() and target_dir.name != 'reports':
                    targets.append(target_dir.name)
        
        return targets


class HybridPipeline:
    """
    Hybrid pipeline that uses both legacy and agentic approaches
    Gradually shifts work to agentic system
    """
    
    def __init__(self, agentic_percentage: float = 50.0):
        self.agentic_percentage = agentic_percentage
        self.adapter = LegacyPipelineAdapter()
        
    async def run_hybrid(self, targets: List[str]) -> Dict[str, Any]:
        """
        Run pipeline with mixed legacy/agentic approach
        """
        results = {
            'agentic': [],
            'legacy': [],
            'total': len(targets)
        }
        
        # Split targets between agentic and legacy
        split_point = int(len(targets) * (self.agentic_percentage / 100))
        
        agentic_targets = targets[:split_point]
        legacy_targets = targets[split_point:]
        
        # Run agentic system
        if agentic_targets:
            logger.info(f"Running agentic system on {len(agentic_targets)} targets")
            agentic_result = await run_complete_agentic_system(
                agentic_targets,
                pipeline_type='full_recon'
            )
            results['agentic'] = agentic_result
        
        # Run legacy pipeline
        if legacy_targets:
            logger.info(f"Running legacy pipeline on {len(legacy_targets)} targets")
            for target in legacy_targets:
                legacy_result = await self.adapter.run_legacy_stage('recon', target)
                results['legacy'].append({
                    'target': target,
                    'result': legacy_result
                })
        
        return results


class SelfHealingSystem:
    """
    Self-healing capabilities for the agentic system
    Automatically recovers from failures and learns from errors
    """
    
    def __init__(self):
        self.failure_log: List[Dict[str, Any]] = []
        self.recovery_strategies: Dict[str, callable] = {}
        
    def register_recovery_strategy(self, error_type: str, strategy: callable):
        """Register a recovery strategy for error type"""
        self.recovery_strategies[error_type] = strategy
        
    async def attempt_recovery(self, task: Task, error: str) -> bool:
        """Attempt to recover from task failure"""
        
        # Log failure
        self.failure_log.append({
            'task': task.name,
            'error': error,
            'timestamp': asyncio.get_event_loop().time()
        })
        
        # Identify error type
        error_type = self._classify_error(error)
        
        # Try recovery strategy
        if error_type in self.recovery_strategies:
            strategy = self.recovery_strategies[error_type]
            try:
                return await strategy(task, error)
            except Exception as e:
                logger.error(f"Recovery failed: {e}")
                return False
        
        return False
    
    def _classify_error(self, error: str) -> str:
        """Classify error type for recovery selection"""
        if 'timeout' in error.lower():
            return 'timeout'
        elif 'connection' in error.lower() or 'network' in error.lower():
            return 'network'
        elif 'permission' in error.lower() or 'denied' in error.lower():
            return 'permission'
        elif 'not found' in error.lower() or '404' in error:
            return 'not_found'
        else:
            return 'unknown'


# Recovery strategies
async def recover_from_timeout(task: Task, error: str) -> bool:
    """Recovery strategy for timeout errors"""
    logger.info(f"Attempting timeout recovery for {task.name}")
    
    # Increase timeout and retry
    task.estimated_duration *= 2
    task.retry_count = 0  # Reset retry count
    
    return True


async def recover_from_network_error(task: Task, error: str) -> bool:
    """Recovery strategy for network errors"""
    logger.info(f"Attempting network error recovery for {task.name}")
    
    # Wait and retry
    await asyncio.sleep(5)
    task.retry_count = 0
    
    return True


def setup_self_healing() -> SelfHealingSystem:
    """Setup self-healing system with recovery strategies"""
    healer = SelfHealingSystem()
    
    healer.register_recovery_strategy('timeout', recover_from_timeout)
    healer.register_recovery_strategy('network', recover_from_network_error)
    
    return healer


class PerformanceOptimizer:
    """
    Continuously optimizes system performance
    """
    
    def __init__(self):
        self.metrics_history: List[Dict[str, Any]] = []
        self.optimizations_applied: List[str] = []
        
    async def optimize_continuously(self, orchestrator):
        """Continuously monitor and optimize"""
        while orchestrator.running:
            await asyncio.sleep(30)  # Check every 30 seconds
            
            # Get current metrics
            status = orchestrator.get_system_status()
            
            # Store metrics
            self.metrics_history.append(status['metrics'])
            
            # Analyze and optimize
            if len(self.metrics_history) >= 3:
                await self._analyze_and_optimize(orchestrator)
        
        # Keep last 100 entries
        if len(self.metrics_history) > 100:
            self.metrics_history = self.metrics_history[-100:]
    
    async def _analyze_and_optimize(self, orchestrator):
        """Analyze metrics and apply optimizations"""
        
        recent_metrics = self.metrics_history[-3:]
        
        # Check for consistently high queue
        avg_queue = sum(m.get('queue_size', 0) for m in recent_metrics) / 3
        
        if avg_queue > 10 and 'increase_concurrency' not in self.optimizations_applied:
            logger.info("Optimization: Increasing concurrency")
            # Would adjust max_concurrent_tasks here
            self.optimizations_applied.append('increase_concurrency')


# ============================================================================
# UNIFIED ENTRY POINT
# ============================================================================

async def run_unified_pipeline(
    targets: List[str],
    mode: str = "agentic",
    pipeline_type: str = "full_recon"
):
    """
    Unified entry point supporting multiple modes:
    - 'agentic': Full agentic system
    - 'legacy': Legacy shell pipeline
    - 'hybrid': Mix of both (gradual migration)
    """
    
    if mode == "agentic":
        logger.info("Running full agentic system")
        return await run_complete_agentic_system(targets, pipeline_type)
        
    elif mode == "legacy":
        logger.info("Running legacy pipeline")
        adapter = LegacyPipelineAdapter()
        results = []
        for target in targets:
            result = await adapter.run_legacy_stage('recon', target)
            results.append({'target': target, 'result': result})
        return {'mode': 'legacy', 'results': results}
        
    elif mode == "hybrid":
        logger.info("Running hybrid pipeline (50% agentic, 50% legacy)")
        hybrid = HybridPipeline(agentic_percentage=50.0)
        return await hybrid.run_hybrid(targets)
        
    else:
        raise ValueError(f"Unknown mode: {mode}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Unified Pipeline Entry Point")
    parser.add_argument('targets', nargs='+', help="Target domains")
    parser.add_argument(
        '--mode',
        choices=['agentic', 'legacy', 'hybrid'],
        default='agentic',
        help="Execution mode"
    )
    parser.add_argument(
        '--pipeline',
        choices=['full_recon', 'quick_scan', 'deep_discovery', 'focused_vuln'],
        default='full_recon',
        help="Pipeline type"
    )
    
    args = parser.parse_args()
    
    asyncio.run(run_unified_pipeline(args.targets, args.mode, args.pipeline))
