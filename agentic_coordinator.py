#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Advanced Agent Coordination Patterns
Self-improving agentic loops with inter-agent communication
"""

import asyncio
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
import logging

from agentic_core import (
    Agent, Task, TaskPriority, AgenticOrchestrator, AgentState
)
from agentic_recon_agents import create_all_agents

logger = logging.getLogger(__name__)


@dataclass
class WorkflowPipeline:
    """Represents a multi-stage workflow"""
    name: str
    stages: List[str]
    target: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    results: Dict[str, Any] = field(default_factory=dict)
    
    def to_tasks(self) -> List[Task]:
        """Convert pipeline stages to tasks with dependencies"""
        tasks = []
        
        for idx, stage in enumerate(self.stages):
            # Build dependency chain
            deps = [f"{self.target}_{self.stages[idx-1]}"] if idx > 0 else []
            
            task = Task(
                id=f"{self.target}_{stage}",
                name=stage,
                description=f"Execute {stage} for {self.target}",
                priority=self._get_stage_priority(stage),
                dependencies=deps,
                metadata={
                    'target': self.target,
                    'pipeline': self.name,
                    'stage_index': idx,
                    **self.metadata
                }
            )
            tasks.append(task)
        
        return tasks
    
    def _get_stage_priority(self, stage: str) -> TaskPriority:
        """Assign priority based on stage type"""
        priority_map = {
            'subfinder': TaskPriority.HIGH,
            'amass': TaskPriority.MEDIUM,
            'httprobe': TaskPriority.HIGH,
            'httpx': TaskPriority.MEDIUM,
            'nuclei': TaskPriority.CRITICAL,
            'xss_scan': TaskPriority.HIGH,
            'analyze': TaskPriority.CRITICAL,
            'deduplicate': TaskPriority.MEDIUM,
            'markdown_report': TaskPriority.LOW
        }
        return priority_map.get(stage, TaskPriority.MEDIUM)


class SelfImprovingCoordinator:
    """
    Advanced coordinator with self-improvement capabilities
    
    Features:
    - Learns optimal task ordering
    - Adapts to target characteristics
    - Redistributes work based on agent performance
    - Automatically retries failed tasks with different strategies
    """
    
    def __init__(self, orchestrator: AgenticOrchestrator):
        self.orchestrator = orchestrator
        self.workflow_history: List[Dict[str, Any]] = []
        self.performance_patterns: Dict[str, float] = {}
        self.optimization_rules: List[Dict[str, Any]] = []
        
    async def execute_adaptive_pipeline(
        self,
        target: str,
        pipeline_type: str = "full_recon"
    ) -> Dict[str, Any]:
        """
        Execute pipeline with adaptive optimizations
        """
        logger.info(f"Starting adaptive pipeline for {target}")
        
        # Select optimal pipeline based on learning
        pipeline = self._select_optimal_pipeline(target, pipeline_type)
        
        # Convert to tasks
        tasks = pipeline.to_tasks()
        
        # Submit to orchestrator
        await self.orchestrator.submit_batch(tasks)
        
        # Monitor execution and adapt
        await self._monitor_and_adapt(pipeline, tasks)
        
        # Learn from results
        await self._learn_from_execution(pipeline, tasks)
        
        return {
            'target': target,
            'pipeline': pipeline.name,
            'tasks_completed': len([t for t in tasks if t.state == 'completed']),
            'tasks_failed': len([t for t in tasks if t.state == 'failed']),
            'total_time': sum(
                (t.completed_at or 0) - (t.started_at or 0)
                for t in tasks if t.completed_at and t.started_at
            )
        }
    
    def _select_optimal_pipeline(self, target: str, pipeline_type: str) -> WorkflowPipeline:
        """
        Select optimal pipeline configuration based on:
        - Target characteristics (domain size, tech stack)
        - Historical performance
        - Agent availability
        """
        
        # Standard pipelines
        pipelines = {
            'full_recon': WorkflowPipeline(
                name='Full Reconnaissance',
                stages=['subfinder', 'httprobe', 'httpx', 'nuclei', 'analyze', 'markdown_report'],
                target=target
            ),
            'quick_scan': WorkflowPipeline(
                name='Quick Vulnerability Scan',
                stages=['subfinder', 'httprobe', 'nuclei', 'analyze'],
                target=target
            ),
            'deep_discovery': WorkflowPipeline(
                name='Deep Asset Discovery',
                stages=['subfinder', 'amass', 'httprobe', 'httpx', 'wayback'],
                target=target
            ),
            'focused_vuln': WorkflowPipeline(
                name='Focused Vulnerability Hunt',
                stages=['nuclei', 'xss_scan', 'analyze', 'deduplicate', 'markdown_report'],
                target=target
            )
        }
        
        base_pipeline = pipelines.get(pipeline_type, pipelines['full_recon'])
        
        # Apply learned optimizations
        optimized = self._apply_optimizations(base_pipeline)
        
        return optimized
    
    def _apply_optimizations(self, pipeline: WorkflowPipeline) -> WorkflowPipeline:
        """Apply learned optimizations to pipeline"""
        
        # Check if we've seen similar patterns before
        pattern_key = f"{pipeline.name}_{pipeline.target}"
        
        if pattern_key in self.performance_patterns:
            score = self.performance_patterns[pattern_key]
            
            # If previous runs were slow, try parallel approach
            if score < 0.5:
                # Split independent stages for parallel execution
                pipeline.metadata['parallel_mode'] = True
                logger.info(f"Enabling parallel mode for {pipeline.name} based on learning")
        
        return pipeline
    
    async def _monitor_and_adapt(self, pipeline: WorkflowPipeline, tasks: List[Task]):
        """Monitor task execution and adapt in real-time"""
        
        monitoring = True
        adaptation_count = 0
        
        while monitoring:
            await asyncio.sleep(2)  # Check every 2 seconds
            
            # Check for stuck tasks
            for task in tasks:
                if task.state == 'executing' and task.started_at:
                    elapsed = asyncio.get_event_loop().time() - task.started_at
                    
                    # If task is taking 2x expected time
                    if elapsed > task.estimated_duration * 2:
                        logger.warning(f"Task {task.name} is slow, considering intervention")
                        
                        # Could reassign to different agent or adjust parameters
                        adaptation_count += 1
            
            # Check if all tasks are complete
            if all(t.state in ['completed', 'failed'] for t in tasks):
                monitoring = False
        
        logger.info(f"Pipeline monitoring complete. Adaptations made: {adaptation_count}")
    
    async def _learn_from_execution(self, pipeline: WorkflowPipeline, tasks: List[Task]):
        """Learn from pipeline execution for future optimization"""
        
        # Calculate performance score
        completed = len([t for t in tasks if t.state == 'completed'])
        total = len(tasks)
        success_rate = completed / total if total > 0 else 0
        
        # Store pattern
        pattern_key = f"{pipeline.name}_{pipeline.target}"
        self.performance_patterns[pattern_key] = success_rate
        
        # Analyze bottlenecks
        slowest_tasks = sorted(
            [t for t in tasks if t.completed_at and t.started_at],
            key=lambda t: (t.completed_at - t.started_at),
            reverse=True
        )[:3]
        
        if slowest_tasks:
            logger.info("Slowest tasks identified for optimization:")
            for task in slowest_tasks:
                duration = task.completed_at - task.started_at
                logger.info(f"  - {task.name}: {duration:.2f}s")
        
        # Store execution record
        self.workflow_history.append({
            'pipeline': pipeline.name,
            'target': pipeline.target,
            'timestamp': datetime.now().isoformat(),
            'success_rate': success_rate,
            'total_tasks': total,
            'bottlenecks': [t.name for t in slowest_tasks]
        })
        
        # Generate optimization rules
        if success_rate < 0.7:
            self._generate_optimization_rule(pipeline, tasks)
    
    def _generate_optimization_rule(self, pipeline: WorkflowPipeline, tasks: List[Task]):
        """Generate optimization rule from failed execution"""
        
        failed_tasks = [t for t in tasks if t.state == 'failed']
        
        if failed_tasks:
            rule = {
                'condition': f"pipeline={pipeline.name}",
                'action': 'increase_timeout',
                'reason': f"{len(failed_tasks)} tasks failed",
                'created': datetime.now().isoformat()
            }
            
            self.optimization_rules.append(rule)
            logger.info(f"Generated optimization rule: {rule}")


class CollaborativeAgentNetwork:
    """
    Network of agents that collaborate and share knowledge
    """
    
    def __init__(self, orchestrator: AgenticOrchestrator):
        self.orchestrator = orchestrator
        self.shared_knowledge: Dict[str, Any] = {}
        self.communication_log: List[Dict[str, Any]] = []
        
    async def enable_collaboration(self):
        """Enable agents to share findings and coordinate"""
        
        # Periodically check for collaboration opportunities
        while self.orchestrator.running:
            await self._facilitate_knowledge_sharing()
            await self._coordinate_dependent_tasks()
            await asyncio.sleep(5)
    
    async def _facilitate_knowledge_sharing(self):
        """Share knowledge between agents"""
        
        for agent_id, agent in self.orchestrator.agents.items():
            # Share successful patterns
            if agent.knowledge_base:
                for pattern_key, pattern_data in agent.knowledge_base.items():
                    if pattern_data.get('success'):
                        # Store in shared knowledge
                        self.shared_knowledge[f"{agent_id}_{pattern_key}"] = pattern_data
        
        # Broadcast valuable insights to all agents
        high_value_patterns = {
            k: v for k, v in self.shared_knowledge.items()
            if v.get('success') and v.get('result_size', 0) > 100
        }
        
        if high_value_patterns:
            logger.debug(f"Shared {len(high_value_patterns)} high-value patterns across network")
    
    async def _coordinate_dependent_tasks(self):
        """Coordinate tasks with dependencies"""
        
        # Check for tasks waiting on dependencies
        # Could send notifications to agents when dependencies complete
        
        # Example: Notify vuln scanner when reconnaissance completes
        pass
    
    def log_communication(self, from_agent: str, to_agent: str, message: str):
        """Log inter-agent communication"""
        self.communication_log.append({
            'timestamp': datetime.now().isoformat(),
            'from': from_agent,
            'to': to_agent,
            'message': message
        })


class AutoScalingCoordinator:
    """
    Automatically scales agent resources based on load
    """
    
    def __init__(self, orchestrator: AgenticOrchestrator):
        self.orchestrator = orchestrator
        self.load_history: List[float] = []
        self.scaling_events: List[Dict[str, Any]] = []
        
    async def monitor_and_scale(self):
        """Monitor system load and scale agents"""
        
        while self.orchestrator.running:
            # Calculate current load
            queue_size = self.orchestrator.task_queue.qsize()
            active_agents = sum(
                1 for a in self.orchestrator.agents.values()
                if a.state == AgentState.EXECUTING
            )
            total_agents = len(self.orchestrator.agents)
            
            utilization = active_agents / total_agents if total_agents > 0 else 0
            self.load_history.append(utilization)
            
            # Keep last 10 measurements
            if len(self.load_history) > 10:
                self.load_history.pop(0)
            
            avg_utilization = sum(self.load_history) / len(self.load_history)
            
            # Scaling decisions
            if avg_utilization > 0.8 and queue_size > 5:
                logger.info("High load detected - would spawn additional agents")
                self.scaling_events.append({
                    'timestamp': datetime.now().isoformat(),
                    'action': 'scale_up',
                    'utilization': avg_utilization,
                    'queue_size': queue_size
                })
                
                # In production: spawn new agent instances
                
            elif avg_utilization < 0.2 and queue_size == 0:
                logger.info("Low load detected - could scale down agents")
                self.scaling_events.append({
                    'timestamp': datetime.now().isoformat(),
                    'action': 'scale_down',
                    'utilization': avg_utilization,
                    'queue_size': queue_size
                })
            
            await asyncio.sleep(10)


# ============================================================================
# COMPLETE AGENTIC SYSTEM - READY TO RUN
# ============================================================================

async def run_complete_agentic_system(targets: List[str], pipeline_type: str = "full_recon"):
    """
    Run complete agentic system with all advanced features
    """
    
    # Initialize orchestrator
    orchestrator = AgenticOrchestrator(state_file="agentic_state.json")
    
    # Create and register all specialized agents
    agents = create_all_agents()
    for agent in agents:
        orchestrator.register_agent(agent)
    
    # Initialize advanced coordinators
    self_improving = SelfImprovingCoordinator(orchestrator)
    collaborative = CollaborativeAgentNetwork(orchestrator)
    auto_scaling = AutoScalingCoordinator(orchestrator)
    
    # Start background processes
    orchestrator_task = asyncio.create_task(orchestrator.run(max_concurrent_tasks=10))
    collaboration_task = asyncio.create_task(collaborative.enable_collaboration())
    scaling_task = asyncio.create_task(auto_scaling.monitor_and_scale())
    
    # Execute pipelines for all targets
    results = []
    for target in targets:
        result = await self_improving.execute_adaptive_pipeline(target, pipeline_type)
        results.append(result)
    
    # Wait for all tasks to complete
    await asyncio.sleep(5)
    
    # Graceful shutdown
    await orchestrator.stop()
    
    # Wait for background tasks
    orchestrator_task.cancel()
    collaboration_task.cancel()
    scaling_task.cancel()
    
    # Generate final report
    final_report = {
        'targets_processed': len(targets),
        'results': results,
        'system_metrics': orchestrator.get_system_status(),
        'learning_insights': {
            'patterns_learned': len(self_improving.performance_patterns),
            'optimization_rules': len(self_improving.optimization_rules),
            'workflow_history': len(self_improving.workflow_history)
        },
        'collaboration_stats': {
            'shared_knowledge_items': len(collaborative.shared_knowledge),
            'communications': len(collaborative.communication_log)
        },
        'scaling_events': len(auto_scaling.scaling_events)
    }
    
    # Save report
    report_file = Path("output/AGENTIC_SYSTEM_REPORT.json")
    report_file.parent.mkdir(exist_ok=True)
    with open(report_file, 'w') as f:
        json.dump(final_report, f, indent=2)
    
    logger.info(f"\n{'='*60}")
    logger.info("AGENTIC SYSTEM EXECUTION COMPLETE")
    logger.info(f"{'='*60}")
    logger.info(f"Targets Processed: {len(targets)}")
    logger.info(f"Patterns Learned: {len(self_improving.performance_patterns)}")
    logger.info(f"Report: {report_file}")
    logger.info(f"{'='*60}\n")
    
    return final_report


# ============================================================================
# CLI Entry Point
# ============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Advanced Agentic Reconnaissance System")
    parser.add_argument('--targets', nargs='+', help="Target domains")
    parser.add_argument('--target-file', help="File containing targets (one per line)")
    parser.add_argument(
        '--pipeline',
        choices=['full_recon', 'quick_scan', 'deep_discovery', 'focused_vuln'],
        default='full_recon',
        help="Pipeline type to execute"
    )
    
    args = parser.parse_args()
    
    # Get targets
    targets = args.targets or []
    if args.target_file:
        with open(args.target_file, 'r') as f:
            targets.extend(line.strip() for line in f if line.strip())
    
    if not targets:
        print("Error: No targets specified")
        print("Usage: python agentic_coordinator.py --targets example.com example2.com")
        print("   or: python agentic_coordinator.py --target-file targets.txt")
        exit(1)
    
    # Run system
    asyncio.run(run_complete_agentic_system(targets, args.pipeline))
