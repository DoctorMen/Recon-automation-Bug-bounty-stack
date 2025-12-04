#!/usr/bin/env python3
"""
Integration Layer for Divergent Thinking Engine with Existing Agentic System
Bridges divergent thinking with the bug bounty automation stack

Copyright (c) 2025 Khallid Hakeem Nurse - All Rights Reserved
Proprietary and Confidential
Owner: Khallid Hakeem Nurse
"""
"""
Copyright (c) 2025 - All Rights Reserved
Proprietary and Confidential

DIVERGENT THINKING SYSTEM™
System ID: DIVERGENT_THINKING_20251105

This software and documentation contains proprietary and confidential information.
Unauthorized copying, modification, distribution, public display, or public performance
is strictly prohibited.

PROTECTED INTELLECTUAL PROPERTY:
1. Divergent thinking algorithms and implementations
2. Seven thinking mode methodologies (lateral, parallel, associative, generative, 
   combinatorial, perspective, constraint-free)
3. Creative path generation patterns
4. Attack vector combination algorithms
5. Integration architecture
6. All source code and documentation

TRADE SECRETS:
- Path prioritization algorithms
- Thinking mode selection logic
- Creative pattern databases
- Success prediction models

For licensing inquiries, contact the copyright holder.

LEGAL NOTICE: This system is protected by copyright law and trade secret law.
Violations may result in severe civil and criminal penalties, including but not limited to:
- Copyright infringement damages
- Trade secret misappropriation claims
- Injunctive relief
- Attorney's fees and costs

VALUE: Estimated at $350,000 - $950,000 over 3 years
"""

import asyncio
import json
from typing import List, Dict, Any, Optional
from pathlib import Path
import logging

from DIVERGENT_THINKING_ENGINE import (
    DivergentThinkingEngine,
    ThinkingMode,
    ExplorationStrategy,
    DivergentPath,
    CreativeSession
)

logger = logging.getLogger(__name__)


class DivergentAgent:
    """
    Specialized agent that uses divergent thinking for bug bounty hunting
    Integrates with existing agentic_core.Agent system
    """
    
    def __init__(self, agent_id: str = "divergent_thinker"):
        self.agent_id = agent_id
        self.name = "Divergent Thinker"
        self.role = "Creative exploration and alternative approach generation"
        self.engine = DivergentThinkingEngine()
        self.active_sessions: Dict[str, CreativeSession] = {}
        
    async def brainstorm_target(
        self,
        target: str,
        goal: str = "Find vulnerabilities",
        modes: Optional[List[ThinkingMode]] = None
    ) -> CreativeSession:
        """
        Brainstorm creative approaches for a target
        Returns session with generated paths
        """
        logger.info(f"[{self.name}] Brainstorming target: {target}")
        
        session = await self.engine.start_divergent_session(
            target=target,
            goal=goal,
            thinking_modes=modes,
            max_paths=20,
            duration=300
        )
        
        self.active_sessions[session.session_id] = session
        return session
    
    def get_prioritized_paths(
        self,
        session_id: str,
        strategy: ExplorationStrategy = ExplorationStrategy.HYBRID,
        limit: int = 10
    ) -> List[DivergentPath]:
        """Get prioritized exploration paths from a session"""
        if session_id not in self.active_sessions:
            logger.error(f"Session {session_id} not found")
            return []
        
        session = self.active_sessions[session_id]
        prioritized = self.engine.prioritize_paths(session.generated_paths, strategy)
        
        return prioritized[:limit]
    
    def convert_paths_to_tasks(
        self,
        paths: List[DivergentPath]
    ) -> List[Dict[str, Any]]:
        """
        Convert divergent paths to executable tasks for main agent system
        Returns task definitions compatible with agentic_core.Task
        """
        tasks = []
        
        for path in paths:
            task = {
                'id': f"task_{path.path_id}",
                'name': path.name,
                'description': path.description,
                'priority': self._map_to_task_priority(path.priority),
                'estimated_duration': 600,  # 10 minutes per path
                'metadata': {
                    'thinking_mode': path.thinking_mode.value,
                    'hypothesis': path.hypothesis,
                    'attack_vectors': path.attack_vectors,
                    'target_areas': path.target_areas,
                    'tools_required': path.tools_required,
                    'creativity_score': path.creativity_score,
                    'feasibility_score': path.feasibility_score,
                    'divergent_path_id': path.path_id
                }
            }
            tasks.append(task)
        
        return tasks
    
    def _map_to_task_priority(self, path_priority: int) -> int:
        """Map path priority to task priority enum value"""
        # path_priority 1-5, TaskPriority.CRITICAL = 5
        return path_priority


class DivergentIntegration:
    """
    Integration manager for divergent thinking with main system
    Coordinates between DivergentAgent and existing agents
    """
    
    def __init__(self, repo_root: Optional[Path] = None):
        self.repo_root = repo_root or Path(__file__).parent
        self.divergent_agent = DivergentAgent()
        self.integration_log: List[Dict[str, Any]] = []
        
    async def generate_creative_workflow(
        self,
        target: str,
        existing_findings: Optional[List[Dict]] = None
    ) -> Dict[str, Any]:
        """
        Generate a creative exploration workflow for a target
        Combines divergent thinking with existing findings
        """
        logger.info(f"Generating creative workflow for: {target}")
        
        # Step 1: Divergent brainstorming
        session = await self.divergent_agent.brainstorm_target(
            target=target,
            goal="Find high-value vulnerabilities",
            modes=[
                ThinkingMode.LATERAL,
                ThinkingMode.PARALLEL,
                ThinkingMode.COMBINATORIAL,
                ThinkingMode.PERSPECTIVE
            ]
        )
        
        # Step 2: Prioritize paths
        top_paths = self.divergent_agent.get_prioritized_paths(
            session.session_id,
            strategy=ExplorationStrategy.HYBRID,
            limit=10
        )
        
        # Step 3: Convert to executable tasks
        tasks = self.divergent_agent.convert_paths_to_tasks(top_paths)
        
        # Step 4: Create workflow
        workflow = {
            'target': target,
            'session_id': session.session_id,
            'total_paths_generated': len(session.generated_paths),
            'total_thoughts_generated': len(session.generated_thoughts),
            'selected_paths': len(top_paths),
            'tasks': tasks,
            'execution_order': [task['id'] for task in tasks],
            'estimated_total_time': sum(task['estimated_duration'] for task in tasks)
        }
        
        # Log integration
        self.integration_log.append({
            'timestamp': session.started_at,
            'target': target,
            'workflow': workflow
        })
        
        logger.info(f"Generated workflow with {len(tasks)} tasks")
        
        return workflow
    
    async def apply_divergent_thinking_to_pipeline(
        self,
        targets_file: str = "targets.txt"
    ) -> List[Dict[str, Any]]:
        """
        Apply divergent thinking to existing pipeline targets
        Returns workflows for each target
        """
        targets_path = self.repo_root / targets_file
        
        if not targets_path.exists():
            logger.error(f"Targets file not found: {targets_path}")
            return []
        
        # Read targets
        with open(targets_path, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        workflows = []
        
        for target in targets[:5]:  # Limit to first 5 for demo
            workflow = await self.generate_creative_workflow(target)
            workflows.append(workflow)
            
            # Small delay between targets
            await asyncio.sleep(1)
        
        return workflows
    
    def export_workflows(self, workflows: List[Dict], output_file: str = "divergent_workflows.json"):
        """Export generated workflows to file"""
        output_path = self.repo_root / output_file
        
        with open(output_path, 'w') as f:
            json.dump(workflows, f, indent=2, default=str)
        
        logger.info(f"Exported workflows to {output_path}")
    
    def generate_agent_commands(self, workflow: Dict[str, Any]) -> List[str]:
        """
        Generate agent orchestrator commands for workflow tasks
        Returns list of commands to execute via agent_orchestrator.py
        """
        commands = []
        
        for task in workflow['tasks']:
            metadata = task['metadata']
            
            # Map thinking modes to agent roles
            if metadata['thinking_mode'] in ['lateral', 'generative', 'constraint']:
                role = "Strategist"
                task_name = "plan"
            elif metadata['thinking_mode'] in ['parallel']:
                role = "Composer 2 — Parallelization & Optimization"
                task_name = "parallel-setup"
            else:
                role = "Executor"
                task_name = "full-run"
            
            cmd = f"python3 scripts/agent_orchestrator.py --role \"{role}\" --task {task_name}"
            commands.append(cmd)
        
        return commands


async def demo_integration():
    """Demonstrate the integration"""
    
    integration = DivergentIntegration()
    
    # Generate workflow for a target
    workflow = await integration.generate_creative_workflow(
        target="example.com",
        existing_findings=None
    )
    
    print("\n" + "="*80)
    print("DIVERGENT THINKING INTEGRATION DEMO")
    print("="*80)
    print(f"\nTarget: {workflow['target']}")
    print(f"Paths Generated: {workflow['total_paths_generated']}")
    print(f"Creative Thoughts: {workflow['total_thoughts_generated']}")
    print(f"Selected for Execution: {workflow['selected_paths']}")
    print(f"Estimated Time: {workflow['estimated_total_time']} seconds")
    
    print("\n" + "-"*80)
    print("EXECUTABLE TASKS:")
    print("-"*80)
    
    for i, task in enumerate(workflow['tasks'][:5], 1):
        print(f"\n{i}. {task['name']}")
        print(f"   Hypothesis: {task['metadata']['hypothesis']}")
        print(f"   Attack Vectors: {', '.join(task['metadata']['attack_vectors'][:3])}")
        print(f"   Tools: {', '.join(task['metadata']['tools_required'])}")
        print(f"   Creativity: {task['metadata']['creativity_score']:.2f} | Feasibility: {task['metadata']['feasibility_score']:.2f}")
    
    # Generate agent commands
    commands = integration.generate_agent_commands(workflow)
    
    print("\n" + "-"*80)
    print("AGENT ORCHESTRATOR COMMANDS:")
    print("-"*80)
    for cmd in commands[:5]:
        print(f"  {cmd}")
    
    # Export
    integration.export_workflows([workflow], "divergent_workflow_demo.json")
    
    print("\n" + "="*80)
    print("Workflow exported to divergent_workflow_demo.json")
    print("="*80 + "\n")


if __name__ == "__main__":
    asyncio.run(demo_integration())
