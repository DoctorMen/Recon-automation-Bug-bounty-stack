"""
Agent Orchestrator - Multi-Agent Workflow Coordination
Copyright © 2025. All Rights Reserved.

Coordinates multiple AI agents for complex workflow automation
"""

import asyncio
import json
import uuid
from datetime import datetime
from enum import Enum
from typing import Dict, List, Any, Optional

from agents.strategist import StrategistAgent
from agents.executor import ExecutorAgent
from agents.composers.automation_engineer import AutomationEngineer
from agents.composers.parallelization_expert import ParallelizationExpert
from agents.composers.documentation_specialist import DocumentationSpecialist
from agents.composers.cicd_operations import CICDOperations
from agents.divergent_thinker import DivergentThinker
from utils.prompt_templates import PromptTemplates

class AgentRole(Enum):
    """Define agent roles in the workflow"""
    STRATEGIST = "strategist"
    EXECUTOR = "executor"
    AUTOMATION_ENGINEER = "automation_engineer"
    PARALLELIZATION_EXPERT = "parallelization_expert"
    DOCUMENTATION_SPECIALIST = "documentation_specialist"
    CICD_OPERATIONS = "cicd_operations"
    DIVERGENT_THINKER = "divergent_thinker"

class WorkflowStep:
    """Represents a single step in a workflow"""
    def __init__(self, step_id: str, agent_role: AgentRole, prompt: str, 
                 dependencies: List[str] = None, context: Dict = None):
        self.step_id = step_id
        self.agent_role = agent_role
        self.prompt = prompt
        self.dependencies = dependencies or []
        self.context = context or {}
        self.status = "pending"
        self.result = None
        self.error = None
        self.created_at = datetime.now()
        self.completed_at = None

class AgentOrchestrator:
    """
    Orchestrates multiple AI agents to execute complex workflows
    """
    
    def __init__(self):
        self.workflow_id = None
        self.steps: List[WorkflowStep] = []
        self.agents = {}
        self.prompt_templates = PromptTemplates()
        self.execution_log = []
        
    async def initialize(self):
        """Initialize all agents"""
        print("🤖 Initializing Agent Orchestrator...")
        
        # Initialize core agents
        self.agents = {
            AgentRole.STRATEGIST: StrategistAgent(),
            AgentRole.EXECUTOR: ExecutorAgent(),
            AgentRole.AUTOMATION_ENGINEER: AutomationEngineer(),
            AgentRole.PARALLELIZATION_EXPERT: ParallelizationExpert(),
            AgentRole.DOCUMENTATION_SPECIALIST: DocumentationSpecialist(),
            AgentRole.CICD_OPERATIONS: CICDOperations(),
            AgentRole.DIVERGENT_THINKER: DivergentThinker()
        }
        
        # Initialize each agent
        for role, agent in self.agents.items():
            await agent.initialize()
            print(f"  ✅ {role.value} agent ready")
            
    async def create_workflow(self, command: str, context: Dict = None) -> str:
        """
        Create a workflow from natural language command
        
        Args:
            command: Natural language description of desired workflow
            context: Additional context for workflow creation
            
        Returns:
            Workflow ID for tracking
        """
        self.workflow_id = str(uuid.uuid4())
        
        # Use Strategist agent to plan workflow
        strategist = self.agents[AgentRole.STRATEGIST]
        
        planning_prompt = self.prompt_templates.get_workflow_planning_prompt(
            command, context
        )
        
        workflow_plan = await strategist.execute(planning_prompt)
        
        # Convert plan to workflow steps
        self.steps = self._parse_workflow_plan(workflow_plan)
        
        self.execution_log.append({
            'timestamp': datetime.now().isoformat(),
            'action': 'workflow_created',
            'workflow_id': self.workflow_id,
            'steps_count': len(self.steps)
        })
        
        return self.workflow_id
    
    async def execute_workflow(self, workflow_plan: Dict = None) -> Dict:
        """
        Execute the complete workflow
        
        Args:
            workflow_plan: Pre-computed workflow plan (optional)
            
        Returns:
            Execution results with metrics
        """
        if workflow_plan:
            self.workflow_id = str(uuid.uuid4())
            self.steps = self._parse_workflow_plan(workflow_plan)
        
        if not self.steps:
            raise ValueError("No workflow steps to execute")
        
        print(f"🚀 Executing workflow {self.workflow_id} with {len(self.steps)} steps")
        
        completed_tasks = []
        failed_tasks = []
        
        # Execute steps in dependency order
        for step in self._get_execution_order():
            try:
                # Check dependencies
                if not self._check_dependencies(step):
                    continue
                
                print(f"  📋 Executing step: {step.step_id} ({step.agent_role.value})")
                
                # Get appropriate agent
                agent = self.agents[step.agent_role]
                
                # Execute step
                result = await agent.execute(step.prompt, step.context)
                
                step.status = "completed"
                step.result = result
                step.completed_at = datetime.now()
                
                completed_tasks.append({
                    'step_id': step.step_id,
                    'agent': step.agent_role.value,
                    'result': result,
                    'completed_at': step.completed_at.isoformat()
                })
                
                print(f"    ✅ Step completed")
                
            except Exception as e:
                step.status = "failed"
                step.error = str(e)
                
                failed_tasks.append({
                    'step_id': step.step_id,
                    'agent': step.agent_role.value,
                    'error': str(e)
                })
                
                print(f"    ❌ Step failed: {str(e)}")
        
        # Calculate success metrics
        total_steps = len(self.steps)
        success_rate = (len(completed_tasks) / total_steps) * 100 if total_steps > 0 else 0
        
        # Calculate cost savings (example calculation)
        cost_savings = self._calculate_cost_savings(completed_tasks)
        
        results = {
            'workflow_id': self.workflow_id,
            'status': 'completed' if success_rate > 80 else 'partial',
            'completed_tasks': completed_tasks,
            'failed_tasks': failed_tasks,
            'success_rate': success_rate,
            'cost_savings': cost_savings,
            'execution_time': self._calculate_execution_time(),
            'timestamp': datetime.now().isoformat()
        }
        
        self.execution_log.append({
            'timestamp': datetime.now().isoformat(),
            'action': 'workflow_completed',
            'workflow_id': self.workflow_id,
            'results': results
        })
        
        return results
    
    def _parse_workflow_plan(self, plan: Dict) -> List[WorkflowStep]:
        """Parse workflow plan into executable steps"""
        steps = []
        
        # Example parsing logic - adapt based on your plan structure
        for i, step_data in enumerate(plan.get('steps', [])):
            step = WorkflowStep(
                step_id=step_data.get('id', f'step_{i}'),
                agent_role=AgentRole(step_data.get('agent', 'executor')),
                prompt=step_data.get('prompt', ''),
                dependencies=step_data.get('dependencies', []),
                context=step_data.get('context', {})
            )
            steps.append(step)
        
        return steps
    
    def _get_execution_order(self) -> List[WorkflowStep]:
        """Get steps in dependency-respected execution order"""
        # Simple topological sort for dependencies
        ordered = []
        remaining = self.steps.copy()
        
        while remaining:
            # Find steps with no unmet dependencies
            ready = [
                step for step in remaining
                if all(dep in [s.step_id for s in ordered] for dep in step.dependencies)
            ]
            
            if not ready:
                # Circular dependency or missing dependency
                break
            
            ordered.extend(ready)
            for step in ready:
                remaining.remove(step)
        
        return ordered
    
    def _check_dependencies(self, step: WorkflowStep) -> bool:
        """Check if all dependencies for a step are completed"""
        for dep_id in step.dependencies:
            dep_step = next((s for s in self.steps if s.step_id == dep_id), None)
            if not dep_step or dep_step.status != "completed":
                return False
        return True
    
    def _calculate_cost_savings(self, completed_tasks: List[Dict]) -> float:
        """Calculate estimated cost savings from automation"""
        # Example: $50/hour saved per automated task
        hourly_rate = 50
        hours_saved_per_task = 2  # Average hours saved per automated task
        
        return len(completed_tasks) * hourly_rate * hours_saved_per_task
    
    def _calculate_execution_time(self) -> float:
        """Calculate total workflow execution time in minutes"""
        if not self.steps:
            return 0
        
        start_time = min(step.created_at for step in self.steps)
        end_time = max(
            step.completed_at for step in self.steps 
            if step.completed_at
        ) or datetime.now()
        
        return (end_time - start_time).total_seconds() / 60
    
    async def get_agent_status(self) -> Dict:
        """Get status of all agents"""
        return {
            role.value: {
                'status': 'active' if agent else 'inactive',
                'capabilities': agent.get_capabilities() if agent else []
            }
            for role, agent in self.agents.items()
        }
    
    async def shutdown(self):
        """Shutdown all agents"""
        print("🛑 Shutting down Agent Orchestrator...")
        
        for agent in self.agents.values():
            if hasattr(agent, 'shutdown'):
                await agent.shutdown()
        
        print("  ✅ All agents shutdown complete")
