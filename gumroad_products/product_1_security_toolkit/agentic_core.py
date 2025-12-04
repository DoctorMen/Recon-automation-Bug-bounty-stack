#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Advanced Agentic Loop System
Production-grade multi-agent orchestration with self-improvement capabilities
"""

import asyncio
import json
import time
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Callable, Set
from enum import Enum
from pathlib import Path
from datetime import datetime
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class AgentState(Enum):
    """Agent execution states"""
    IDLE = "idle"
    PLANNING = "planning"
    EXECUTING = "executing"
    LEARNING = "learning"
    BLOCKED = "blocked"
    FAILED = "failed"
    COMPLETED = "completed"


class TaskPriority(Enum):
    """Task priority levels"""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    BACKGROUND = 1


@dataclass
class Task:
    """Represents a task in the agentic system"""
    id: str
    name: str
    description: str
    priority: TaskPriority
    dependencies: List[str] = field(default_factory=list)
    estimated_duration: int = 60  # seconds
    max_retries: int = 3
    retry_count: int = 0
    state: str = "pending"
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    assigned_agent: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['priority'] = self.priority.value
        return data


@dataclass
class AgentCapability:
    """Agent capability definition"""
    name: str
    description: str
    execution_func: Callable
    required_resources: List[str] = field(default_factory=list)
    estimated_cost: float = 1.0  # Relative cost metric


@dataclass
class AgentPerformance:
    """Track agent performance metrics"""
    tasks_completed: int = 0
    tasks_failed: int = 0
    total_execution_time: float = 0.0
    average_success_rate: float = 1.0
    expertise_scores: Dict[str, float] = field(default_factory=dict)
    last_updated: float = field(default_factory=time.time)

    def update_success_rate(self):
        """Recalculate success rate"""
        total = self.tasks_completed + self.tasks_failed
        if total > 0:
            self.average_success_rate = self.tasks_completed / total


class Agent:
    """
    Autonomous agent with learning capabilities
    """
    
    def __init__(
        self,
        agent_id: str,
        name: str,
        role: str,
        capabilities: List[AgentCapability]
    ):
        self.agent_id = agent_id
        self.name = name
        self.role = role
        self.capabilities = {cap.name: cap for cap in capabilities}
        self.state = AgentState.IDLE
        self.current_task: Optional[Task] = None
        self.performance = AgentPerformance()
        self.knowledge_base: Dict[str, Any] = {}
        self.communication_queue: asyncio.Queue = asyncio.Queue()
        
    async def execute_task(self, task: Task) -> Dict[str, Any]:
        """Execute a task with error handling and learning"""
        logger.info(f"[{self.name}] Starting task: {task.name}")
        
        self.state = AgentState.EXECUTING
        self.current_task = task
        task.assigned_agent = self.agent_id
        task.started_at = time.time()
        
        try:
            # Find appropriate capability
            capability = self._select_capability(task)
            
            if not capability:
                raise ValueError(f"No capability found for task: {task.name}")
            
            # Execute with timeout
            result = await asyncio.wait_for(
                capability.execution_func(task),
                timeout=task.estimated_duration * 2
            )
            
            # Update performance
            execution_time = time.time() - task.started_at
            self.performance.tasks_completed += 1
            self.performance.total_execution_time += execution_time
            self.performance.update_success_rate()
            
            # Learn from success
            await self._learn_from_success(task, result)
            
            task.state = "completed"
            task.result = result
            task.completed_at = time.time()
            
            logger.info(f"[{self.name}] Completed task: {task.name} in {execution_time:.2f}s")
            
            self.state = AgentState.IDLE
            self.current_task = None
            
            return result
            
        except asyncio.TimeoutError:
            logger.error(f"[{self.name}] Task timeout: {task.name}")
            return await self._handle_failure(task, "Execution timeout")
            
        except Exception as e:
            logger.error(f"[{self.name}] Task failed: {task.name} - {str(e)}")
            return await self._handle_failure(task, str(e))
    
    def _select_capability(self, task: Task) -> Optional[AgentCapability]:
        """Select best capability for task using learned preferences"""
        # Try exact match first
        if task.name in self.capabilities:
            return self.capabilities[task.name]
        
        # Use expertise scores for fuzzy matching
        best_match = None
        best_score = 0.0
        
        for cap_name, capability in self.capabilities.items():
            score = self.performance.expertise_scores.get(cap_name, 0.5)
            if score > best_score:
                best_score = score
                best_match = capability
        
        return best_match
    
    async def _learn_from_success(self, task: Task, result: Dict[str, Any]):
        """Update knowledge base from successful execution"""
        capability_name = task.metadata.get('capability_used', 'unknown')
        
        # Increase expertise score
        current_score = self.performance.expertise_scores.get(capability_name, 0.5)
        self.performance.expertise_scores[capability_name] = min(1.0, current_score + 0.1)
        
        # Store successful patterns
        pattern_key = f"{task.name}_{task.priority.name}"
        self.knowledge_base[pattern_key] = {
            'success': True,
            'execution_time': time.time() - task.started_at,
            'result_size': len(str(result)),
            'timestamp': time.time()
        }
    
    async def _handle_failure(self, task: Task, error: str) -> Dict[str, Any]:
        """Handle task failure with retry logic"""
        self.performance.tasks_failed += 1
        self.performance.update_success_rate()
        
        task.error = error
        task.retry_count += 1
        
        if task.retry_count < task.max_retries:
            logger.warning(f"[{self.name}] Retrying task: {task.name} (attempt {task.retry_count})")
            task.state = "pending"
        else:
            logger.error(f"[{self.name}] Task permanently failed: {task.name}")
            task.state = "failed"
        
        self.state = AgentState.IDLE
        self.current_task = None
        
        return {'success': False, 'error': error}
    
    async def send_message(self, target_agent_id: str, message: Dict[str, Any]):
        """Send message to another agent"""
        message['from'] = self.agent_id
        message['to'] = target_agent_id
        message['timestamp'] = time.time()
        await self.communication_queue.put(message)
    
    async def receive_messages(self) -> List[Dict[str, Any]]:
        """Receive pending messages"""
        messages = []
        while not self.communication_queue.empty():
            messages.append(await self.communication_queue.get())
        return messages


class AgenticOrchestrator:
    """
    Master orchestrator for multi-agent system
    Handles task distribution, agent coordination, and system-level learning
    """
    
    def __init__(self, state_file: str = "agentic_state.json"):
        self.agents: Dict[str, Agent] = {}
        self.task_queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self.completed_tasks: List[Task] = []
        self.failed_tasks: List[Task] = []
        self.state_file = Path(state_file)
        self.running = False
        self.system_metrics = {
            'total_tasks': 0,
            'completed_tasks': 0,
            'failed_tasks': 0,
            'total_execution_time': 0.0,
            'agent_utilization': {}
        }
        
    def register_agent(self, agent: Agent):
        """Register an agent with the orchestrator"""
        self.agents[agent.agent_id] = agent
        self.system_metrics['agent_utilization'][agent.agent_id] = 0.0
        logger.info(f"Registered agent: {agent.name} ({agent.role})")
    
    async def submit_task(self, task: Task):
        """Submit a task to the orchestration queue"""
        self.system_metrics['total_tasks'] += 1
        
        # Priority queue: lower number = higher priority
        priority_value = -task.priority.value  # Negative for max-heap behavior
        await self.task_queue.put((priority_value, task.id, task))
        
        logger.info(f"Task submitted: {task.name} (Priority: {task.priority.name})")
    
    async def submit_batch(self, tasks: List[Task]):
        """Submit multiple tasks"""
        for task in tasks:
            await self.submit_task(task)
    
    def _select_agent_for_task(self, task: Task) -> Optional[Agent]:
        """
        Intelligent agent selection based on:
        - Agent capabilities
        - Current load
        - Performance history
        - Task requirements
        """
        available_agents = [
            agent for agent in self.agents.values()
            if agent.state == AgentState.IDLE
        ]
        
        if not available_agents:
            return None
        
        # Score each agent
        agent_scores = []
        for agent in available_agents:
            score = self._calculate_agent_score(agent, task)
            agent_scores.append((score, agent))
        
        # Select highest scoring agent
        agent_scores.sort(reverse=True, key=lambda x: x[0])
        return agent_scores[0][1] if agent_scores else None
    
    def _calculate_agent_score(self, agent: Agent, task: Task) -> float:
        """Calculate agent suitability score for task"""
        score = 0.0
        
        # Performance factor (higher is better)
        score += agent.performance.average_success_rate * 10
        
        # Capability match
        has_capability = any(
            cap_name in task.name or task.name in cap_name
            for cap_name in agent.capabilities.keys()
        )
        score += 5 if has_capability else 0
        
        # Expertise in similar tasks
        similar_tasks = sum(
            1 for key in agent.knowledge_base.keys()
            if task.name in key or any(word in key for word in task.name.split('_'))
        )
        score += min(similar_tasks, 5)
        
        # Penalize recent failures
        if agent.performance.tasks_failed > 0:
            failure_penalty = agent.performance.tasks_failed / max(agent.performance.tasks_completed, 1)
            score -= failure_penalty * 2
        
        return score
    
    async def _execute_task_with_agent(self, agent: Agent, task: Task):
        """Execute task and track metrics"""
        start_time = time.time()
        
        try:
            result = await agent.execute_task(task)
            
            execution_time = time.time() - start_time
            self.system_metrics['total_execution_time'] += execution_time
            
            if task.state == "completed":
                self.completed_tasks.append(task)
                self.system_metrics['completed_tasks'] += 1
            else:
                self.failed_tasks.append(task)
                self.system_metrics['failed_tasks'] += 1
                
        except Exception as e:
            logger.error(f"Orchestrator error executing task {task.name}: {e}")
            task.state = "failed"
            task.error = str(e)
            self.failed_tasks.append(task)
    
    async def run(self, max_concurrent_tasks: int = 10):
        """
        Main orchestration loop
        Continuously assigns tasks to agents and monitors execution
        """
        self.running = True
        logger.info(f"Agentic orchestrator started with {len(self.agents)} agents")
        
        active_tasks: Set[asyncio.Task] = set()
        
        try:
            while self.running or not self.task_queue.empty() or active_tasks:
                # Clean up completed tasks
                done_tasks = {task for task in active_tasks if task.done()}
                active_tasks -= done_tasks
                
                # Assign new tasks if capacity available
                while len(active_tasks) < max_concurrent_tasks and not self.task_queue.empty():
                    try:
                        _, task_id, task = await asyncio.wait_for(
                            self.task_queue.get(),
                            timeout=0.1
                        )
                        
                        # Check dependencies
                        if not self._dependencies_satisfied(task):
                            # Re-queue with lower priority
                            await self.task_queue.put((-task.priority.value + 1, task.id, task))
                            continue
                        
                        # Select agent
                        agent = self._select_agent_for_task(task)
                        
                        if agent:
                            # Create task execution coroutine
                            task_coro = self._execute_task_with_agent(agent, task)
                            active_tasks.add(asyncio.create_task(task_coro))
                        else:
                            # No agent available, re-queue
                            await self.task_queue.put((-task.priority.value, task.id, task))
                            await asyncio.sleep(0.1)
                            
                    except asyncio.TimeoutError:
                        break
                
                # Brief sleep to prevent busy loop
                await asyncio.sleep(0.1)
                
                # Periodic state save
                if int(time.time()) % 30 == 0:
                    await self.save_state()
                    
        except KeyboardInterrupt:
            logger.info("Orchestrator shutdown requested")
        finally:
            self.running = False
            await self.save_state()
            logger.info("Orchestrator stopped")
    
    def _dependencies_satisfied(self, task: Task) -> bool:
        """Check if all task dependencies are completed"""
        if not task.dependencies:
            return True
        
        completed_ids = {t.id for t in self.completed_tasks}
        return all(dep_id in completed_ids for dep_id in task.dependencies)
    
    async def save_state(self):
        """Save orchestrator state to disk"""
        state = {
            'metrics': self.system_metrics,
            'completed_tasks': [t.to_dict() for t in self.completed_tasks[-100:]],
            'failed_tasks': [t.to_dict() for t in self.failed_tasks[-50:]],
            'agent_performance': {
                agent_id: {
                    'tasks_completed': agent.performance.tasks_completed,
                    'tasks_failed': agent.performance.tasks_failed,
                    'success_rate': agent.performance.average_success_rate,
                    'expertise_scores': agent.performance.expertise_scores
                }
                for agent_id, agent in self.agents.items()
            },
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            with open(self.state_file, 'w') as f:
                json.dump(state, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save state: {e}")
    
    async def load_state(self):
        """Load orchestrator state from disk"""
        if not self.state_file.exists():
            return
        
        try:
            with open(self.state_file, 'r') as f:
                state = json.load(f)
            
            self.system_metrics = state.get('metrics', self.system_metrics)
            
            # Restore agent performance
            agent_perf = state.get('agent_performance', {})
            for agent_id, perf_data in agent_perf.items():
                if agent_id in self.agents:
                    agent = self.agents[agent_id]
                    agent.performance.tasks_completed = perf_data.get('tasks_completed', 0)
                    agent.performance.tasks_failed = perf_data.get('tasks_failed', 0)
                    agent.performance.average_success_rate = perf_data.get('success_rate', 1.0)
                    agent.performance.expertise_scores = perf_data.get('expertise_scores', {})
            
            logger.info("State loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load state: {e}")
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get current system status"""
        return {
            'total_agents': len(self.agents),
            'active_agents': sum(1 for a in self.agents.values() if a.state == AgentState.EXECUTING),
            'idle_agents': sum(1 for a in self.agents.values() if a.state == AgentState.IDLE),
            'queue_size': self.task_queue.qsize(),
            'metrics': self.system_metrics,
            'agents': {
                agent_id: {
                    'name': agent.name,
                    'state': agent.state.value,
                    'current_task': agent.current_task.name if agent.current_task else None,
                    'performance': {
                        'completed': agent.performance.tasks_completed,
                        'failed': agent.performance.tasks_failed,
                        'success_rate': f"{agent.performance.average_success_rate * 100:.1f}%"
                    }
                }
                for agent_id, agent in self.agents.items()
            }
        }
    
    async def stop(self):
        """Graceful shutdown"""
        logger.info("Stopping orchestrator...")
        self.running = False
        await self.save_state()


# Example usage and testing
if __name__ == "__main__":
    async def example_task_func(task: Task) -> Dict[str, Any]:
        """Example task execution function"""
        await asyncio.sleep(0.5)  # Simulate work
        return {'status': 'success', 'data': f"Completed {task.name}"}
    
    async def main():
        # Create orchestrator
        orchestrator = AgenticOrchestrator()
        
        # Create agents with capabilities
        recon_caps = [
            AgentCapability("subdomain_enum", "Find subdomains", example_task_func),
            AgentCapability("port_scan", "Scan ports", example_task_func),
        ]
        
        vuln_caps = [
            AgentCapability("nuclei_scan", "Run Nuclei", example_task_func),
            AgentCapability("xss_detect", "Detect XSS", example_task_func),
        ]
        
        recon_agent = Agent("agent_1", "Recon Specialist", "reconnaissance", recon_caps)
        vuln_agent = Agent("agent_2", "Vuln Hunter", "vulnerability_scanning", vuln_caps)
        
        orchestrator.register_agent(recon_agent)
        orchestrator.register_agent(vuln_agent)
        
        # Create sample tasks
        tasks = [
            Task("task_1", "subdomain_enum", "Find subdomains for target", TaskPriority.HIGH),
            Task("task_2", "port_scan", "Scan open ports", TaskPriority.MEDIUM, dependencies=["task_1"]),
            Task("task_3", "nuclei_scan", "Run vulnerability scan", TaskPriority.CRITICAL, dependencies=["task_2"]),
        ]
        
        # Submit tasks
        await orchestrator.submit_batch(tasks)
        
        # Run orchestrator for 10 seconds
        run_task = asyncio.create_task(orchestrator.run(max_concurrent_tasks=5))
        await asyncio.sleep(10)
        await orchestrator.stop()
        await run_task
        
        # Print status
        status = orchestrator.get_system_status()
        print(json.dumps(status, indent=2))
    
    asyncio.run(main())
