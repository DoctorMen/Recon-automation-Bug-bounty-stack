#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Distributed Agent Execution System
Enable agents to run across multiple machines for massive scale
"""

import asyncio
import json
import hashlib
from typing import Dict, Any, List, Set, Optional
from dataclasses import dataclass, field
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


@dataclass
class Node:
    """Represents a compute node in distributed system"""
    node_id: str
    hostname: str
    port: int
    capacity: int = 10  # Max concurrent tasks
    current_load: int = 0
    capabilities: Set[str] = field(default_factory=set)
    status: str = "online"  # online, offline, maintenance
    last_heartbeat: float = 0.0


@dataclass
class DistributedTask:
    """Task that can be distributed across nodes"""
    task_id: str
    payload: Dict[str, Any]
    required_capabilities: Set[str] = field(default_factory=set)
    assigned_node: Optional[str] = None
    priority: int = 5
    retry_count: int = 0
    max_retries: int = 3


class ConsistentHashRing:
    """
    Consistent hashing for task distribution
    Ensures tasks are evenly distributed and minimize reshuffling when nodes change
    """
    
    def __init__(self, virtual_nodes: int = 150):
        self.virtual_nodes = virtual_nodes
        self.ring: Dict[int, str] = {}
        self.nodes: Set[str] = set()
        
    def _hash(self, key: str) -> int:
        """Hash function for ring positions"""
        return int(hashlib.md5(key.encode()).hexdigest(), 16)
    
    def add_node(self, node_id: str):
        """Add node to hash ring"""
        self.nodes.add(node_id)
        
        # Add virtual nodes
        for i in range(self.virtual_nodes):
            virtual_key = f"{node_id}:{i}"
            hash_val = self._hash(virtual_key)
            self.ring[hash_val] = node_id
    
    def remove_node(self, node_id: str):
        """Remove node from hash ring"""
        self.nodes.discard(node_id)
        
        # Remove virtual nodes
        keys_to_remove = [k for k, v in self.ring.items() if v == node_id]
        for key in keys_to_remove:
            del self.ring[key]
    
    def get_node(self, task_id: str) -> Optional[str]:
        """Get node for task using consistent hashing"""
        if not self.ring:
            return None
        
        task_hash = self._hash(task_id)
        
        # Find first node in ring >= task_hash
        sorted_hashes = sorted(self.ring.keys())
        
        for ring_hash in sorted_hashes:
            if ring_hash >= task_hash:
                return self.ring[ring_hash]
        
        # Wrap around to first node
        return self.ring[sorted_hashes[0]]


class DistributedQueue:
    """
    Distributed task queue with partitioning
    """
    
    def __init__(self, num_partitions: int = 16):
        self.num_partitions = num_partitions
        self.partitions: List[asyncio.Queue] = [
            asyncio.Queue() for _ in range(num_partitions)
        ]
    
    def _get_partition(self, task_id: str) -> int:
        """Get partition number for task"""
        hash_val = int(hashlib.md5(task_id.encode()).hexdigest(), 16)
        return hash_val % self.num_partitions
    
    async def put(self, task: DistributedTask):
        """Add task to appropriate partition"""
        partition = self._get_partition(task.task_id)
        await self.partitions[partition].put(task)
    
    async def get(self, partition: int) -> DistributedTask:
        """Get task from specific partition"""
        return await self.partitions[partition].get()
    
    def qsize(self) -> int:
        """Total size across all partitions"""
        return sum(q.qsize() for q in self.partitions)


class NodeManager:
    """
    Manage distributed nodes
    """
    
    def __init__(self):
        self.nodes: Dict[str, Node] = {}
        self.hash_ring = ConsistentHashRing()
        
    def register_node(self, node: Node):
        """Register a new node"""
        self.nodes[node.node_id] = node
        self.hash_ring.add_node(node.node_id)
        logger.info(f"Registered node: {node.node_id} at {node.hostname}:{node.port}")
    
    def unregister_node(self, node_id: str):
        """Unregister a node"""
        if node_id in self.nodes:
            del self.nodes[node_id]
            self.hash_ring.remove_node(node_id)
            logger.info(f"Unregistered node: {node_id}")
    
    def get_node_for_task(self, task: DistributedTask) -> Optional[Node]:
        """Select best node for task"""
        
        # Filter nodes by capabilities
        capable_nodes = [
            node for node in self.nodes.values()
            if (not task.required_capabilities or 
                task.required_capabilities.issubset(node.capabilities))
            and node.status == "online"
        ]
        
        if not capable_nodes:
            return None
        
        # Use consistent hashing first
        hash_node_id = self.hash_ring.get_node(task.task_id)
        if hash_node_id and hash_node_id in [n.node_id for n in capable_nodes]:
            hash_node = self.nodes[hash_node_id]
            if hash_node.current_load < hash_node.capacity:
                return hash_node
        
        # Fall back to least loaded node
        capable_nodes.sort(key=lambda n: n.current_load / n.capacity)
        
        for node in capable_nodes:
            if node.current_load < node.capacity:
                return node
        
        return None
    
    def update_node_load(self, node_id: str, delta: int):
        """Update node load"""
        if node_id in self.nodes:
            self.nodes[node_id].current_load += delta
            self.nodes[node_id].current_load = max(0, self.nodes[node_id].current_load)
    
    def get_cluster_stats(self) -> Dict[str, Any]:
        """Get cluster statistics"""
        total_capacity = sum(n.capacity for n in self.nodes.values())
        total_load = sum(n.current_load for n in self.nodes.values())
        
        return {
            'total_nodes': len(self.nodes),
            'online_nodes': sum(1 for n in self.nodes.values() if n.status == "online"),
            'total_capacity': total_capacity,
            'current_load': total_load,
            'utilization': total_load / total_capacity if total_capacity > 0 else 0
        }


class WorkStealing:
    """
    Work stealing for load balancing
    Idle nodes can steal work from busy nodes
    """
    
    def __init__(self, node_manager: NodeManager):
        self.node_manager = node_manager
        self.steal_threshold = 0.8  # Steal if node > 80% loaded
        
    def should_steal_work(self, from_node_id: str, to_node_id: str) -> bool:
        """Determine if work stealing should occur"""
        from_node = self.node_manager.nodes.get(from_node_id)
        to_node = self.node_manager.nodes.get(to_node_id)
        
        if not from_node or not to_node:
            return False
        
        from_util = from_node.current_load / from_node.capacity
        to_util = to_node.current_load / to_node.capacity
        
        # Steal if source is heavily loaded and destination is lightly loaded
        return from_util > self.steal_threshold and to_util < 0.3
    
    def find_steal_target(self, idle_node_id: str) -> Optional[str]:
        """Find node to steal work from"""
        idle_node = self.node_manager.nodes.get(idle_node_id)
        if not idle_node:
            return None
        
        # Find heavily loaded nodes
        candidates = [
            node for node in self.node_manager.nodes.values()
            if node.node_id != idle_node_id
            and (node.current_load / node.capacity) > self.steal_threshold
        ]
        
        if not candidates:
            return None
        
        # Steal from most loaded node
        candidates.sort(key=lambda n: n.current_load / n.capacity, reverse=True)
        return candidates[0].node_id


class DistributedOrchestrator:
    """
    Orchestrator for distributed agent execution
    """
    
    def __init__(self):
        self.node_manager = NodeManager()
        self.task_queue = DistributedQueue(num_partitions=16)
        self.work_stealing = WorkStealing(self.node_manager)
        self.running_tasks: Dict[str, DistributedTask] = {}
        self.completed_tasks: List[DistributedTask] = []
        
    async def submit_task(self, task: DistributedTask):
        """Submit task for distributed execution"""
        await self.task_queue.put(task)
        logger.info(f"Submitted task {task.task_id} to distributed queue")
    
    async def distribute_tasks(self):
        """Main distribution loop"""
        while True:
            # Process each partition
            for partition_idx in range(self.task_queue.num_partitions):
                if not self.task_queue.partitions[partition_idx].empty():
                    try:
                        task = await asyncio.wait_for(
                            self.task_queue.get(partition_idx),
                            timeout=0.1
                        )
                        
                        # Find suitable node
                        node = self.node_manager.get_node_for_task(task)
                        
                        if node:
                            # Assign task to node
                            task.assigned_node = node.node_id
                            self.running_tasks[task.task_id] = task
                            self.node_manager.update_node_load(node.node_id, 1)
                            
                            # Would send task to node here
                            logger.info(f"Assigned task {task.task_id} to node {node.node_id}")
                            
                            # Simulate task execution
                            asyncio.create_task(self._execute_remote_task(task, node))
                        else:
                            # No suitable node, requeue
                            await self.task_queue.put(task)
                            
                    except asyncio.TimeoutError:
                        pass
            
            # Check for work stealing opportunities
            await self._attempt_work_stealing()
            
            await asyncio.sleep(0.1)
    
    async def _execute_remote_task(self, task: DistributedTask, node: Node):
        """Simulate remote task execution"""
        try:
            # Simulate work
            await asyncio.sleep(1.0)
            
            # Mark complete
            if task.task_id in self.running_tasks:
                del self.running_tasks[task.task_id]
            
            self.completed_tasks.append(task)
            self.node_manager.update_node_load(node.node_id, -1)
            
            logger.info(f"Completed task {task.task_id} on node {node.node_id}")
            
        except Exception as e:
            logger.error(f"Task {task.task_id} failed: {e}")
            
            # Retry logic
            if task.retry_count < task.max_retries:
                task.retry_count += 1
                task.assigned_node = None
                await self.task_queue.put(task)
    
    async def _attempt_work_stealing(self):
        """Attempt work stealing for load balancing"""
        for node_id, node in self.node_manager.nodes.items():
            if node.current_load == 0:
                # Idle node, try to steal work
                steal_from = self.work_stealing.find_steal_target(node_id)
                if steal_from:
                    logger.info(f"Work stealing: {node_id} stealing from {steal_from}")
                    # Would implement actual work transfer here
    
    def get_distribution_stats(self) -> Dict[str, Any]:
        """Get distribution statistics"""
        return {
            'cluster': self.node_manager.get_cluster_stats(),
            'queue_size': self.task_queue.qsize(),
            'running_tasks': len(self.running_tasks),
            'completed_tasks': len(self.completed_tasks),
            'tasks_per_node': {
                node_id: sum(1 for t in self.running_tasks.values() if t.assigned_node == node_id)
                for node_id in self.node_manager.nodes.keys()
            }
        }


class FaultTolerance:
    """
    Fault tolerance mechanisms for distributed system
    """
    
    def __init__(self, orchestrator: DistributedOrchestrator):
        self.orchestrator = orchestrator
        self.node_failures: Dict[str, int] = {}
        self.checkpoint_interval = 60  # seconds
        
    async def monitor_node_health(self):
        """Monitor node health and handle failures"""
        while True:
            for node_id, node in list(self.orchestrator.node_manager.nodes.items()):
                # Check heartbeat (would be actual network check in production)
                import time
                if time.time() - node.last_heartbeat > 30:
                    logger.warning(f"Node {node_id} appears unhealthy")
                    await self._handle_node_failure(node_id)
            
            await asyncio.sleep(10)
    
    async def _handle_node_failure(self, node_id: str):
        """Handle node failure"""
        logger.error(f"Handling failure of node {node_id}")
        
        # Count failure
        self.node_failures[node_id] = self.node_failures.get(node_id, 0) + 1
        
        # Reschedule tasks from failed node
        failed_tasks = [
            task for task in self.orchestrator.running_tasks.values()
            if task.assigned_node == node_id
        ]
        
        for task in failed_tasks:
            task.assigned_node = None
            task.retry_count += 1
            
            if task.retry_count < task.max_retries:
                await self.orchestrator.task_queue.put(task)
            else:
                logger.error(f"Task {task.task_id} exceeded max retries")
        
        # Mark node offline
        if node_id in self.orchestrator.node_manager.nodes:
            self.orchestrator.node_manager.nodes[node_id].status = "offline"
    
    async def checkpoint_state(self):
        """Periodically checkpoint system state"""
        while True:
            try:
                state = {
                    'timestamp': asyncio.get_event_loop().time(),
                    'running_tasks': [
                        {'task_id': t.task_id, 'node': t.assigned_node}
                        for t in self.orchestrator.running_tasks.values()
                    ],
                    'node_status': {
                        node_id: node.status
                        for node_id, node in self.orchestrator.node_manager.nodes.items()
                    }
                }
                
                checkpoint_file = Path("output/distributed_checkpoint.json")
                checkpoint_file.parent.mkdir(exist_ok=True)
                
                with open(checkpoint_file, 'w') as f:
                    json.dump(state, f, indent=2)
                
            except Exception as e:
                logger.error(f"Checkpoint failed: {e}")
            
            await asyncio.sleep(self.checkpoint_interval)


# Example usage
async def run_distributed_system():
    """Run distributed orchestration system"""
    
    # Create orchestrator
    orchestrator = DistributedOrchestrator()
    
    # Register nodes
    for i in range(5):
        node = Node(
            node_id=f"node_{i}",
            hostname=f"worker-{i}",
            port=8000 + i,
            capacity=10,
            capabilities={'recon', 'scan', 'analyze'}
        )
        node.last_heartbeat = asyncio.get_event_loop().time()
        orchestrator.node_manager.register_node(node)
    
    # Start distribution
    distribution_task = asyncio.create_task(orchestrator.distribute_tasks())
    
    # Submit tasks
    for i in range(50):
        task = DistributedTask(
            task_id=f"task_{i}",
            payload={'target': f"example{i}.com"},
            required_capabilities={'recon'}
        )
        await orchestrator.submit_task(task)
    
    # Run for a while
    await asyncio.sleep(10)
    
    # Get stats
    stats = orchestrator.get_distribution_stats()
    print(json.dumps(stats, indent=2))
    
    distribution_task.cancel()


if __name__ == "__main__":
    asyncio.run(run_distributed_system())
