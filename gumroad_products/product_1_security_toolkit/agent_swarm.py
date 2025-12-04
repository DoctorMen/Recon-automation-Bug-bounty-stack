#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
10-Agent Parallel Orchestration System
Real multi-process parallelization with specialized agents
"""

import os
import sys
import time
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from multiprocessing import Process, Queue, Manager, Event
from queue import Empty
import signal

class Agent:
    """Individual agent with specialization"""
    
    def __init__(self, agent_id: int, name: str, specialty: str, color: str):
        self.agent_id = agent_id
        self.name = name
        self.specialty = specialty
        self.color = color
        self.tasks_completed = 0
        self.status = "idle"
        self.current_task = None
        self.efficiency = 1.0
    
    def to_dict(self) -> Dict:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "specialty": self.specialty,
            "color": self.color,
            "tasks_completed": self.tasks_completed,
            "status": self.status,
            "current_task": self.current_task,
            "efficiency": self.efficiency
        }


class TaskQueue:
    """Thread-safe task queue for agent coordination"""
    
    def __init__(self):
        self.queue = Queue()
        self.completed = []
        self.failed = []
    
    def add_task(self, task: Dict[str, Any]):
        """Add task to queue"""
        self.queue.put(task)
    
    def get_task(self, timeout: float = 1.0) -> Optional[Dict[str, Any]]:
        """Get next task from queue"""
        try:
            return self.queue.get(timeout=timeout)
        except Empty:
            return None
    
    def mark_completed(self, task: Dict[str, Any], result: Any):
        """Mark task as completed"""
        task['result'] = result
        task['completed_at'] = datetime.now().isoformat()
        self.completed.append(task)
    
    def mark_failed(self, task: Dict[str, Any], error: str):
        """Mark task as failed"""
        task['error'] = error
        task['failed_at'] = datetime.now().isoformat()
        self.failed.append(task)
    
    def is_empty(self) -> bool:
        """Check if queue is empty"""
        return self.queue.empty()
    
    def get_stats(self) -> Dict[str, int]:
        """Get queue statistics"""
        return {
            "pending": self.queue.qsize(),
            "completed": len(self.completed),
            "failed": len(self.failed)
        }


class AgentWorker:
    """Worker process that executes tasks"""
    
    def __init__(self, agent: Agent, task_queue: TaskQueue, 
                 shared_state: Dict, stop_event: Event):
        self.agent = agent
        self.task_queue = task_queue
        self.shared_state = shared_state
        self.stop_event = stop_event
    
    def run(self):
        """Main worker loop"""
        print(f"[{self.agent.name}] Agent started - specialty: {self.agent.specialty}")
        
        while not self.stop_event.is_set():
            # Get next task
            task = self.task_queue.get_task(timeout=1.0)
            
            if task is None:
                # Update status to idle
                self.shared_state[f"agent_{self.agent.agent_id}_status"] = "idle"
                continue
            
            # Update status to working
            self.shared_state[f"agent_{self.agent.agent_id}_status"] = "working"
            self.shared_state[f"agent_{self.agent.agent_id}_task"] = task.get('name', 'unknown')
            
            print(f"[{self.agent.name}] Starting task: {task.get('name')}")
            
            try:
                # Execute task
                start_time = time.time()
                result = self._execute_task(task)
                duration = time.time() - start_time
                
                # Mark as completed
                self.task_queue.mark_completed(task, result)
                self.agent.tasks_completed += 1
                
                # Update shared state
                self.shared_state[f"agent_{self.agent.agent_id}_completed"] = self.agent.tasks_completed
                
                print(f"[{self.agent.name}] Completed task: {task.get('name')} in {duration:.2f}s")
            
            except Exception as e:
                print(f"[{self.agent.name}] Task failed: {task.get('name')} - {str(e)}")
                self.task_queue.mark_failed(task, str(e))
        
        print(f"[{self.agent.name}] Agent stopped")
    
    def _execute_task(self, task: Dict[str, Any]) -> Any:
        """Execute specific task based on type"""
        task_type = task.get('type')
        
        if task_type == 'subdomain_enum':
            return self._run_subdomain_enum(task)
        elif task_type == 'http_probe':
            return self._run_http_probe(task)
        elif task_type == 'vulnerability_scan':
            return self._run_vulnerability_scan(task)
        elif task_type == 'custom_command':
            return self._run_custom_command(task)
        else:
            raise ValueError(f"Unknown task type: {task_type}")
    
    def _run_subdomain_enum(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Run subdomain enumeration"""
        target = task.get('target')
        tool = task.get('tool', 'subfinder')
        
        if tool == 'subfinder':
            cmd = f"subfinder -d {target} -silent"
        elif tool == 'amass':
            cmd = f"amass enum -passive -d {target}"
        else:
            cmd = f"subfinder -d {target} -silent"
        
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
        
        subdomains = result.stdout.strip().split('\n')
        subdomains = [s for s in subdomains if s]
        
        return {
            "tool": tool,
            "target": target,
            "subdomains_found": len(subdomains),
            "subdomains": subdomains[:100]  # Limit to first 100
        }
    
    def _run_http_probe(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Run HTTP probing"""
        input_file = task.get('input_file')
        output_file = task.get('output_file', 'output/http_probed.txt')
        
        cmd = f"httpx -l {input_file} -silent -json -o {output_file}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
        
        # Count results
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                count = sum(1 for line in f if line.strip())
        else:
            count = 0
        
        return {
            "input_file": input_file,
            "output_file": output_file,
            "urls_found": count
        }
    
    def _run_vulnerability_scan(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Run vulnerability scanning"""
        target = task.get('target')
        severity = task.get('severity', 'medium,high,critical')
        output_file = task.get('output_file', f'output/nuclei_{self.agent.agent_id}.json')
        
        cmd = f"nuclei -u {target} -severity {severity} -json -o {output_file}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
        
        # Count findings
        findings = 0
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                findings = sum(1 for line in f if line.strip())
        
        return {
            "target": target,
            "output_file": output_file,
            "findings": findings
        }
    
    def _run_custom_command(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Run custom shell command"""
        cmd = task.get('command')
        timeout = task.get('timeout', 300)
        
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        
        return {
            "command": cmd,
            "return_code": result.returncode,
            "stdout": result.stdout[:1000],  # Limit output
            "stderr": result.stderr[:1000]
        }


class AgentSwarm:
    """Main orchestrator for 10-agent parallel system"""
    
    AGENTS_CONFIG = [
        {"agent_id": 1, "name": "RECON-ALPHA", "specialty": "subdomain_enumeration", "color": "#00ff88"},
        {"agent_id": 2, "name": "RECON-BETA", "specialty": "subdomain_enumeration", "color": "#00d4ff"},
        {"agent_id": 3, "name": "HTTP-MAPPER", "specialty": "http_probing", "color": "#ff0080"},
        {"agent_id": 4, "name": "VULN-HUNTER-1", "specialty": "vulnerability_scanning", "color": "#ffaa00"},
        {"agent_id": 5, "name": "VULN-HUNTER-2", "specialty": "vulnerability_scanning", "color": "#8b5cf6"},
        {"agent_id": 6, "name": "VULN-HUNTER-3", "specialty": "vulnerability_scanning", "color": "#10b981"},
        {"agent_id": 7, "name": "ANALYZER", "specialty": "result_processing", "color": "#06b6d4"},
        {"agent_id": 8, "name": "VALIDATOR", "specialty": "finding_validation", "color": "#f59e0b"},
        {"agent_id": 9, "name": "REPORTER", "specialty": "report_generation", "color": "#ec4899"},
        {"agent_id": 10, "name": "COORDINATOR", "specialty": "task_coordination", "color": "#6366f1"}
    ]
    
    def __init__(self):
        self.agents = [Agent(**config) for config in self.AGENTS_CONFIG]
        self.task_queue = TaskQueue()
        self.manager = Manager()
        self.shared_state = self.manager.dict()
        self.stop_event = Event()
        self.processes = []
        self.output_dir = Path("output/.agent_swarm")
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def start(self):
        """Start all agent workers"""
        print(f"\n[*] Starting Agent Swarm with {len(self.agents)} agents...\n")
        
        for agent in self.agents:
            worker = AgentWorker(agent, self.task_queue, self.shared_state, self.stop_event)
            process = Process(target=worker.run)
            process.start()
            self.processes.append(process)
            
            # Initialize shared state
            self.shared_state[f"agent_{agent.agent_id}_status"] = "idle"
            self.shared_state[f"agent_{agent.agent_id}_task"] = ""
            self.shared_state[f"agent_{agent.agent_id}_completed"] = 0
        
        print(f"[OK] All {len(self.agents)} agents started and ready\n")
    
    def stop(self):
        """Stop all agent workers"""
        print("\n[*] Stopping Agent Swarm...")
        self.stop_event.set()
        
        for process in self.processes:
            process.join(timeout=5)
            if process.is_alive():
                process.terminate()
        
        print("[OK] All agents stopped\n")
    
    def add_task(self, task_type: str, **kwargs):
        """Add a task to the queue"""
        task = {
            "type": task_type,
            "added_at": datetime.now().isoformat(),
            **kwargs
        }
        self.task_queue.add_task(task)
    
    def wait_for_completion(self, poll_interval: float = 2.0):
        """Wait for all tasks to complete"""
        print("\n[*] Waiting for tasks to complete...\n")
        
        while not self.task_queue.is_empty() or self._any_agent_working():
            self._print_status()
            time.sleep(poll_interval)
        
        print("\n[OK] All tasks completed!\n")
    
    def _any_agent_working(self) -> bool:
        """Check if any agent is currently working"""
        for agent in self.agents:
            status = self.shared_state.get(f"agent_{agent.agent_id}_status", "idle")
            if status == "working":
                return True
        return False
    
    def _print_status(self):
        """Print current status of all agents"""
        stats = self.task_queue.get_stats()
        
        print(f"\r[*] Queue: {stats['pending']} pending | "
              f"{stats['completed']} completed | "
              f"{stats['failed']} failed", end='', flush=True)
    
    def get_results(self) -> Dict[str, Any]:
        """Get all completed task results"""
        return {
            "completed_tasks": self.task_queue.completed,
            "failed_tasks": self.task_queue.failed,
            "stats": self.task_queue.get_stats()
        }
    
    def parallel_scan(self, target: str, workflow: str = "full"):
        """
        Run a parallel scan using all agents
        
        Workflows:
        - full: Complete scan (recon + http + vuln)
        - recon: Subdomain enumeration only
        - vuln: Vulnerability scanning only
        """
        
        print(f"\n[*] Starting {workflow} scan on {target}\n")
        
        if workflow in ["full", "recon"]:
            # Distribute subdomain enumeration across multiple agents
            self.add_task("subdomain_enum", target=target, tool="subfinder", name=f"Subfinder-{target}")
            self.add_task("subdomain_enum", target=target, tool="amass", name=f"Amass-{target}")
        
        if workflow == "full":
            # Add HTTP probing
            self.add_task("http_probe", 
                         input_file="output/subs.txt",
                         output_file="output/http.txt",
                         name=f"HTTP-Probe-{target}")
            
            # Add multiple vulnerability scans in parallel
            for i in range(3):  # 3 parallel nuclei scans
                self.add_task("vulnerability_scan",
                             target=target,
                             severity="medium,high,critical",
                             output_file=f"output/nuclei_agent_{i}.json",
                             name=f"Nuclei-{i}-{target}")
        
        elif workflow == "vuln":
            # Vulnerability scanning only
            for i in range(5):  # 5 parallel nuclei scans
                self.add_task("vulnerability_scan",
                             target=target,
                             severity="medium,high,critical",
                             output_file=f"output/nuclei_agent_{i}.json",
                             name=f"Nuclei-{i}-{target}")


# CLI Interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="10-Agent Parallel Orchestration System")
    parser.add_argument('action', choices=['scan', 'demo'],
                       help='Action to perform')
    parser.add_argument('--target', help='Target domain to scan')
    parser.add_argument('--workflow', choices=['full', 'recon', 'vuln'],
                       default='full', help='Scan workflow')
    
    args = parser.parse_args()
    
    swarm = AgentSwarm()
    
    def signal_handler(sig, frame):
        """Handle Ctrl+C gracefully"""
        print("\n\n[!] Interrupt received, stopping agents...")
        swarm.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        swarm.start()
        
        if args.action == 'scan':
            if not args.target:
                print("Error: --target required for scan")
                swarm.stop()
                sys.exit(1)
            
            swarm.parallel_scan(args.target, args.workflow)
            swarm.wait_for_completion()
            
            # Print results
            results = swarm.get_results()
            print(json.dumps(results, indent=2))
        
        elif args.action == 'demo':
            # Demo mode - show agents working
            print("[DEMO] Demo Mode - Running sample tasks\n")
            
            for i in range(20):
                swarm.add_task("custom_command",
                              command=f"echo 'Task {i}' && sleep 2",
                              name=f"Demo-Task-{i}")
            
            swarm.wait_for_completion()
        
        swarm.stop()
    
    except Exception as e:
        print(f"\n[ERROR] Error: {e}")
        swarm.stop()
        sys.exit(1)
