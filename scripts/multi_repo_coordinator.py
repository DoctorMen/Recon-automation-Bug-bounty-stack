#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
MULTI-REPOSITORY COORDINATOR
Coordinates agent loops across multiple repositories

Features:
- Manages multiple repo agent loops simultaneously
- Cross-repo task coordination
- Resource balancing
- Shared state management
- Unified monitoring
"""

import os
import sys
import json
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, List
from dataclasses import dataclass
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class Repository:
    """Repository configuration"""
    name: str
    path: Path
    priority: int
    max_resources: float  # CPU allocation (0-1)
    agent_script: str
    enabled: bool = True


class MultiRepoCoordinator:
    """Coordinates agent loops across multiple repositories"""
    
    def __init__(self, config_file: Path):
        self.config_file = config_file
        self.repositories = []
        self.running_loops = {}
        self.lock = threading.Lock()
        self.load_config()
    
    def load_config(self):
        """Load repository configuration"""
        if self.config_file.exists():
            with open(self.config_file) as f:
                config = json.load(f)
                for repo_cfg in config.get('repositories', []):
                    repo = Repository(
                        name=repo_cfg['name'],
                        path=Path(repo_cfg['path']).expanduser().resolve(),
                        priority=repo_cfg.get('priority', 5),
                        max_resources=repo_cfg.get('max_resources', 0.25),
                        agent_script=repo_cfg.get('agent_script', 'scripts/autonomous_agent_loop.py'),
                        enabled=repo_cfg.get('enabled', True)
                    )
                    self.repositories.append(repo)
        else:
            # Default configuration
            self.create_default_config()
    
    def create_default_config(self):
        """Create default configuration"""
        home = Path.home()
        default_repos = [
            {
                'name': 'Recon-automation-Bug-bounty-stack',
                'path': str(home / 'Recon-automation-Bug-bounty-stack'),
                'priority': 1,
                'max_resources': 0.4,
                'agent_script': 'scripts/autonomous_agent_loop.py',
                'enabled': True
            },
            {
                'name': 'notification_system',
                'path': str(home / 'Recon-automation-Bug-bounty-stack/notification_system'),
                'priority': 2,
                'max_resources': 0.3,
                'agent_script': 'agent1_automation/delivery_monitor.py',
                'enabled': True
            },
            {
                'name': 'NEXUS_ENGINE',
                'path': str(home / 'Recon-automation-Bug-bounty-stack'),
                'priority': 3,
                'max_resources': 0.2,
                'agent_script': 'NEXUS_AGENTS_SYSTEM.js',
                'enabled': False
            }
        ]
        
        config = {'repositories': default_repos}
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        logger.info(f"Created default configuration: {self.config_file}")
    
    def start_repo_loop(self, repo: Repository, runtime_hours: float = 4.0):
        """Start agent loop for a single repository"""
        if not repo.enabled:
            logger.info(f"⏸️  {repo.name} is disabled, skipping")
            return
        
        if not repo.path.exists():
            logger.warning(f"⚠️  {repo.name} path not found: {repo.path}")
            return
        
        script_path = repo.path / repo.agent_script
        if not script_path.exists():
            logger.warning(f"⚠️  {repo.name} agent script not found: {script_path}")
            return
        
        logger.info(f"🚀 Starting {repo.name} agent loop...")
        
        try:
            # Start agent loop in background
            if script_path.suffix == '.py':
                cmd = [sys.executable, str(script_path), '--hours', str(runtime_hours)]
            elif script_path.suffix == '.js':
                cmd = ['node', str(script_path)]
            else:
                logger.warning(f"⚠️  Unknown script type: {script_path.suffix}")
                return
            
            process = subprocess.Popen(
                cmd,
                cwd=str(repo.path),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            with self.lock:
                self.running_loops[repo.name] = {
                    'process': process,
                    'repo': repo,
                    'started_at': time.time()
                }
            
            logger.info(f"✅ {repo.name} loop started (PID: {process.pid})")
        
        except Exception as e:
            logger.error(f"❌ Failed to start {repo.name}: {e}")
    
    def monitor_loops(self):
        """Monitor running loops"""
        while True:
            time.sleep(30)  # Check every 30 seconds
            
            with self.lock:
                for name, loop_info in list(self.running_loops.items()):
                    process = loop_info['process']
                    repo = loop_info['repo']
                    
                    # Check if process is still running
                    if process.poll() is not None:
                        runtime = time.time() - loop_info['started_at']
                        logger.info(f"🏁 {name} completed (runtime: {runtime/3600:.2f}h)")
                        del self.running_loops[name]
                    else:
                        runtime = time.time() - loop_info['started_at']
                        logger.info(f"🔄 {name} running... ({runtime/3600:.2f}h)")
    
    def start_all(self, runtime_hours: float = 4.0):
        """Start all enabled repository loops"""
        logger.info(f"""
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║       MULTI-REPOSITORY COORDINATOR                       ║
║       Coordinating Agent Loops Across Repos              ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
        """)
        
        # Sort by priority
        sorted_repos = sorted(self.repositories, key=lambda r: r.priority)
        
        logger.info(f"📋 Found {len(sorted_repos)} repositories")
        
        # Start loops with staggered startup (30 second delay between each)
        for i, repo in enumerate(sorted_repos):
            if i > 0:
                delay = 30
                logger.info(f"⏳ Waiting {delay}s before starting {repo.name}...")
                time.sleep(delay)
            
            thread = threading.Thread(
                target=self.start_repo_loop,
                args=(repo, runtime_hours)
            )
            thread.daemon = True
            thread.start()
        
        # Start monitoring
        monitor_thread = threading.Thread(target=self.monitor_loops)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Wait for all loops to complete
        try:
            while True:
                with self.lock:
                    if not self.running_loops:
                        logger.info("🏁 All repository loops completed")
                        break
                time.sleep(10)
        
        except KeyboardInterrupt:
            logger.info("\n⛔ Interrupted by user")
            self.stop_all()
    
    def stop_all(self):
        """Stop all running loops"""
        logger.info("⏹️  Stopping all repository loops...")
        
        with self.lock:
            for name, loop_info in self.running_loops.items():
                process = loop_info['process']
                logger.info(f"⏹️  Stopping {name}...")
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
            
            self.running_loops.clear()
        
        logger.info("✅ All loops stopped")
    
    def status(self):
        """Show status of all repositories"""
        logger.info("\n📊 REPOSITORY STATUS:")
        logger.info("=" * 80)
        
        with self.lock:
            for repo in self.repositories:
                status = "🟢 RUNNING" if repo.name in self.running_loops else "⚪ IDLE"
                enabled = "✓" if repo.enabled else "✗"
                
                logger.info(f"{status} [{enabled}] {repo.name}")
                logger.info(f"    Priority: {repo.priority} | Resources: {repo.max_resources*100:.0f}%")
                logger.info(f"    Path: {repo.path}")
                
                if repo.name in self.running_loops:
                    loop_info = self.running_loops[repo.name]
                    runtime = time.time() - loop_info['started_at']
                    logger.info(f"    Runtime: {runtime/3600:.2f} hours")
                
                logger.info("")


def main():
    """Entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Multi-Repository Agent Coordinator')
    parser.add_argument('--config', default='multi_repo_config.json', help='Configuration file')
    parser.add_argument('--hours', type=float, default=4.0, help='Runtime in hours for each repo')
    parser.add_argument('--status', action='store_true', help='Show status and exit')
    args = parser.parse_args()
    
    config_path = Path(__file__).parent.parent / args.config
    coordinator = MultiRepoCoordinator(config_path)
    
    if args.status:
        coordinator.status()
    else:
        coordinator.start_all(runtime_hours=args.hours)


if __name__ == '__main__':
    main()
