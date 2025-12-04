#!/usr/bin/env python3
"""
AI Workflow Automation Platform
Copyright © 2025. All Rights Reserved.

Transform business processes into autonomous agentic workflows
"""

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any

from core.agent_orchestrator import AgentOrchestrator
from core.vibe_command import VibeCommand
from core.workflow_engine import WorkflowEngine
from utils.metrics import MetricsCollector
from utils.config import Config

class AIWorkflowPlatform:
    """
    Main platform class that orchestrates AI-driven workflow automation
    """
    
    def __init__(self, config_path: str = "config/platform.json"):
        self.config = Config(config_path)
        self.orchestrator = AgentOrchestrator()
        self.vibe_command = VibeCommand()
        self.workflow_engine = WorkflowEngine()
        self.metrics = MetricsCollector()
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
    async def initialize(self):
        """Initialize all platform components"""
        self.logger.info("🚀 Initializing AI Workflow Platform...")
        
        await self.orchestrator.initialize()
        await self.vibe_command.initialize()
        await self.workflow_engine.initialize()
        
        self.logger.info("✅ Platform initialization complete")
        
    async def execute_workflow(self, command: str, context: Dict = None) -> Dict:
        """
        Execute a workflow from natural language command
        
        Args:
            command: Natural language description of workflow
            context: Additional context for execution
            
        Returns:
            Dict with execution results and metrics
        """
        start_time = datetime.now()
        
        try:
            # Process natural language command
            self.logger.info(f"📝 Processing command: {command}")
            
            # Parse and plan workflow
            workflow_plan = await self.vibe_command.parse_command(command, context)
            
            # Execute through agent orchestrator
            execution_result = await self.orchestrator.execute_workflow(workflow_plan)
            
            # Calculate metrics
            execution_time = (datetime.now() - start_time).total_seconds()
            metrics = {
                'execution_time': execution_time,
                'tasks_completed': len(execution_result.get('completed_tasks', [])),
                'success_rate': execution_result.get('success_rate', 0),
                'cost_savings': execution_result.get('cost_savings', 0)
            }
            
            # Record metrics
            await self.metrics.record_execution(command, metrics)
            
            return {
                'status': 'success',
                'workflow_id': execution_result.get('workflow_id'),
                'results': execution_result,
                'metrics': metrics,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"❌ Workflow execution failed: {str(e)}")
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    async def get_performance_metrics(self) -> Dict:
        """Get platform performance metrics"""
        return await self.metrics.get_summary()
    
    async def shutdown(self):
        """Graceful shutdown of platform components"""
        self.logger.info("🛑 Shutting down AI Workflow Platform...")
        await self.orchestrator.shutdown()
        await self.workflow_engine.shutdown()

async def main():
    """Main entry point for the platform"""
    platform = AIWorkflowPlatform()
    
    try:
        await platform.initialize()
        
        # Example workflows
        examples = [
            "optimize customer onboarding process and reduce friction points",
            "analyze Q3 sales data and generate executive summary",
            "automate compliance reporting for quarterly audit"
        ]
        
        print("\n🎯 AI Workflow Automation Platform")
        print("=" * 50)
        print("\nExample workflows:")
        for i, example in enumerate(examples, 1):
            print(f"{i}. {example}")
        
        print("\nEnter your workflow command (or 'quit' to exit):")
        
        while True:
            command = input("\n> ").strip()
            
            if command.lower() in ['quit', 'exit', 'q']:
                break
                
            if not command:
                continue
                
            # Execute workflow
            result = await platform.execute_workflow(command)
            
            if result['status'] == 'success':
                print(f"\n✅ Workflow completed successfully!")
                print(f"📊 Metrics: {result['metrics']}")
            else:
                print(f"\n❌ Error: {result['error']}")
    
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
    
    finally:
        await platform.shutdown()

if __name__ == "__main__":
    asyncio.run(main())
