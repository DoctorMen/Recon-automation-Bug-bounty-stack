"""
Test suite for AI Workflow Automation Platform Demo
Copyright © 2025. All Rights Reserved.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch
from datetime import datetime

# Import demo components
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from demo import DemoPlatform, MockVibeCommand, MockOrchestrator

class TestDemoPlatform:
    """Test suite for DemoPlatform functionality"""
    
    @pytest.fixture
    async def platform(self):
        """Create a demo platform for testing"""
        platform = DemoPlatform()
        await platform.initialize()
        return platform
    
    @pytest.mark.asyncio
    async def test_platform_initialization(self):
        """Test that platform initializes correctly"""
        platform = DemoPlatform()
        await platform.initialize()
        
        assert platform.vibe_command is not None
        assert platform.orchestrator is not None
        assert platform.orchestrator.agents is not None
        assert len(platform.orchestrator.agents) > 0
    
    @pytest.mark.asyncio
    async def test_sales_analysis_workflow(self, platform):
        """Test sales analysis workflow execution"""
        command = "analyze Q3 sales data and generate executive summary"
        
        result = await platform.execute_workflow(command)
        
        assert result['status'] == 'completed'
        assert result['success_rate'] == 100.0
        assert len(result['completed_tasks']) > 0
        assert result['cost_savings'] > 0
        assert 'workflow_id' in result
        assert result['workflow_id'].startswith('demo_')
    
    @pytest.mark.asyncio
    async def test_optimization_workflow(self, platform):
        """Test process optimization workflow execution"""
        command = "optimize customer onboarding workflow and reduce friction points"
        
        result = await platform.execute_workflow(command)
        
        assert result['status'] == 'completed'
        assert result['success_rate'] == 100.0
        assert len(result['completed_tasks']) >= 3  # Should have analysis, optimization, implementation
        assert result['cost_savings'] >= 300  # 3 tasks * $100 each
    
    @pytest.mark.asyncio
    async def test_custom_workflow(self, platform):
        """Test custom command workflow execution"""
        command = "generate monthly performance report for leadership team"
        
        result = await platform.execute_workflow(command)
        
        assert result['status'] == 'completed'
        assert result['success_rate'] == 100.0
        assert len(result['completed_tasks']) > 0
        assert 'timestamp' in result

class TestMockVibeCommand:
    """Test suite for MockVibeCommand functionality"""
    
    @pytest.fixture
    def vibe_command(self):
        """Create a MockVibeCommand for testing"""
        return MockVibeCommand()
    
    @pytest.mark.asyncio
    async def test_parse_analysis_command(self, vibe_command):
        """Test parsing analysis commands"""
        command = "analyze sales data for insights"
        
        result = await vibe_command.parse_command(command)
        
        assert result['intent'] == 'analyze'
        assert 'steps' in result
        assert len(result['steps']) > 0
        assert result['complexity'] in ['low', 'medium', 'high']
        assert result['estimated_duration'] > 0
    
    @pytest.mark.asyncio
    async def test_parse_optimization_command(self, vibe_command):
        """Test parsing optimization commands"""
        command = "optimize the current workflow"
        
        result = await vibe_command.parse_command(command)
        
        assert result['intent'] == 'optimize'
        assert 'steps' in result
        assert len(result['steps']) >= 3
        assert result['complexity'] == 'high'  # Optimization is complex
    
    @pytest.mark.asyncio
    async def test_parse_general_command(self, vibe_command):
        """Test parsing general commands"""
        command = "help me with this task"
        
        result = await vibe_command.parse_command(command)
        
        assert result['intent'] == 'general'
        assert 'steps' in result
        assert len(result['steps']) >= 2
        assert result['complexity'] == 'low'

class TestMockOrchestrator:
    """Test suite for MockOrchestrator functionality"""
    
    @pytest.fixture
    async def orchestrator(self):
        """Create a MockOrchestrator for testing"""
        orchestrator = MockOrchestrator()
        await orchestrator.initialize()
        return orchestrator
    
    @pytest.mark.asyncio
    async def test_orchestrator_initialization(self, orchestrator):
        """Test that orchestrator initializes correctly"""
        assert len(orchestrator.agents) > 0
        assert 'strategist' in orchestrator.agents
        assert 'executor' in orchestrator.agents
        assert 'automation_engineer' in orchestrator.agents
    
    @pytest.mark.asyncio
    async def test_execute_simple_workflow(self, orchestrator):
        """Test executing a simple workflow"""
        workflow_plan = {
            'intent': 'general',
            'steps': [
                {'id': 'test_step', 'agent': 'executor', 'prompt': 'Test task'}
            ]
        }
        
        result = await orchestrator.execute_workflow(workflow_plan)
        
        assert result['status'] == 'completed'
        assert len(result['completed_tasks']) == 1
        assert result['success_rate'] == 100.0
        assert result['workflow_id'].startswith('demo_')
    
    @pytest.mark.asyncio
    async def test_execute_complex_workflow(self, orchestrator):
        """Test executing a complex workflow with multiple agents"""
        workflow_plan = {
            'intent': 'analyze',
            'steps': [
                {'id': 'step1', 'agent': 'automation_engineer', 'prompt': 'Collect data'},
                {'id': 'step2', 'agent': 'divergent_thinker', 'prompt': 'Analyze data'},
                {'id': 'step3', 'agent': 'documentation_specialist', 'prompt': 'Create report'}
            ]
        }
        
        result = await orchestrator.execute_workflow(workflow_plan)
        
        assert result['status'] == 'completed'
        assert len(result['completed_tasks']) == 3
        assert result['success_rate'] == 100.0
        assert result['cost_savings'] == 300  # 3 tasks * $100 each

class TestIntegration:
    """Integration tests for the complete demo system"""
    
    @pytest.mark.asyncio
    async def test_end_to_end_workflow(self):
        """Test complete end-to-end workflow execution"""
        platform = DemoPlatform()
        await platform.initialize()
        
        # Test multiple workflows
        commands = [
            "analyze sales data",
            "optimize workflow",
            "generate report"
        ]
        
        results = []
        for command in commands:
            result = await platform.execute_workflow(command)
            results.append(result)
            
            assert result['status'] == 'completed'
            assert result['success_rate'] == 100.0
        
        # Verify all workflows completed successfully
        assert len(results) == 3
        for result in results:
            assert result['cost_savings'] > 0
            assert len(result['completed_tasks']) > 0
    
    @pytest.mark.asyncio
    async def test_performance_metrics(self):
        """Test that performance metrics are calculated correctly"""
        platform = DemoPlatform()
        await platform.initialize()
        
        command = "analyze Q3 sales data and generate executive summary"
        start_time = datetime.now()
        
        result = await platform.execute_workflow(command)
        
        end_time = datetime.now()
        
        # Verify metrics are reasonable
        assert result['execution_time'] > 0
        assert result['cost_savings'] > 0
        assert result['success_rate'] == 100.0
        
        # Verify timestamp is recent
        result_time = datetime.fromisoformat(result['timestamp'].replace('Z', '+00:00'))
        assert start_time <= result_time <= end_time

# Performance tests
class TestPerformance:
    """Performance tests for the demo system"""
    
    @pytest.mark.asyncio
    async def test_concurrent_workflows(self):
        """Test executing multiple workflows concurrently"""
        platform = DemoPlatform()
        await platform.initialize()
        
        commands = [
            "analyze sales data",
            "optimize workflow", 
            "generate report"
        ]
        
        # Execute workflows concurrently
        tasks = [platform.execute_workflow(cmd) for cmd in commands]
        results = await asyncio.gather(*tasks)
        
        # Verify all completed successfully
        assert len(results) == 3
        for result in results:
            assert result['status'] == 'completed'
            assert result['success_rate'] == 100.0
    
    @pytest.mark.asyncio
    async def test_execution_time(self):
        """Test that execution times are within reasonable bounds"""
        platform = DemoPlatform()
        await platform.initialize()
        
        import time
        start_time = time.time()
        
        result = await platform.execute_workflow("analyze sales data")
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        # Should complete within 10 seconds (demo timing)
        assert execution_time < 10.0
        assert result['execution_time'] > 0

if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])
