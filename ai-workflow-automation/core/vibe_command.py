"""
Vibe Command System - Natural Language to Workflow Transformation
Copyright © 2025. All Rights Reserved.

Transforms natural language business requirements into automated workflows
"""

import re
import json
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime

from utils.prompt_templates import PromptTemplates
from utils.nlp_processor import NLPProcessor

class VibeCommand:
    """
    Natural language interface for workflow automation
    """
    
    def __init__(self):
        self.prompt_templates = PromptTemplates()
        self.nlp_processor = NLPProcessor()
        self.command_history = []
        self.intent_patterns = self._load_intent_patterns()
        
    async def initialize(self):
        """Initialize the Vibe Command system"""
        print("💬 Initializing Vibe Command System...")
        await self.nlp_processor.initialize()
        print("  ✅ Natural language processing ready")
        print("  ✅ Intent patterns loaded")
        
    async def parse_command(self, command: str, context: Dict = None) -> Dict:
        """
        Parse natural language command into structured workflow
        
        Args:
            command: Natural language input from user
            context: Additional context for parsing
            
        Returns:
            Structured workflow plan
        """
        print(f"📝 Parsing command: '{command}'")
        
        # Record command
        self.command_history.append({
            'command': command,
            'context': context,
            'timestamp': datetime.now().isoformat()
        })
        
        # Extract intent and entities
        intent = await self._extract_intent(command)
        entities = await self._extract_entities(command)
        
        # Generate workflow plan
        workflow_plan = await self._generate_workflow_plan(intent, entities, context)
        
        # Optimize for efficiency
        optimized_plan = await self._optimize_workflow(workflow_plan)
        
        print(f"  ✅ Generated workflow with {len(optimized_plan.get('steps', []))} steps")
        
        return optimized_plan
    
    async def _extract_intent(self, command: str) -> str:
        """Extract the primary intent from the command"""
        command_lower = command.lower()
        
        # Intent patterns with confidence scoring
        intents = {
            'analyze': {
                'patterns': ['analyze', 'examine', 'review', 'audit', 'assess'],
                'confidence': 0
            },
            'optimize': {
                'patterns': ['optimize', 'improve', 'enhance', 'streamline', 'make better'],
                'confidence': 0
            },
            'automate': {
                'patterns': ['automate', 'automated', 'automatic', 'create workflow'],
                'confidence': 0
            },
            'generate': {
                'patterns': ['generate', 'create', 'produce', 'make', 'build'],
                'confidence': 0
            },
            'monitor': {
                'patterns': ['monitor', 'watch', 'track', 'observe', 'keep an eye on'],
                'confidence': 0
            },
            'integrate': {
                'patterns': ['integrate', 'connect', 'link', 'combine', 'merge'],
                'confidence': 0
            }
        }
        
        # Calculate confidence for each intent
        for intent_name, intent_data in intents.items():
            for pattern in intent_data['patterns']:
                if pattern in command_lower:
                    intent_data['confidence'] += 1
            
            # Normalize confidence
            intent_data['confidence'] = min(intent_data['confidence'] / len(intent_data['patterns']), 1.0)
        
        # Return highest confidence intent
        best_intent = max(intents.items(), key=lambda x: x[1]['confidence'])
        return best_intent[0] if best_intent[1]['confidence'] > 0 else 'general'
    
    async def _extract_entities(self, command: str) -> Dict[str, Any]:
        """Extract entities like targets, metrics, timeframes"""
        entities = {}
        
        # Extract timeframes
        time_patterns = {
            'daily': r'\b(daily|every day|each day)\b',
            'weekly': r'\b(weekly|every week|each week)\b',
            'monthly': r'\b(monthly|every month|each month)\b',
            'quarterly': r'\b(quarterly|q[1-4]|quarter)\b',
            'yearly': r'\b(yearly|annually|every year)\b'
        }
        
        for timeframe, pattern in time_patterns.items():
            if re.search(pattern, command.lower()):
                entities['timeframe'] = timeframe
                break
        
        # Extract business processes
        process_patterns = [
            'customer onboarding', 'user registration', 'sales process',
            'report generation', 'data analysis', 'compliance audit',
            'inventory management', 'order processing', 'support ticket',
            'employee onboarding', 'performance review', 'budget planning'
        ]
        
        for process in process_patterns:
            if process in command.lower():
                entities['business_process'] = process
                break
        
        # Extract metrics/KPIs
        metric_patterns = [
            'revenue', 'cost', 'efficiency', 'productivity', 'satisfaction',
            'conversion rate', 'churn rate', 'response time', 'error rate',
            'throughput', 'utilization', 'availability', 'performance'
        ]
        
        found_metrics = []
        for metric in metric_patterns:
            if metric in command.lower():
                found_metrics.append(metric)
        
        if found_metrics:
            entities['metrics'] = found_metrics
        
        # Extract data sources
        data_patterns = [
            'sales data', 'customer data', 'financial data', 'analytics',
            'logs', 'database', 'api', 'spreadsheet', 'reports'
        ]
        
        for data_source in data_patterns:
            if data_source in command.lower():
                entities['data_source'] = data_source
                break
        
        return entities
    
    async def _generate_workflow_plan(self, intent: str, entities: Dict, context: Dict = None) -> Dict:
        """Generate structured workflow plan from intent and entities"""
        
        # Base workflow structure
        workflow = {
            'intent': intent,
            'entities': entities,
            'context': context or {},
            'steps': [],
            'estimated_duration': 0,
            'complexity': 'medium'
        }
        
        # Generate steps based on intent
        if intent == 'analyze':
            workflow['steps'] = await self._generate_analysis_steps(entities)
        elif intent == 'optimize':
            workflow['steps'] = await self._generate_optimization_steps(entities)
        elif intent == 'automate':
            workflow['steps'] = await self._generate_automation_steps(entities)
        elif intent == 'generate':
            workflow['steps'] = await self._generate_generation_steps(entities)
        elif intent == 'monitor':
            workflow['steps'] = await self._generate_monitoring_steps(entities)
        elif intent == 'integrate':
            workflow['steps'] = await self._generate_integration_steps(entities)
        else:
            workflow['steps'] = await self._generate_general_steps(entities)
        
        # Calculate estimated duration
        workflow['estimated_duration'] = len(workflow['steps']) * 15  # 15 minutes per step
        
        # Determine complexity
        workflow['complexity'] = self._calculate_complexity(workflow['steps'])
        
        return workflow
    
    async def _generate_analysis_steps(self, entities: Dict) -> List[Dict]:
        """Generate steps for data analysis workflows"""
        steps = [
            {
                'id': 'data_collection',
                'agent': 'automation_engineer',
                'prompt': f'Collect and prepare {entities.get("data_source", "relevant")} data for analysis',
                'dependencies': []
            },
            {
                'id': 'data_processing',
                'agent': 'automation_engineer',
                'prompt': 'Process and clean the collected data, handle missing values and outliers',
                'dependencies': ['data_collection']
            },
            {
                'id': 'statistical_analysis',
                'agent': 'divergent_thinker',
                'prompt': f'Perform statistical analysis focusing on {", ".join(entities.get("metrics", ["key metrics"]))}',
                'dependencies': ['data_processing']
            },
            {
                'id': 'insight_generation',
                'agent': 'divergent_thinker',
                'prompt': 'Generate actionable insights and identify trends from the analysis results',
                'dependencies': ['statistical_analysis']
            },
            {
                'id': 'report_creation',
                'agent': 'documentation_specialist',
                'prompt': 'Create comprehensive analysis report with visualizations and recommendations',
                'dependencies': ['insight_generation']
            }
        ]
        
        return steps
    
    async def _generate_optimization_steps(self, entities: Dict) -> List[Dict]:
        """Generate steps for process optimization workflows"""
        process = entities.get('business_process', 'business process')
        
        steps = [
            {
                'id': 'process_analysis',
                'agent': 'automation_engineer',
                'prompt': f'Analyze current {process} workflow to identify bottlenecks and inefficiencies',
                'dependencies': []
            },
            {
                'id': 'bottleneck_identification',
                'agent': 'divergent_thinker',
                'prompt': 'Identify specific bottlenecks and quantify their impact on performance',
                'dependencies': ['process_analysis']
            },
            {
                'id': 'solution_design',
                'agent': 'divergent_thinker',
                'prompt': 'Design optimized workflow solutions to eliminate identified bottlenecks',
                'dependencies': ['bottleneck_identification']
            },
            {
                'id': 'automation_implementation',
                'agent': 'automation_engineer',
                'prompt': 'Implement automation solutions for the optimized workflow',
                'dependencies': ['solution_design']
            },
            {
                'id': 'performance_validation',
                'agent': 'executor',
                'prompt': 'Test and validate the optimized workflow performance improvements',
                'dependencies': ['automation_implementation']
            }
        ]
        
        return steps
    
    async def _generate_automation_steps(self, entities: Dict) -> List[Dict]:
        """Generate steps for automation workflows"""
        steps = [
            {
                'id': 'requirement_analysis',
                'agent': 'strategist',
                'prompt': 'Analyze automation requirements and define success criteria',
                'dependencies': []
            },
            {
                'id': 'workflow_design',
                'agent': 'automation_engineer',
                'prompt': 'Design automated workflow with error handling and monitoring',
                'dependencies': ['requirement_analysis']
            },
            {
                'id': 'implementation',
                'agent': 'executor',
                'prompt': 'Implement the automated workflow with all necessary integrations',
                'dependencies': ['workflow_design']
            },
            {
                'id': 'testing',
                'agent': 'executor',
                'prompt': 'Test the automation thoroughly with edge cases and error scenarios',
                'dependencies': ['implementation']
            },
            {
                'id': 'deployment',
                'agent': 'cicd_operations',
                'prompt': 'Deploy the automation to production with monitoring and alerting',
                'dependencies': ['testing']
            }
        ]
        
        return steps
    
    async def _generate_generation_steps(self, entities: Dict) -> List[Dict]:
        """Generate steps for content/report generation workflows"""
        steps = [
            {
                'id': 'requirement_gathering',
                'agent': 'strategist',
                'prompt': 'Gather requirements for the generation task and define output specifications',
                'dependencies': []
            },
            {
                'id': 'data_preparation',
                'agent': 'automation_engineer',
                'prompt': 'Prepare and structure data needed for generation',
                'dependencies': ['requirement_gathering']
            },
            {
                'id': 'content_generation',
                'agent': 'divergent_thinker',
                'prompt': 'Generate high-quality content with appropriate structure and formatting',
                'dependencies': ['data_preparation']
            },
            {
                'id': 'quality_assurance',
                'agent': 'documentation_specialist',
                'prompt': 'Review and enhance the generated content for quality and accuracy',
                'dependencies': ['content_generation']
            },
            {
                'id': 'finalization',
                'agent': 'executor',
                'prompt': 'Finalize and deliver the generated content in the required format',
                'dependencies': ['quality_assurance']
            }
        ]
        
        return steps
    
    async def _generate_monitoring_steps(self, entities: Dict) -> List[Dict]:
        """Generate steps for monitoring workflows"""
        steps = [
            {
                'id': 'monitoring_setup',
                'agent': 'automation_engineer',
                'prompt': 'Set up comprehensive monitoring for the specified system or process',
                'dependencies': []
            },
            {
                'id': 'alert_configuration',
                'agent': 'automation_engineer',
                'prompt': 'Configure intelligent alerts with appropriate thresholds and escalation',
                'dependencies': ['monitoring_setup']
            },
            {
                'id': 'dashboard_creation',
                'agent': 'documentation_specialist',
                'prompt': 'Create monitoring dashboard with visualizations and key metrics',
                'dependencies': ['alert_configuration']
            },
            {
                'id': 'testing_validation',
                'agent': 'executor',
                'prompt': 'Test monitoring system with simulated events and validate alert responses',
                'dependencies': ['dashboard_creation']
            }
        ]
        
        return steps
    
    async def _generate_integration_steps(self, entities: Dict) -> List[Dict]:
        """Generate steps for integration workflows"""
        steps = [
            {
                'id': 'integration_analysis',
                'agent': 'strategist',
                'prompt': 'Analyze integration requirements and identify connection points',
                'dependencies': []
            },
            {
                'id': 'api_design',
                'agent': 'automation_engineer',
                'prompt': 'Design API connections and data flow between systems',
                'dependencies': ['integration_analysis']
            },
            {
                'id': 'implementation',
                'agent': 'executor',
                'prompt': 'Implement the integration with proper error handling and retry logic',
                'dependencies': ['api_design']
            },
            {
                'id': 'testing',
                'agent': 'executor',
                'prompt': 'Test integration thoroughly with various data scenarios',
                'dependencies': ['implementation']
            },
            {
                'id': 'deployment',
                'agent': 'cicd_operations',
                'prompt': 'Deploy integration with monitoring and rollback capabilities',
                'dependencies': ['testing']
            }
        ]
        
        return steps
    
    async def _generate_general_steps(self, entities: Dict) -> List[Dict]:
        """Generate steps for general workflows"""
        steps = [
            {
                'id': 'analysis',
                'agent': 'strategist',
                'prompt': 'Analyze the request and break it down into actionable steps',
                'dependencies': []
            },
            {
                'id': 'planning',
                'agent': 'strategist',
                'prompt': 'Create detailed execution plan with timeline and resources',
                'dependencies': ['analysis']
            },
            {
                'id': 'execution',
                'agent': 'executor',
                'prompt': 'Execute the planned workflow with proper monitoring',
                'dependencies': ['planning']
            },
            {
                'id': 'validation',
                'agent': 'executor',
                'prompt': 'Validate results and ensure quality standards are met',
                'dependencies': ['execution']
            }
        ]
        
        return steps
    
    async def _optimize_workflow(self, workflow: Dict) -> Dict:
        """Optimize workflow for parallel execution and efficiency"""
        steps = workflow['steps']
        
        # Identify steps that can run in parallel
        parallel_groups = self._identify_parallel_steps(steps)
        
        # Reorganize steps for optimal execution
        optimized_steps = []
        for group in parallel_groups:
            if len(group) == 1:
                optimized_steps.extend(group)
            else:
                # Mark parallel steps
                for i, step in enumerate(group):
                    step['parallel_group'] = f"parallel_{len(optimized_steps)}"
                    step['parallel_index'] = i
                optimized_steps.extend(group)
        
        workflow['steps'] = optimized_steps
        workflow['parallel_groups'] = len([g for g in parallel_groups if len(g) > 1])
        
        return workflow
    
    def _identify_parallel_steps(self, steps: List[Dict]) -> List[List[Dict]]:
        """Identify steps that can be executed in parallel"""
        # Simple implementation - group steps with no dependencies
        parallel_groups = []
        remaining_steps = steps.copy()
        
        while remaining_steps:
            current_group = []
            steps_to_remove = []
            
            for step in remaining_steps:
                # Check if all dependencies are already in previous groups
                deps_met = all(
                    any(dep in s['id'] for s in parallel_groups for s in [s] if isinstance(s, list))
                    for dep in step.get('dependencies', [])
                )
                
                if deps_met:
                    current_group.append(step)
                    steps_to_remove.append(step)
            
            if not current_group:
                # No progress - add remaining steps individually
                for step in remaining_steps:
                    parallel_groups.append([step])
                break
            
            parallel_groups.append(current_group)
            for step in steps_to_remove:
                remaining_steps.remove(step)
        
        return parallel_groups
    
    def _calculate_complexity(self, steps: List[Dict]) -> str:
        """Calculate workflow complexity based on steps and dependencies"""
        step_count = len(steps)
        dependency_count = sum(len(step.get('dependencies', [])) for step in steps)
        
        if step_count <= 3 and dependency_count <= 2:
            return 'low'
        elif step_count <= 6 and dependency_count <= 5:
            return 'medium'
        else:
            return 'high'
    
    def _load_intent_patterns(self) -> Dict:
        """Load intent recognition patterns"""
        return {
            'analyze': {
                'keywords': ['analyze', 'examine', 'review', 'audit', 'assess', 'evaluate'],
                'context': ['data', 'performance', 'metrics', 'reports']
            },
            'optimize': {
                'keywords': ['optimize', 'improve', 'enhance', 'streamline'],
                'context': ['process', 'workflow', 'efficiency', 'performance']
            },
            'automate': {
                'keywords': ['automate', 'automatic', 'workflow'],
                'context': ['manual', 'repetitive', 'process', 'task']
            }
        }
    
    def get_command_history(self) -> List[Dict]:
        """Get history of processed commands"""
        return self.command_history
    
    def get_capabilities(self) -> List[str]:
        """Get system capabilities"""
        return [
            "Natural language understanding",
            "Intent recognition",
            "Entity extraction",
            "Workflow generation",
            "Parallel optimization",
            "Context awareness",
            "Multi-step planning",
            "Error handling"
        ]
