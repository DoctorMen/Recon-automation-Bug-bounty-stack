"""
Prompt Templates for AI Workflow Automation Platform
Copyright © 2025. All Rights Reserved.
"""

class PromptTemplates:
    """Manages prompt templates for different agent types and scenarios"""
    
    def __init__(self):
        self.templates = {
            'workflow_planning': """
Analyze the following business requirement and create a structured workflow plan:

Requirement: {command}
Context: {context}

Break this down into specific, actionable steps that can be executed by AI agents.
For each step, specify:
1. The agent type best suited for the task
2. A clear prompt for the agent
3. Dependencies on other steps
4. Expected output

Focus on efficiency, parallel execution where possible, and measurable outcomes.
""",
            
            'analysis_task': """
You are an AI analyst. Process the following task:

{prompt}

Provide detailed analysis with:
- Key findings
- Data-driven insights
- Recommendations
- Risk assessment
""",
            
            'optimization_task': """
You are an optimization specialist. Analyze and improve:

{prompt}

Identify:
- Current inefficiencies
- Bottlenecks
- Optimization opportunities
- Implementation plan
""",
            
            'automation_task': """
You are an automation engineer. Design automation for:

{prompt}

Include:
- Process mapping
- Automation triggers
- Error handling
- Monitoring requirements
""",
            
            'documentation_task': """
You are a documentation specialist. Create documentation for:

{prompt}

Ensure:
- Clear structure
- Executive summary
- Technical details
- Action items
"""
        }
    
    def get_workflow_planning_prompt(self, command: str, context: dict = None) -> str:
        """Get prompt for workflow planning"""
        context_str = str(context) if context else "No additional context"
        return self.templates['workflow_planning'].format(
            command=command,
            context=context_str
        )
    
    def get_agent_prompt(self, agent_type: str, task: str) -> str:
        """Get prompt for specific agent type"""
        template_key = f"{agent_type}_task"
        if template_key in self.templates:
            return self.templates[template_key].format(prompt=task)
        return f"Execute the following task: {task}"
