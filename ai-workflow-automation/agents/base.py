"""
Base Agent Class for AI Workflow Automation Platform
Copyright © 2025. All Rights Reserved.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional

class BaseAgent(ABC):
    """Abstract base class for all AI agents"""
    
    def __init__(self, name: str, role: str):
        self.name = name
        self.role = role
        self.capabilities = []
        self.status = "inactive"
        
    @abstractmethod
    async def initialize(self):
        """Initialize the agent"""
        pass
    
    @abstractmethod
    async def execute(self, prompt: str, context: Dict = None) -> Dict:
        """Execute a task with the given prompt"""
        pass
    
    def get_capabilities(self) -> List[str]:
        """Get agent capabilities"""
        return self.capabilities
    
    async def shutdown(self):
        """Shutdown the agent"""
        self.status = "inactive"
