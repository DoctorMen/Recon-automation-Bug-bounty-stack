"""
Configuration Management for AI Workflow Automation Platform
Copyright © 2025. All Rights Reserved.
"""

import json
import os
from typing import Dict, Any, Optional

class Config:
    """Manages platform configuration"""
    
    def __init__(self, config_path: str = "config/platform.json"):
        self.config_path = config_path
        self.config = self._load_default_config()
        
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration"""
        return {
            "platform": {
                "name": "AI Workflow Automation Platform",
                "version": "1.0.0",
                "debug": False
            },
            "agents": {
                "max_concurrent": 5,
                "timeout": 300,
                "retry_attempts": 3
            },
            "ai_models": {
                "primary": "gpt-4",
                "fallback": "claude-3",
                "max_tokens": 4000,
                "temperature": 0.7
            },
            "performance": {
                "metrics_enabled": True,
                "log_level": "INFO",
                "cache_enabled": True
            }
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
                
        return value
    
    def set(self, key: str, value: Any):
        """Set configuration value by key"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
            
        config[keys[-1]] = value
    
    def load_from_file(self, path: Optional[str] = None):
        """Load configuration from file"""
        file_path = path or self.config_path
        
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                file_config = json.load(f)
                self.config.update(file_config)
    
    def save_to_file(self, path: Optional[str] = None):
        """Save configuration to file"""
        file_path = path or self.config_path
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        with open(file_path, 'w') as f:
            json.dump(self.config, f, indent=2)
