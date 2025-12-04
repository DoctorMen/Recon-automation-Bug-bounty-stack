#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
# -*- coding: utf-8 -*-
"""
Polymorphic Command System
Learns, upgrades, and executes from natural language commands
"""

import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

class PolymorphicCommandSystem:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.memory_file = self.base_dir / "output" / "polymorphic_memory.json"
        self.safety_file = self.base_dir / "output" / "safety_rules.json"
        self.command_history_file = self.base_dir / "output" / "command_history.json"
        
        # Load memory and safety rules
        self.memory = self.load_memory()
        self.safety_rules = self.load_safety_rules()
        self.command_history = self.load_command_history()
        
        # Command patterns (learned and built-in)
        self.command_patterns = self.load_command_patterns()
        
    def load_memory(self) -> Dict:
        """Load learned patterns and upgrades"""
        if self.memory_file.exists():
            with open(self.memory_file, 'r') as f:
                return json.load(f)
        return {
            "learned_patterns": {},
            "upgrades": [],
            "user_preferences": {},
            "successful_commands": [],
            "failed_commands": []
        }
    
    def save_memory(self):
        """Save learned patterns"""
        self.memory_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.memory_file, 'w') as f:
            json.dump(self.memory, f, indent=2)
    
    def load_safety_rules(self) -> Dict:
        """Load safety rules"""
        if self.safety_file.exists():
            with open(self.safety_file, 'r') as f:
                return json.load(f)
        return {
            "dangerous_patterns": [
                "rm -rf",
                "delete all",
                "format",
                "drop database",
                "sudo rm"
            ],
            "require_confirmation": [
                "delete",
                "remove",
                "overwrite",
                "replace all"
            ],
            "protected_files": [
                "AI_UPWORK_MASTER_KNOWLEDGE_BASE.md",
                "scripts/automate_first_dollar.py",
                "tracking.json"
            ],
            "safe_operations": [
                "generate",
                "create",
                "update",
                "add",
                "show",
                "list",
                "analyze"
            ]
        }
    
    def load_command_history(self) -> List:
        """Load command history"""
        if self.command_history_file.exists():
            with open(self.command_history_file, 'r') as f:
                return json.load(f)
        return []
    
    def save_command_history(self, command: str, result: str, success: bool):
        """Save command to history"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "command": command,
            "result": result,
            "success": success
        }
        self.command_history.append(entry)
        # Keep last 1000 commands
        if len(self.command_history) > 1000:
            self.command_history = self.command_history[-1000:]
        
        with open(self.command_history_file, 'w') as f:
            json.dump(self.command_history, f, indent=2)
    
    def load_command_patterns(self) -> Dict:
        """Load command patterns (learned + built-in)"""
        built_in = {
            "generate": {
                "patterns": ["generate", "create", "make", "build"],
                "handler": self.handle_generate
            },
            "deploy": {
                "patterns": ["deploy", "run", "execute", "start"],
                "handler": self.handle_deploy
            },
            "analyze": {
                "patterns": ["analyze", "check", "review", "examine"],
                "handler": self.handle_analyze
            },
            "update": {
                "patterns": ["update", "upgrade", "improve", "enhance"],
                "handler": self.handle_update
            },
            "track": {
                "patterns": ["track", "log", "record", "save"],
                "handler": self.handle_track
            },
            "show": {
                "patterns": ["show", "display", "list", "view"],
                "handler": self.handle_show
            }
        }
        
        # Merge with learned patterns
        if "learned_patterns" in self.memory:
            built_in.update(self.memory["learned_patterns"])
        
        return built_in
    
    def check_safety(self, command: str) -> Tuple[bool, Optional[str]]:
        """Check if command is safe to execute"""
        command_lower = command.lower()
        
        # Check for dangerous patterns
        for pattern in self.safety_rules["dangerous_patterns"]:
            if pattern in command_lower:
                return False, f"Dangerous pattern detected: {pattern}"
        
        # Check for protected files
        for protected in self.safety_rules["protected_files"]:
            if protected in command and "delete" in command_lower:
                return False, f"Protected file: {protected}"
        
        return True, None
    
    def learn_pattern(self, command: str, result: str, success: bool):
        """Learn from command execution"""
        if success:
            # Extract pattern
            words = command.lower().split()
            if len(words) >= 2:
                key = f"{words[0]}_{words[1]}"
                if key not in self.memory["learned_patterns"]:
                    self.memory["learned_patterns"][key] = {
                        "pattern": command,
                        "result": result,
                        "count": 1
                    }
                else:
                    self.memory["learned_patterns"][key]["count"] += 1
            
            self.memory["successful_commands"].append({
                "command": command,
                "timestamp": datetime.now().isoformat()
            })
        else:
            self.memory["failed_commands"].append({
                "command": command,
                "timestamp": datetime.now().isoformat(),
                "error": result
            })
        
        self.save_memory()
    
    def parse_command(self, command: str) -> Tuple[str, Dict]:
        """Parse natural language command"""
        command_lower = command.lower()
        
        # Check learned patterns first
        for pattern_key, pattern_data in self.memory.get("learned_patterns", {}).items():
            if pattern_data["pattern"].lower() in command_lower:
                return pattern_key, {"original": command, "learned": True}
        
        # Check built-in patterns
        for action, data in self.command_patterns.items():
            for pattern in data["patterns"]:
                if pattern in command_lower:
                    # Extract parameters
                    params = self.extract_parameters(command, action)
                    return action, params
        
        # Default: treat as generate/create
        return "generate", {"original": command, "type": "general"}
    
    def extract_parameters(self, command: str, action: str) -> Dict:
        """Extract parameters from command"""
        params = {"original": command}
        
        # Extract file references
        file_refs = re.findall(r'@(\S+)', command)
        if file_refs:
            params["files"] = file_refs
        
        # Extract keywords
        keywords = {
            "proposal": ["proposal", "template"],
            "report": ["report", "documentation"],
            "website": ["website", "html", "web"],
            "script": ["script", "automation", "tool"],
            "tracking": ["track", "log", "dashboard"]
        }
        
        for key, terms in keywords.items():
            if any(term in command.lower() for term in terms):
                params["type"] = key
                break
        
        # Extract numbers (prices, counts, etc.)
        numbers = re.findall(r'\$?(\d+)', command)
        if numbers:
            params["numbers"] = numbers
        
        return params
    
    def handle_generate(self, params: Dict) -> Tuple[str, bool]:
        """Handle generate/create commands"""
        command = params.get("original", "")
        
        # Check for screenshot processing
        if "screenshot" in command.lower() or "image" in command.lower() or command.endswith(('.png', '.jpg', '.jpeg')):
            return self.process_screenshot(command)
        elif "proposal" in command.lower() or "template" in command.lower():
            return self.generate_proposal(params)
        elif "website" in command.lower() or "html" in command.lower():
            return self.generate_website(params)
        elif "report" in command.lower():
            return self.generate_report(params)
        elif "script" in command.lower() or "automation" in command.lower():
            return self.generate_script(params)
        else:
            return "Generated based on command. Specify type (proposal/website/report/script) for better results.", True
    
    def process_screenshot(self, command: str) -> Tuple[str, bool]:
        """Process screenshot from command"""
        # Extract file path
        import re
        file_match = re.search(r'([/\w\.\-]+\.(png|jpg|jpeg))', command)
        if file_match:
            image_path = file_match.group(1)
        else:
            # Check if command is a file path
            if os.path.exists(command):
                image_path = command
            else:
                return "Screenshot path not found. Provide path to screenshot file.", False
        
        try:
            from screenshot_analyzer import ScreenshotAnalyzer
            analyzer = ScreenshotAnalyzer()
            result = analyzer.analyze_and_execute(image_path)
            return result, True
        except Exception as e:
            return f"Error processing screenshot: {e}", False
    
    def handle_deploy(self, params: Dict) -> Tuple[str, bool]:
        """Handle deploy/execute commands"""
        command = params.get("original", "")
        
        if "proposal" in command.lower():
            return self.deploy_proposal(params)
        elif "scan" in command.lower() or "pipeline" in command.lower():
            return self.deploy_scan(params)
        elif "workflow" in command.lower():
            return self.deploy_workflow(params)
        else:
            return "Deployment initiated. Specify target (proposal/scan/workflow) for better results.", True
    
    def handle_analyze(self, params: Dict) -> Tuple[str, bool]:
        """Handle analyze commands"""
        command = params.get("original", "")
        
        if "tracking" in command.lower() or "performance" in command.lower():
            return self.analyze_tracking()
        elif "knowledge" in command.lower() or "base" in command.lower():
            return self.analyze_knowledge_base()
        else:
            return self.analyze_general(params)
    
    def handle_update(self, params: Dict) -> Tuple[str, bool]:
        """Handle update/upgrade commands"""
        command = params.get("original", "")
        
        if "knowledge" in command.lower():
            return self.update_knowledge_base(params)
        elif "script" in command.lower():
            return self.update_script(params)
        else:
            return "Update initiated. Specify target (knowledge/script) for better results.", True
    
    def handle_track(self, params: Dict) -> Tuple[str, bool]:
        """Handle tracking commands"""
        return self.track_action(params)
    
    def handle_show(self, params: Dict) -> Tuple[str, bool]:
        """Handle show/display commands"""
        command = params.get("original", "")
        
        if "dashboard" in command.lower():
            return self.show_dashboard()
        elif "history" in command.lower():
            return self.show_history()
        elif "memory" in command.lower():
            return self.show_memory()
        else:
            return self.show_general(params)
    
    def generate_proposal(self, params: Dict) -> Tuple[str, bool]:
        """Generate proposal using automation"""
        try:
            client = params.get("client", "Client")
            price = params.get("numbers", ["300"])[0] if params.get("numbers") else "300"
            
            cmd = [
                "python3", "scripts/automate_first_dollar.py",
                "--action", "proposal",
                "--client", client,
                "--price", price
            ]
            
            result = subprocess.run(cmd, cwd=self.base_dir, capture_output=True, text=True)
            return result.stdout if result.returncode == 0 else result.stderr, result.returncode == 0
        except Exception as e:
            return f"Error generating proposal: {e}", False
    
    def generate_website(self, params: Dict) -> Tuple[str, bool]:
        """Generate website"""
        files = params.get("files", [])
        if not files:
            files = ["AI_UPWORK_MASTER_KNOWLEDGE_BASE.md"]
        
        return f"Website generation from {files[0]} - Use: @{files[0]} create Fortune 500 HTML website", True
    
    def generate_report(self, params: Dict) -> Tuple[str, bool]:
        """Generate report"""
        return "Report generation - Specify client name and domain for full report", True
    
    def generate_script(self, params: Dict) -> Tuple[str, bool]:
        """Generate script"""
        return "Script generation - Specify functionality and I'll create it", True
    
    def deploy_proposal(self, params: Dict) -> Tuple[str, bool]:
        """Deploy proposal"""
        return "Proposal deployment - Use automation scripts", True
    
    def deploy_scan(self, params: Dict) -> Tuple[str, bool]:
        """Deploy scan"""
        return "Scan deployment - Specify domain", True
    
    def deploy_workflow(self, params: Dict) -> Tuple[str, bool]:
        """Deploy workflow"""
        return "Workflow deployment - Use quick_client_workflow.py", True
    
    def analyze_tracking(self) -> Tuple[str, bool]:
        """Analyze tracking data"""
        try:
            cmd = ["python3", "scripts/automate_first_dollar.py", "--action", "dashboard"]
            result = subprocess.run(cmd, cwd=self.base_dir, capture_output=True, text=True)
            return result.stdout if result.returncode == 0 else result.stderr, result.returncode == 0
        except Exception as e:
            return f"Error analyzing tracking: {e}", False
    
    def analyze_knowledge_base(self) -> Tuple[str, bool]:
        """Analyze knowledge base"""
        kb_file = self.base_dir / "AI_UPWORK_MASTER_KNOWLEDGE_BASE.md"
        if kb_file.exists():
            size = kb_file.stat().st_size
            return f"Knowledge base: {size} bytes, {len(self.memory.get('learned_patterns', {}))} learned patterns", True
        return "Knowledge base not found", False
    
    def analyze_general(self, params: Dict) -> Tuple[str, bool]:
        """General analysis"""
        return "Analysis complete - Specify target for detailed analysis", True
    
    def update_knowledge_base(self, params: Dict) -> Tuple[str, bool]:
        """Update knowledge base"""
        return "Knowledge base update - Specify what to add/update", True
    
    def update_script(self, params: Dict) -> Tuple[str, bool]:
        """Update script"""
        return "Script update - Specify script and changes", True
    
    def track_action(self, params: Dict) -> Tuple[str, bool]:
        """Track action"""
        return "Action tracked", True
    
    def show_dashboard(self) -> Tuple[str, bool]:
        """Show dashboard"""
        return self.analyze_tracking()
    
    def show_history(self) -> Tuple[str, bool]:
        """Show command history"""
        recent = self.command_history[-10:] if len(self.command_history) > 10 else self.command_history
        output = "Recent Commands:\n"
        for cmd in recent:
            status = "✓" if cmd["success"] else "✗"
            output += f"{status} {cmd['timestamp']}: {cmd['command']}\n"
        return output, True
    
    def show_memory(self) -> Tuple[str, bool]:
        """Show learned patterns"""
        patterns = self.memory.get("learned_patterns", {})
        output = f"Learned Patterns: {len(patterns)}\n"
        for key, data in list(patterns.items())[:10]:
            output += f"  {key}: {data['count']} uses\n"
        return output, True
    
    def show_general(self, params: Dict) -> Tuple[str, bool]:
        """General show command"""
        return "Showing information - Specify what to show (dashboard/history/memory)", True
    
    def execute(self, command: str) -> str:
        """Execute natural language command"""
        # Safety check
        safe, error = self.check_safety(command)
        if not safe:
            return f"❌ Safety check failed: {error}"
        
        # Parse command
        action, params = self.parse_command(command)
        
        # Execute
        if action in self.command_patterns:
            handler = self.command_patterns[action]["handler"]
            result, success = handler(params)
            
            # Learn from execution
            self.learn_pattern(command, result, success)
            self.save_command_history(command, result, success)
            
            # Also capture for manual input learning
            try:
                from manual_input_learner import ManualInputLearner
                learner = ManualInputLearner()
                learner.capture_manual_input(
                    input_type="command",
                    content=command,
                    context="Polymorphic command execution",
                    result=result,
                    success=success
                )
            except Exception:
                pass  # Graceful failure if manual learner not available
            
            status = "✅" if success else "⚠️"
            return f"{status} {result}"
        else:
            return f"❓ Command not recognized: {command}. Learning pattern..."
    
    def auto_upgrade(self):
        """Automatically upgrade system based on learned patterns"""
        upgrades = []
        
        # Check for frequently used patterns
        patterns = self.memory.get("learned_patterns", {})
        for key, data in patterns.items():
            if data["count"] > 5:
                upgrades.append({
                    "pattern": key,
                    "usage": data["count"],
                    "suggestion": f"Add '{key}' as built-in pattern"
                })
        
        # Check for failed commands that could be improved
        failed = self.memory.get("failed_commands", [])
        if len(failed) > 0:
            upgrades.append({
                "type": "error_handling",
                "suggestion": f"Improve error handling for {len(failed)} failed commands"
            })
        
        return upgrades


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 polymorphic_command_system.py 'your command here'")
        print("\nExamples:")
        print("  python3 polymorphic_command_system.py 'generate proposal for Acme Corp $300'")
        print("  python3 polymorphic_command_system.py 'show dashboard'")
        print("  python3 polymorphic_command_system.py 'analyze tracking'")
        sys.exit(1)
    
    command = " ".join(sys.argv[1:])
    system = PolymorphicCommandSystem()
    result = system.execute(command)
    print(result)
    
    # Show auto-upgrades if any
    upgrades = system.auto_upgrade()
    if upgrades:
        print("\n💡 Suggested Upgrades:")
        for upgrade in upgrades[:3]:
            print(f"  • {upgrade.get('suggestion', 'Upgrade available')}")


if __name__ == "__main__":
    main()

