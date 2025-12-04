#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
# -*- coding: utf-8 -*-
"""
Natural Language Bridge - Perfect Human ↔ Machine Translation
Translates between human language and system commands
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional

class NaturalLanguageBridge:
    """
    Translates between human requests and machine commands
    """
    
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        
        # Human → Machine patterns
        self.intent_patterns = {
            # MONEY MAKING
            "make money": "python3 scripts/money_making_toolkit.py potential",
            "need money": "python3 scripts/roi_plan_generator.py immediate",
            "earn today": "python3 scripts/multi_platform_domination.py strategy 8",
            "get paid": "python3 scripts/money_making_toolkit.py dashboard",
            
            # PROPOSALS
            "write proposal": "python3 scripts/multi_platform_domination.py proposal upwork {budget}",
            "create proposal": "python3 scripts/money_making_toolkit.py proposal {job_id} {budget} {urgent}",
            "generate bid": "python3 scripts/multi_platform_domination.py proposal freelancer {budget}",
            
            # PRICING
            "what price": "python3 scripts/money_making_toolkit.py price {budget} {urgency}",
            "how much charge": "python3 scripts/multi_platform_domination.py price {platform} {budget} {reviews}",
            "optimal price": "python3 scripts/money_making_toolkit.py price {budget} urgent",
            
            # CLIENT EVALUATION
            "good client": "python3 scripts/money_making_toolkit.py score '{client_data}'",
            "should apply": "python3 scripts/money_making_toolkit.py score '{client_data}'",
            "client worth it": "python3 scripts/money_making_toolkit.py score '{client_data}'",
            
            # SCANNING
            "scan domain": "python3 run_pipeline.py --target {domain} --output output/{client}",
            "run security scan": "./scripts/first_dollar_cli.sh workflow {client} {domain} {amount}",
            "vulnerability scan": "python3 run_pipeline.py --target {domain}",
            
            # TRACKING
            "track application": "python3 scripts/money_making_toolkit.py track {job_id} {budget}",
            "mark won": "python3 scripts/money_making_toolkit.py won {job_id} {revenue}",
            "show dashboard": "python3 scripts/money_making_toolkit.py dashboard",
            "check earnings": "python3 scripts/money_making_toolkit.py dashboard",
            
            # PLATFORM STRATEGY
            "best platform": "python3 scripts/multi_platform_domination.py recommend",
            "which platform": "python3 scripts/multi_platform_domination.py recommend",
            "platform strategy": "python3 scripts/multi_platform_domination.py strategy {hours}",
            
            # FIVERR
            "fiverr gig": "python3 scripts/multi_platform_domination.py fiverr-gig",
            "optimize fiverr": "python3 scripts/multi_platform_domination.py fiverr-gig",
            
            # SYSTEM STATUS
            "system status": "python3 scripts/polymorphic_moat_builder.py status",
            "check progress": "python3 scripts/manual_input_learner.py summary",
            "show stats": "python3 scripts/money_making_toolkit.py dashboard",
        }
        
        # Machine → Human explanations
        self.command_explanations = {
            "python3 run_pipeline.py": "Run complete security scan on target domain",
            "python3 scripts/money_making_toolkit.py": "Money-making optimization tools",
            "python3 scripts/multi_platform_domination.py": "Multi-platform freelance tools",
            "python3 scripts/generate_report.py": "Generate professional security report",
            "./scripts/first_dollar_cli.sh": "Complete client workflow automation",
        }
    
    def human_to_machine(self, human_input: str) -> Dict:
        """
        Convert human language to machine command
        
        Examples:
        "I need money today" → python3 scripts/roi_plan_generator.py immediate
        "What price should I charge for $300 job?" → python3 scripts/money_making_toolkit.py price 300 normal
        "Should I apply to this client?" → python3 scripts/money_making_toolkit.py score {...}
        """
        human_input = human_input.lower().strip()
        
        # Extract parameters
        budget = self._extract_number(human_input, "budget")
        domain = self._extract_domain(human_input)
        job_id = self._extract_job_id(human_input)
        
        # Match intent
        for intent, command_template in self.intent_patterns.items():
            if intent in human_input:
                # Fill in parameters
                command = command_template
                
                if "{budget}" in command:
                    command = command.replace("{budget}", str(budget or 300))
                if "{domain}" in command:
                    command = command.replace("{domain}", domain or "example.com")
                if "{job_id}" in command:
                    command = command.replace("{job_id}", job_id or "job1")
                if "{urgent}" in command:
                    is_urgent = any(word in human_input for word in ["urgent", "asap", "emergency", "now"])
                    command = command.replace("{urgent}", "true" if is_urgent else "false")
                if "{platform}" in command:
                    platform = self._extract_platform(human_input)
                    command = command.replace("{platform}", platform or "upwork")
                if "{urgency}" in command:
                    urgency = "urgent" if any(word in human_input for word in ["urgent", "asap", "emergency"]) else "normal"
                    command = command.replace("{urgency}", urgency)
                if "{hours}" in command:
                    hours = self._extract_number(human_input, "hours") or 4
                    command = command.replace("{hours}", str(hours))
                if "{client}" in command:
                    client = self._extract_client_name(human_input)
                    command = command.replace("{client}", client or "Client")
                if "{amount}" in command:
                    command = command.replace("{amount}", str(budget or 300))
                if "{reviews}" in command:
                    command = command.replace("{reviews}", "0")
                
                return {
                    "understood": True,
                    "intent": intent,
                    "command": command,
                    "explanation": self._explain_command(command),
                    "human_friendly": self._humanize_command(command)
                }
        
        # No match found
        return {
            "understood": False,
            "intent": "unknown",
            "suggestion": "Try: 'I need money today' or 'write proposal for $300' or 'what's the best platform?'",
            "available_commands": list(self.intent_patterns.keys())[:10]
        }
    
    def machine_to_human(self, command: str) -> str:
        """
        Convert machine command to human-friendly explanation
        
        Example:
        "python3 scripts/money_making_toolkit.py price 300 urgent"
        → "Calculate the optimal price for a $300 urgent job to maximize win rate and revenue"
        """
        command = command.strip()
        
        # Pattern matching for specific commands
        if "money_making_toolkit.py price" in command:
            parts = command.split()
            budget = parts[-2] if len(parts) > 3 else "300"
            urgency = parts[-1] if len(parts) > 4 else "normal"
            return f"Calculate optimal price for ${budget} {urgency} job to win while maximizing revenue"
        
        elif "money_making_toolkit.py proposal" in command:
            parts = command.split()
            budget = parts[-2] if len(parts) > 3 else "300"
            return f"Generate winning proposal for ${budget} job optimized for high conversion"
        
        elif "money_making_toolkit.py dashboard" in command:
            return "Show complete earnings dashboard: today's stats, win rate, total revenue"
        
        elif "money_making_toolkit.py potential" in command:
            return "Calculate how much money you can realistically earn today"
        
        elif "multi_platform_domination.py proposal" in command:
            parts = command.split()
            platform = parts[-2] if "proposal" in parts else "upwork"
            return f"Generate proposal optimized specifically for {platform.capitalize()}'s algorithm"
        
        elif "multi_platform_domination.py recommend" in command:
            return "Analyze your performance data and recommend which platform to focus on"
        
        elif "multi_platform_domination.py strategy" in command:
            parts = command.split()
            hours = parts[-1] if parts else "4"
            return f"Create optimal strategy for spending {hours} hours across all platforms for max earnings"
        
        elif "run_pipeline.py" in command:
            return "Execute complete security scan: reconnaissance + vulnerability detection + reporting"
        
        elif "first_dollar_cli.sh workflow" in command:
            return "Complete client delivery: run scan, generate report, track project, build moats"
        
        elif "roi_plan_generator.py immediate" in command:
            return "Generate step-by-step plan to earn money in next 4 hours"
        
        # Generic explanation
        for cmd_prefix, explanation in self.command_explanations.items():
            if cmd_prefix in command:
                return explanation
        
        return f"Execute: {command}"
    
    def _extract_number(self, text: str, context: str = "budget") -> Optional[int]:
        """Extract numbers (budget, price, etc.)"""
        # Look for $300, 300, etc.
        patterns = [r'\$(\d+)', r'(\d+)\s*dollars?', r'(\d+)\s*usd', r'(?<!\d)(\d{2,5})(?!\d)']
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return int(match.group(1))
        return None
    
    def _extract_domain(self, text: str) -> Optional[str]:
        """Extract domain names"""
        pattern = r'(?:https?://)?(?:www\.)?([a-zA-Z0-9-]+\.[a-zA-Z]{2,})'
        match = re.search(pattern, text)
        return match.group(1) if match else None
    
    def _extract_job_id(self, text: str) -> Optional[str]:
        """Extract job IDs"""
        pattern = r'job\s*[#:]?\s*([a-zA-Z0-9_-]+)'
        match = re.search(pattern, text.lower())
        return match.group(1) if match else None
    
    def _extract_platform(self, text: str) -> Optional[str]:
        """Extract platform names"""
        platforms = ["upwork", "fiverr", "freelancer", "peopleperhour", "guru"]
        for platform in platforms:
            if platform in text.lower():
                return platform
        return None
    
    def _extract_client_name(self, text: str) -> Optional[str]:
        """Extract client names"""
        pattern = r'client[:\s]+([A-Z][a-zA-Z\s]+)'
        match = re.search(pattern, text)
        return match.group(1).strip() if match else None
    
    def _explain_command(self, command: str) -> str:
        """Explain what a command does"""
        return self.machine_to_human(command)
    
    def _humanize_command(self, command: str) -> str:
        """Create human-friendly version of command"""
        # Simplify for display
        if "money_making_toolkit.py" in command:
            return f"💰 {self._explain_command(command)}"
        elif "multi_platform_domination.py" in command:
            return f"🚀 {self._explain_command(command)}"
        elif "run_pipeline.py" in command:
            return f"🔒 {self._explain_command(command)}"
        else:
            return f"⚡ {self._explain_command(command)}"
    
    def interactive_mode(self):
        """Interactive natural language shell"""
        print("="*60)
        print("🗣️  NATURAL LANGUAGE BRIDGE - Interactive Mode")
        print("="*60)
        print("\nTalk to me in plain English, I'll translate to commands.")
        print("Examples:")
        print('  "I need money today"')
        print('  "Write a proposal for $300"')
        print('  "What\'s the best platform?"')
        print("\nType 'exit' to quit.\n")
        
        while True:
            try:
                user_input = input("You: ").strip()
                
                if not user_input:
                    continue
                
                if user_input.lower() in ['exit', 'quit', 'q']:
                    print("👋 Goodbye!")
                    break
                
                result = self.human_to_machine(user_input)
                
                if result["understood"]:
                    print(f"\n✅ I understand: {result['intent']}")
                    print(f"🗣️  Human: {result['human_friendly']}")
                    print(f"🤖 Machine: {result['command']}")
                    print(f"\nRun this? (y/n): ", end="")
                    
                    confirm = input().strip().lower()
                    if confirm == 'y':
                        import subprocess
                        print("\n🚀 Executing...\n")
                        subprocess.run(result['command'], shell=True, cwd=self.base_dir)
                else:
                    print(f"\n❌ Hmm, I didn't understand that.")
                    print(f"💡 Suggestion: {result['suggestion']}")
                
                print("\n" + "-"*60 + "\n")
                
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"\n⚠️  Error: {e}\n")


def main():
    """CLI interface"""
    import sys
    
    bridge = NaturalLanguageBridge()
    
    if len(sys.argv) < 2:
        print("🗣️  Natural Language Bridge - Commands:")
        print("\n  TRANSLATE HUMAN TO MACHINE:")
        print('    python3 scripts/natural_language_bridge.py "I need money today"')
        print('    python3 scripts/natural_language_bridge.py "Write proposal for $300"')
        print('    python3 scripts/natural_language_bridge.py "What price should I charge?"')
        print("\n  TRANSLATE MACHINE TO HUMAN:")
        print('    python3 scripts/natural_language_bridge.py --explain "python3 scripts/money_making_toolkit.py price 300 urgent"')
        print("\n  INTERACTIVE MODE:")
        print('    python3 scripts/natural_language_bridge.py --interactive')
        return
    
    if sys.argv[1] == "--interactive" or sys.argv[1] == "-i":
        bridge.interactive_mode()
    elif sys.argv[1] == "--explain" or sys.argv[1] == "-e":
        if len(sys.argv) < 3:
            print("❌ Please provide command to explain")
            return
        command = " ".join(sys.argv[2:])
        explanation = bridge.machine_to_human(command)
        print(f"🗣️  {explanation}")
    else:
        # Translate human input to machine
        human_input = " ".join(sys.argv[1:])
        result = bridge.human_to_machine(human_input)
        
        if result["understood"]:
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

