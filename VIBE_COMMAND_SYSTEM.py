#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
VIBE COMMAND SYSTEM - Natural Language Interface for Recon Automation
Based on ThePrimeagen's Vibe Coding Principles

Instead of remembering complex commands like:
  python3 run_pipeline.py --targets targets.txt --mode aggressive

Just say what you want:
  "scan all targets aggressively"
  "find vulnerabilities in example.com"
  "run a quick recon on my high priority targets"
  
The vibe command system translates natural language to actions.
"""

import re
import sys
import subprocess
from pathlib import Path

class VibeCommandSystem:
    """
    Natural language command interpreter for security automation.
    
    Vibe Coding Principle: Problem-first approach
    - Focus on WHAT you want to do, not HOW to do it
    - Let AI/system figure out the technical details
    """
    
    def __init__(self):
        self.base_path = Path(__file__).parent
        
        # Vibe Coding Principle: Pattern matching over rigid syntax
        # Define natural language patterns that map to actions
        self.command_patterns = {
            # Scanning commands
            r'scan (all|everything)': self.scan_all_targets,
            r'scan (.+?) (quickly|fast|quick)': self.quick_scan,
            r'scan (.+?) (aggressively|deep|thorough)': self.aggressive_scan,
            r'find (vulnerabilities|vulns|bugs) in (.+)': self.find_vulns,
            r'recon (.+)': self.run_recon,
            
            # Target management
            r'add target (.+)': self.add_target,
            r'show (targets|domains)': self.show_targets,
            r'(what|which) targets': self.show_targets,
            
            # Results and reports
            r'show (results|findings|output)': self.show_results,
            r'generate report': self.generate_report,
            r'what (did you find|was found)': self.show_results,
            
            # Pipeline control
            r'run pipeline': self.run_pipeline,
            r'run full (scan|pipeline)': self.run_full_pipeline,
            r'stop (everything|all|scans)': self.stop_all,
            
            # Status and monitoring
            r'(status|what.s happening|what are you doing)': self.check_status,
            r'show progress': self.check_status,
            
            # Help and guidance
            r'(help|what can you do|commands)': self.show_help,
        }
    
    def parse_and_execute(self, natural_language_input):
        """
        Vibe Coding Principle: Intent over syntax
        Parse natural language and figure out what the user wants
        """
        input_lower = natural_language_input.lower().strip()
        
        # Try to match against known patterns
        for pattern, action in self.command_patterns.items():
            match = re.search(pattern, input_lower)
            if match:
                # Extract captured groups (if any)
                args = match.groups()
                return action(*args)
        
        # If no match, try to be helpful
        return self.suggest_alternatives(input_lower)
    
    def scan_all_targets(self, *args):
        """Scan all targets in targets.txt"""
        print("🎯 Vibe Command: Scanning ALL targets")
        print("📋 Reading targets from targets.txt...")
        
        cmd = f"python3 {self.base_path}/run_pipeline.py"
        return self.execute_command(cmd, "Full pipeline scan started")
    
    def quick_scan(self, target, *args):
        """Quick scan of a specific target"""
        print(f"⚡ Vibe Command: Quick scan of '{target}'")
        print("🚀 Running fast recon (subdomain enumeration + httpx)")
        
        # Add target if not exists
        self.add_target_to_file(target)
        
        cmd = f"python3 {self.base_path}/run_recon.py && python3 {self.base_path}/run_httpx.py"
        return self.execute_command(cmd, f"Quick scan of {target} started")
    
    def aggressive_scan(self, target, *args):
        """Deep, thorough scan of a target"""
        print(f"🔥 Vibe Command: Aggressive scan of '{target}'")
        print("💪 Running full pipeline with all tools")
        
        self.add_target_to_file(target)
        
        cmd = f"python3 {self.base_path}/run_pipeline.py --aggressive"
        return self.execute_command(cmd, f"Aggressive scan of {target} started")
    
    def find_vulns(self, vuln_type, target):
        """Find specific vulnerabilities in a target"""
        print(f"🔍 Vibe Command: Finding {vuln_type} in '{target}'")
        print("🎯 Running Nuclei with relevant templates")
        
        self.add_target_to_file(target)
        
        cmd = f"python3 {self.base_path}/run_nuclei.py"
        return self.execute_command(cmd, f"Vulnerability scan of {target} started")
    
    def run_recon(self, target):
        """Run reconnaissance on a target"""
        print(f"🔎 Vibe Command: Recon on '{target}'")
        print("📡 Running subdomain enumeration")
        
        self.add_target_to_file(target)
        
        cmd = f"python3 {self.base_path}/run_recon.py"
        return self.execute_command(cmd, f"Recon of {target} started")
    
    def add_target(self, target):
        """Add a target to targets.txt"""
        print(f"➕ Vibe Command: Adding target '{target}'")
        
        self.add_target_to_file(target)
        
        return {
            'status': 'success',
            'message': f"Target '{target}' added to targets.txt",
            'action': 'Would you like to scan it now? Say: "scan {target}"'
        }
    
    def show_targets(self, *args):
        """Show all targets"""
        print("📋 Vibe Command: Showing all targets")
        
        targets_file = self.base_path / 'targets.txt'
        if targets_file.exists():
            with open(targets_file, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            print(f"\n✅ Found {len(targets)} targets:")
            for i, target in enumerate(targets, 1):
                print(f"  {i}. {target}")
            
            return {'status': 'success', 'targets': targets}
        else:
            return {'status': 'error', 'message': 'No targets.txt file found'}
    
    def show_results(self, *args):
        """Show recent scan results"""
        print("📊 Vibe Command: Showing recent results")
        
        output_dir = self.base_path / 'output'
        if output_dir.exists():
            # Find most recent files
            files = sorted(output_dir.rglob('*.txt'), key=lambda x: x.stat().st_mtime, reverse=True)[:5]
            
            print("\n🔍 Recent findings:")
            for file in files:
                size = file.stat().st_size
                print(f"  📄 {file.name} ({size} bytes)")
            
            return {'status': 'success', 'files': [str(f) for f in files]}
        else:
            return {'status': 'info', 'message': 'No results found yet. Run a scan first!'}
    
    def generate_report(self, *args):
        """Generate a summary report"""
        print("📑 Vibe Command: Generating report")
        
        cmd = f"python3 {self.base_path}/scripts/generate_report.py"
        return self.execute_command(cmd, "Report generation started")
    
    def run_pipeline(self, *args):
        """Run the full pipeline"""
        print("🚀 Vibe Command: Running full pipeline")
        
        cmd = f"python3 {self.base_path}/run_pipeline.py"
        return self.execute_command(cmd, "Full pipeline started")
    
    def run_full_pipeline(self, *args):
        """Run complete pipeline with all stages"""
        return self.run_pipeline()
    
    def stop_all(self, *args):
        """Stop all running scans"""
        print("🛑 Vibe Command: Stopping all scans")
        
        # Kill relevant processes
        subprocess.run(['pkill', '-f', 'run_pipeline'], check=False)
        subprocess.run(['pkill', '-f', 'run_recon'], check=False)
        subprocess.run(['pkill', '-f', 'run_nuclei'], check=False)
        
        return {'status': 'success', 'message': 'All scans stopped'}
    
    def check_status(self, *args):
        """Check status of running scans"""
        print("⏳ Vibe Command: Checking status")
        
        # Check for running processes
        result = subprocess.run(['pgrep', '-f', 'run_pipeline'], capture_output=True, text=True)
        
        if result.stdout.strip():
            return {'status': 'running', 'message': 'Scans are currently running'}
        else:
            return {'status': 'idle', 'message': 'No scans running. Ready for new commands!'}
    
    def show_help(self, *args):
        """Show available vibe commands"""
        print("\n💬 VIBE COMMAND SYSTEM - Natural Language Interface")
        print("=" * 60)
        print("\nJust tell me what you want to do in plain English:")
        print("\n🎯 Scanning:")
        print("  • 'scan all targets'")
        print("  • 'scan example.com quickly'")
        print("  • 'scan target.com aggressively'")
        print("  • 'find vulnerabilities in example.com'")
        print("  • 'recon example.com'")
        print("\n📋 Targets:")
        print("  • 'add target example.com'")
        print("  • 'show targets'")
        print("  • 'what targets do I have'")
        print("\n📊 Results:")
        print("  • 'show results'")
        print("  • 'what did you find'")
        print("  • 'generate report'")
        print("\n🎮 Control:")
        print("  • 'run pipeline'")
        print("  • 'stop everything'")
        print("  • 'what's happening'")
        print("\n💡 Tip: Just describe what you want - the system figures out the rest!")
        print("=" * 60)
        
        return {'status': 'help_displayed'}
    
    def suggest_alternatives(self, input_text):
        """Suggest alternatives when command not understood"""
        print(f"\n🤔 Hmm, I'm not sure what '{input_text}' means.")
        print("\n💡 Did you mean one of these?")
        print("  • 'scan all targets' - to scan everything")
        print("  • 'show targets' - to see what targets you have")
        print("  • 'help' - to see all available commands")
        print("\n🎯 Pro tip: Just describe what you want to do in plain English!")
        
        return {'status': 'unknown_command', 'input': input_text}
    
    def add_target_to_file(self, target):
        """Helper: Add target to targets.txt if not exists"""
        targets_file = self.base_path / 'targets.txt'
        
        # Read existing targets
        existing = set()
        if targets_file.exists():
            with open(targets_file, 'r') as f:
                existing = {line.strip() for line in f if line.strip() and not line.startswith('#')}
        
        # Add if not exists
        if target not in existing:
            with open(targets_file, 'a') as f:
                f.write(f"{target}\n")
            print(f"  ✅ Added '{target}' to targets.txt")
        else:
            print(f"  ℹ️  '{target}' already in targets.txt")
    
    def execute_command(self, cmd, success_message):
        """Helper: Execute a shell command"""
        print(f"\n🔧 Executing: {cmd}")
        print(f"✅ {success_message}\n")
        
        try:
            # In interactive mode, run the command
            result = subprocess.run(cmd, shell=True, check=False)
            
            return {
                'status': 'executed',
                'command': cmd,
                'message': success_message,
                'exit_code': result.returncode
            }
        except Exception as e:
            return {
                'status': 'error',
                'command': cmd,
                'error': str(e)
            }

def vibe(command_text):
    """
    Main vibe function - the only function you need to remember!
    
    Usage:
        vibe("scan all targets")
        vibe("find vulnerabilities in example.com")
        vibe("show me what you found")
    """
    system = VibeCommandSystem()
    return system.parse_and_execute(command_text)

def main():
    """
    Interactive vibe coding interface
    """
    print("\n" + "="*60)
    print("🎵 VIBE COMMAND SYSTEM - Natural Language Security Automation")
    print("="*60)
    print("\nType commands in plain English (or 'help' to see examples)")
    print("Type 'exit' or 'quit' to leave\n")
    
    system = VibeCommandSystem()
    
    while True:
        try:
            # Get natural language input
            user_input = input("vibe> ").strip()
            
            # Exit conditions
            if user_input.lower() in ['exit', 'quit', 'bye']:
                print("\n👋 Goodbye! Happy hacking!\n")
                break
            
            # Skip empty input
            if not user_input:
                continue
            
            # Process command
            print()  # Blank line for readability
            result = system.parse_and_execute(user_input)
            print()  # Blank line after execution
            
        except KeyboardInterrupt:
            print("\n\n👋 Interrupted. Type 'exit' to quit.\n")
        except Exception as e:
            print(f"\n❌ Error: {e}\n")

if __name__ == '__main__':
    if len(sys.argv) > 1:
        # Command line mode: run a single command
        command = ' '.join(sys.argv[1:])
        vibe(command)
    else:
        # Interactive mode
        main()
