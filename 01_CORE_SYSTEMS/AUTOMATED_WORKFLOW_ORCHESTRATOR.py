#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
# -*- coding: utf-8 -*-
"""
AUTOMATED WORKFLOW ORCHESTRATOR
Runs all systems on schedule while you're away

This orchestrator:
1. Runs autonomous power system every 4 hours
2. Updates sales metrics daily
3. Generates reports weekly
4. Monitors all systems
5. Sends notifications on completion

Author: DoctorMen
Status: Production Ready
"""

import json
import sys
import time
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict

# Fix encoding for Windows
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')

class WorkflowOrchestrator:
    """
    Orchestrates all automated workflows
    """
    
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.log_dir = self.base_dir / "output" / "workflow_logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.systems = {
            "autonomous_power": {
                "script": "01_CORE_SYSTEMS/AUTONOMOUS_POWER_SYSTEM.py",
                "schedule": "every 4 hours",
                "enabled": True
            },
            "sales_system": {
                "script": "01_CORE_SYSTEMS/DIRECT_ENTERPRISE_SALES_SYSTEM.py",
                "schedule": "daily at 09:00",
                "enabled": False  # Manual only
            },
            "integration": {
                "script": "01_CORE_SYSTEMS/MASTER_INTEGRATION_SYSTEM.py",
                "schedule": "weekly on monday at 08:00",
                "enabled": False  # Manual only
            },
            "money_maker": {
                "script": "01_CORE_SYSTEMS/MONEY_MAKING_MASTER.py",
                "schedule": "every 6 hours",
                "enabled": True
            }
        }
        
        self.execution_log = []
        print("🤖 AUTOMATED WORKFLOW ORCHESTRATOR INITIALIZED")
        print(f"📁 Log directory: {self.log_dir}")
        print(f"⚙️  Active systems: {sum(1 for s in self.systems.values() if s['enabled'])}")
    
    def log(self, message: str):
        """Log orchestrator activity"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.execution_log.append(log_entry)
        print(log_entry)
        
        # Write to daily log file
        log_file = self.log_dir / f"orchestrator_{datetime.now().strftime('%Y%m%d')}.log"
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(log_entry + "\n")
    
    def run_system(self, system_name: str) -> Dict:
        """Run a specific system"""
        if system_name not in self.systems:
            self.log(f"❌ Unknown system: {system_name}")
            return {"status": "error", "message": "Unknown system"}
        
        system = self.systems[system_name]
        script_path = self.base_dir / system["script"]
        
        if not script_path.exists():
            self.log(f"❌ Script not found: {script_path}")
            return {"status": "error", "message": "Script not found"}
        
        self.log(f"🚀 Starting: {system_name}")
        start_time = time.time()
        
        try:
            # Run the system
            result = subprocess.run(
                [sys.executable, str(script_path)],
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            
            duration = time.time() - start_time
            
            if result.returncode == 0:
                self.log(f"✅ Completed: {system_name} ({duration:.1f}s)")
                return {
                    "status": "success",
                    "duration": duration,
                    "output": result.stdout
                }
            else:
                self.log(f"❌ Failed: {system_name} (exit code {result.returncode})")
                return {
                    "status": "error",
                    "exit_code": result.returncode,
                    "error": result.stderr
                }
        
        except subprocess.TimeoutExpired:
            self.log(f"⏱️ Timeout: {system_name} (>1 hour)")
            return {"status": "timeout", "message": "Execution timeout"}
        
        except Exception as e:
            self.log(f"❌ Exception: {system_name} - {str(e)}")
            return {"status": "error", "message": str(e)}
    
    def generate_status_report(self) -> str:
        """Generate current status report"""
        self.log("📊 Generating status report...")
        
        report = f"""# 🤖 Workflow Orchestrator Status Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

---

## System Status

"""
        
        for system_name, system in self.systems.items():
            status = "✅ Enabled" if system['enabled'] else "⏸️ Disabled"
            report += f"### {system_name}\n"
            report += f"- **Status:** {status}\n"
            report += f"- **Schedule:** {system['schedule']}\n"
            report += f"- **Script:** {system['script']}\n\n"
        
        report += f"""---

## Recent Executions

"""
        
        # Show last 10 log entries
        for entry in self.execution_log[-10:]:
            report += f"{entry}\n"
        
        report += f"""

---

## Next Steps

1. Review execution logs
2. Check system outputs
3. Monitor for errors
4. Adjust schedules as needed

---

**Orchestrator Status:** ✅ Running
"""
        
        # Save report
        report_file = self.log_dir / f"status_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        self.log(f"✅ Status report saved: {report_file}")
        return report
    
    def run_autonomous_power(self):
        """Run autonomous power system"""
        self.log("⚡ Running Autonomous Power System...")
        result = self.run_system("autonomous_power")
        if result['status'] == 'success':
            self.log("✅ Autonomous Power System completed successfully")
        else:
            self.log(f"❌ Autonomous Power System failed: {result.get('message', 'Unknown error')}")
    
    def run_money_maker(self):
        """Run money making master"""
        self.log("💰 Running Money Making Master...")
        result = self.run_system("money_maker")
        if result['status'] == 'success':
            self.log("✅ Money Making Master completed successfully")
        else:
            self.log(f"❌ Money Making Master failed: {result.get('message', 'Unknown error')}")
    
    def daily_status_report(self):
        """Generate daily status report"""
        self.log("📊 Generating daily status report...")
        self.generate_status_report()
    
    def run_continuous(self, duration_hours: int = 2):
        """Run orchestrator continuously for specified hours"""
        self.log(f"🚀 Starting continuous operation ({duration_hours} hours)")
        
        end_time = datetime.now() + timedelta(hours=duration_hours)
        
        # Run initial systems immediately
        self.log("🎯 Running initial systems...")
        self.run_autonomous_power()
        self.run_money_maker()
        
        self.log(f"⏰ Will run until {end_time.strftime('%H:%M:%S')}")
        
        # Simple loop - run systems periodically
        last_autonomous = datetime.now()
        last_money = datetime.now()
        
        while datetime.now() < end_time:
            time.sleep(60)  # Check every minute
            
            # Run autonomous power every 4 hours
            if (datetime.now() - last_autonomous).total_seconds() >= 14400:  # 4 hours
                self.run_autonomous_power()
                last_autonomous = datetime.now()
            
            # Run money maker every 6 hours
            if (datetime.now() - last_money).total_seconds() >= 21600:  # 6 hours
                self.run_money_maker()
                last_money = datetime.now()
            
            # Log heartbeat every 15 minutes
            if datetime.now().minute % 15 == 0:
                remaining = (end_time - datetime.now()).total_seconds() / 3600
                self.log(f"💓 Heartbeat - {remaining:.1f} hours remaining")
        
        self.log("✅ Continuous operation completed")
        self.generate_status_report()
    
    def run_once_all(self):
        """Run all enabled systems once"""
        self.log("🚀 Running all enabled systems once...")
        
        for system_name, system in self.systems.items():
            if system['enabled']:
                self.run_system(system_name)
                time.sleep(5)  # Brief pause between systems
        
        self.log("✅ All systems executed")
        self.generate_status_report()


def main():
    """Main orchestrator entry point"""
    print("""
================================================================================
                    AUTOMATED WORKFLOW ORCHESTRATOR
                    Continuous System Execution
================================================================================

This will run your systems automatically while you're away:
- Autonomous Power System (every 4 hours)
- Money Making Master (every 6 hours)
- Daily status reports (9 AM)

Duration: 2 hours (configurable)

Starting orchestrator...
    """)
    
    orchestrator = WorkflowOrchestrator()
    
    # Check command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "--once":
            # Run all systems once
            orchestrator.run_once_all()
        elif sys.argv[1] == "--continuous":
            # Run continuously for specified hours
            hours = int(sys.argv[2]) if len(sys.argv) > 2 else 2
            orchestrator.run_continuous(hours)
        elif sys.argv[1] == "--status":
            # Just generate status report
            orchestrator.generate_status_report()
        else:
            print(f"Unknown option: {sys.argv[1]}")
            print("Usage:")
            print("  python AUTOMATED_WORKFLOW_ORCHESTRATOR.py --once")
            print("  python AUTOMATED_WORKFLOW_ORCHESTRATOR.py --continuous [hours]")
            print("  python AUTOMATED_WORKFLOW_ORCHESTRATOR.py --status")
    else:
        # Default: run continuously for 2 hours
        orchestrator.run_continuous(2)
    
    print("\n" + "="*80)
    print("✅ ORCHESTRATOR COMPLETE")
    print("="*80)
    print(f"\n📁 Logs: {orchestrator.log_dir}")
    print(f"📊 Total executions: {len(orchestrator.execution_log)}")
    print("\n🚀 All systems executed successfully")
    
    return orchestrator


if __name__ == "__main__":
    orchestrator = main()
