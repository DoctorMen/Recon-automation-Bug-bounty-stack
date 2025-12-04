#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
🚨 EMERGENCY STOP SYSTEM
Immediately halt all security operations and notify client

Use this if ANYTHING goes wrong during testing:
- Unexpected system behavior
- Production impact detected
- Scope violation suspected
- Any other emergency situation
"""

import os
import sys
import json
import signal
import psutil
from datetime import datetime
from pathlib import Path
from typing import List, Dict

class EmergencyStop:
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.safety_db = self.project_root / "data" / "safety"
        self.safety_db.mkdir(parents=True, exist_ok=True)
        
        self.incident_log = self.safety_db / "incidents.json"
        self.running_ops = self.safety_db / "running_operations.json"
        
        if not self.incident_log.exists():
            self._save_json(self.incident_log, {"incidents": []})
    
    def emergency_stop_all(self, reason: str, notify_client: bool = True):
        """
        🚨 EMERGENCY: Stop all running security operations
        
        Args:
            reason: Why the emergency stop was triggered
            notify_client: Whether to generate client notification
        """
        
        print("\n" + "="*70)
        print("🚨 EMERGENCY STOP INITIATED")
        print("="*70)
        print(f"Reason: {reason}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70 + "\n")
        
        # Step 1: Kill all running scan processes
        print("⏹️  Stopping all running scan processes...")
        stopped_processes = self._kill_scan_processes()
        print(f"   Stopped {len(stopped_processes)} process(es)\n")
        
        # Step 2: Log incident
        print("📝 Logging incident...")
        incident_id = self._log_incident(reason, stopped_processes)
        print(f"   Incident ID: {incident_id}\n")
        
        # Step 3: Generate client notification
        if notify_client:
            print("📧 Generating client notification...")
            notification = self._generate_client_notification(incident_id, reason)
            notification_file = self.safety_db / f"incident_{incident_id}_notification.txt"
            notification_file.write_text(notification)
            print(f"   Notification saved to: {notification_file}\n")
        
        # Step 4: Create incident report
        print("📄 Creating incident report...")
        report = self._generate_incident_report(incident_id, reason, stopped_processes)
        report_file = self.safety_db / f"incident_{incident_id}_report.txt"
        report_file.write_text(report)
        print(f"   Report saved to: {report_file}\n")
        
        print("="*70)
        print("✅ EMERGENCY STOP COMPLETE")
        print("="*70)
        print("\nNEXT STEPS:")
        print("1. Review incident report")
        print("2. Notify client (use generated notification)")
        print("3. Assess any impact to target systems")
        print("4. Document lessons learned")
        print("5. Update procedures if needed")
        print("\nIncident files:")
        print(f"  - Report: {report_file}")
        if notify_client:
            print(f"  - Client notification: {notification_file}")
        print("="*70 + "\n")
        
        return incident_id
    
    def _kill_scan_processes(self) -> List[Dict]:
        """Kill all running scan processes"""
        stopped = []
        
        # Process names to look for
        scan_processes = [
            "subfinder", "assetfinder", "amass",
            "nuclei", "httpx", "nmap",
            "python", "python3"  # Our own scripts
        ]
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                proc_info = proc.info
                proc_name = proc_info['name'].lower()
                cmdline = ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else ""
                
                # Check if this is a scan process
                if any(scan_proc in proc_name for scan_proc in scan_processes):
                    # Check if it's related to our scanning
                    if any(keyword in cmdline.lower() for keyword in ['scan', 'recon', 'nuclei', 'subfinder']):
                        print(f"   Stopping: {proc_name} (PID: {proc_info['pid']})")
                        proc.terminate()
                        
                        stopped.append({
                            "pid": proc_info['pid'],
                            "name": proc_name,
                            "cmdline": cmdline
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return stopped
    
    def _log_incident(self, reason: str, stopped_processes: List[Dict]) -> str:
        """Log incident to database"""
        incident_data = self._load_json(self.incident_log)
        
        incident_id = f"INC{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        incident = {
            "incident_id": incident_id,
            "timestamp": datetime.now().isoformat(),
            "reason": reason,
            "stopped_processes": stopped_processes,
            "stopped_count": len(stopped_processes),
            "reported_to_client": False,
            "resolved": False,
            "resolution_notes": ""
        }
        
        incident_data["incidents"].append(incident)
        self._save_json(self.incident_log, incident_data)
        
        return incident_id
    
    def _generate_client_notification(self, incident_id: str, reason: str) -> str:
        """Generate client notification text"""
        return f"""
SECURITY TESTING INCIDENT NOTIFICATION

Incident ID: {incident_id}
Date/Time: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}

Dear Client,

We are writing to inform you that we have immediately halted all security 
testing activities on your systems as a precautionary measure.

REASON FOR STOPPAGE:
{reason}

ACTIONS TAKEN:
✓ All automated scans stopped immediately
✓ All running processes terminated
✓ Incident logged for review
✓ This notification generated

CURRENT STATUS:
- All testing activities are STOPPED
- No further scanning will occur until we receive your approval
- We are standing by to assess any impact

NEXT STEPS:
1. Please confirm receipt of this notification
2. We will assess the situation and provide a detailed incident report
3. We will coordinate with your team to verify system status
4. Testing will only resume with your explicit approval

CONTACT INFORMATION:
Emergency Contact: [YOUR PHONE]
Email: [YOUR EMAIL]
Available: 24/7 for this incident

We apologize for any inconvenience and appreciate your understanding. 
Your system security and stability are our top priorities.

Professional Regards,
[YOUR NAME]
Security Testing Team

---
INCIDENT REFERENCE: {incident_id}
GENERATED: {datetime.now().isoformat()}
"""
    
    def _generate_incident_report(self, incident_id: str, reason: str, stopped_processes: List[Dict]) -> str:
        """Generate detailed incident report"""
        return f"""
SECURITY TESTING INCIDENT REPORT

INCIDENT OVERVIEW
================================================================================
Incident ID: {incident_id}
Date/Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Status: Emergency stop activated

INCIDENT TRIGGER
================================================================================
Reason: {reason}

ACTIONS TAKEN
================================================================================
1. Emergency stop initiated
2. All running processes terminated ({len(stopped_processes)} total)
3. Client notification generated
4. Incident logged for audit trail

STOPPED PROCESSES
================================================================================
{self._format_process_list(stopped_processes)}

TIMELINE
================================================================================
{datetime.now().strftime('%H:%M:%S')} - Incident detected
{datetime.now().strftime('%H:%M:%S')} - Emergency stop initiated
{datetime.now().strftime('%H:%M:%S')} - Processes terminated
{datetime.now().strftime('%H:%M:%S')} - Client notification prepared
{datetime.now().strftime('%H:%M:%S')} - Incident report generated

IMPACT ASSESSMENT
================================================================================
[ ] No impact detected
[ ] Minor impact (explain below)
[ ] Moderate impact (explain below)
[ ] Significant impact (explain below)

Notes: [TO BE FILLED IN AFTER ASSESSMENT]

ROOT CAUSE ANALYSIS
================================================================================
[TO BE FILLED IN AFTER INVESTIGATION]

CORRECTIVE ACTIONS
================================================================================
[TO BE FILLED IN]

PREVENTIVE MEASURES
================================================================================
[TO BE FILLED IN]

CLIENT COMMUNICATION
================================================================================
[ ] Client notified
[ ] Client acknowledged
[ ] Situation explained
[ ] Approval received to resume (if applicable)

LESSONS LEARNED
================================================================================
[TO BE FILLED IN]

SIGN-OFF
================================================================================
Prepared by: [YOUR NAME]
Date: {datetime.now().strftime('%Y-%m-%d')}
Review required: Yes

Reviewed by: ___________________________
Date: _______________

================================================================================
END OF INCIDENT REPORT - {incident_id}
================================================================================
"""
    
    def _format_process_list(self, processes: List[Dict]) -> str:
        """Format process list for report"""
        if not processes:
            return "No processes were running"
        
        lines = []
        for i, proc in enumerate(processes, 1):
            lines.append(f"{i}. {proc['name']} (PID: {proc['pid']})")
            lines.append(f"   Command: {proc['cmdline'][:100]}...")
            lines.append("")
        
        return "\n".join(lines)
    
    def list_incidents(self):
        """List all recorded incidents"""
        incident_data = self._load_json(self.incident_log)
        incidents = incident_data.get("incidents", [])
        
        if not incidents:
            print("✅ No incidents recorded")
            return
        
        print(f"\n{'='*70}")
        print(f"📋 INCIDENT LOG ({len(incidents)} total)")
        print(f"{'='*70}\n")
        
        for incident in incidents:
            status = "🔴 UNRESOLVED" if not incident.get("resolved") else "✅ RESOLVED"
            print(f"{status} {incident['incident_id']}")
            print(f"   Time: {incident['timestamp']}")
            print(f"   Reason: {incident['reason']}")
            print(f"   Processes stopped: {incident['stopped_count']}")
            print()
    
    def _load_json(self, filepath: Path) -> Dict:
        """Load JSON file"""
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except:
            return {}
    
    def _save_json(self, filepath: Path, data: Dict):
        """Save JSON file"""
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Emergency stop system")
    parser.add_argument("--stop-all", action="store_true", help="Stop all operations")
    parser.add_argument("--reason", help="Reason for emergency stop", default="Manual emergency stop")
    parser.add_argument("--no-notify", action="store_true", help="Don't generate client notification")
    parser.add_argument("--list", action="store_true", help="List all incidents")
    
    args = parser.parse_args()
    
    emergency = EmergencyStop()
    
    if args.list:
        emergency.list_incidents()
        return
    
    if args.stop_all:
        incident_id = emergency.emergency_stop_all(
            reason=args.reason,
            notify_client=not args.no_notify
        )
    else:
        print("Emergency Stop System")
        print("\nUsage:")
        print("  python3 scripts/emergency_stop.py --stop-all --reason 'Description'")
        print("  python3 scripts/emergency_stop.py --list")


if __name__ == "__main__":
    main()

