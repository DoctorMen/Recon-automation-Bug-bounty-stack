#!/usr/bin/env python3
"""
Copyright (c) 2025 YOUR_NAME_HERE
Proprietary and Confidential
All Rights Reserved

This software is proprietary and confidential.
Unauthorized copying, modification, or distribution is prohibited.

System ID: BB_20251102_5946
Owner: YOUR_NAME_HERE
"""

"""
Agent Performance Investigation Script
Diagnoses what's taking agents so long and identifies bottlenecks
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = REPO_ROOT / "output"

def check_running_processes() -> List[Dict]:
    """Check for running agent processes"""
    processes = []
    try:
        if sys.platform == "win32":
            # Windows PowerShell command
            cmd = ["powershell", "-Command", 
                   "Get-Process | Where-Object {$_.ProcessName -match 'python|bash|subfinder|amass|httpx|nuclei'} | Select-Object ProcessName, Id, CPU, StartTime | ConvertTo-Json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout:
                try:
                    ps_data = json.loads(result.stdout)
                    if isinstance(ps_data, dict):
                        ps_data = [ps_data]
                    processes = ps_data
                except:
                    pass
        else:
            # Unix/Linux
            cmd = ["ps", "aux"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if any(tool in line.lower() for tool in ['python', 'bash', 'subfinder', 'amass', 'httpx', 'nuclei']):
                        processes.append({"raw": line})
    except Exception as e:
        pass
    return processes

def analyze_timeouts() -> Dict:
    """Analyze configured timeouts"""
    timeouts = {
        "RECON_TIMEOUT": int(os.getenv("RECON_TIMEOUT", "1800")),  # 30 min default
        "HTTPX_TIMEOUT": int(os.getenv("HTTPX_TIMEOUT", "10")),
        "NUCLEI_TIMEOUT": int(os.getenv("NUCLEI_TIMEOUT", "10")),
        "NUCLEI_SCAN_TIMEOUT": int(os.getenv("NUCLEI_SCAN_TIMEOUT", "3600")),  # 1 hour default
    }
    return timeouts

def check_file_sizes() -> Dict:
    """Check output file sizes to see if agents are producing data"""
    files = {
        "subs.txt": OUTPUT_DIR / "subs.txt",
        "http.json": OUTPUT_DIR / "http.json",
        "nuclei-findings.json": OUTPUT_DIR / "nuclei-findings.json",
        "recon-run.log": OUTPUT_DIR / "recon-run.log",
    }
    
    file_info = {}
    for name, path in files.items():
        if path.exists():
            size = path.stat().st_size
            mtime = datetime.fromtimestamp(path.stat().st_mtime)
            file_info[name] = {
                "size": size,
                "size_mb": round(size / (1024 * 1024), 2),
                "modified": mtime.isoformat(),
                "age_seconds": (datetime.now() - mtime).total_seconds(),
            }
        else:
            file_info[name] = {"exists": False}
    
    return file_info

def check_log_tail(lines: int = 20) -> List[str]:
    """Get recent log entries"""
    log_file = OUTPUT_DIR / "recon-run.log"
    if not log_file.exists():
        return []
    
    try:
        with open(log_file, "r", encoding="utf-8") as f:
            all_lines = f.readlines()
            return [line.strip() for line in all_lines[-lines:]]
    except:
        return []

def check_pipeline_status() -> Dict:
    """Check pipeline completion status"""
    status_file = OUTPUT_DIR / ".pipeline_status"
    completed = []
    if status_file.exists():
        try:
            with open(status_file, "r", encoding="utf-8") as f:
                completed = [line.strip() for line in f if line.strip()]
        except:
            pass
    
    stages = ["recon", "httpx", "nuclei", "triage", "reports"]
    status = {}
    for stage in stages:
        status[stage] = stage in completed
    
    return status

def analyze_agent_config() -> Dict:
    """Analyze agents.json configuration"""
    agents_file = REPO_ROOT / "agents.json"
    if not agents_file.exists():
        return {"error": "agents.json not found"}
    
    try:
        with open(agents_file, "r", encoding="utf-8") as f:
            config = json.load(f)
        
        agents = config.get("agents", [])
        model_usage = {}
        for agent in agents:
            model = agent.get("model", "unknown")
            model_usage[model] = model_usage.get(model, []) + [agent.get("name")]
        
        return {
            "total_agents": len(agents),
            "models": model_usage,
            "agents": agents
        }
    except Exception as e:
        return {"error": str(e)}

def check_blocking_operations() -> List[Dict]:
    """Identify potential blocking operations in scripts"""
    issues = []
    
    scripts_to_check = [
        ("run_recon.py", ["subfinder", "amass", "dnsx"]),
        ("run_httpx.py", ["httpx"]),
        ("run_nuclei.py", ["nuclei"]),
    ]
    
    for script_name, tools in scripts_to_check:
        script_path = REPO_ROOT / script_name
        if script_path.exists():
            try:
                content = script_path.read_text(encoding="utf-8")
                # Check for blocking subprocess calls
                if "subprocess.run" in content:
                    if "timeout=" not in content:
                        issues.append({
                            "script": script_name,
                            "issue": "subprocess.run() without explicit timeout",
                            "severity": "medium"
                        })
                    if "capture_output=True" in content and "check=False" not in content:
                        issues.append({
                            "script": script_name,
                            "issue": "subprocess.run() may raise exception on failure",
                            "severity": "low"
                        })
            except:
                pass
    
    return issues

def main():
    print("=" * 70)
    print("AGENT PERFORMANCE INVESTIGATION REPORT")
    print("=" * 70)
    print(f"Generated: {datetime.now().isoformat()}")
    print()
    
    # 1. Check running processes
    print("1. RUNNING PROCESSES")
    print("-" * 70)
    processes = check_running_processes()
    if processes:
        print(f"Found {len(processes)} potentially related processes:")
        for proc in processes[:10]:  # Limit output
            print(f"  {proc}")
    else:
        print("  No matching processes found (agents may have completed or not started)")
    print()
    
    # 2. Timeout analysis
    print("2. CONFIGURED TIMEOUTS")
    print("-" * 70)
    timeouts = analyze_timeouts()
    for key, value in timeouts.items():
        minutes = value / 60
        print(f"  {key}: {value}s ({minutes:.1f} minutes)")
    print()
    
    # 3. File sizes and modification times
    print("3. OUTPUT FILES STATUS")
    print("-" * 70)
    file_info = check_file_sizes()
    for name, info in file_info.items():
        if info.get("exists") is False:
            print(f"  {name}: NOT CREATED")
        else:
            age_min = info.get("age_seconds", 0) / 60
            print(f"  {name}: {info.get('size_mb', 0)} MB, modified {age_min:.1f} minutes ago")
    print()
    
    # 4. Pipeline status
    print("4. PIPELINE COMPLETION STATUS")
    print("-" * 70)
    status = check_pipeline_status()
    for stage, completed in status.items():
        icon = "✓" if completed else "⏸"
        print(f"  {icon} {stage.capitalize()}: {'COMPLETE' if completed else 'PENDING'}")
    print()
    
    # 5. Agent configuration
    print("5. AGENT CONFIGURATION")
    print("-" * 70)
    agent_config = analyze_agent_config()
    if "error" in agent_config:
        print(f"  ERROR: {agent_config['error']}")
    else:
        print(f"  Total agents: {agent_config['total_agents']}")
        print("  Models in use:")
        for model, agents in agent_config["models"].items():
            print(f"    - {model}: {len(agents)} agent(s)")
            for agent in agents:
                print(f"      • {agent}")
    print()
    
    # 6. Blocking operations
    print("6. POTENTIAL BLOCKING OPERATIONS")
    print("-" * 70)
    blocking_issues = check_blocking_operations()
    if blocking_issues:
        for issue in blocking_issues:
            print(f"  [{issue['severity'].upper()}] {issue['script']}: {issue['issue']}")
    else:
        print("  No obvious blocking issues found")
    print()
    
    # 7. Recent log entries
    print("7. RECENT LOG ENTRIES (last 10 lines)")
    print("-" * 70)
    log_lines = check_log_tail(10)
    if log_lines:
        for line in log_lines:
            print(f"  {line}")
    else:
        print("  No log file found")
    print()
    
    # 8. Recommendations
    print("8. RECOMMENDATIONS")
    print("-" * 70)
    print("  • Check if agents are stuck waiting for external tools (subfinder, amass, httpx, nuclei)")
    print("  • Verify network connectivity and API rate limits")
    print("  • Consider reducing timeouts for faster failure detection")
    print("  • Add progress indicators to long-running operations")
    print("  • Consider parallelizing independent operations")
    print("  • Check system resources (CPU, memory, disk)")
    print()
    
    print("=" * 70)
    print("To monitor in real-time: python scripts/scan_monitor.py")
    print("=" * 70)

if __name__ == "__main__":
    main()


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
