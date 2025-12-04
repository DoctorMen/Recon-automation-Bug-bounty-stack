#!/usr/bin/env python3
"""
MCP ORCHESTRATOR - AI-Ready Bug Bounty Stack
=============================================
Central orchestrator coordinating specialized agents via MCP-style interfaces.
Transforms the stack from point-to-point integrations to intelligent coordination.

Architecture:
- Central Orchestrator (Brain)
- Specialized Agents (Tools)
- Structured Data Layer (Memory)
- Signal Filtering (Attention)

Copyright (c) 2025 DoctorMen
"""

import json
import asyncio
import sqlite3
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import subprocess

class AgentType(Enum):
    """Types of specialized agents"""
    RECONNAISSANCE = "reconnaissance"
    VULNERABILITY_SCANNER = "vulnerability_scanner"
    EXPLOIT_CHAIN_BUILDER = "exploit_chain_builder"
    PREDICTIVE_ANALYZER = "predictive_analyzer"
    VERIFICATION_AGENT = "verification_agent"
    SUBMISSION_AGENT = "submission_agent"

@dataclass
class Task:
    """Task definition for agent coordination"""
    id: str
    agent_type: AgentType
    target: str
    parameters: Dict[str, Any]
    priority: int
    dependencies: List[str]
    expected_outcome: str
    created_at: datetime

@dataclass
class AgentCapability:
    """What an agent can do (MCP-style interface)"""
    agent_type: AgentType
    name: str
    description: str
    inputs: List[str]
    outputs: List[str]
    tools: List[str]

@dataclass
class Finding:
    """Structured finding for AI consumption"""
    id: str
    target: str
    agent_type: AgentType
    vulnerability_type: str
    severity: str
    confidence: float
    evidence: Dict[str, Any]
    exploit_potential: float
    bounty_estimate: float
    status: str  # discovered, verified, submitted, paid
    created_at: datetime

class MCPDatabase:
    """AI-ready structured data layer"""
    
    def __init__(self, db_path: str = "mcp_orchestrator.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize structured database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Tasks table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY,
                agent_type TEXT,
                target TEXT,
                parameters TEXT,
                priority INTEGER,
                dependencies TEXT,
                expected_outcome TEXT,
                status TEXT,
                created_at TEXT,
                completed_at TEXT
            )
        """)
        
        # Findings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                target TEXT,
                agent_type TEXT,
                vulnerability_type TEXT,
                severity TEXT,
                confidence REAL,
                evidence TEXT,
                exploit_potential REAL,
                bounty_estimate REAL,
                status TEXT,
                created_at TEXT
            )
        """)
        
        # Agents table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                agent_type TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                capabilities TEXT,
                status TEXT,
                last_active TEXT
            )
        """)
        
        # Runs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY,
                target TEXT,
                goal TEXT,
                tasks_created INTEGER,
                findings_discovered INTEGER,
                status TEXT,
                started_at TEXT,
                completed_at TEXT
            )
        """)
        
        conn.commit()
        conn.close()
    
    def store_finding(self, finding: Finding):
        """Store structured finding"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO findings 
            (id, target, agent_type, vulnerability_type, severity, confidence, 
             evidence, exploit_potential, bounty_estimate, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            finding.id, finding.target, finding.agent_type.value,
            finding.vulnerability_type, finding.severity, finding.confidence,
            json.dumps(finding.evidence), finding.exploit_potential,
            finding.bounty_estimate, finding.status, finding.created_at.isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def get_high_value_findings(self, min_bounty: float = 1000) -> List[Finding]:
        """Get findings above bounty threshold"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM findings 
            WHERE bounty_estimate >= ? AND status = 'discovered'
            ORDER BY bounty_estimate DESC
        """, (min_bounty,))
        
        findings = []
        for row in cursor.fetchall():
            finding = Finding(
                id=row[0], target=row[1], agent_type=AgentType(row[2]),
                vulnerability_type=row[3], severity=row[4], confidence=row[5],
                evidence=json.loads(row[6]), exploit_potential=row[7],
                bounty_estimate=row[8], status=row[9], 
                created_at=datetime.fromisoformat(row[10])
            )
            findings.append(finding)
        
        conn.close()
        return findings
    
    def store_task(self, task: Task):
        """Store task definition"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO tasks 
            (id, agent_type, target, parameters, priority, dependencies, 
             expected_outcome, status, created_at, completed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            task.id, task.agent_type.value, task.target,
            json.dumps(task.parameters), task.priority,
            json.dumps(task.dependencies), task.expected_outcome,
            "pending", task.created_at.isoformat(), None
        ))
        
        conn.commit()
        conn.close()

class SignalFilter:
    """Filters noise and surfaces actionable intelligence"""
    
    def __init__(self):
        self.noise_patterns = {
            "missing_headers": {"max_bounty": 500, "min_confidence": 0.9},
            "dns_resolution": {"max_bounty": 200, "min_confidence": 0.8},
            "information_disclosure": {"max_bounty": 1000, "min_confidence": 0.7},
            "defi_endpoint": {"max_bounty": 2000, "min_confidence": 0.6},
        }
        
        self.high_value_patterns = {
            "reentrancy": {"min_bounty": 5000, "min_confidence": 0.7},
            "flash_loan": {"min_bounty": 10000, "min_confidence": 0.6},
            "oracle_manipulation": {"min_bounty": 8000, "min_confidence": 0.6},
            "access_control": {"min_bounty": 3000, "min_confidence": 0.7},
            "clickjacking": {"min_bounty": 1000, "min_confidence": 0.8},
        }
    
    def filter_finding(self, finding: Finding) -> Dict[str, Any]:
        """Filter and categorize finding"""
        vuln_type = finding.vulnerability_type.lower()
        
        # Check if it's noise
        if vuln_type in self.noise_patterns:
            pattern = self.noise_patterns[vuln_type]
            if finding.bounty_estimate <= pattern["max_bounty"]:
                if finding.confidence < pattern["min_confidence"]:
                    return {
                        "action": "filter_out",
                        "reason": f"Low-value {vuln_type} below threshold",
                        "category": "noise"
                    }
        
        # Check if it's high value
        if vuln_type in self.high_value_patterns:
            pattern = self.high_value_patterns[vuln_type]
            if finding.bounty_estimate >= pattern["min_bounty"]:
                if finding.confidence >= pattern["min_confidence"]:
                    return {
                        "action": "escalate",
                        "reason": f"High-value {vuln_type} detected",
                        "category": "critical"
                    }
        
        # Default: moderate value
        return {
            "action": "queue",
            "reason": "Moderate value finding",
            "category": "standard"
        }

class MCPOrchestrator:
    """Central orchestrator coordinating specialized agents"""
    
    def __init__(self):
        self.db = MCPDatabase()
        self.signal_filter = SignalFilter()
        self.agents = self._register_agents()
        self.active_tasks = {}
    
    def _register_agents(self) -> Dict[AgentType, AgentCapability]:
        """Register specialized agents with their capabilities"""
        return {
            AgentType.RECONNAISSANCE: AgentCapability(
                agent_type=AgentType.RECONNAISSANCE,
                name="Reconnaissance Agent",
                description="Discovers subdomains, technologies, and attack surface",
                inputs=["target", "scope"],
                outputs=["subdomains", "technologies", "endpoints"],
                tools=["subfinder", "httpx", "dig", "nmap"]
            ),
            AgentType.VULNERABILITY_SCANNER: AgentCapability(
                agent_type=AgentType.VULNERABILITY_SCANNER,
                name="Vulnerability Scanner",
                description="Scans for security vulnerabilities",
                inputs=["target", "endpoints", "technologies"],
                outputs=["vulnerabilities", "security_issues"],
                tools=["nuclei", "nmap", "sslscan", "dirsearch"]
            ),
            AgentType.EXPLOIT_CHAIN_BUILDER: AgentCapability(
                agent_type=AgentType.EXPLOIT_CHAIN_BUILDER,
                name="Exploit Chain Builder",
                description="Builds exploit chains from individual vulnerabilities",
                inputs=["vulnerabilities", "technologies"],
                outputs=["exploit_chains", "attack_paths"],
                tools=["chain_builder", "impact_analyzer"]
            ),
            AgentType.PREDICTIVE_ANALYZER: AgentCapability(
                agent_type=AgentType.PREDICTIVE_ANALYZER,
                name="Predictive Analyzer",
                description="Predicts vulnerabilities based on patterns",
                inputs=["target", "technologies", "historical_data"],
                outputs=["predictions", "probability_scores"],
                tools=["ml_models", "pattern_matcher", "historical_db"]
            ),
            AgentType.VERIFICATION_AGENT: AgentCapability(
                agent_type=AgentType.VERIFICATION_AGENT,
                name="Verification Agent",
                description="Verifies findings are real and exploitable",
                inputs=["findings", "evidence"],
                outputs=["verified_findings", "false_positives"],
                tools=["verifier", "evidence_checker", "manual_review"]
            ),
            AgentType.SUBMISSION_AGENT: AgentCapability(
                agent_type=AgentType.SUBMISSION_AGENT,
                name="Submission Agent",
                description="Prepares and submits verified findings",
                inputs=["verified_findings", "bounty_program"],
                outputs=["submissions", "tracking"],
                tools=["report_generator", "submission_tracker"]
            )
        }
    
    def create_goal(self, target: str, goal: str) -> str:
        """Create a new goal and orchestrate agents to achieve it"""
        
        run_id = f"run_{int(datetime.now().timestamp())}"
        
        print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║              MCP ORCHESTRATOR - GOAL CREATION                        ║
║          AI-Ready Coordination | Intelligent Dispatch                 ║
╚══════════════════════════════════════════════════════════════════════╝

🎯 Target: {target}
🎯 Goal: {goal}
🆔 Run ID: {run_id}
        """)
        
        # Create task sequence based on goal
        tasks = self._plan_task_sequence(target, goal, run_id)
        
        # Store tasks
        for task in tasks:
            self.db.store_task(task)
        
        # Store run
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO runs (id, target, goal, tasks_created, findings_discovered, status, started_at, completed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (run_id, target, goal, len(tasks), 0, "running", datetime.now().isoformat(), None))
        conn.commit()
        conn.close()
        
        print(f"📋 Created {len(tasks)} tasks to achieve goal")
        print(f"🚀 Starting orchestrated execution...")
        
        return run_id
    
    def _plan_task_sequence(self, target: str, goal: str, run_id: str) -> List[Task]:
        """Plan optimal task sequence to achieve goal"""
        
        tasks = []
        task_counter = 1
        
        # Phase 1: Reconnaissance (always first)
        tasks.append(Task(
            id=f"{run_id}_task_{task_counter}",
            agent_type=AgentType.RECONNAISSANCE,
            target=target,
            parameters={"deep_scan": True, "subdomain_bruteforce": True},
            priority=10,
            dependencies=[],
            expected_outcome="Complete attack surface mapping",
            created_at=datetime.now()
        ))
        task_counter += 1
        
        # Phase 2: Predictive Analysis (uses recon data)
        tasks.append(Task(
            id=f"{run_id}_task_{task_counter}",
            agent_type=AgentType.PREDICTIVE_ANALYZER,
            target=target,
            parameters={"use_historical_patterns": True},
            priority=9,
            dependencies=[tasks[0].id],
            expected_outcome="Vulnerability predictions and probability scores",
            created_at=datetime.now()
        ))
        task_counter += 1
        
        # Phase 3: Vulnerability Scanning
        tasks.append(Task(
            id=f"{run_id}_task_{task_counter}",
            agent_type=AgentType.VULNERABILITY_SCANNER,
            target=target,
            parameters={"use_predictions": True, "scan_depth": "deep"},
            priority=8,
            dependencies=[tasks[0].id],
            expected_outcome="Security vulnerabilities and issues",
            created_at=datetime.now()
        ))
        task_counter += 1
        
        # Phase 4: Exploit Chain Building
        tasks.append(Task(
            id=f"{run_id}_task_{task_counter}",
            agent_type=AgentType.EXPLOIT_CHAIN_BUILDER,
            target=target,
            parameters={"max_chain_length": 3, "min_impact": "high"},
            priority=7,
            dependencies=[tasks[2].id],
            expected_outcome="Exploit chains and attack paths",
            created_at=datetime.now()
        ))
        task_counter += 1
        
        # Phase 5: Verification
        tasks.append(Task(
            id=f"{run_id}_task_{task_counter}",
            agent_type=AgentType.VERIFICATION_AGENT,
            target=target,
            parameters={"strict_verification": True, "evidence_required": True},
            priority=6,
            dependencies=[tasks[2].id, tasks[3].id],
            expected_outcome="Verified findings and filtered false positives",
            created_at=datetime.now()
        ))
        task_counter += 1
        
        # Phase 6: Submission (if goal is bounty hunting)
        if "bounty" in goal.lower():
            tasks.append(Task(
                id=f"{run_id}_task_{task_counter}",
                agent_type=AgentType.SUBMISSION_AGENT,
                target=target,
                parameters={"program": "cantina", "format": "standard"},
                priority=5,
                dependencies=[tasks[4].id],
                expected_outcome="Submission-ready reports and tracking",
                created_at=datetime.now()
            ))
        
        return tasks
    
    def execute_run(self, run_id: str):
        """Execute orchestrated run"""
        
        print(f"\n🚀 EXECUTING ORCHESTRATED RUN: {run_id}")
        
        # Get tasks for this run
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tasks WHERE id LIKE ?", (f"{run_id}%",))
        task_rows = cursor.fetchall()
        conn.close()
        
        # Execute tasks in dependency order
        executed_tasks = set()
        
        for attempt in range(len(task_rows)):  # Max attempts
            for row in task_rows:
                task_id = row[0]
                
                if task_id in executed_tasks:
                    continue
                
                # Check dependencies
                dependencies = json.loads(row[5])
                if all(dep in executed_tasks for dep in dependencies):
                    print(f"\n📋 Executing Task: {task_id}")
                    
                    # Execute task (simplified)
                    success = self._execute_task(row)
                    
                    if success:
                        executed_tasks.add(task_id)
                        print(f"   ✅ Task completed: {task_id}")
                    else:
                        print(f"   ❌ Task failed: {task_id}")
        
        print(f"\n✅ Run {run_id} completed")
        print(f"📊 Tasks executed: {len(executed_tasks)}")
        
        # Show high-value findings
        high_value = self.db.get_high_value_findings()
        if high_value:
            print(f"\n💎 HIGH-VALUE FINDINGS DISCOVERED:")
            for finding in high_value[:5]:
                print(f"   🎯 {finding.vulnerability_type}: ${finding.bounty_estimate:,.0f}")
    
    def _execute_task(self, task_row) -> bool:
        """Execute individual task (simplified implementation)"""
        
        task_id = task_row[0]
        agent_type = AgentType(task_row[1])
        target = task_row[2]
        parameters = json.loads(task_row[3])
        
        try:
            # Simulate task execution based on agent type
            if agent_type == AgentType.RECONNAISSANCE:
                return self._execute_reconnaissance(target, parameters, task_id)
            elif agent_type == AgentType.VULNERABILITY_SCANNER:
                return self._execute_vulnerability_scan(target, parameters, task_id)
            elif agent_type == AgentType.PREDICTIVE_ANALYZER:
                return self._execute_predictive_analysis(target, parameters, task_id)
            elif agent_type == AgentType.EXPLOIT_CHAIN_BUILDER:
                return self._execute_exploit_chain_builder(target, parameters, task_id)
            elif agent_type == AgentType.VERIFICATION_AGENT:
                return self._execute_verification(target, parameters, task_id)
            elif agent_type == AgentType.SUBMISSION_AGENT:
                return self._execute_submission(target, parameters, task_id)
            
        except Exception as e:
            print(f"   ❌ Task execution error: {e}")
            return False
        
        return True
    
    def _execute_reconnaissance(self, target: str, parameters: Dict, task_id: str) -> bool:
        """Execute reconnaissance task"""
        print(f"   🔍 Running reconnaissance on {target}")
        
        # Simulate reconnaissance findings
        findings = [
            Finding(
                id=f"{task_id}_dns",
                target=target,
                agent_type=AgentType.RECONNAISSANCE,
                vulnerability_type="dns_resolution",
                severity="info",
                confidence=1.0,
                evidence={"ips": ["93.184.216.34"], "count": 1},
                exploit_potential=0.1,
                bounty_estimate=100,
                status="discovered",
                created_at=datetime.now()
            ),
            Finding(
                id=f"{task_id}_tech",
                target=target,
                agent_type=AgentType.RECONNAISSANCE,
                vulnerability_type="technology_detected",
                severity="info",
                confidence=0.9,
                evidence={"technologies": ["nginx", "cloudflare"]},
                exploit_potential=0.2,
                bounty_estimate=200,
                status="discovered",
                created_at=datetime.now()
            )
        ]
        
        # Filter and store findings
        for finding in findings:
            filter_result = self.signal_filter.filter_finding(finding)
            
            if filter_result["action"] != "filter_out":
                self.db.store_finding(finding)
                print(f"      📊 Finding: {finding.vulnerability_type} (${finding.bounty_estimate})")
        
        return True
    
    def _execute_vulnerability_scan(self, target: str, parameters: Dict, task_id: str) -> bool:
        """Execute vulnerability scan"""
        print(f"   🔍 Running vulnerability scan on {target}")
        
        # Simulate vulnerability findings
        findings = [
            Finding(
                id=f"{task_id}_clickjack",
                target=target,
                agent_type=AgentType.VULNERABILITY_SCANNER,
                vulnerability_type="clickjacking",
                severity="medium",
                confidence=0.8,
                evidence={"missing_xfo": True, "missing_csp": True},
                exploit_potential=0.6,
                bounty_estimate=1500,
                status="discovered",
                created_at=datetime.now()
            )
        ]
        
        # Filter and store findings
        for finding in findings:
            filter_result = self.signal_filter.filter_finding(finding)
            
            if filter_result["action"] == "escalate":
                print(f"      🚨 CRITICAL: {finding.vulnerability_type} (${finding.bounty_estimate})")
                self.db.store_finding(finding)
            elif filter_result["action"] == "queue":
                print(f"      📊 Finding: {finding.vulnerability_type} (${finding.bounty_estimate})")
                self.db.store_finding(finding)
        
        return True
    
    def _execute_predictive_analysis(self, target: str, parameters: Dict, task_id: str) -> bool:
        """Execute predictive analysis"""
        print(f"   🔍 Running predictive analysis for {target}")
        
        # Simulate predictions
        predictions = [
            {"vulnerability": "smart_contract_risk", "confidence": 0.7, "potential_bounty": 5000},
            {"vulnerability": "api_access_control", "confidence": 0.6, "potential_bounty": 3000}
        ]
        
        for pred in predictions:
            print(f"      🔮 Prediction: {pred['vulnerability']} ({pred['confidence']:.0%} confidence)")
        
        return True
    
    def _execute_exploit_chain_builder(self, target: str, parameters: Dict, task_id: str) -> bool:
        """Execute exploit chain building"""
        print(f"   🔍 Building exploit chains for {target}")
        
        # Get existing findings
        findings = self.db.get_high_value_findings(min_bounty=0)
        
        if len(findings) >= 2:
            print(f"      ⚡ Chain potential: {len(findings)} findings available")
        else:
            print(f"      ℹ️  Insufficient findings for chaining")
        
        return True
    
    def _execute_verification(self, target: str, parameters: Dict, task_id: str) -> bool:
        """Execute verification"""
        print(f"   🔍 Verifying findings for {target}")
        
        # Get discovered findings
        findings = self.db.get_high_value_findings(min_bounty=0)
        
        verified_count = 0
        for finding in findings:
            # Simulate verification
            if finding.confidence >= 0.7:
                finding.status = "verified"
                self.db.store_finding(finding)
                verified_count += 1
                print(f"      ✅ Verified: {finding.vulnerability_type}")
        
        print(f"      📊 Verification complete: {verified_count}/{len(findings)} verified")
        return True
    
    def _execute_submission(self, target: str, parameters: Dict, task_id: str) -> bool:
        """Execute submission preparation"""
        print(f"   📋 Preparing submissions for {target}")
        
        # Get verified findings
        findings = [f for f in self.db.get_high_value_findings(min_bounty=0) if f.status == "verified"]
        
        if findings:
            print(f"      📦 Submission package: {len(findings)} verified findings")
            
            # Create submission package
            submission = {
                "target": target,
                "findings": [asdict(f) for f in findings],
                "total_bounty_potential": sum(f.bounty_estimate for f in findings),
                "created_at": datetime.now().isoformat()
            }
            
            with open(f"mcp_submission_{target.replace('.', '_')}.json", 'w') as f:
                json.dump(submission, f, indent=2)
            
            print(f"      💾 Submission saved: mcp_submission_{target.replace('.', '_')}.json")
        
        return True
    
    def show_capabilities(self):
        """Show all registered agent capabilities"""
        
        print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║              MCP ORCHESTRATOR - REGISTERED AGENTS                     ║
║          Specialized Tools | Clear Interfaces | Coordinated            ║
╚══════════════════════════════════════════════════════════════════════╝
        """)
        
        for agent_type, capability in self.agents.items():
            print(f"""
🤖 {capability.name} ({agent_type.value})
   📝 Description: {capability.description}
   🔧 Inputs: {', '.join(capability.inputs)}
   📤 Outputs: {', '.join(capability.outputs)}
   🛠️  Tools: {', '.join(capability.tools)}
            """)

def main():
    """Demonstrate MCP orchestrator"""
    
    orchestrator = MCPOrchestrator()
    
    print("""
🧠 MCP-READY AI ARCHITECTURE DEMONSTRATION
==========================================

This transforms your bug bounty stack from:
❌ Point-to-point integrations
❌ Ad-hoc tool coordination  
❌ Unstructured data dumps
❌ No signal filtering

Into:
✅ Central orchestrator coordination
✅ MCP-style tool interfaces
✅ Structured findings database
✅ Intelligent signal filtering
    """)
    
    # Show capabilities
    orchestrator.show_capabilities()
    
    # Create goal and orchestrate
    target = "example.com"
    goal = "Find high-value vulnerabilities for bounty submission"
    
    run_id = orchestrator.create_goal(target, goal)
    orchestrator.execute_run(run_id)
    
    print(f"""
{'='*60}
🎯 MCP ARCHITECTURE BENEFITS ACHIEVED:
{'='*60}

✅ Central Orchestration:
   - Coordinated 6 specialized agents
   - Dependency-aware task execution
   - Goal-driven automation

✅ MCP-Style Interfaces:
   - Each agent exposes capabilities
   - Clear input/output contracts
   - Tool-based modularity

✅ Structured Data Layer:
   - SQLite database with proper schema
   - Queryable findings and runs
   - AI-consumable data structure

✅ Signal Filtering:
   - Filtered low-value noise
   - Escalated high-priority findings
   - Focus on actionable intelligence

🚀 NEXT STEPS:
   1. Replace simulated agents with real tools
   2. Add more sophisticated filtering
   3. Integrate with real bounty platforms
   4. Add human-in-the-loop review

💡 This is the future of AI-powered security research!
    """)

if __name__ == "__main__":
    main()
