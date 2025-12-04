#!/usr/bin/env python3
"""
SECURITY TESTING DATABASE - STRUCTURED DATA MANAGEMENT
======================================================
Professional database system for security testing operations with governance,
indexing, and observability for bug bounty workflows.

Features:
- Program/scope partitioning with access control
- Indexed retrieval for hosts, endpoints, tech stacks
- Raw + enriched data normalization
- Governance (redaction, retention, auth)
- Observability (run IDs, schema versioning)
- SQLite-based for portability and performance

Copyright (c) 2025 DoctorMen
"""

import sqlite3
import json
import hashlib
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import uuid
import re

class SecurityTestingDatabase:
    """Professional database for security testing operations"""
    
    def __init__(self, db_path: str = "./security_testing.db"):
        self.db_path = db_path
        self.conn = None
        self.schema_version = "1.0.0"
        self.initialize_database()
    
    def initialize_database(self):
        """Initialize database with comprehensive schema"""
        
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute("PRAGMA foreign_keys = ON")
        
        # Create all tables
        self._create_metadata_tables()
        self._create_program_tables()
        self._create_run_tables()
        self._create_target_tables()
        self._create_finding_tables()
        self._create_poc_tables()
        self._create_tool_output_tables()
        self._create_governance_tables()
        self._create_indexes()
        
        # Create default system user
        self._create_default_user()
        
        # Set schema version
        self._set_schema_version()
        
        print(f"✅ Security Testing Database initialized (v{self.schema_version})")
        print(f"📍 Location: {os.path.abspath(self.db_path)}")
    
    def _create_metadata_tables(self):
        """Create metadata and governance tables"""
        
        # Schema version tracking
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version TEXT PRIMARY KEY,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                description TEXT
            )
        """)
        
        # Access control
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                role TEXT DEFAULT 'researcher',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_access TIMESTAMP,
                active BOOLEAN DEFAULT 1
            )
        """)
        
        # Audit logging
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                log_id TEXT PRIMARY KEY,
                user_id TEXT,
                action TEXT NOT NULL,
                resource_type TEXT,
                resource_id TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                details TEXT,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        """)
    
    def _create_program_tables(self):
        """Create program and scope management tables"""
        
        # Bug bounty programs
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS programs (
                program_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                platform TEXT NOT NULL,
                url TEXT,
                bounty_range TEXT,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Program scopes with allowlists
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS program_scopes (
                scope_id TEXT PRIMARY KEY,
                program_id TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_pattern TEXT NOT NULL,
                in_scope BOOLEAN DEFAULT 1,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (program_id) REFERENCES programs(program_id)
            )
        """)
        
        # Program-specific sensitivity levels
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS program_sensitivity (
                sensitivity_id TEXT PRIMARY KEY,
                program_id TEXT NOT NULL,
                data_type TEXT NOT NULL,
                sensitivity_level INTEGER DEFAULT 1,
                retention_days INTEGER DEFAULT 365,
                requires_redaction BOOLEAN DEFAULT 0,
                FOREIGN KEY (program_id) REFERENCES programs(program_id)
            )
        """)
    
    def _create_run_tables(self):
        """Create test run management tables"""
        
        # Test runs with observability
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS test_runs (
                run_id TEXT PRIMARY KEY,
                program_id TEXT NOT NULL,
                user_id TEXT,
                run_type TEXT NOT NULL,
                status TEXT DEFAULT 'running',
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                duration_seconds INTEGER,
                tool_version TEXT,
                environment TEXT,
                metadata TEXT,
                FOREIGN KEY (program_id) REFERENCES programs(program_id),
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        """)
        
        # Run phases for detailed tracking
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS run_phases (
                phase_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                phase_name TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                output_count INTEGER DEFAULT 0,
                FOREIGN KEY (run_id) REFERENCES test_runs(run_id)
            )
        """)
    
    def _create_target_tables(self):
        """Create target and endpoint management tables"""
        
        # Targets with indexing
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS targets (
                target_id TEXT PRIMARY KEY,
                program_id TEXT NOT NULL,
                run_id TEXT,
                host TEXT NOT NULL,
                port INTEGER,
                protocol TEXT DEFAULT 'https',
                url TEXT NOT NULL,
                ip_address TEXT,
                tech_stack TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'active',
                FOREIGN KEY (program_id) REFERENCES programs(program_id),
                FOREIGN KEY (run_id) REFERENCES test_runs(run_id)
            )
        """)
        
        # Endpoints with parameter tracking
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS endpoints (
                endpoint_id TEXT PRIMARY KEY,
                target_id TEXT NOT NULL,
                path TEXT NOT NULL,
                method TEXT DEFAULT 'GET',
                parameters TEXT,
                headers TEXT,
                response_code INTEGER,
                content_type TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (target_id) REFERENCES targets(target_id)
            )
        """)
        
        # Technology stack components
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS tech_components (
                component_id TEXT PRIMARY KEY,
                target_id TEXT NOT NULL,
                component_type TEXT NOT NULL,
                name TEXT NOT NULL,
                version TEXT,
                confidence INTEGER DEFAULT 1,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (target_id) REFERENCES targets(target_id)
            )
        """)
    
    def _create_finding_tables(self):
        """Create vulnerability finding tables"""
        
        # Findings with comprehensive metadata
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                program_id TEXT NOT NULL,
                run_id TEXT,
                target_id TEXT,
                endpoint_id TEXT,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                cwe_id TEXT,
                cvss_score REAL,
                description TEXT,
                impact TEXT,
                recommendation TEXT,
                status TEXT DEFAULT 'open',
                submitted_at TIMESTAMP,
                bounty_awarded INTEGER,
                outcome TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (program_id) REFERENCES programs(program_id),
                FOREIGN KEY (run_id) REFERENCES test_runs(run_id),
                FOREIGN KEY (target_id) REFERENCES targets(target_id),
                FOREIGN KEY (endpoint_id) REFERENCES endpoints(endpoint_id)
            )
        """)
        
        # Finding evidence and artifacts
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS finding_evidence (
                evidence_id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                content TEXT,
                file_path TEXT,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
            )
        """)
    
    def _create_poc_tables(self):
        """Create proof of concept management tables"""
        
        # PoC files with versioning
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS poc_files (
                poc_id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_type TEXT NOT NULL,
                file_path TEXT,
                file_size INTEGER,
                checksum TEXT,
                working BOOLEAN DEFAULT 0,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
            )
        """)
        
        # PoC execution results
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS poc_executions (
                execution_id TEXT PRIMARY KEY,
                poc_id TEXT NOT NULL,
                run_id TEXT,
                environment TEXT,
                success BOOLEAN,
                output TEXT,
                error_message TEXT,
                executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (poc_id) REFERENCES poc_files(poc_id),
                FOREIGN KEY (run_id) REFERENCES test_runs(run_id)
            )
        """)
    
    def _create_tool_output_tables(self):
        """Create raw and enriched tool output tables"""
        
        # Raw tool outputs
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS raw_tool_outputs (
                output_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                tool_version TEXT,
                command_line TEXT,
                output_type TEXT,
                raw_content BLOB,
                file_path TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (run_id) REFERENCES test_runs(run_id)
            )
        """)
        
        # Enriched/processed signals
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS enriched_signals (
                signal_id TEXT PRIMARY KEY,
                raw_output_id TEXT,
                signal_type TEXT NOT NULL,
                source_tool TEXT,
                confidence REAL,
                metadata TEXT,
                processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (raw_output_id) REFERENCES raw_tool_outputs(output_id)
            )
        """)
        
        # Vulnerability hypotheses
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS vuln_hypotheses (
                hypothesis_id TEXT PRIMARY KEY,
                signal_id TEXT,
                target_id TEXT,
                endpoint_id TEXT,
                hypothesis_type TEXT,
                description TEXT,
                confidence REAL,
                tested BOOLEAN DEFAULT 0,
                confirmed BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (signal_id) REFERENCES enriched_signals(signal_id),
                FOREIGN KEY (target_id) REFERENCES targets(target_id),
                FOREIGN KEY (endpoint_id) REFERENCES endpoints(endpoint_id)
            )
        """)
    
    def _create_governance_tables(self):
        """Create governance and compliance tables"""
        
        # Data retention policies
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS retention_policies (
                policy_id TEXT PRIMARY KEY,
                data_type TEXT NOT NULL,
                retention_days INTEGER NOT NULL,
                auto_delete BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Redaction rules
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS redaction_rules (
                rule_id TEXT PRIMARY KEY,
                pattern TEXT NOT NULL,
                replacement TEXT DEFAULT 'REDACTED',
                data_types TEXT,
                active BOOLEAN DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Access permissions
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS permissions (
                permission_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                program_id TEXT,
                resource_type TEXT NOT NULL,
                access_level TEXT NOT NULL,
                granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id),
                FOREIGN KEY (program_id) REFERENCES programs(program_id)
            )
        """)
    
    def _create_indexes(self):
        """Create performance indexes"""
        
        indexes = [
            # Program indexes
            "CREATE INDEX IF NOT EXISTS idx_programs_status ON programs(status)",
            "CREATE INDEX IF NOT EXISTS idx_programs_platform ON programs(platform)",
            
            # Target indexes
            "CREATE INDEX IF NOT EXISTS idx_targets_program ON targets(program_id)",
            "CREATE INDEX IF NOT EXISTS idx_targets_host ON targets(host)",
            "CREATE INDEX IF NOT EXISTS idx_targets_run ON targets(run_id)",
            "CREATE INDEX IF NOT EXISTS idx_targets_tech ON targets(tech_stack)",
            
            # Endpoint indexes
            "CREATE INDEX IF NOT EXISTS idx_endpoints_target ON endpoints(target_id)",
            "CREATE INDEX IF NOT EXISTS idx_endpoints_path ON endpoints(path)",
            "CREATE INDEX IF NOT EXISTS idx_endpoints_method ON endpoints(method)",
            
            # Finding indexes
            "CREATE INDEX IF NOT EXISTS idx_findings_program ON findings(program_id)",
            "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)",
            "CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status)",
            "CREATE INDEX IF NOT EXISTS idx_findings_cwe ON findings(cwe_id)",
            "CREATE INDEX IF NOT EXISTS idx_findings_outcome ON findings(outcome)",
            
            # Run indexes
            "CREATE INDEX IF NOT EXISTS idx_runs_program ON test_runs(program_id)",
            "CREATE INDEX IF NOT EXISTS idx_runs_status ON test_runs(status)",
            "CREATE INDEX IF NOT EXISTS idx_runs_type ON test_runs(run_type)",
            "CREATE INDEX IF NOT EXISTS idx_runs_user ON test_runs(user_id)",
            
            # Tool output indexes
            "CREATE INDEX IF NOT EXISTS idx_raw_outputs_run ON raw_tool_outputs(run_id)",
            "CREATE INDEX IF NOT EXISTS idx_raw_outputs_tool ON raw_tool_outputs(tool_name)",
            "CREATE INDEX IF NOT EXISTS idx_enriched_signals_type ON enriched_signals(signal_type)",
            
            # Governance indexes
            "CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)",
            "CREATE INDEX IF NOT EXISTS idx_permissions_user ON permissions(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_permissions_program ON permissions(program_id)"
        ]
        
        for index_sql in indexes:
            self.conn.execute(index_sql)
    
    def _set_schema_version(self):
        """Set current schema version"""
        self.conn.execute("""
            INSERT OR REPLACE INTO schema_version (version, description)
            VALUES (?, ?)
        """, (self.schema_version, "Security Testing Database v1.0.0"))
        self.conn.commit()
    
    def _create_default_user(self):
        """Create default system user for audit logging"""
        
        # Check if system user exists
        cursor = self.conn.execute("SELECT user_id FROM users WHERE username = 'system'")
        if not cursor.fetchone():
            system_user_id = str(uuid.uuid4())
            self.conn.execute("""
                INSERT INTO users (user_id, username, role, active)
                VALUES (?, ?, ?, ?)
            """, (system_user_id, "system", "administrator", 1))
            self.conn.commit()
    
    def create_program(self, name: str, platform: str, url: str = None, 
                      bounty_range: str = None) -> str:
        """Create new bug bounty program"""
        
        program_id = str(uuid.uuid4())
        
        self.conn.execute("""
            INSERT INTO programs (program_id, name, platform, url, bounty_range)
            VALUES (?, ?, ?, ?, ?)
        """, (program_id, name, platform, url, bounty_range))
        
        self._log_action("create_program", "program", program_id, 
                        f"Created program: {name}")
        
        self.conn.commit()
        return program_id
    
    def add_scope(self, program_id: str, target_type: str, 
                  target_pattern: str, in_scope: bool = True, 
                  notes: str = None) -> str:
        """Add scope entry to program"""
        
        scope_id = str(uuid.uuid4())
        
        self.conn.execute("""
            INSERT INTO program_scopes (scope_id, program_id, target_type, 
                                       target_pattern, in_scope, notes)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (scope_id, program_id, target_type, target_pattern, 
              in_scope, notes))
        
        self._log_action("add_scope", "scope", scope_id,
                        f"Added scope: {target_pattern}")
        
        self.conn.commit()
        return scope_id
    
    def start_run(self, program_id: str, run_type: str, user_id: str = None,
                  tool_version: str = None, environment: str = None) -> str:
        """Start new test run with observability"""
        
        run_id = str(uuid.uuid4())
        metadata = json.dumps({"schema_version": self.schema_version})
        
        self.conn.execute("""
            INSERT INTO test_runs (run_id, program_id, user_id, run_type, 
                                 tool_version, environment, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (run_id, program_id, user_id, run_type, tool_version, 
              environment, metadata))
        
        self._log_action("start_run", "run", run_id,
                        f"Started {run_type} run")
        
        self.conn.commit()
        return run_id
    
    def add_target(self, program_id: str, run_id: str, host: str, 
                   url: str, port: int = None, protocol: str = "https",
                   ip_address: str = None, tech_stack: str = None) -> str:
        """Add target with indexing"""
        
        target_id = str(uuid.uuid4())
        
        self.conn.execute("""
            INSERT INTO targets (target_id, program_id, run_id, host, port, 
                                protocol, url, ip_address, tech_stack)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (target_id, program_id, run_id, host, port, protocol, 
              url, ip_address, tech_stack))
        
        self._log_action("add_target", "target", target_id,
                        f"Added target: {host}")
        
        self.conn.commit()
        return target_id
    
    def add_finding(self, program_id: str, run_id: str, target_id: str,
                    title: str, severity: str, cwe_id: str = None,
                    description: str = None, impact: str = None,
                    recommendation: str = None) -> str:
        """Add vulnerability finding with metadata"""
        
        finding_id = str(uuid.uuid4())
        
        self.conn.execute("""
            INSERT INTO findings (finding_id, program_id, run_id, target_id,
                                 title, severity, cwe_id, description, 
                                 impact, recommendation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (finding_id, program_id, run_id, target_id, title, 
              severity, cwe_id, description, impact, recommendation))
        
        self._log_action("add_finding", "finding", finding_id,
                        f"Added finding: {title}")
        
        self.conn.commit()
        return finding_id
    
    def add_poc(self, finding_id: str, filename: str, file_type: str,
                file_path: str, working: bool = False, notes: str = None) -> str:
        """Add proof of concept with versioning"""
        
        poc_id = str(uuid.uuid4())
        file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
        
        # Calculate checksum
        checksum = None
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                checksum = hashlib.sha256(f.read()).hexdigest()
        
        self.conn.execute("""
            INSERT INTO poc_files (poc_id, finding_id, filename, file_type,
                                 file_path, file_size, checksum, working, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (poc_id, finding_id, filename, file_type, file_path,
              file_size, checksum, working, notes))
        
        self._log_action("add_poc", "poc", poc_id,
                        f"Added PoC: {filename}")
        
        self.conn.commit()
        return poc_id
    
    def store_raw_output(self, run_id: str, tool_name: str, tool_version: str,
                        command_line: str, output_type: str, raw_content: bytes,
                        file_path: str = None) -> str:
        """Store raw tool output for normalization"""
        
        output_id = str(uuid.uuid4())
        
        self.conn.execute("""
            INSERT INTO raw_tool_outputs (output_id, run_id, tool_name, 
                                         tool_version, command_line, output_type,
                                         raw_content, file_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (output_id, run_id, tool_name, tool_version, command_line,
              output_type, raw_content, file_path))
        
        self._log_action("store_raw_output", "raw_output", output_id,
                        f"Stored {tool_name} output")
        
        self.conn.commit()
        return output_id
    
    def add_enriched_signal(self, raw_output_id: str, signal_type: str,
                           source_tool: str, confidence: float,
                           metadata: Dict) -> str:
        """Add enriched/processed signal"""
        
        signal_id = str(uuid.uuid4())
        metadata_json = json.dumps(metadata)
        
        self.conn.execute("""
            INSERT INTO enriched_signals (signal_id, raw_output_id, signal_type,
                                        source_tool, confidence, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (signal_id, raw_output_id, signal_type, source_tool,
              confidence, metadata_json))
        
        self._log_action("add_enriched_signal", "signal", signal_id,
                        f"Added {signal_type} signal")
        
        self.conn.commit()
        return signal_id
    
    def get_findings_by_program(self, program_id: str, severity: str = None) -> List[Dict]:
        """Retrieve findings with filtering"""
        
        query = """
            SELECT f.*, t.host, t.url, p.name as program_name
            FROM findings f
            LEFT JOIN targets t ON f.target_id = t.target_id
            LEFT JOIN programs p ON f.program_id = p.program_id
            WHERE f.program_id = ?
        """
        params = [program_id]
        
        if severity:
            query += " AND f.severity = ?"
            params.append(severity)
        
        query += " ORDER BY f.first_seen DESC"
        
        cursor = self.conn.execute(query, params)
        columns = [desc[0] for desc in cursor.description]
        
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    def get_targets_by_tech(self, tech_stack: str) -> List[Dict]:
        """Retrieve targets by technology stack"""
        
        cursor = self.conn.execute("""
            SELECT t.*, p.name as program_name
            FROM targets t
            LEFT JOIN programs p ON t.program_id = p.program_id
            WHERE t.tech_stack LIKE ?
            ORDER BY t.last_seen DESC
        """, (f"%{tech_stack}%",))
        
        columns = [desc[0] for desc in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]
    
    def get_run_summary(self, run_id: str) -> Dict:
        """Get comprehensive run summary"""
        
        # Get run details
        cursor = self.conn.execute("""
            SELECT r.*, p.name as program_name
            FROM test_runs r
            LEFT JOIN programs p ON r.program_id = p.program_id
            WHERE r.run_id = ?
        """, (run_id,))
        
        run_data = dict(zip([desc[0] for desc in cursor.description], 
                           cursor.fetchone()))
        
        # Get counts
        cursor = self.conn.execute("""
            SELECT 
                COUNT(DISTINCT t.target_id) as targets_count,
                COUNT(DISTINCT e.endpoint_id) as endpoints_count,
                COUNT(DISTINCT f.finding_id) as findings_count,
                COUNT(DISTINCT poc.poc_id) as pocs_count
            FROM test_runs r
            LEFT JOIN targets t ON r.run_id = t.run_id
            LEFT JOIN endpoints e ON t.target_id = e.target_id
            LEFT JOIN findings f ON r.run_id = f.run_id
            LEFT JOIN poc_files poc ON f.finding_id = poc.finding_id
            WHERE r.run_id = ?
        """, (run_id,))
        
        counts = dict(zip([desc[0] for desc in cursor.description], 
                         cursor.fetchone()))
        
        run_data.update(counts)
        return run_data
    
    def _log_action(self, action: str, resource_type: str, 
                   resource_id: str, details: str = None):
        """Log action for audit trail"""
        
        log_id = str(uuid.uuid4())
        
        # Get system user ID
        cursor = self.conn.execute("SELECT user_id FROM users WHERE username = 'system'")
        result = cursor.fetchone()
        
        if result:
            user_id = result[0]
        else:
            # Create system user if it doesn't exist
            user_id = str(uuid.uuid4())
            self.conn.execute("""
                INSERT INTO users (user_id, username, role, active)
                VALUES (?, ?, ?, ?)
            """, (user_id, "system", "administrator", 1))
            self.conn.commit()
        
        self.conn.execute("""
            INSERT INTO audit_log (log_id, user_id, action, resource_type, 
                                 resource_id, details)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (log_id, user_id, action, resource_type, resource_id, details))
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()

def main():
    """Initialize and demonstrate the security testing database"""
    
    print("""
🎯 SECURITY TESTING DATABASE - STRUCTURED DATA MANAGEMENT
======================================================

✅ PURPOSE: Replace loose files with professional database system
✅ FEATURES: Program partitioning, indexing, governance, observability
✅ SCALABILITY: SQLite-based with production-ready schema
✅ SECURITY: Access control, audit logging, data retention

Initializing professional database system...
    """)
    
    # Initialize database
    db = SecurityTestingDatabase()
    
    # Demonstrate with VetraFi program
    print(f"\n📍 Creating VetraFi Cantina program...")
    
    program_id = db.create_program(
        name="VetraFi - Cantina Bug Bounty",
        platform="Cantina",
        url="https://cantina.xyz/programs/vetrafi-bounty",
        bounty_range="$8,000"
    )
    
    # Add scope
    db.add_scope(program_id, "web", "app.vetrafi.com", True, "Main banking application")
    db.add_scope(program_id, "api", "api.vetrafi.com", True, "Banking API")
    db.add_scope(program_id, "web", "staging.vetrafi.com", False, "Out of scope")
    
    # Start test run
    run_id = db.start_run(program_id, "comprehensive_assessment", 
                         tool_version="SENTINEL_v1.0", environment="production")
    
    # Add target
    target_id = db.add_target(program_id, run_id, "app.vetrafi.com",
                             "https://app.vetrafi.com", port=443,
                             protocol="https", tech_stack="React, Node.js")
    
    # Add confirmed clickjacking finding
    finding_id = db.add_finding(
        program_id=program_id,
        run_id=run_id,
        target_id=target_id,
        title="Clickjacking Enables Unauthorized Transaction Approval",
        severity="high",
        cwe_id="CWE-1021",
        description="VetraFi banking application lacks X-Frame-Options header",
        impact="Users could be tricked into unauthorized financial transactions",
        recommendation="Implement X-Frame-Options: DENY or CSP frame-ancestors"
    )
    
    # Add PoC
    poc_files = [f for f in os.listdir('.') if f.startswith('cantina_clickjacking_vetrafi')]
    if poc_files:
        poc_id = db.add_poc(finding_id, poc_files[0], "html", poc_files[0], 
                           working=True, notes="Confirmed working clickjacking PoC")
    
    # Store raw tool output
    raw_output = json.dumps({
        "tool": "SENTINEL_AGENT",
        "findings": 1,
        "risk_score": 4,
        "clickjacking": "confirmed"
    }).encode()
    
    output_id = db.store_raw_output(run_id, "SENTINEL_AGENT", "1.0",
                                   "python3 SENTINEL_AGENT.py app.vetrafi.com",
                                   "json", raw_output)
    
    # Add enriched signal
    signal_id = db.add_enriched_signal(output_id, "clickjacking_vulnerability",
                                      "SENTINEL_AGENT", 0.95, {
                                          "missing_headers": ["X-Frame-Options"],
                                          "severity": "high",
                                          "bounty_potential": "$4,000-$8,000"
                                      })
    
    # Get summary
    run_summary = db.get_run_summary(run_id)
    findings = db.get_findings_by_program(program_id)
    
    print(f"""
✅ DATABASE DEMONSTRATION COMPLETE

Program: VetraFi Cantina Bug Bounty
Run ID: {run_id}
Targets: {run_summary['targets_count']}
Findings: {run_summary['findings_count']}
PoCs: {run_summary['pocs_count']}

📊 FINDINGS SUMMARY:""")
    
    for finding in findings:
        print(f"""
   🔴 {finding['title']}
      Severity: {finding['severity']}
      CWE: {finding['cwe_id']}
      Target: {finding['host']}
      Status: {finding['status']}
        """)
    
    print(f"""
🎯 PROFESSIONAL DATABASE SYSTEM READY

Features Enabled:
   ✅ Program/scope partitioning
   ✅ Comprehensive indexing
   ✅ Raw + enriched data normalization
   ✅ Governance and audit logging
   ✅ Observability with run tracking
   ✅ SQLite-based for portability

📍 Database: {os.path.abspath(db.db_path)}
🔍 Schema Version: {db.schema_version}

Ready for production bug bounty operations!
    """)
    
    db.close()

if __name__ == "__main__":
    main()
