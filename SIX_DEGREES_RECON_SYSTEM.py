#!/usr/bin/env python3
"""
SIX DEGREES SECURITY RECONNAISSANCE SYSTEM
==========================================
Graph-based agentic reconnaissance that maps relationships
and pivots through connected assets automatically.

CONCEPT: Like "Six Degrees of Kevin Bacon" but for attack surfaces.
- Degree 1: Direct assets (subdomains, IPs)
- Degree 2: Connected services (CDNs, APIs, third-parties)
- Degree 3: Related entities (acquisitions, partners)
- Degree 4: Developer footprints (repos, commits, leaks)
- Degree 5: Infrastructure patterns (shared hosting, similar configs)
- Degree 6: Vulnerability correlation (same bugs across related targets)

SAFETY: All operations require authorization and stay in scope.

Copyright (c) 2025 DoctorMen
"""

import json
import subprocess
import hashlib
import os
import sys
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import logging
import re

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('six_degrees_recon.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class NodeType(Enum):
    """Types of nodes in the reconnaissance graph"""
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    TECHNOLOGY = "technology"
    PERSON = "person"
    EMAIL = "email"
    REPOSITORY = "repository"
    API_ENDPOINT = "api_endpoint"
    VULNERABILITY = "vulnerability"
    CERTIFICATE = "certificate"
    ORGANIZATION = "organization"
    SERVICE = "service"


class EdgeType(Enum):
    """Types of relationships between nodes"""
    RESOLVES_TO = "resolves_to"
    HAS_SUBDOMAIN = "has_subdomain"
    USES_TECHNOLOGY = "uses_technology"
    OWNED_BY = "owned_by"
    SIMILAR_TO = "similar_to"
    HAS_VULNERABILITY = "has_vulnerability"
    CONNECTED_TO = "connected_to"
    SHARES_CERTIFICATE = "shares_certificate"
    DEVELOPED_BY = "developed_by"
    ACQUIRED = "acquired"
    PARTNERS_WITH = "partners_with"
    HOSTS = "hosts"


@dataclass
class Node:
    """A node in the reconnaissance graph"""
    id: str
    type: NodeType
    value: str
    degree: int  # How many hops from the seed target
    metadata: Dict = field(default_factory=dict)
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    explored: bool = False
    in_scope: bool = True
    findings: List[Dict] = field(default_factory=list)
    
    def to_dict(self):
        d = asdict(self)
        d['type'] = self.type.value
        return d


@dataclass
class Edge:
    """A relationship between two nodes"""
    source_id: str
    target_id: str
    type: EdgeType
    metadata: Dict = field(default_factory=dict)
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self):
        d = asdict(self)
        d['type'] = self.type.value
        return d


class ScopeGuard:
    """
    CRITICAL SAFETY COMPONENT
    Ensures all reconnaissance stays within authorized scope.
    """
    
    def __init__(self, authorized_scope: List[str], forbidden: List[str] = None):
        self.authorized_scope = authorized_scope
        self.forbidden = forbidden or []
        self.checked_targets: Set[str] = set()
        self.blocked_attempts: List[Dict] = []
    
    def is_in_scope(self, target: str) -> Tuple[bool, str]:
        """Check if a target is within authorized scope"""
        target_lower = target.lower().strip()
        
        # Check forbidden list first
        for forbidden in self.forbidden:
            if forbidden.lower() in target_lower:
                reason = f"Target matches forbidden pattern: {forbidden}"
                self._log_blocked(target, reason)
                return False, reason
        
        # Check against authorized scope
        for scope_item in self.authorized_scope:
            scope_lower = scope_item.lower()
            
            # Exact match
            if target_lower == scope_lower:
                return True, "Exact match"
            
            # Wildcard subdomain match (*.example.com)
            if scope_lower.startswith("*."):
                base_domain = scope_lower[2:]
                if target_lower.endswith(base_domain):
                    return True, f"Wildcard match: {scope_item}"
            
            # Subdomain of authorized domain
            if target_lower.endswith("." + scope_lower):
                return True, f"Subdomain of: {scope_item}"
        
        reason = f"Target not in authorized scope: {self.authorized_scope}"
        self._log_blocked(target, reason)
        return False, reason
    
    def _log_blocked(self, target: str, reason: str):
        """Log blocked access attempts"""
        self.blocked_attempts.append({
            "target": target,
            "reason": reason,
            "timestamp": datetime.now().isoformat()
        })
        logger.warning(f"SCOPE BLOCKED: {target} - {reason}")


class ReconGraph:
    """
    Graph database for storing reconnaissance findings.
    Maps relationships between discovered assets.
    """
    
    def __init__(self):
        self.nodes: Dict[str, Node] = {}
        self.edges: List[Edge] = []
        self.node_index: Dict[str, Set[str]] = {}  # type -> node_ids
    
    def add_node(self, node: Node) -> bool:
        """Add a node to the graph"""
        if node.id in self.nodes:
            return False
        
        self.nodes[node.id] = node
        
        # Index by type
        type_key = node.type.value
        if type_key not in self.node_index:
            self.node_index[type_key] = set()
        self.node_index[type_key].add(node.id)
        
        logger.info(f"Added node: {node.type.value} - {node.value} (degree {node.degree})")
        return True
    
    def add_edge(self, edge: Edge) -> bool:
        """Add an edge to the graph"""
        if edge.source_id not in self.nodes or edge.target_id not in self.nodes:
            logger.warning(f"Cannot add edge: missing node(s)")
            return False
        
        self.edges.append(edge)
        logger.info(f"Added edge: {edge.source_id} --[{edge.type.value}]--> {edge.target_id}")
        return True
    
    def get_node(self, node_id: str) -> Optional[Node]:
        """Get a node by ID"""
        return self.nodes.get(node_id)
    
    def get_nodes_by_type(self, node_type: NodeType) -> List[Node]:
        """Get all nodes of a specific type"""
        type_key = node_type.value
        if type_key not in self.node_index:
            return []
        return [self.nodes[nid] for nid in self.node_index[type_key]]
    
    def get_unexplored_nodes(self, max_degree: int = 6) -> List[Node]:
        """Get nodes that haven't been explored yet"""
        return [
            n for n in self.nodes.values() 
            if not n.explored and n.in_scope and n.degree < max_degree
        ]
    
    def get_neighbors(self, node_id: str) -> List[Node]:
        """Get all nodes connected to a given node"""
        neighbors = []
        for edge in self.edges:
            if edge.source_id == node_id:
                if edge.target_id in self.nodes:
                    neighbors.append(self.nodes[edge.target_id])
            elif edge.target_id == node_id:
                if edge.source_id in self.nodes:
                    neighbors.append(self.nodes[edge.source_id])
        return neighbors
    
    def get_statistics(self) -> Dict:
        """Get graph statistics"""
        stats = {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "nodes_by_type": {},
            "nodes_by_degree": {},
            "explored": sum(1 for n in self.nodes.values() if n.explored),
            "unexplored": sum(1 for n in self.nodes.values() if not n.explored),
            "in_scope": sum(1 for n in self.nodes.values() if n.in_scope),
            "out_of_scope": sum(1 for n in self.nodes.values() if not n.in_scope),
            "vulnerabilities_found": sum(len(n.findings) for n in self.nodes.values())
        }
        
        for node in self.nodes.values():
            # By type
            type_key = node.type.value
            stats["nodes_by_type"][type_key] = stats["nodes_by_type"].get(type_key, 0) + 1
            
            # By degree
            degree_key = str(node.degree)
            stats["nodes_by_degree"][degree_key] = stats["nodes_by_degree"].get(degree_key, 0) + 1
        
        return stats
    
    def to_dict(self) -> Dict:
        """Export graph to dictionary"""
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "statistics": self.get_statistics()
        }
    
    def save(self, filepath: str):
        """Save graph to JSON file"""
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
        logger.info(f"Graph saved to: {filepath}")


class ToolRunner:
    """Execute real reconnaissance tools"""
    
    def __init__(self, timeout: int = 60):
        self.timeout = timeout
        self.available_tools = self._check_tools()
    
    def _check_tools(self) -> Dict[str, bool]:
        """Check which tools are available"""
        tools = {}
        tool_checks = [
            ("subfinder", "subfinder -version"),
            ("httpx", "httpx -version"),
            ("nuclei", "nuclei -version"),
            ("dig", "dig -v"),
            ("curl", "curl --version"),
            ("nmap", "nmap --version"),
            ("whois", "whois --version"),
        ]
        
        for name, cmd in tool_checks:
            try:
                result = subprocess.run(
                    cmd, shell=True, capture_output=True, 
                    text=True, timeout=10
                )
                tools[name] = result.returncode == 0 or name in result.stdout or name in result.stderr
            except:
                tools[name] = False
        
        return tools
    
    def run(self, cmd: str, timeout: int = None) -> Tuple[str, str, int]:
        """Run a command and return output"""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True,
                text=True, timeout=timeout or self.timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Timeout", -1
        except Exception as e:
            return "", str(e), -1


class SixDegreesReconSystem:
    """
    Main reconnaissance system that explores targets using
    the six degrees methodology.
    """
    
    def __init__(self, seed_target: str, scope: List[str], 
                 max_degree: int = 3, dry_run: bool = False):
        self.seed_target = seed_target
        self.max_degree = max_degree
        self.dry_run = dry_run
        
        # Initialize components
        self.scope_guard = ScopeGuard(scope)
        self.graph = ReconGraph()
        self.tools = ToolRunner()
        
        # Add seed node
        seed_node = Node(
            id=self._make_id(seed_target),
            type=NodeType.DOMAIN,
            value=seed_target,
            degree=0
        )
        self.graph.add_node(seed_node)
        
        logger.info(f"Six Degrees Recon initialized for: {seed_target}")
        logger.info(f"Scope: {scope}")
        logger.info(f"Max degree: {max_degree}")
        logger.info(f"Dry run: {dry_run}")
    
    def _make_id(self, value: str) -> str:
        """Generate a unique ID for a value"""
        return hashlib.md5(value.encode()).hexdigest()[:12]
    
    def run(self) -> Dict:
        """Run the full reconnaissance workflow"""
        print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║           SIX DEGREES SECURITY RECONNAISSANCE SYSTEM                 ║
║        Graph-Based | Relationship Mapping | Real Tools               ║
╚══════════════════════════════════════════════════════════════════════╝

🎯 Seed Target: {self.seed_target}
📊 Max Degree: {self.max_degree}
🔒 Scope: {self.scope_guard.authorized_scope}
        """)
        
        # Process each degree
        for degree in range(self.max_degree + 1):
            print(f"\n{'='*60}")
            print(f"📍 DEGREE {degree}: Exploring connections")
            print(f"{'='*60}")
            
            # Get unexplored nodes at current degree
            nodes_to_explore = [
                n for n in self.graph.get_unexplored_nodes()
                if n.degree == degree
            ]
            
            if not nodes_to_explore:
                print(f"   No nodes to explore at degree {degree}")
                continue
            
            print(f"   Nodes to explore: {len(nodes_to_explore)}")
            
            for node in nodes_to_explore:
                self._explore_node(node)
        
        # Generate summary
        return self._generate_report()
    
    def _explore_node(self, node: Node):
        """Explore a single node and discover connected assets"""
        print(f"\n   🔍 Exploring: {node.value} ({node.type.value})")
        
        # Check scope
        in_scope, reason = self.scope_guard.is_in_scope(node.value)
        if not in_scope:
            print(f"      ⛔ Out of scope: {reason}")
            node.in_scope = False
            node.explored = True
            return
        
        # Mark as explored
        node.explored = True
        
        # Run appropriate reconnaissance based on node type
        if node.type == NodeType.DOMAIN or node.type == NodeType.SUBDOMAIN:
            self._explore_domain(node)
        elif node.type == NodeType.IP_ADDRESS:
            self._explore_ip(node)
        elif node.type == NodeType.REPOSITORY:
            self._explore_repo(node)
    
    def _explore_domain(self, node: Node):
        """Explore a domain node"""
        domain = node.value
        next_degree = node.degree + 1
        
        if next_degree > self.max_degree:
            print(f"      ⏹️  Max degree reached, not exploring further")
            return
        
        # 1. DNS Resolution
        print(f"      → DNS resolution...")
        if not self.dry_run:
            stdout, _, _ = self.tools.run(f"dig +short {domain} A")
            for ip in stdout.strip().split('\n'):
                if ip.strip() and self._is_valid_ip(ip.strip()):
                    ip_node = Node(
                        id=self._make_id(ip.strip()),
                        type=NodeType.IP_ADDRESS,
                        value=ip.strip(),
                        degree=next_degree
                    )
                    if self.graph.add_node(ip_node):
                        self.graph.add_edge(Edge(
                            source_id=node.id,
                            target_id=ip_node.id,
                            type=EdgeType.RESOLVES_TO
                        ))
                        print(f"         Found IP: {ip.strip()}")
        
        # 2. Subdomain Enumeration
        print(f"      → Subdomain enumeration...")
        if not self.dry_run and self.tools.available_tools.get("subfinder"):
            stdout, _, _ = self.tools.run(f"subfinder -d {domain} -silent", timeout=120)
            subdomains = [s.strip() for s in stdout.strip().split('\n') if s.strip()]
            
            for subdomain in subdomains[:20]:  # Limit to prevent explosion
                in_scope, _ = self.scope_guard.is_in_scope(subdomain)
                sub_node = Node(
                    id=self._make_id(subdomain),
                    type=NodeType.SUBDOMAIN,
                    value=subdomain,
                    degree=next_degree,
                    in_scope=in_scope
                )
                if self.graph.add_node(sub_node):
                    self.graph.add_edge(Edge(
                        source_id=node.id,
                        target_id=sub_node.id,
                        type=EdgeType.HAS_SUBDOMAIN
                    ))
            
            print(f"         Found {len(subdomains)} subdomains")
        
        # 3. Technology Detection
        print(f"      → Technology detection...")
        if not self.dry_run:
            stdout, _, code = self.tools.run(f"curl -sI https://{domain} 2>/dev/null | head -20")
            if stdout:
                techs = self._detect_technologies(stdout)
                for tech in techs:
                    tech_node = Node(
                        id=self._make_id(f"tech:{tech}"),
                        type=NodeType.TECHNOLOGY,
                        value=tech,
                        degree=next_degree
                    )
                    if self.graph.add_node(tech_node):
                        self.graph.add_edge(Edge(
                            source_id=node.id,
                            target_id=tech_node.id,
                            type=EdgeType.USES_TECHNOLOGY
                        ))
                        print(f"         Found tech: {tech}")
        
        # 4. Security Header Check
        print(f"      → Security header analysis...")
        if not self.dry_run:
            findings = self._check_security_headers(domain)
            node.findings.extend(findings)
            if findings:
                print(f"         Found {len(findings)} security issues")
    
    def _explore_ip(self, node: Node):
        """Explore an IP address node"""
        # Could add reverse DNS, port scanning, etc.
        pass
    
    def _explore_repo(self, node: Node):
        """Explore a repository node"""
        # Could add commit analysis, secret scanning, etc.
        pass
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IP address"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    
    def _detect_technologies(self, headers: str) -> List[str]:
        """Detect technologies from HTTP headers"""
        techs = []
        headers_lower = headers.lower()
        
        tech_signatures = {
            "nginx": "nginx",
            "apache": "apache",
            "cloudflare": "cloudflare",
            "aws": "amazons3",
            "express": "express",
            "php": "x-powered-by: php",
            "asp.net": "x-aspnet",
            "react": "x-react",
            "next.js": "x-nextjs",
        }
        
        for tech, signature in tech_signatures.items():
            if signature in headers_lower:
                techs.append(tech)
        
        return techs
    
    def _check_security_headers(self, domain: str) -> List[Dict]:
        """Check for missing security headers"""
        findings = []
        
        stdout, _, _ = self.tools.run(f"curl -sI https://{domain} 2>/dev/null")
        if not stdout:
            stdout, _, _ = self.tools.run(f"curl -sI http://{domain} 2>/dev/null")
        
        if not stdout:
            return findings
        
        headers_lower = stdout.lower()
        
        security_headers = {
            "x-frame-options": ("Clickjacking Protection", "medium"),
            "x-content-type-options": ("MIME Sniffing Protection", "low"),
            "content-security-policy": ("XSS Protection", "medium"),
            "strict-transport-security": ("HTTPS Enforcement", "medium"),
        }
        
        for header, (purpose, severity) in security_headers.items():
            if header not in headers_lower:
                findings.append({
                    "type": "missing_security_header",
                    "header": header,
                    "purpose": purpose,
                    "severity": severity,
                    "target": domain,
                    "evidence": f"Header '{header}' not found in HTTP response"
                })
        
        return findings
    
    def _generate_report(self) -> Dict:
        """Generate final reconnaissance report"""
        stats = self.graph.get_statistics()
        
        # Collect all findings
        all_findings = []
        for node in self.graph.nodes.values():
            all_findings.extend(node.findings)
        
        report = {
            "seed_target": self.seed_target,
            "timestamp": datetime.now().isoformat(),
            "max_degree": self.max_degree,
            "statistics": stats,
            "findings": all_findings,
            "graph": self.graph.to_dict()
        }
        
        # Print summary
        print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║                    RECONNAISSANCE COMPLETE                           ║
╚══════════════════════════════════════════════════════════════════════╝

📊 GRAPH STATISTICS:
   Total Nodes: {stats['total_nodes']}
   Total Edges: {stats['total_edges']}
   Explored: {stats['explored']}
   In Scope: {stats['in_scope']}

📍 NODES BY DEGREE:""")
        
        for degree, count in sorted(stats['nodes_by_degree'].items()):
            print(f"   Degree {degree}: {count} nodes")
        
        print(f"""
📦 NODES BY TYPE:""")
        for ntype, count in stats['nodes_by_type'].items():
            print(f"   {ntype}: {count}")
        
        print(f"""
🚨 VULNERABILITIES FOUND: {len(all_findings)}
""")
        
        for i, finding in enumerate(all_findings[:10], 1):
            print(f"   [{i}] {finding.get('severity', 'info').upper()}: {finding.get('type')}")
            print(f"       Target: {finding.get('target')}")
        
        # Save report
        report_file = f"six_degrees_{self.seed_target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n💾 Full report saved: {report_file}")
        
        return report


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Six Degrees Security Reconnaissance")
    parser.add_argument("target", help="Seed target domain")
    parser.add_argument("--scope", nargs="+", help="Authorized scope (domains)")
    parser.add_argument("--max-degree", type=int, default=2, help="Maximum degrees to explore")
    parser.add_argument("--dry-run", action="store_true", help="Don't run actual tools")
    
    args = parser.parse_args()
    
    # Default scope is the target and its subdomains
    scope = args.scope or [args.target, f"*.{args.target}"]
    
    system = SixDegreesReconSystem(
        seed_target=args.target,
        scope=scope,
        max_degree=args.max_degree,
        dry_run=args.dry_run
    )
    
    report = system.run()


if __name__ == "__main__":
    main()
