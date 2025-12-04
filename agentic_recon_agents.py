#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Specialized Reconnaissance Agents
Purpose-built agents for bug bounty automation
"""

import asyncio
import subprocess
import json
from pathlib import Path
from typing import Dict, Any, List
from agentic_core import Agent, AgentCapability, Task, TaskPriority
import logging

logger = logging.getLogger(__name__)


# ============================================================================
# RECON AGENT - Subdomain Discovery & Asset Enumeration
# ============================================================================

async def subfinder_scan(task: Task) -> Dict[str, Any]:
    """Run subfinder for subdomain enumeration"""
    target = task.metadata.get('target', '')
    output_file = Path(f"output/{target}/subdomains.txt")
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    cmd = ['subfinder', '-d', target, '-o', str(output_file), '-silent']
    
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        if output_file.exists():
            subdomains = output_file.read_text().strip().split('\n')
            return {
                'success': True,
                'subdomains': subdomains,
                'count': len(subdomains),
                'output_file': str(output_file)
            }
        
        return {'success': False, 'error': 'No subdomains found'}
        
    except Exception as e:
        logger.error(f"Subfinder error: {e}")
        return {'success': False, 'error': str(e)}


async def amass_scan(task: Task) -> Dict[str, Any]:
    """Run amass for deep subdomain enumeration"""
    target = task.metadata.get('target', '')
    output_file = Path(f"output/{target}/amass_subdomains.txt")
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    cmd = ['amass', 'enum', '-passive', '-d', target, '-o', str(output_file)]
    
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.communicate()
        
        if output_file.exists():
            subdomains = output_file.read_text().strip().split('\n')
            return {
                'success': True,
                'subdomains': subdomains,
                'count': len(subdomains),
                'output_file': str(output_file)
            }
        
        return {'success': False, 'error': 'Amass scan failed'}
        
    except Exception as e:
        logger.error(f"Amass error: {e}")
        return {'success': False, 'error': str(e)}


async def httprobe_check(task: Task) -> Dict[str, Any]:
    """Probe for live HTTP/HTTPS services"""
    input_file = task.metadata.get('input_file', '')
    target = task.metadata.get('target', '')
    output_file = Path(f"output/{target}/live_hosts.txt")
    
    try:
        # Read subdomains
        with open(input_file, 'r') as f:
            subdomains = f.read()
        
        # Run httprobe
        proc = await asyncio.create_subprocess_exec(
            'httprobe',
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await proc.communicate(input=subdomains.encode())
        
        live_hosts = stdout.decode().strip().split('\n')
        
        # Save results
        output_file.write_text('\n'.join(live_hosts))
        
        return {
            'success': True,
            'live_hosts': live_hosts,
            'count': len(live_hosts),
            'output_file': str(output_file)
        }
        
    except Exception as e:
        logger.error(f"Httprobe error: {e}")
        return {'success': False, 'error': str(e)}


# ============================================================================
# WEB MAPPER AGENT - Technology Detection & Crawling
# ============================================================================

async def httpx_scan(task: Task) -> Dict[str, Any]:
    """Run httpx for detailed HTTP analysis"""
    input_file = task.metadata.get('input_file', '')
    target = task.metadata.get('target', '')
    output_file = Path(f"output/{target}/httpx_results.json")
    
    cmd = [
        'httpx',
        '-l', input_file,
        '-json',
        '-o', str(output_file),
        '-tech-detect',
        '-status-code',
        '-content-length',
        '-title'
    ]
    
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.communicate()
        
        if output_file.exists():
            results = []
            with open(output_file, 'r') as f:
                for line in f:
                    if line.strip():
                        results.append(json.loads(line))
            
            return {
                'success': True,
                'results': results,
                'count': len(results),
                'output_file': str(output_file)
            }
        
        return {'success': False, 'error': 'Httpx scan failed'}
        
    except Exception as e:
        logger.error(f"Httpx error: {e}")
        return {'success': False, 'error': str(e)}


async def waybackurls_fetch(task: Task) -> Dict[str, Any]:
    """Fetch URLs from Wayback Machine"""
    target = task.metadata.get('target', '')
    output_file = Path(f"output/{target}/wayback_urls.txt")
    
    cmd = f"echo {target} | waybackurls"
    
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        urls = stdout.decode().strip().split('\n')
        
        output_file.write_text('\n'.join(urls))
        
        return {
            'success': True,
            'urls': urls,
            'count': len(urls),
            'output_file': str(output_file)
        }
        
    except Exception as e:
        logger.error(f"Waybackurls error: {e}")
        return {'success': False, 'error': str(e)}


# ============================================================================
# VULNERABILITY HUNTER AGENT - Security Scanning
# ============================================================================

async def nuclei_scan(task: Task) -> Dict[str, Any]:
    """Run Nuclei vulnerability scanner"""
    input_file = task.metadata.get('input_file', '')
    target = task.metadata.get('target', '')
    severity = task.metadata.get('severity', 'medium,high,critical')
    output_file = Path(f"output/{target}/nuclei_results.json")
    
    cmd = [
        'nuclei',
        '-l', input_file,
        '-severity', severity,
        '-json',
        '-o', str(output_file),
        '-silent'
    ]
    
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.communicate()
        
        if output_file.exists():
            vulnerabilities = []
            with open(output_file, 'r') as f:
                for line in f:
                    if line.strip():
                        vulnerabilities.append(json.loads(line))
            
            # Categorize by severity
            severity_counts = {}
            for vuln in vulnerabilities:
                sev = vuln.get('info', {}).get('severity', 'unknown')
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            return {
                'success': True,
                'vulnerabilities': vulnerabilities,
                'total_count': len(vulnerabilities),
                'severity_breakdown': severity_counts,
                'output_file': str(output_file)
            }
        
        return {'success': True, 'vulnerabilities': [], 'total_count': 0}
        
    except Exception as e:
        logger.error(f"Nuclei error: {e}")
        return {'success': False, 'error': str(e)}


async def dalfox_xss_scan(task: Task) -> Dict[str, Any]:
    """Run Dalfox for XSS detection"""
    url = task.metadata.get('url', '')
    target = task.metadata.get('target', '')
    output_file = Path(f"output/{target}/dalfox_xss.json")
    
    cmd = ['dalfox', 'url', url, '--output', str(output_file), '--format', 'json']
    
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await proc.communicate()
        
        if output_file.exists():
            with open(output_file, 'r') as f:
                results = json.load(f)
            
            return {
                'success': True,
                'xss_found': len(results) > 0,
                'results': results,
                'output_file': str(output_file)
            }
        
        return {'success': True, 'xss_found': False}
        
    except Exception as e:
        logger.error(f"Dalfox error: {e}")
        return {'success': False, 'error': str(e)}


# ============================================================================
# TRIAGE AGENT - Result Analysis & Prioritization
# ============================================================================

async def analyze_vulnerabilities(task: Task) -> Dict[str, Any]:
    """Analyze and prioritize vulnerabilities"""
    vuln_file = task.metadata.get('vuln_file', '')
    
    try:
        vulnerabilities = []
        with open(vuln_file, 'r') as f:
            for line in f:
                if line.strip():
                    vulnerabilities.append(json.loads(line))
        
        # Prioritize vulnerabilities
        critical = [v for v in vulnerabilities if v.get('info', {}).get('severity') == 'critical']
        high = [v for v in vulnerabilities if v.get('info', {}).get('severity') == 'high']
        medium = [v for v in vulnerabilities if v.get('info', {}).get('severity') == 'medium']
        
        # Extract unique templates
        templates_used = list(set(v.get('template-id', 'unknown') for v in vulnerabilities))
        
        return {
            'success': True,
            'total': len(vulnerabilities),
            'critical': len(critical),
            'high': len(high),
            'medium': len(medium),
            'unique_templates': len(templates_used),
            'priority_vulns': critical[:10],  # Top 10 critical
            'analysis': {
                'immediate_action_required': len(critical) > 0,
                'bug_bounty_potential': len(critical) + len(high),
                'report_ready': len(critical) > 0 or len(high) >= 3
            }
        }
        
    except Exception as e:
        logger.error(f"Analysis error: {e}")
        return {'success': False, 'error': str(e)}


async def deduplicate_results(task: Task) -> Dict[str, Any]:
    """Remove duplicate findings"""
    input_file = task.metadata.get('input_file', '')
    
    try:
        results = []
        with open(input_file, 'r') as f:
            for line in f:
                if line.strip():
                    results.append(json.loads(line))
        
        # Dedup by template-id and matched-at
        seen = set()
        unique_results = []
        
        for result in results:
            key = (
                result.get('template-id'),
                result.get('matched-at', '')
            )
            if key not in seen:
                seen.add(key)
                unique_results.append(result)
        
        duplicates_removed = len(results) - len(unique_results)
        
        return {
            'success': True,
            'original_count': len(results),
            'unique_count': len(unique_results),
            'duplicates_removed': duplicates_removed,
            'results': unique_results
        }
        
    except Exception as e:
        logger.error(f"Deduplication error: {e}")
        return {'success': False, 'error': str(e)}


# ============================================================================
# REPORT WRITER AGENT - Documentation Generation
# ============================================================================

async def generate_markdown_report(task: Task) -> Dict[str, Any]:
    """Generate markdown report from findings"""
    vulns = task.metadata.get('vulnerabilities', [])
    target = task.metadata.get('target', '')
    output_file = Path(f"output/{target}/REPORT.md")
    
    try:
        report_lines = [
            f"# Security Assessment Report: {target}",
            f"\nGenerated: {asyncio.get_event_loop().time()}",
            f"\n## Executive Summary",
            f"\n- Total Vulnerabilities: {len(vulns)}",
        ]
        
        # Group by severity
        by_severity = {}
        for vuln in vulns:
            sev = vuln.get('info', {}).get('severity', 'unknown')
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(vuln)
        
        for sev in ['critical', 'high', 'medium', 'low']:
            if sev in by_severity:
                report_lines.append(f"- {sev.upper()}: {len(by_severity[sev])}")
        
        report_lines.append("\n## Detailed Findings\n")
        
        for sev in ['critical', 'high', 'medium']:
            if sev in by_severity:
                report_lines.append(f"\n### {sev.upper()} Severity\n")
                for vuln in by_severity[sev]:
                    info = vuln.get('info', {})
                    report_lines.append(f"\n#### {info.get('name', 'Unknown')}")
                    report_lines.append(f"- **Template**: {vuln.get('template-id')}")
                    report_lines.append(f"- **URL**: {vuln.get('matched-at')}")
                    report_lines.append(f"- **Description**: {info.get('description', 'N/A')}")
                    report_lines.append("")
        
        output_file.write_text('\n'.join(report_lines))
        
        return {
            'success': True,
            'report_file': str(output_file),
            'sections': len(by_severity)
        }
        
    except Exception as e:
        logger.error(f"Report generation error: {e}")
        return {'success': False, 'error': str(e)}


# ============================================================================
# AGENT FACTORY - Create Specialized Agents
# ============================================================================

def create_recon_agent() -> Agent:
    """Create reconnaissance specialist agent"""
    capabilities = [
        AgentCapability("subfinder", "Subfinder subdomain enumeration", subfinder_scan),
        AgentCapability("amass", "Amass deep enumeration", amass_scan),
        AgentCapability("httprobe", "HTTP/HTTPS probing", httprobe_check),
    ]
    
    return Agent(
        agent_id="recon_agent",
        name="Recon Specialist",
        role="Asset Discovery & Enumeration",
        capabilities=capabilities
    )


def create_web_mapper_agent() -> Agent:
    """Create web mapping agent"""
    capabilities = [
        AgentCapability("httpx", "HTTP analysis with httpx", httpx_scan),
        AgentCapability("wayback", "Wayback Machine URL fetching", waybackurls_fetch),
    ]
    
    return Agent(
        agent_id="web_mapper",
        name="Web Mapper",
        role="Technology Detection & Crawling",
        capabilities=capabilities
    )


def create_vuln_hunter_agent() -> Agent:
    """Create vulnerability hunting agent"""
    capabilities = [
        AgentCapability("nuclei", "Nuclei vulnerability scanning", nuclei_scan),
        AgentCapability("xss_scan", "XSS detection with Dalfox", dalfox_xss_scan),
    ]
    
    return Agent(
        agent_id="vuln_hunter",
        name="Vulnerability Hunter",
        role="Security Scanning & Exploitation",
        capabilities=capabilities
    )


def create_triage_agent() -> Agent:
    """Create triage agent"""
    capabilities = [
        AgentCapability("analyze", "Vulnerability analysis", analyze_vulnerabilities),
        AgentCapability("deduplicate", "Result deduplication", deduplicate_results),
    ]
    
    return Agent(
        agent_id="triage_agent",
        name="Triage Specialist",
        role="Result Analysis & Prioritization",
        capabilities=capabilities
    )


def create_report_agent() -> Agent:
    """Create reporting agent"""
    capabilities = [
        AgentCapability("markdown_report", "Markdown report generation", generate_markdown_report),
    ]
    
    return Agent(
        agent_id="report_writer",
        name="Report Writer",
        role="Documentation & Reporting",
        capabilities=capabilities
    )


def create_all_agents() -> List[Agent]:
    """Create all specialized agents"""
    return [
        create_recon_agent(),
        create_web_mapper_agent(),
        create_vuln_hunter_agent(),
        create_triage_agent(),
        create_report_agent()
    ]
