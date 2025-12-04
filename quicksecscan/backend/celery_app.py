#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
QuickSecScan Backend - Celery Worker
Executes scan jobs, generates reports, sends emails
"""
import os
import subprocess
import json
import tempfile
import shutil
from datetime import datetime
from celery import Celery
from jinja2 import Template
from weasyprint import HTML
import boto3
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import logging
from api_security_scanner import APISecurityScanner

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Celery config
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
app = Celery('quicksecscan', broker=REDIS_URL, backend=REDIS_URL)

# AWS S3/R2 config
S3_BUCKET = os.getenv("S3_BUCKET", "quicksecscan-reports")
S3_REGION = os.getenv("S3_REGION", "us-east-1")
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
s3_client = boto3.client('s3', region_name=S3_REGION, aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY)

# SendGrid config
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
FROM_EMAIL = os.getenv("FROM_EMAIL", "reports@quicksecscan.com")
MONITORING_EMAIL = os.getenv("MONITORING_EMAIL", "doctormen131@outlook.com")

@app.task(bind=True, max_retries=2)
def scan_task(self, domain=None, api_endpoint=None, customer_email=None, session_id=None, tier='basic', scan_type='web'):
    """Execute security scan and deliver report
    
    scan_type: 'web' for web security scan, 'api' for API security scan
    """
    target = api_endpoint or domain
    logger.info(f"Starting {scan_type} scan for {target}, session {session_id}")
    
    # Create temp workspace
    workspace = tempfile.mkdtemp(prefix=f"scan_{target}_")
    output_dir = os.path.join(workspace, "output")
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        if scan_type == 'api':
            # Step 1: Run API security scan
            findings = run_api_scan_pipeline(api_endpoint, tier, workspace)
        else:
            # Step 1: Run web security scan pipeline
            findings = run_scan_pipeline(domain, output_dir)
        
        # Step 2: Save snapshot for self-improvement
        save_scan_snapshot(target, findings, workspace, scan_type)
        
        # Step 3: Generate PDF report
        pdf_path = generate_pdf_report(target, findings, workspace, scan_type)
        
        # Step 4: Upload to S3
        report_url = upload_to_s3(pdf_path, target, session_id)
        
        # Step 5: Email customer
        send_report_email(customer_email, target, report_url, findings, scan_type)
        
        logger.info(f"Scan completed for {target}, report: {report_url}")
        return {"status": "success", "report_url": report_url, "findings_count": len(findings)}
        
    except Exception as e:
        logger.error(f"Scan failed for {target}: {str(e)}")
        # Retry or notify customer of failure
        send_failure_email(customer_email, target, str(e))
        raise self.retry(exc=e, countdown=300)  # Retry after 5 min
        
    finally:
        # Cleanup
        shutil.rmtree(workspace, ignore_errors=True)

def run_api_scan_pipeline(api_endpoint, tier, workspace):
    """Execute API security scan pipeline"""
    logger.info(f"Running API security scan for {api_endpoint}, tier: {tier}")
    
    # Initialize API scanner
    scanner = APISecurityScanner(api_endpoint)
    
    # Run comprehensive scan based on tier
    findings = scanner.scan(tier=tier)
    
    # Convert findings to standard format
    standardized_findings = []
    for finding in findings:
        standardized_findings.append({
            'severity': finding.get('severity', 'MEDIUM').upper(),
            'name': finding.get('type', 'API Security Issue'),
            'description': finding.get('description', ''),
            'host': finding.get('endpoint', api_endpoint),
            'matched_at': finding.get('endpoint', api_endpoint),
            'poc': finding.get('poc', ''),
            'recommendation': finding.get('recommendation', ''),
            'cwe': finding.get('cwe', []),
            'cvss': 0
        })
    
    logger.info(f"API security scan found {len(standardized_findings)} issues")
    return standardized_findings

def run_scan_pipeline(domain, output_dir):
    """Execute HTTPx + Nuclei pipeline"""
    logger.info(f"Running scan pipeline for {domain}")
    findings = []
    
    # Step 1: Subdomain enumeration (subfinder)
    logger.info(f"Enumerating subdomains for {domain}")
    subdomains_file = os.path.join(output_dir, "subdomains.txt")
    try:
        subprocess.run([
            "subfinder", "-d", domain, "-silent", "-o", subdomains_file
        ], check=True, timeout=300)
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
        logger.warning(f"Subfinder failed for {domain}: {e}")
        # Fallback: just scan apex domain
        with open(subdomains_file, 'w') as f:
            f.write(f"{domain}\n")
    
    # Step 2: HTTP probing (HTTPx)
    logger.info(f"Probing live hosts for {domain}")
    httpx_file = os.path.join(output_dir, "httpx.txt")
    try:
        subprocess.run([
            "httpx", "-l", subdomains_file, "-silent", "-o", httpx_file,
            "-title", "-status-code", "-content-length", "-tech-detect"
        ], check=True, timeout=600)
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
        logger.error(f"HTTPx failed for {domain}: {e}")
        return findings
    
    # Step 3: Vulnerability scanning (Nuclei)
    logger.info(f"Running Nuclei for {domain}")
    nuclei_output = os.path.join(output_dir, "nuclei.json")
    try:
        subprocess.run([
            "nuclei", "-l", httpx_file, "-silent", "-jsonl", "-o", nuclei_output,
            "-severity", "critical,high,medium", "-rate-limit", "150"
        ], check=True, timeout=1800)
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
        logger.warning(f"Nuclei completed with errors for {domain}: {e}")
    
    # Parse Nuclei findings
    if os.path.exists(nuclei_output):
        with open(nuclei_output, 'r') as f:
            for line in f:
                try:
                    finding = json.loads(line.strip())
                    findings.append({
                        'severity': finding.get('info', {}).get('severity', 'unknown').upper(),
                        'name': finding.get('info', {}).get('name', 'Unknown'),
                        'description': finding.get('info', {}).get('description', ''),
                        'host': finding.get('host', ''),
                        'matched_at': finding.get('matched-at', ''),
                        'cwe': finding.get('info', {}).get('classification', {}).get('cwe-id', []),
                        'cvss': finding.get('info', {}).get('classification', {}).get('cvss-score', 0)
                    })
                except json.JSONDecodeError:
                    continue
    
    logger.info(f"Found {len(findings)} issues for {domain}")
    return findings

def save_scan_snapshot(target, findings, workspace, scan_type='web'):
    """Save scan snapshot for self-improvement analysis"""
    snapshot = {
        'target': target,
        'scan_type': scan_type,
        'timestamp': datetime.utcnow().isoformat(),
        'findings_count': len(findings),
        'findings_by_severity': {
            'CRITICAL': len([f for f in findings if f['severity'] == 'CRITICAL']),
            'HIGH': len([f for f in findings if f['severity'] == 'HIGH']),
            'MEDIUM': len([f for f in findings if f['severity'] == 'MEDIUM']),
        },
        'findings': findings
    }
    
    snapshot_file = os.path.join(workspace, "snapshot.json")
    with open(snapshot_file, 'w') as f:
        json.dump(snapshot, f, indent=2)
    
    # Upload snapshot to S3 for later analysis
    snapshot_key = f"snapshots/{scan_type}/{target.replace('://', '_').replace('/', '_')}/{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        s3_client.upload_file(snapshot_file, S3_BUCKET, snapshot_key)
        logger.info(f"Snapshot saved: s3://{S3_BUCKET}/{snapshot_key}")
    except Exception as e:
        logger.warning(f"Failed to upload snapshot: {e}")

def generate_pdf_report(target, findings, workspace, scan_type='web'):
    """Generate PDF report from findings"""
    logger.info(f"Generating PDF report for {target} (type: {scan_type})")
    
    # Load appropriate HTML template
    if scan_type == 'api':
        template_name = "api_report_template.html"
    else:
        template_name = "report_template.html"
    
    template_path = os.path.join(os.path.dirname(__file__), "templates", template_name)
    
    # Use default template if API template doesn't exist
    if not os.path.exists(template_path):
        template_path = os.path.join(os.path.dirname(__file__), "templates", "report_template.html")
    
    with open(template_path, 'r') as f:
        template = Template(f.read())
    
    # Prepare data for template
    severity_counts = {
        'CRITICAL': len([f for f in findings if f['severity'] == 'CRITICAL']),
        'HIGH': len([f for f in findings if f['severity'] == 'HIGH']),
        'MEDIUM': len([f for f in findings if f['severity'] == 'MEDIUM']),
    }
    
    # Render HTML
    html_content = template.render(
        target=target,
        scan_type=scan_type.upper(),
        scan_date=datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'),
        findings=findings,
        severity_counts=severity_counts,
        total_findings=len(findings)
    )
    
    # Generate PDF
    safe_target = target.replace('://', '_').replace('/', '_')[:50]
    pdf_path = os.path.join(workspace, f"QuickSecScan_API_{safe_target}_{datetime.utcnow().strftime('%Y%m%d')}.pdf")
    HTML(string=html_content).write_pdf(pdf_path)
    
    logger.info(f"PDF generated: {pdf_path}")
    return pdf_path

def upload_to_s3(pdf_path, target, session_id):
    """Upload PDF to S3 and return public URL"""
    safe_target = target.replace('://', '_').replace('/', '_')[:50]
    key = f"reports/{safe_target}/{session_id}_{os.path.basename(pdf_path)}"
    s3_client.upload_file(pdf_path, S3_BUCKET, key, ExtraArgs={'ContentType': 'application/pdf'})
    
    # Generate presigned URL (valid for 30 days)
    url = s3_client.generate_presigned_url(
        'get_object',
        Params={'Bucket': S3_BUCKET, 'Key': key},
        ExpiresIn=2592000  # 30 days
    )
    
    logger.info(f"Report uploaded: {url}")
    return url

def send_report_email(customer_email, target, report_url, findings, scan_type='web'):
    """Send report delivery email to customer"""
    severity_counts = {
        'CRITICAL': len([f for f in findings if f['severity'] == 'CRITICAL']),
        'HIGH': len([f for f in findings if f['severity'] == 'HIGH']),
        'MEDIUM': len([f for f in findings if f['severity'] == 'MEDIUM']),
    }
    
    scan_type_label = 'API Security' if scan_type == 'api' else 'Security'
    
    message = Mail(
        from_email=FROM_EMAIL,
        to_emails=[customer_email, MONITORING_EMAIL],
        subject=f'QuickSecScan {scan_type_label} Report Ready — {target}',
        html_content=f"""
        <h2>Your QuickSecScan {scan_type_label} Report is Ready</h2>
        <p>Hi there,</p>
        <p>Your automated {scan_type_label.lower()} scan for <strong>{target}</strong> is complete.</p>
        <h3>Summary:</h3>
        <ul>
            <li>Critical: {severity_counts['CRITICAL']}</li>
            <li>High: {severity_counts['HIGH']}</li>
            <li>Medium: {severity_counts['MEDIUM']}</li>
            <li><strong>Total Findings: {len(findings)}</strong></li>
        </ul>
        <p><a href="{report_url}" style="background:#0ea5e9;color:#fff;padding:12px 24px;text-decoration:none;border-radius:8px;display:inline-block;margin:16px 0;">Download Full Report (PDF)</a></p>
        <p>Your report link is valid for 30 days.</p>
        <p>Questions? Reply to this email.</p>
        <p>—<br>QuickSecScan<br><a href="https://quicksecscan.com">quicksecscan.com</a></p>
        """
    )
    
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        logger.info(f"Email sent to {customer_email}, status: {response.status_code}")
    except Exception as e:
        logger.error(f"Failed to send email to {customer_email}: {e}")
        raise

def send_failure_email(customer_email, target, error_message):
    """Notify customer of scan failure and offer refund"""
    message = Mail(
        from_email=FROM_EMAIL,
        to_emails=[customer_email, MONITORING_EMAIL],
        subject=f'QuickSecScan — Issue with {target} scan',
        html_content=f"""
        <h2>Scan Issue — {target}</h2>
        <p>Hi there,</p>
        <p>We encountered an issue scanning <strong>{target}</strong>:</p>
        <p style="background:#fef2f2;border-left:4px solid #ef4444;padding:12px;margin:16px 0;"><em>{error_message}</em></p>
        <p>We're looking into it and will either:</p>
        <ul>
            <li>Re-run the scan automatically (if transient issue)</li>
            <li>Process a 50% refund (if domain issue)</li>
        </ul>
        <p>You'll receive an update within 24 hours. Reply to this email with questions.</p>
        <p>—<br>QuickSecScan<br><a href="https://quicksecscan.com">quicksecscan.com</a></p>
        """
    )
    
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        sg.send(message)
    except Exception as e:
        logger.error(f"Failed to send failure email: {e}")

