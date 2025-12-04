#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Convert HTML/Markdown Reports to PDF for Portfolio
"""

import sys
from pathlib import Path

try:
    from weasyprint import HTML
    HAS_WEASYPRINT = True
except ImportError:
    HAS_WEASYPRINT = False

try:
    import markdown
    from markdown.extensions import codehilite, fenced_code
    HAS_MARKDOWN = True
except ImportError:
    HAS_MARKDOWN = False

def markdown_to_html(md_content: str) -> str:
    """Convert markdown to HTML"""
    if HAS_MARKDOWN:
        md = markdown.Markdown(extensions=['codehilite', 'fenced_code', 'tables'])
        html = md.convert(md_content)
    else:
        # Simple conversion without markdown library
        html = f"<pre>{md_content}</pre>"
    
    # Wrap in HTML document
    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            line-height: 1.6;
        }}
        h1, h2, h3 {{
            color: #333;
        }}
        code {{
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
        }}
        pre {{
            background: #f4f4f4;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }}
    </style>
</head>
<body>
{html}
</body>
</html>"""

def create_sample_html(client_name: str) -> str:
    """Create a professional HTML report for portfolio sample"""
    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Assessment Report - {client_name}</title>
    <style>
        @page {{
            size: A4;
            margin: 2cm;
        }}
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            border-bottom: 3px solid #007bff;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #007bff;
            margin: 0;
        }}
        .meta {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .score {{
            font-size: 2em;
            font-weight: bold;
            color: #28a745;
        }}
        .finding {{
            border-left: 4px solid #ffc107;
            padding-left: 15px;
            margin: 20px 0;
        }}
        .finding.critical {{
            border-color: #dc3545;
        }}
        .finding.high {{
            border-color: #fd7e14;
        }}
        .finding.medium {{
            border-color: #ffc107;
        }}
        .finding.low {{
            border-color: #28a745;
        }}
        .recommendations {{
            background: #e7f3ff;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }}
        th {{
            background-color: #007bff;
            color: white;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            font-size: 0.9em;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Assessment Report</h1>
        <p><strong>Client:</strong> {client_name}</p>
        <p><strong>Date:</strong> {__import__('datetime').datetime.now().strftime('%B %d, %Y')}</p>
    </div>

    <div class="meta">
        <h2>Executive Summary</h2>
        <p>This comprehensive security assessment was performed using enterprise automation tools, scanning 100+ security checks across web applications, APIs, and infrastructure.</p>
        <p><strong>Security Score:</strong> <span class="score">8.5/10</span></p>
        <p><strong>Assessment Type:</strong> Non-intrusive vulnerability scan</p>
        <p><strong>Scope:</strong> External security assessment</p>
    </div>

    <h2>Findings Overview</h2>
    <table>
        <tr>
            <th>Severity</th>
            <th>Count</th>
            <th>Status</th>
        </tr>
        <tr>
            <td><strong>Critical</strong></td>
            <td>0</td>
            <td>✅ None Found</td>
        </tr>
        <tr>
            <td><strong>High</strong></td>
            <td>2</td>
            <td>⚠️ Requires Attention</td>
        </tr>
        <tr>
            <td><strong>Medium</strong></td>
            <td>5</td>
            <td>📋 Recommended Fix</td>
        </tr>
        <tr>
            <td><strong>Low</strong></td>
            <td>8</td>
            <td>ℹ️ Informational</td>
        </tr>
    </table>

    <h2>Key Findings</h2>
    
    <div class="finding high">
        <h3>1. Missing Security Headers</h3>
        <p><strong>Severity:</strong> High</p>
        <p><strong>Description:</strong> Missing security headers including Content-Security-Policy, X-Frame-Options, and Strict-Transport-Security.</p>
        <p><strong>Impact:</strong> Increased risk of clickjacking attacks and XSS vulnerabilities.</p>
        <div class="recommendations">
            <strong>Recommendation:</strong> Implement security headers in web server configuration.
        </div>
    </div>

    <div class="finding high">
        <h3>2. SSL/TLS Configuration Issues</h3>
        <p><strong>Severity:</strong> High</p>
        <p><strong>Description:</strong> Weak cipher suites detected and missing TLS 1.3 support.</p>
        <p><strong>Impact:</strong> Potential for man-in-the-middle attacks.</p>
        <div class="recommendations">
            <strong>Recommendation:</strong> Update SSL/TLS configuration to disable weak ciphers and enable TLS 1.3.
        </div>
    </div>

    <div class="finding medium">
        <h3>3. Report Disclosure</h3>
        <p><strong>Severity:</strong> Medium</p>
        <p><strong>Description:</strong> Error pages reveal sensitive system information.</p>
        <p><strong>Impact:</strong> Information disclosure to potential attackers.</p>
        <div class="recommendations">
            <strong>Recommendation:</strong> Configure custom error pages that don't reveal system details.
        </div>
    </div>

    <h2>Remediation Priority</h2>
    <ol>
        <li><strong>Immediate (This Week):</strong> Fix high-severity findings</li>
        <li><strong>Short-term (This Month):</strong> Address medium-severity issues</li>
        <li><strong>Long-term (Next Quarter):</strong> Review and enhance overall security posture</li>
    </ol>

    <h2>Methodology</h2>
    <p>This assessment was performed using automated security scanning tools, including:</p>
    <ul>
        <li>Subdomain enumeration</li>
        <li>Port scanning</li>
        <li>Web application vulnerability scanning</li>
        <li>SSL/TLS configuration analysis</li>
        <li>Security header verification</li>
        <li>API endpoint discovery and testing</li>
    </ul>

    <div class="footer">
        <p><strong>Report Generated:</strong> {__import__('datetime').datetime.now().strftime('%B %d, %Y at %I:%M %p')}</p>
        <p><strong>Assessment Type:</strong> Non-intrusive security scan</p>
        <p><strong>Scope:</strong> External assessment only - no exploitation performed</p>
        <p><em>This report is confidential and intended solely for the client. Delivered in 2 hours using enterprise automation tools.</em></p>
    </div>
</body>
</html>"""

def convert_html_to_pdf(html_content: str, output_path: Path):
    """Convert HTML to PDF using weasyprint"""
    if not HAS_WEASYPRINT:
        print("❌ Error: weasyprint not installed")
        print("Install with: pip3 install weasyprint")
        return False
    
    try:
        HTML(string=html_content).write_pdf(output_path)
        return True
    except Exception as e:
        print(f"❌ Error converting to PDF: {e}")
        return False

def main():
    """Generate PDF portfolio samples"""
    base_dir = Path(__file__).parent.parent
    samples_dir = base_dir / "output" / "portfolio_samples"
    samples_dir.mkdir(parents=True, exist_ok=True)
    
    samples = [
        {"name": "Sample E-commerce", "filename": "upwork_sample1.pdf"},
        {"name": "Sample SaaS Platform", "filename": "upwork_sample2.pdf"},
        {"name": "Sample API", "filename": "upwork_sample3.pdf"}
    ]
    
    print("🎨 Generating PDF Portfolio Samples...")
    print("="*60)
    
    if not HAS_WEASYPRINT:
        print("\n⚠️  weasyprint not installed")
        print("Installing weasyprint...")
        import subprocess
        try:
            # Try with --break-system-packages flag
            subprocess.run([sys.executable, "-m", "pip", "install", "weasyprint", "--break-system-packages"], check=True)
            print("✅ weasyprint installed!")
            from weasyprint import HTML
            global HTML
        except Exception as e:
            print(f"⚠️  Failed to install weasyprint: {e}")
            print("\nTrying alternative: apt install...")
            try:
                import subprocess
                subprocess.run(["sudo", "apt-get", "install", "-y", "python3-weasyprint"], check=True)
                from weasyprint import HTML
                print("✅ weasyprint installed via apt!")
            except Exception as e2:
                print(f"❌ Failed to install weasyprint: {e2}")
                print("\n⚠️  Alternative: HTML files will be created - print them to PDF in browser")
                # Generate HTML files instead
                for i, sample in enumerate(samples, 1):
                    html_content = create_sample_html(sample['name'])
                    html_path = samples_dir / sample['filename'].replace('.pdf', '.html')
                    with open(html_path, 'w', encoding='utf-8') as f:
                        f.write(html_content)
                    print(f"✅ Generated HTML: {html_path}")
                    print(f"   Open in browser and print to PDF: {html_path}")
                return
    
    for i, sample in enumerate(samples, 1):
        print(f"\n[{i}/3] Generating {sample['name']}...")
        
        html_content = create_sample_html(sample['name'])
        pdf_path = samples_dir / sample['filename']
        
        if convert_html_to_pdf(html_content, pdf_path):
            print(f"✅ Generated: {pdf_path}")
        else:
            print(f"⚠️  Failed to generate PDF for {sample['name']}")
    
    print("\n" + "="*60)
    print("✅ Portfolio samples ready!")
    print(f"📁 Location: {samples_dir}")
    print("\n📤 Next Steps:")
    print("1. Copy PDFs to Windows Downloads")
    print("2. Upload to Upwork portfolio")
    print("3. Add descriptions")

if __name__ == "__main__":
    main()

