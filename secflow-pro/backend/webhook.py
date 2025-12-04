#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
SecFlow Pro - Stripe Webhook Handler
Automatically triggers security scans when customers subscribe
"""

from flask import Flask, request, jsonify
import subprocess
import os
import json
from datetime import datetime

app = Flask(__name__)

# Your existing pipeline path
PIPELINE_PATH = os.path.join(os.path.dirname(__file__), '../../run_pipeline.py')
REPORT_SCRIPT = os.path.join(os.path.dirname(__file__), '../../scripts/generate_report.py')

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    """Handle Stripe webhook events"""
    event = request.json
    
    try:
        event_type = event['type']
        
        if event_type == 'checkout.session.completed':
            # Customer completed checkout
            session = event['data']['object']
            customer_email = session.get('customer_email', '')
            metadata = session.get('metadata', {})
            domain = metadata.get('domain', '')
            tier = metadata.get('tier', 'starter')
            
            if domain:
                # Trigger automated scan
                result = run_security_scan(domain, tier, customer_email)
                return jsonify({'status': 'success', 'scan_id': result}), 200
            else:
                return jsonify({'status': 'no_domain'}), 200
                
        elif event_type == 'customer.subscription.created':
            # New subscription created
            subscription = event['data']['object']
            customer_email = subscription.get('customer_email', '')
            tier = subscription.get('metadata', {}).get('tier', 'starter')
            
            # Schedule recurring scans
            schedule_recurring_scans(customer_email, tier)
            
            return jsonify({'status': 'subscription_created'}), 200
            
        elif event_type == 'invoice.payment_succeeded':
            # Recurring payment succeeded - trigger monthly scan
            invoice = event['data']['object']
            customer_email = invoice.get('customer_email', '')
            metadata = invoice.get('metadata', {})
            domain = metadata.get('domain', '')
            tier = metadata.get('tier', 'starter')
            
            if domain:
                run_security_scan(domain, tier, customer_email)
            
            return jsonify({'status': 'payment_succeeded'}), 200
            
    except Exception as e:
        print(f"Error processing webhook: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
    
    return jsonify({'status': 'unhandled_event'}), 200


def run_security_scan(domain, tier, customer_email):
    """Run automated security scan"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = f'/tmp/secflow_scans/{domain}_{timestamp}'
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Run pipeline
    cmd = [
        'python3', PIPELINE_PATH,
        '--target', domain,
        '--output', output_dir
    ]
    
    # Add tier-specific options
    if tier == 'pro':
        cmd.extend(['--deep-scan', '--api-scan'])
    elif tier == 'enterprise':
        cmd.extend(['--deep-scan', '--api-scan', '--full-recon'])
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        
        # Generate report
        report_cmd = [
            'python3', REPORT_SCRIPT,
            '--format', 'professional',
            '--client-name', domain,
            '--client-email', customer_email,
            '--output', f'{output_dir}/report.pdf'
        ]
        subprocess.run(report_cmd, capture_output=True, text=True)
        
        # Send email with report (implement your email sending)
        send_report_email(customer_email, domain, f'{output_dir}/report.pdf')
        
        return {'domain': domain, 'tier': tier, 'timestamp': timestamp}
        
    except subprocess.TimeoutExpired:
        return {'error': 'scan_timeout'}
    except Exception as e:
        return {'error': str(e)}


def schedule_recurring_scans(customer_email, tier):
    """Schedule recurring scans based on tier"""
    # Starter: weekly
    # Pro: daily
    # Enterprise: real-time (on-demand + scheduled)
    
    # Implement your scheduling logic here
    # Could use cron, celery, or scheduled tasks
    pass


def send_report_email(customer_email, domain, report_path):
    """Send email with security report"""
    # Implement email sending
    # Use your existing email system or SMTP
    print(f"Would send email to {customer_email} with report for {domain}")
    pass


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'secflow-pro-webhook'}), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

