#!/usr/bin/env python3
"""
BREACH GUARDIAN - Real-Time Security Breach Detection System
Copyright © 2025 DoctorMen. All Rights Reserved.

Monitors for security breaches and alerts IMMEDIATELY:
- File integrity violations
- Unauthorized access attempts
- Suspicious process activity
- Network intrusions
- Code modifications
- Configuration changes

Sends instant alerts via Discord, Email, SMS when breach detected.
"""

import os
import sys
import json
import hashlib
import time
import socket
import platform
import subprocess
import threading
import requests
from datetime import datetime
from pathlib import Path
from collections import defaultdict
import psutil

class BreachGuardian:
    """
    Real-time security breach detection and alerting system.
    Monitors system integrity and sends immediate alerts.
    """
    
    def __init__(self, repo_path='.', config_file='breach_config.json'):
        self.repo_path = Path(repo_path).resolve()
        self.config_file = self.repo_path / config_file
        self.state_file = self.repo_path / '.breach_guardian_state.json'
        self.alert_log = self.repo_path / '.breach_alerts.log'
        
        # Load configuration
        self.config = self.load_config()
        
        # Critical files to monitor
        self.critical_files = {
            'LEGAL_AUTHORIZATION_SYSTEM.py',
            'AUTO_COPYRIGHT_GUARDIAN.py',
            'BREACH_GUARDIAN.py',
            '.env',
            '.git/config',
            'targets.txt',
            'authorizations/'
        }
        
        # Suspicious patterns
        self.suspicious_patterns = [
            'rm -rf',
            'del /f /q',
            'format',
            'DROP TABLE',
            'eval(',
            'exec(',
            'base64',
            '__import__',
            'os.system',
            'subprocess.call'
        ]
        
        # Alert thresholds
        self.failed_login_threshold = 3
        self.file_change_threshold = 10  # changes per minute
        self.process_spawn_threshold = 20  # new processes per minute
        
        # State tracking
        self.state = self.load_state()
        self.failed_login_count = 0
        self.recent_file_changes = []
        self.recent_process_spawns = []
        self.alert_cooldown = {}  # Prevent alert spam
        
        # Start monitoring threads
        self.running = False
        self.threads = []
    
    def load_config(self):
        """Load alert configuration"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        
        # Default configuration
        default_config = {
            'discord_webhook': '',
            'email': {
                'enabled': False,
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'from_email': '',
                'to_email': '',
                'password': ''
            },
            'sms': {
                'enabled': False,
                'twilio_sid': '',
                'twilio_token': '',
                'twilio_from': '',
                'to_number': ''
            },
            'check_interval': 5,  # seconds
            'alert_cooldown': 60  # seconds between same alert type
        }
        
        # Save default config
        with open(self.config_file, 'w') as f:
            json.dump(default_config, f, indent=2)
        
        return default_config
    
    def load_state(self):
        """Load previous state"""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        
        return {
            'file_hashes': {},
            'known_processes': [],
            'baseline_network': {},
            'last_check': None,
            'breach_count': 0,
            'last_breach': None
        }
    
    def save_state(self):
        """Save current state"""
        with open(self.state_file, 'w') as f:
            json.dump(self.state, f, indent=2)
    
    def log_alert(self, severity, alert_type, message, details=None):
        """Log security alert"""
        timestamp = datetime.now().isoformat()
        
        alert = {
            'timestamp': timestamp,
            'severity': severity,
            'type': alert_type,
            'message': message,
            'details': details or {},
            'hostname': socket.gethostname(),
            'platform': platform.system()
        }
        
        # Log to file
        try:
            with open(self.alert_log, 'a', encoding='utf-8') as f:
                f.write(json.dumps(alert) + '\n')
        except Exception as e:
            print(f"Failed to write alert log: {e}")
        
        # Print to console (handle encoding)
        severity_prefix = {
            'CRITICAL': '[!]',
            'HIGH': '[!]',
            'MEDIUM': '[*]',
            'LOW': '[i]'
        }
        
        prefix = severity_prefix.get(severity, '[?]')
        try:
            print(f"\n{prefix} [{severity}] {alert_type}: {message}")
        except UnicodeEncodeError:
            print(f"\n{prefix} [{severity}] {alert_type}: {message.encode('ascii', 'ignore').decode('ascii')}")
        
        if details:
            for key, value in details.items():
                try:
                    print(f"  {key}: {value}")
                except UnicodeEncodeError:
                    print(f"  {key}: {str(value).encode('ascii', 'ignore').decode('ascii')}")
        
        return alert
    
    def send_discord_alert(self, alert):
        """Send alert to Discord webhook"""
        webhook_url = self.config.get('discord_webhook')
        if not webhook_url:
            return False
        
        # Check cooldown
        alert_key = f"discord_{alert['type']}"
        if self.is_in_cooldown(alert_key):
            return False
        
        # Color by severity
        colors = {
            'CRITICAL': 0xFF0000,  # Red
            'HIGH': 0xFF6600,      # Orange
            'MEDIUM': 0xFFFF00,    # Yellow
            'LOW': 0x0099FF        # Blue
        }
        
        embed = {
            'title': f"🚨 SECURITY BREACH DETECTED",
            'description': alert['message'],
            'color': colors.get(alert['severity'], 0xFF0000),
            'fields': [
                {'name': 'Severity', 'value': alert['severity'], 'inline': True},
                {'name': 'Type', 'value': alert['type'], 'inline': True},
                {'name': 'Hostname', 'value': alert['hostname'], 'inline': True},
                {'name': 'Timestamp', 'value': alert['timestamp'], 'inline': False}
            ],
            'footer': {'text': 'BREACH GUARDIAN - Immediate Response Required'}
        }
        
        # Add details
        if alert.get('details'):
            for key, value in alert['details'].items():
                embed['fields'].append({
                    'name': str(key),
                    'value': str(value)[:1024],  # Discord field limit
                    'inline': False
                })
        
        payload = {
            'username': 'BREACH GUARDIAN',
            'embeds': [embed]
        }
        
        try:
            response = requests.post(webhook_url, json=payload, timeout=10)
            if response.status_code == 204:
                self.set_cooldown(alert_key)
                return True
        except Exception as e:
            print(f"Discord alert failed: {e}")
        
        return False
    
    def send_email_alert(self, alert):
        """Send alert via email"""
        if not self.config.get('email', {}).get('enabled'):
            return False
        
        # Check cooldown
        alert_key = f"email_{alert['type']}"
        if self.is_in_cooldown(alert_key):
            return False
        
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            
            email_config = self.config['email']
            
            msg = MIMEMultipart()
            msg['From'] = email_config['from_email']
            msg['To'] = email_config['to_email']
            msg['Subject'] = f"🚨 BREACH ALERT: {alert['type']} - {alert['severity']}"
            
            body = f"""
SECURITY BREACH DETECTED

Severity: {alert['severity']}
Type: {alert['type']}
Message: {alert['message']}
Hostname: {alert['hostname']}
Timestamp: {alert['timestamp']}

Details:
{json.dumps(alert.get('details', {}), indent=2)}

--- BREACH GUARDIAN ---
IMMEDIATE RESPONSE REQUIRED
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port'])
            server.starttls()
            server.login(email_config['from_email'], email_config['password'])
            server.send_message(msg)
            server.quit()
            
            self.set_cooldown(alert_key)
            return True
        
        except Exception as e:
            print(f"Email alert failed: {e}")
        
        return False
    
    def send_sms_alert(self, alert):
        """Send alert via SMS (Twilio)"""
        if not self.config.get('sms', {}).get('enabled'):
            return False
        
        # Check cooldown
        alert_key = f"sms_{alert['type']}"
        if self.is_in_cooldown(alert_key):
            return False
        
        try:
            from twilio.rest import Client
            
            sms_config = self.config['sms']
            client = Client(sms_config['twilio_sid'], sms_config['twilio_token'])
            
            message_body = f"🚨 BREACH ALERT\n{alert['severity']}: {alert['type']}\n{alert['message']}\nHost: {alert['hostname']}"
            
            message = client.messages.create(
                body=message_body[:160],  # SMS limit
                from_=sms_config['twilio_from'],
                to=sms_config['to_number']
            )
            
            self.set_cooldown(alert_key)
            return True
        
        except Exception as e:
            print(f"SMS alert failed: {e}")
        
        return False
    
    def send_alert(self, alert):
        """Send alert through all configured channels"""
        sent = False
        
        # Try Discord (fastest)
        if self.send_discord_alert(alert):
            sent = True
        
        # Try Email
        if self.send_email_alert(alert):
            sent = True
        
        # Try SMS (most urgent)
        if alert['severity'] in ['CRITICAL', 'HIGH']:
            if self.send_sms_alert(alert):
                sent = True
        
        if sent:
            self.state['breach_count'] += 1
            self.state['last_breach'] = alert['timestamp']
            self.save_state()
        
        return sent
    
    def is_in_cooldown(self, alert_key):
        """Check if alert is in cooldown period"""
        cooldown_seconds = self.config.get('alert_cooldown', 60)
        
        if alert_key in self.alert_cooldown:
            elapsed = time.time() - self.alert_cooldown[alert_key]
            if elapsed < cooldown_seconds:
                return True
        
        return False
    
    def set_cooldown(self, alert_key):
        """Set cooldown for alert type"""
        self.alert_cooldown[alert_key] = time.time()
    
    def get_file_hash(self, file_path):
        """Get SHA256 hash of file"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except:
            return None
    
    def monitor_file_integrity(self):
        """Monitor critical files for unauthorized changes"""
        changes_detected = []
        
        for root, dirs, files in os.walk(self.repo_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__']]
            
            for filename in files:
                # Check if critical file
                file_path = Path(root) / filename
                relative_path = str(file_path.relative_to(self.repo_path))
                
                is_critical = False
                for critical_pattern in self.critical_files:
                    if critical_pattern in relative_path:
                        is_critical = True
                        break
                
                if not is_critical:
                    continue
                
                # Check hash
                current_hash = self.get_file_hash(file_path)
                if not current_hash:
                    continue
                
                previous_hash = self.state['file_hashes'].get(relative_path)
                
                if previous_hash and previous_hash != current_hash:
                    # UNAUTHORIZED CHANGE DETECTED
                    changes_detected.append({
                        'file': relative_path,
                        'previous_hash': previous_hash,
                        'current_hash': current_hash,
                        'timestamp': datetime.now().isoformat()
                    })
                
                # Update hash
                self.state['file_hashes'][relative_path] = current_hash
        
        if changes_detected:
            # BREACH DETECTED
            alert = self.log_alert(
                'CRITICAL',
                'FILE_INTEGRITY_VIOLATION',
                f'{len(changes_detected)} critical file(s) modified without authorization',
                {'modified_files': [c['file'] for c in changes_detected]}
            )
            self.send_alert(alert)
        
        return changes_detected
    
    def monitor_suspicious_processes(self):
        """Monitor for suspicious process activity"""
        suspicious = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
                try:
                    cmdline = ' '.join(proc.info['cmdline'] or [])
                    
                    # Check for suspicious patterns
                    for pattern in self.suspicious_patterns:
                        if pattern.lower() in cmdline.lower():
                            suspicious.append({
                                'pid': proc.info['pid'],
                                'name': proc.info['name'],
                                'command': cmdline,
                                'user': proc.info['username'],
                                'pattern': pattern
                            })
                            break
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        
        except Exception as e:
            print(f"Process monitoring error: {e}")
        
        if suspicious:
            alert = self.log_alert(
                'HIGH',
                'SUSPICIOUS_PROCESS_DETECTED',
                f'{len(suspicious)} suspicious process(es) running',
                {'processes': suspicious}
            )
            self.send_alert(alert)
        
        return suspicious
    
    def monitor_network_connections(self):
        """Monitor for unauthorized network connections"""
        suspicious_connections = []
        
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                # Check for connections to suspicious ports or IPs
                if conn.raddr:
                    remote_ip, remote_port = conn.raddr
                    
                    # Suspicious ports (common malware)
                    suspicious_ports = [4444, 5555, 6666, 7777, 8888, 31337]
                    
                    if remote_port in suspicious_ports:
                        suspicious_connections.append({
                            'remote_ip': remote_ip,
                            'remote_port': remote_port,
                            'local_port': conn.laddr[1] if conn.laddr else None,
                            'status': conn.status,
                            'pid': conn.pid
                        })
        
        except Exception as e:
            print(f"Network monitoring error: {e}")
        
        if suspicious_connections:
            alert = self.log_alert(
                'HIGH',
                'SUSPICIOUS_NETWORK_CONNECTION',
                f'{len(suspicious_connections)} suspicious network connection(s)',
                {'connections': suspicious_connections}
            )
            self.send_alert(alert)
        
        return suspicious_connections
    
    def monitor_repository_access(self):
        """Monitor for unauthorized repository access"""
        try:
            # Check git log for suspicious activity
            result = subprocess.run(
                ['git', 'log', '--since=5 minutes ago', '--all', '--oneline'],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and result.stdout.strip():
                commits = result.stdout.strip().split('\n')
                
                # Alert on any commits (you should be the only one committing)
                if commits:
                    alert = self.log_alert(
                        'MEDIUM',
                        'REPOSITORY_MODIFICATION',
                        f'{len(commits)} new commit(s) detected',
                        {'commits': commits}
                    )
                    # Don't auto-send (might be legitimate)
                    # self.send_alert(alert)
        
        except Exception as e:
            pass  # Git not available or not a repo
    
    def monitor_login_attempts(self):
        """Monitor for failed login attempts"""
        # This would integrate with system auth logs
        # Simplified version here
        pass
    
    def check_system_integrity(self):
        """Run all integrity checks"""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Running security checks...")
        
        # File integrity
        self.monitor_file_integrity()
        
        # Process monitoring
        self.monitor_suspicious_processes()
        
        # Network monitoring
        self.monitor_network_connections()
        
        # Repository access
        self.monitor_repository_access()
        
        # Save state
        self.state['last_check'] = datetime.now().isoformat()
        self.save_state()
    
    def run_continuous(self):
        """Run continuous monitoring"""
        self.running = True
        check_interval = self.config.get('check_interval', 5)
        
        print(f"\n{'='*60}")
        print(f"BREACH GUARDIAN - ACTIVE")
        print(f"{'='*60}")
        print(f"Repository: {self.repo_path}")
        print(f"Check Interval: {check_interval} seconds")
        print(f"Alert Log: {self.alert_log}")
        print(f"{'='*60}\n")
        
        try:
            while self.running:
                self.check_system_integrity()
                time.sleep(check_interval)
        
        except KeyboardInterrupt:
            print("\n\n[STOP] Breach Guardian stopped by user")
            self.running = False
        
        except Exception as e:
            alert = self.log_alert(
                'CRITICAL',
                'GUARDIAN_FAILURE',
                f'Breach Guardian crashed: {str(e)}',
                {'error': str(e)}
            )
            self.send_alert(alert)
            raise
    
    def run_once(self):
        """Run single check"""
        print(f"\n{'='*60}")
        print(f"BREACH GUARDIAN - SINGLE CHECK")
        print(f"{'='*60}\n")
        
        self.check_system_integrity()
        
        print(f"\n[OK] Security check complete")
        print(f"Total breaches detected: {self.state['breach_count']}")
        if self.state['last_breach']:
            print(f"Last breach: {self.state['last_breach']}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Breach Guardian - Real-time security breach detection'
    )
    parser.add_argument(
        '--daemon',
        action='store_true',
        help='Run as daemon (continuous monitoring)'
    )
    parser.add_argument(
        '--interval',
        type=int,
        default=5,
        help='Check interval in seconds (default: 5)'
    )
    parser.add_argument(
        '--repo',
        type=str,
        default='.',
        help='Repository path (default: current directory)'
    )
    parser.add_argument(
        '--setup-discord',
        type=str,
        help='Setup Discord webhook URL for alerts'
    )
    
    args = parser.parse_args()
    
    # Create guardian
    guardian = BreachGuardian(repo_path=args.repo)
    
    # Setup Discord webhook if provided
    if args.setup_discord:
        guardian.config['discord_webhook'] = args.setup_discord
        with open(guardian.config_file, 'w') as f:
            json.dump(guardian.config, f, indent=2)
        print(f"✅ Discord webhook configured: {args.setup_discord}")
        return
    
    # Update check interval
    guardian.config['check_interval'] = args.interval
    
    if args.daemon:
        # Run continuous monitoring
        guardian.run_continuous()
    else:
        # Run once
        guardian.run_once()

if __name__ == '__main__':
    main()
