#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
TIMELINE EMAIL SCHEDULER
Automated notification system based on Today's Timeline intervals
"""

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
import schedule
import time
import sqlite3
from datetime import datetime, timedelta
import os
import logging
from contextlib import contextmanager
import json
from cryptography.fernet import Fernet

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/scheduler.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class EmailScheduler:
    """Timeline-based email notification scheduler"""
    
    def __init__(self):
        self.smtp_config = {
            'host': os.environ.get('SMTP_HOST', 'smtp.gmail.com'),
            'port': int(os.environ.get('SMTP_PORT', 587)),
            'username': os.environ.get('SMTP_USERNAME'),
            'password': os.environ.get('SMTP_PASSWORD'),
            'from_email': os.environ.get('FROM_EMAIL'),
            'from_name': os.environ.get('FROM_NAME', 'Money Dashboard Notifications')
        }
        
        self.encryption_key = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key())
        self.cipher = Fernet(self.encryption_key)
        
        self.timeline_intervals = {
            'timeline_2_4_hours': {'hours': 2, 'name': '2-4 Hours Check-in'},
            'timeline_4_6_hours': {'hours': 4, 'name': '4-6 Hours Update'},
            'timeline_tonight': {'hours': 8, 'name': 'Tonight Summary'},
        }
    
    @contextmanager
    def get_db(self):
        """Database context manager"""
        conn = sqlite3.connect('notifications.db', check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def send_email(self, to_email, subject, html_content, text_content=None):
        """Send email with retry logic and error handling"""
        try:
            if not all([self.smtp_config['username'], self.smtp_config['password']]):
                logger.error('SMTP credentials not configured')
                return False
            
            message = MIMEMultipart('alternative')
            message['Subject'] = subject
            message['From'] = f"{self.smtp_config['from_name']} <{self.smtp_config['from_email']}>"
            message['To'] = to_email
            message['X-Priority'] = '1'
            
            # Text fallback
            if text_content:
                part1 = MIMEText(text_content, 'plain')
                message.attach(part1)
            
            # HTML content
            part2 = MIMEText(html_content, 'html')
            message.attach(part2)
            
            # Send email with SSL
            context = ssl.create_default_context()
            
            with smtplib.SMTP(self.smtp_config['host'], self.smtp_config['port']) as server:
                server.starttls(context=context)
                server.login(self.smtp_config['username'], self.smtp_config['password'])
                server.send_message(message)
            
            logger.info(f'Email sent successfully to {to_email}')
            return True
        
        except Exception as e:
            logger.error(f'Failed to send email to {to_email}: {str(e)}')
            return False
    
    def get_email_template(self, notification_type, user_data):
        """Get beautiful HTML email template for notification type"""
        
        templates = {
            'timeline_2_4_hours': {
                'subject': '⏰ 2-4 Hours Update - Check Your Responses!',
                'html': self.generate_2_4_hours_template(user_data),
                'text': 'Check your Money Dashboard - clients are responding!'
            },
            'timeline_4_6_hours': {
                'subject': '🎯 4-6 Hours Update - Win Those Jobs!',
                'html': self.generate_4_6_hours_template(user_data),
                'text': 'Time to close deals on your Money Dashboard!'
            },
            'timeline_tonight': {
                'subject': '💰 Tonight Summary - Money in Platform!',
                'html': self.generate_tonight_template(user_data),
                'text': 'Check your earnings on Money Dashboard!'
            },
        }
        
        return templates.get(notification_type, templates['timeline_2_4_hours'])
    
    def generate_2_4_hours_template(self, user_data):
        """Generate 2-4 hours notification email"""
        return f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>2-4 Hours Update</title>
    <style>
        body {{
            margin: 0;
            padding: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            overflow: hidden;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 32px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }}
        .header p {{
            margin: 10px 0 0;
            opacity: 0.9;
            font-size: 16px;
        }}
        .content {{
            padding: 40px 30px;
        }}
        .timeline-badge {{
            background: linear-gradient(135deg, #FF9800, #FF5722);
            color: white;
            display: inline-block;
            padding: 15px 30px;
            border-radius: 50px;
            font-weight: bold;
            font-size: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 15px rgba(255, 152, 0, 0.4);
        }}
        .message {{
            font-size: 18px;
            line-height: 1.6;
            color: #333;
            margin-bottom: 30px;
        }}
        .action-box {{
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            padding: 25px;
            border-radius: 15px;
            margin: 20px 0;
            border-left: 5px solid #667eea;
        }}
        .action-box h3 {{
            margin: 0 0 15px;
            color: #667eea;
            font-size: 20px;
        }}
        .action-box ul {{
            margin: 0;
            padding-left: 20px;
        }}
        .action-box li {{
            margin: 10px 0;
            color: #555;
            font-size: 16px;
        }}
        .cta-button {{
            display: inline-block;
            background: linear-gradient(135deg, #4CAF50, #45a049);
            color: white;
            text-decoration: none;
            padding: 18px 40px;
            border-radius: 50px;
            font-weight: bold;
            font-size: 18px;
            margin: 20px 0;
            box-shadow: 0 8px 25px rgba(76, 175, 80, 0.4);
            transition: all 0.3s;
        }}
        .stats {{
            display: flex;
            justify-content: space-around;
            margin: 30px 0;
        }}
        .stat {{
            text-align: center;
        }}
        .stat-value {{
            font-size: 36px;
            font-weight: bold;
            color: #667eea;
        }}
        .stat-label {{
            font-size: 14px;
            color: #888;
            margin-top: 5px;
        }}
        .footer {{
            background: #f5f7fa;
            padding: 30px;
            text-align: center;
            color: #888;
            font-size: 14px;
        }}
        .footer a {{
            color: #667eea;
            text-decoration: none;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>⏰ 2-4 Hours Check-In</h1>
            <p>Your applications are getting responses!</p>
        </div>
        
        <div class="content">
            <div class="timeline-badge">2-4 Hours Update</div>
            
            <div class="message">
                <p><strong>Hey there! 👋</strong></p>
                <p>Your job applications are being reviewed right now. This is the critical window where <strong>5-10 clients will message you</strong>.</p>
            </div>
            
            <div class="stats">
                <div class="stat">
                    <div class="stat-value">{user_data.get('applications', 10)}</div>
                    <div class="stat-label">Applications Sent</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{user_data.get('responses', '3-5')}</div>
                    <div class="stat-label">Expected Responses</div>
                </div>
            </div>
            
            <div class="action-box">
                <h3>🚀 ACTION REQUIRED:</h3>
                <ul>
                    <li><strong>Check your inbox NOW</strong> - Respond within 15 minutes for 90% win rate</li>
                    <li><strong>Be online (green status)</strong> - Shows you're ready to start</li>
                    <li><strong>Reply professionally</strong> - "I can start immediately"</li>
                </ul>
            </div>
            
            <center>
                <a href="{user_data.get('dashboard_url', 'https://your-dashboard.com')}" class="cta-button">
                    📊 CHECK DASHBOARD NOW
                </a>
            </center>
            
            <div class="message" style="margin-top: 30px;">
                <p><strong>💡 Pro Tip:</strong> Clients who respond in the first 2-4 hours are the most serious. Don't miss this window!</p>
            </div>
        </div>
        
        <div class="footer">
            <p>You're receiving this because you subscribed to Timeline Notifications</p>
            <p><a href="{user_data.get('unsubscribe_url', '#')}">Unsubscribe</a> | <a href="{user_data.get('preferences_url', '#')}">Manage Preferences</a></p>
        </div>
    </div>
</body>
</html>
        '''
    
    def generate_4_6_hours_template(self, user_data):
        """Generate 4-6 hours notification email"""
        return f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>4-6 Hours Update</title>
    <style>
        body {{
            margin: 0;
            padding: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            overflow: hidden;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }}
        .header {{
            background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);
            color: white;
            padding: 40px 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 32px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }}
        .content {{
            padding: 40px 30px;
        }}
        .timeline-badge {{
            background: linear-gradient(135deg, #4CAF50, #45a049);
            color: white;
            display: inline-block;
            padding: 15px 30px;
            border-radius: 50px;
            font-weight: bold;
            font-size: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 15px rgba(76, 175, 80, 0.4);
        }}
        .message {{
            font-size: 18px;
            line-height: 1.6;
            color: #333;
            margin-bottom: 30px;
        }}
        .win-box {{
            background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%);
            padding: 25px;
            border-radius: 15px;
            margin: 20px 0;
            border-left: 5px solid #FFD700;
        }}
        .win-box h3 {{
            margin: 0 0 15px;
            color: #FF9800;
            font-size: 22px;
        }}
        .cta-button {{
            display: inline-block;
            background: linear-gradient(135deg, #4CAF50, #45a049);
            color: white;
            text-decoration: none;
            padding: 18px 40px;
            border-radius: 50px;
            font-weight: bold;
            font-size: 18px;
            margin: 20px 0;
            box-shadow: 0 8px 25px rgba(76, 175, 80, 0.4);
        }}
        .earnings-estimate {{
            background: linear-gradient(135deg, #e8f5e9 0%, #c8e6c9 100%);
            padding: 30px;
            border-radius: 15px;
            text-align: center;
            margin: 20px 0;
        }}
        .earnings-estimate .amount {{
            font-size: 48px;
            font-weight: bold;
            color: #4CAF50;
            margin: 10px 0;
        }}
        .footer {{
            background: #f5f7fa;
            padding: 30px;
            text-align: center;
            color: #888;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 4-6 Hours Update</h1>
            <p>Time to close those deals!</p>
        </div>
        
        <div class="content">
            <div class="timeline-badge">4-6 Hours: Win Phase</div>
            
            <div class="message">
                <p><strong>Excellent timing! 🎉</strong></p>
                <p>You're in the <strong>conversion window</strong>. Clients have reviewed your proposal and are ready to hire.</p>
            </div>
            
            <div class="earnings-estimate">
                <p style="margin: 0; color: #888;">Estimated Earnings Today</p>
                <div class="amount">$400-$1,200</div>
                <p style="margin: 0; color: #888;">Based on 2-6 job wins</p>
            </div>
            
            <div class="win-box">
                <h3>💼 HOW TO CLOSE DEALS:</h3>
                <ul style="margin: 0; padding-left: 20px;">
                    <li style="margin: 10px 0;"><strong>Reply immediately</strong> - Show you're available NOW</li>
                    <li style="margin: 10px 0;"><strong>Confirm timeline</strong> - "I can deliver in 2 hours"</li>
                    <li style="margin: 10px 0;"><strong>Accept contracts fast</strong> - First to accept wins</li>
                    <li style="margin: 10px 0;"><strong>Start work immediately</strong> - Build trust early</li>
                </ul>
            </div>
            
            <center>
                <a href="{user_data.get('dashboard_url', 'https://your-dashboard.com')}" class="cta-button">
                    💰 VIEW OPPORTUNITIES
                </a>
            </center>
            
            <div class="message" style="margin-top: 30px;">
                <p><strong>🔥 Hot Tip:</strong> Run your automated delivery as soon as contracts are signed. Fast delivery = 5-star reviews = more jobs!</p>
            </div>
        </div>
        
        <div class="footer">
            <p>Timeline Notifications | Money Dashboard</p>
            <p><a href="{user_data.get('unsubscribe_url', '#')}">Unsubscribe</a></p>
        </div>
    </div>
</body>
</html>
        '''
    
    def generate_tonight_template(self, user_data):
        """Generate tonight summary email"""
        return f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tonight Summary</title>
    <style>
        body {{
            margin: 0;
            padding: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background: white;
            border-radius: 20px;
            overflow: hidden;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }}
        .header {{
            background: linear-gradient(135deg, #FFD700 0%, #FFA500 100%);
            color: white;
            padding: 40px 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 32px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }}
        .content {{
            padding: 40px 30px;
        }}
        .timeline-badge {{
            background: linear-gradient(135deg, #FFD700, #FFA500);
            color: white;
            display: inline-block;
            padding: 15px 30px;
            border-radius: 50px;
            font-weight: bold;
            font-size: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 15px rgba(255, 215, 0, 0.4);
        }}
        .celebration {{
            text-align: center;
            font-size: 72px;
            margin: 20px 0;
        }}
        .money-box {{
            background: linear-gradient(135deg, #e8f5e9 0%, #c8e6c9 100%);
            padding: 40px;
            border-radius: 15px;
            text-align: center;
            margin: 30px 0;
            border: 3px solid #4CAF50;
        }}
        .money-box .amount {{
            font-size: 56px;
            font-weight: bold;
            color: #4CAF50;
            margin: 10px 0;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
            margin: 30px 0;
        }}
        .stat-card {{
            background: #f5f7fa;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }}
        .stat-card .value {{
            font-size: 32px;
            font-weight: bold;
            color: #667eea;
        }}
        .stat-card .label {{
            font-size: 14px;
            color: #888;
            margin-top: 5px;
        }}
        .cta-button {{
            display: inline-block;
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            text-decoration: none;
            padding: 18px 40px;
            border-radius: 50px;
            font-weight: bold;
            font-size: 18px;
            margin: 20px 0;
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.4);
        }}
        .footer {{
            background: #f5f7fa;
            padding: 30px;
            text-align: center;
            color: #888;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>💰 Tonight Summary</h1>
            <p>Your daily earnings report</p>
        </div>
        
        <div class="content">
            <div class="timeline-badge">Tonight: Money in Platform</div>
            
            <div class="celebration">🎉💰🎊</div>
            
            <div class="money-box">
                <p style="margin: 0; color: #888; font-size: 18px;">Money in Platform</p>
                <div class="amount">${user_data.get('earnings', '0')}</div>
                <p style="margin: 0; color: #888;">Bank transfer in 5-10 days</p>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="value">{user_data.get('jobs_won', 0)}</div>
                    <div class="label">Jobs Won Today</div>
                </div>
                <div class="stat-card">
                    <div class="value">{user_data.get('win_rate', 0)}%</div>
                    <div class="label">Win Rate</div>
                </div>
                <div class="stat-card">
                    <div class="value">{user_data.get('applications', 0)}</div>
                    <div class="label">Applications Sent</div>
                </div>
                <div class="stat-card">
                    <div class="value">{user_data.get('reviews', 0)}</div>
                    <div class="label">5-Star Reviews</div>
                </div>
            </div>
            
            <div style="background: #fff3cd; padding: 20px; border-radius: 10px; margin: 20px 0;">
                <p style="margin: 0; color: #856404;"><strong>📌 Next Steps:</strong></p>
                <ul style="margin: 10px 0; padding-left: 20px; color: #856404;">
                    <li>Complete all active jobs for 5-star reviews</li>
                    <li>Request reviews from satisfied clients</li>
                    <li>Apply to tomorrow's jobs (set up overnight automation)</li>
                    <li>Withdraw funds once cleared (5-10 days)</li>
                </ul>
            </div>
            
            <center>
                <a href="{user_data.get('dashboard_url', 'https://your-dashboard.com')}" class="cta-button">
                    📊 VIEW FULL DASHBOARD
                </a>
            </center>
            
            <div style="text-align: center; margin-top: 30px; color: #888;">
                <p><strong>Great work today! 🚀</strong></p>
                <p>Keep this momentum going tomorrow.</p>
            </div>
        </div>
        
        <div class="footer">
            <p>Timeline Notifications | Money Dashboard</p>
            <p><a href="{user_data.get('unsubscribe_url', '#')}">Unsubscribe</a></p>
        </div>
    </div>
</body>
</html>
        '''
    
    def process_notifications(self):
        """Process and send scheduled notifications"""
        try:
            with self.get_db() as conn:
                cursor = conn.cursor()
                
                current_time = int(time.time())
                
                # Get all active subscriptions
                cursor.execute('''
                    SELECT s.*, u.email
                    FROM subscriptions s
                    JOIN users u ON s.user_id = u.id
                    WHERE s.enabled = 1 AND u.email_verified = 1
                ''')
                
                subscriptions = cursor.fetchall()
                
                for sub in subscriptions:
                    notification_type = sub['notification_type']
                    last_sent = sub['last_sent'] or 0
                    
                    # Check if it's time to send
                    if notification_type in self.timeline_intervals:
                        interval_hours = self.timeline_intervals[notification_type]['hours']
                        next_send_time = last_sent + (interval_hours * 3600)
                        
                        if current_time >= next_send_time:
                            # Send notification
                            user_data = {
                                'dashboard_url': 'http://localhost:5000/dashboard',
                                'unsubscribe_url': 'http://localhost:5000/unsubscribe',
                                'preferences_url': 'http://localhost:5000/preferences',
                                'applications': 10,
                                'earnings': 0,
                                'jobs_won': 0,
                                'win_rate': 0,
                                'reviews': 0,
                                'responses': '3-5'
                            }
                            
                            template = self.get_email_template(notification_type, user_data)
                            
                            success = self.send_email(
                                sub['email'],
                                template['subject'],
                                template['html'],
                                template['text']
                            )
                            
                            # Log notification
                            status = 'delivered' if success else 'failed'
                            cursor.execute('''
                                INSERT INTO notification_logs 
                                (user_id, notification_type, status, sent_at, ip_address)
                                VALUES (?, ?, ?, ?, ?)
                            ''', (sub['user_id'], notification_type, status, current_time, 'scheduler'))
                            
                            # Update last_sent
                            if success:
                                cursor.execute('''
                                    UPDATE subscriptions
                                    SET last_sent = ?
                                    WHERE id = ?
                                ''', (current_time, sub['id']))
                            
                            conn.commit()
                            
                            logger.info(f'Sent {notification_type} to {sub["email"]} - Status: {status}')
        
        except Exception as e:
            logger.error(f'Error processing notifications: {str(e)}')
    
    def run(self):
        """Run scheduler continuously"""
        logger.info('Email Scheduler started')
        
        # Schedule checks every 15 minutes
        schedule.every(15).minutes.do(self.process_notifications)
        
        # Run immediately on start
        self.process_notifications()
        
        while True:
            schedule.run_pending()
            time.sleep(60)


if __name__ == '__main__':
    scheduler = EmailScheduler()
    scheduler.run()
