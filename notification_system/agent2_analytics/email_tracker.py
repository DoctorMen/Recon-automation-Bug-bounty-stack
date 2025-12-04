#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
EMAIL TRACKING & ANALYTICS
Built by Agent 2 (Documentation & Reporting)

Track email opens, clicks, and engagement
Real-time analytics and A/B testing support
"""

import sqlite3
import hashlib
import base64
from io import BytesIO
from PIL import Image
import time
import json
from contextlib import contextmanager
from flask import Flask, request, send_file, jsonify
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EmailTracker:
    """
    Email tracking and analytics system
    
    Features:
    - Open tracking (1x1 pixel)
    - Click tracking (link redirects)
    - Engagement scoring
    - A/B test support
    - Real-time analytics
    """
    
    def __init__(self, db_path='../backend/notifications.db'):
        self.db_path = db_path
        self.initialize_tracking_tables()
    
    @contextmanager
    def get_db(self):
        """Database context manager"""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def initialize_tracking_tables(self):
        """Create tracking tables"""
        with self.get_db() as conn:
            cursor = conn.cursor()
            
            # Email opens tracking
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS email_opens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tracking_id TEXT NOT NULL UNIQUE,
                    user_id INTEGER NOT NULL,
                    notification_type TEXT NOT NULL,
                    opened_at INTEGER NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    device_type TEXT,
                    email_client TEXT
                )
            ''')
            
            # Click tracking
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS email_clicks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tracking_id TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    notification_type TEXT NOT NULL,
                    link_id TEXT NOT NULL,
                    clicked_at INTEGER NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT
                )
            ''')
            
            # Engagement scores
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_engagement (
                    user_id INTEGER PRIMARY KEY,
                    engagement_score REAL DEFAULT 0,
                    total_emails_sent INTEGER DEFAULT 0,
                    total_opens INTEGER DEFAULT 0,
                    total_clicks INTEGER DEFAULT 0,
                    last_engagement INTEGER,
                    updated_at INTEGER NOT NULL
                )
            ''')
            
            # A/B test variants
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ab_test_variants (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    test_name TEXT NOT NULL,
                    variant_name TEXT NOT NULL,
                    notification_type TEXT NOT NULL,
                    subject_line TEXT,
                    template_version TEXT,
                    active INTEGER DEFAULT 1,
                    created_at INTEGER NOT NULL,
                    UNIQUE(test_name, variant_name)
                )
            ''')
            
            # A/B test assignments
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ab_test_assignments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    test_name TEXT NOT NULL,
                    variant_name TEXT NOT NULL,
                    assigned_at INTEGER NOT NULL,
                    UNIQUE(user_id, test_name)
                )
            ''')
            
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_tracking_id ON email_opens(tracking_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_engagement ON user_engagement(engagement_score DESC)')
            
            conn.commit()
    
    def generate_tracking_id(self, user_id, notification_type, timestamp):
        """Generate unique tracking ID"""
        data = f"{user_id}:{notification_type}:{timestamp}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def get_tracking_pixel_url(self, tracking_id, base_url='http://localhost:5001'):
        """Generate tracking pixel URL"""
        return f"{base_url}/track/open/{tracking_id}.png"
    
    def get_tracked_link_url(self, tracking_id, link_id, target_url, base_url='http://localhost:5001'):
        """Generate tracked link URL"""
        encoded_url = base64.urlsafe_b64encode(target_url.encode()).decode()
        return f"{base_url}/track/click/{tracking_id}/{link_id}?target={encoded_url}"
    
    def track_open(self, tracking_id, ip_address, user_agent):
        """Record email open event"""
        with self.get_db() as conn:
            cursor = conn.cursor()
            
            # Check if already tracked (prevent double counting)
            cursor.execute('''
                SELECT id FROM email_opens WHERE tracking_id = ?
            ''', (tracking_id,))
            
            if cursor.fetchone():
                logger.info(f'Email already tracked as opened: {tracking_id}')
                return False
            
            # Get user info from tracking ID
            cursor.execute('''
                SELECT user_id, notification_type FROM notification_logs
                WHERE user_id IN (
                    SELECT DISTINCT user_id FROM subscriptions
                )
                LIMIT 1
            ''')
            
            # Parse device type and email client from user agent
            device_type = self._parse_device_type(user_agent)
            email_client = self._parse_email_client(user_agent)
            
            # Record open
            try:
                cursor.execute('''
                    INSERT INTO email_opens 
                    (tracking_id, user_id, notification_type, opened_at, ip_address, user_agent, device_type, email_client)
                    VALUES (?, 1, 'unknown', ?, ?, ?, ?, ?)
                ''', (tracking_id, int(time.time()), ip_address, user_agent, device_type, email_client))
                
                # Update engagement
                self._update_engagement(cursor, 1, 'open')
                
                conn.commit()
                logger.info(f'Tracked email open: {tracking_id}')
                return True
            except Exception as e:
                logger.error(f'Error tracking open: {e}')
                return False
    
    def track_click(self, tracking_id, link_id, ip_address, user_agent):
        """Record email click event"""
        with self.get_db() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO email_clicks 
                (tracking_id, user_id, notification_type, link_id, clicked_at, ip_address, user_agent)
                VALUES (?, 1, 'unknown', ?, ?, ?, ?)
            ''', (tracking_id, link_id, int(time.time()), ip_address, user_agent))
            
            # Update engagement
            self._update_engagement(cursor, 1, 'click')
            
            conn.commit()
            logger.info(f'Tracked email click: {tracking_id} -> {link_id}')
    
    def _update_engagement(self, cursor, user_id, action):
        """Update user engagement score"""
        # Engagement scoring:
        # Open = 1 point
        # Click = 3 points
        points = {'open': 1, 'click': 3}.get(action, 0)
        
        cursor.execute('''
            INSERT INTO user_engagement 
            (user_id, engagement_score, total_opens, total_clicks, last_engagement, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                engagement_score = engagement_score + ?,
                total_opens = total_opens + ?,
                total_clicks = total_clicks + ?,
                last_engagement = ?,
                updated_at = ?
        ''', (
            user_id, points,
            1 if action == 'open' else 0,
            1 if action == 'click' else 0,
            int(time.time()), int(time.time()),
            points,
            1 if action == 'open' else 0,
            1 if action == 'click' else 0,
            int(time.time()), int(time.time())
        ))
    
    def _parse_device_type(self, user_agent):
        """Parse device type from user agent"""
        ua_lower = user_agent.lower()
        if 'mobile' in ua_lower or 'android' in ua_lower or 'iphone' in ua_lower:
            return 'mobile'
        elif 'tablet' in ua_lower or 'ipad' in ua_lower:
            return 'tablet'
        else:
            return 'desktop'
    
    def _parse_email_client(self, user_agent):
        """Parse email client from user agent"""
        ua_lower = user_agent.lower()
        if 'gmail' in ua_lower:
            return 'gmail'
        elif 'outlook' in ua_lower:
            return 'outlook'
        elif 'apple mail' in ua_lower or 'macos' in ua_lower:
            return 'apple_mail'
        elif 'yahoo' in ua_lower:
            return 'yahoo'
        else:
            return 'unknown'
    
    def get_open_rate(self, notification_type=None, hours=24):
        """Calculate open rate"""
        with self.get_db() as conn:
            cursor = conn.cursor()
            
            cutoff = int(time.time()) - (hours * 3600)
            
            if notification_type:
                cursor.execute('''
                    SELECT 
                        COUNT(DISTINCT nl.id) as total_sent,
                        COUNT(DISTINCT eo.tracking_id) as total_opens
                    FROM notification_logs nl
                    LEFT JOIN email_opens eo ON eo.notification_type = nl.notification_type
                    WHERE nl.notification_type = ? AND nl.sent_at >= ?
                ''', (notification_type, cutoff))
            else:
                cursor.execute('''
                    SELECT 
                        COUNT(DISTINCT nl.id) as total_sent,
                        COUNT(DISTINCT eo.tracking_id) as total_opens
                    FROM notification_logs nl
                    LEFT JOIN email_opens eo ON eo.notification_type = nl.notification_type
                    WHERE nl.sent_at >= ?
                ''', (cutoff,))
            
            result = cursor.fetchone()
            
            if result and result['total_sent'] > 0:
                open_rate = (result['total_opens'] / result['total_sent']) * 100
            else:
                open_rate = 0
            
            return {
                'open_rate': round(open_rate, 2),
                'total_sent': result['total_sent'] if result else 0,
                'total_opens': result['total_opens'] if result else 0
            }
    
    def get_click_rate(self, notification_type=None, hours=24):
        """Calculate click-through rate"""
        with self.get_db() as conn:
            cursor = conn.cursor()
            
            cutoff = int(time.time()) - (hours * 3600)
            
            if notification_type:
                cursor.execute('''
                    SELECT 
                        COUNT(DISTINCT nl.id) as total_sent,
                        COUNT(DISTINCT ec.tracking_id) as total_clicks
                    FROM notification_logs nl
                    LEFT JOIN email_clicks ec ON ec.notification_type = nl.notification_type
                    WHERE nl.notification_type = ? AND nl.sent_at >= ?
                ''', (notification_type, cutoff))
            else:
                cursor.execute('''
                    SELECT 
                        COUNT(DISTINCT nl.id) as total_sent,
                        COUNT(DISTINCT ec.tracking_id) as total_clicks
                    FROM notification_logs nl
                    LEFT JOIN email_clicks ec ON ec.notification_type = nl.notification_type
                    WHERE nl.sent_at >= ?
                ''', (cutoff,))
            
            result = cursor.fetchone()
            
            if result and result['total_sent'] > 0:
                click_rate = (result['total_clicks'] / result['total_sent']) * 100
            else:
                click_rate = 0
            
            return {
                'click_rate': round(click_rate, 2),
                'total_sent': result['total_sent'] if result else 0,
                'total_clicks': result['total_clicks'] if result else 0
            }
    
    def get_engagement_report(self):
        """Generate engagement analytics report"""
        open_rates = {}
        click_rates = {}
        
        for notif_type in ['timeline_2_4_hours', 'timeline_4_6_hours', 'timeline_tonight']:
            open_rates[notif_type] = self.get_open_rate(notif_type, 24)
            click_rates[notif_type] = self.get_click_rate(notif_type, 24)
        
        with self.get_db() as conn:
            cursor = conn.cursor()
            
            # Top engaged users
            cursor.execute('''
                SELECT user_id, engagement_score, total_opens, total_clicks
                FROM user_engagement
                ORDER BY engagement_score DESC
                LIMIT 10
            ''')
            top_users = [dict(row) for row in cursor.fetchall()]
            
            # Device breakdown
            cursor.execute('''
                SELECT device_type, COUNT(*) as count
                FROM email_opens
                GROUP BY device_type
            ''')
            devices = {row['device_type']: row['count'] for row in cursor.fetchall()}
            
            # Email client breakdown
            cursor.execute('''
                SELECT email_client, COUNT(*) as count
                FROM email_opens
                GROUP BY email_client
            ''')
            clients = {row['email_client']: row['count'] for row in cursor.fetchall()}
        
        return {
            'open_rates': open_rates,
            'click_rates': click_rates,
            'top_users': top_users,
            'devices': devices,
            'email_clients': clients,
            'generated_at': time.time()
        }


# Flask app for tracking endpoints
app = Flask(__name__)
tracker = EmailTracker()


@app.route('/track/open/<tracking_id>.png')
def track_open(tracking_id):
    """Tracking pixel endpoint"""
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    
    tracker.track_open(tracking_id, ip, user_agent)
    
    # Return 1x1 transparent pixel
    img = Image.new('RGBA', (1, 1), (0, 0, 0, 0))
    img_io = BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    
    return send_file(img_io, mimetype='image/png')


@app.route('/track/click/<tracking_id>/<link_id>')
def track_click(tracking_id, link_id):
    """Click tracking endpoint"""
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    target_url = request.args.get('target', '')
    
    tracker.track_click(tracking_id, link_id, ip, user_agent)
    
    # Decode and redirect to target URL
    try:
        decoded_url = base64.urlsafe_b64decode(target_url.encode()).decode()
        return f'<meta http-equiv="refresh" content="0;url={decoded_url}">'
    except:
        return 'Invalid tracking link', 400


@app.route('/analytics/open-rates')
def api_open_rates():
    """API endpoint for open rates"""
    notif_type = request.args.get('type')
    hours = int(request.args.get('hours', 24))
    
    return jsonify(tracker.get_open_rate(notif_type, hours))


@app.route('/analytics/click-rates')
def api_click_rates():
    """API endpoint for click rates"""
    notif_type = request.args.get('type')
    hours = int(request.args.get('hours', 24))
    
    return jsonify(tracker.get_click_rate(notif_type, hours))


@app.route('/analytics/report')
def api_report():
    """API endpoint for full engagement report"""
    return jsonify(tracker.get_engagement_report())


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
