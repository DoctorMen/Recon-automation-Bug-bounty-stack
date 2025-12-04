#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
TIMELINE NOTIFICATION SYSTEM - Backend API
Enterprise-Grade Security | Red Team Hardened
"""

from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import secrets
import hashlib
import hmac
import time
import json
import os
from datetime import datetime, timedelta
from functools import wraps
import re
import bleach
from cryptography.fernet import Fernet
import sqlite3
from contextlib import contextmanager
import logging
from logging.handlers import RotatingFileHandler

# Security Configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['JWT_SECRET'] = os.environ.get('JWT_SECRET', secrets.token_hex(32))
app.config['ENCRYPTION_KEY'] = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key())
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# CORS with strict origin control
CORS(app, resources={
    r"/api/*": {
        "origins": os.environ.get('ALLOWED_ORIGINS', 'http://localhost:*').split(','),
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "allow_headers": ["Content-Type", "Authorization", "X-CSRF-Token"],
        "supports_credentials": True
    }
})

# Rate Limiting - Red Team Protection
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Encryption
cipher = Fernet(app.config['ENCRYPTION_KEY'])

# Logging - Security Events
if not os.path.exists('logs'):
    os.makedirs('logs')
    
file_handler = RotatingFileHandler('logs/security.log', maxBytes=10240000, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Timeline Notification System startup')


# Database Context Manager - SQL Injection Protection
@contextmanager
def get_db():
    conn = sqlite3.connect('notifications.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    """Initialize database with security constraints"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Users table with security fields
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email_verified INTEGER DEFAULT 0,
                verification_token TEXT,
                reset_token TEXT,
                reset_token_expires INTEGER,
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until INTEGER DEFAULT 0,
                created_at INTEGER NOT NULL,
                last_login INTEGER,
                api_key_hash TEXT,
                two_factor_secret TEXT
            )
        ''')
        
        # Subscriptions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                notification_type TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                frequency TEXT NOT NULL,
                last_sent INTEGER,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        
        # Notification logs - Audit trail
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notification_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                notification_type TEXT NOT NULL,
                status TEXT NOT NULL,
                sent_at INTEGER NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        
        # Security events
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                user_id INTEGER,
                ip_address TEXT,
                user_agent TEXT,
                details TEXT,
                severity TEXT NOT NULL,
                timestamp INTEGER NOT NULL
            )
        ''')
        
        conn.commit()


# Security Utilities
def sanitize_input(data):
    """Sanitize user input - XSS Protection"""
    if isinstance(data, str):
        return bleach.clean(data.strip())
    return data


def validate_email(email):
    """Email validation with regex"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def generate_csrf_token():
    """Generate CSRF token"""
    token = secrets.token_hex(32)
    session['csrf_token'] = token
    return token


def verify_csrf_token(token):
    """Verify CSRF token"""
    return hmac.compare_digest(session.get('csrf_token', ''), token)


def log_security_event(event_type, severity, details, user_id=None):
    """Log security events for monitoring"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO security_events (event_type, user_id, ip_address, user_agent, details, severity, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            event_type,
            user_id,
            request.remote_addr,
            request.headers.get('User-Agent', ''),
            json.dumps(details),
            severity,
            int(time.time())
        ))
        conn.commit()
    
    app.logger.warning(f'SECURITY EVENT: {event_type} - {severity} - {details}')


def create_jwt_token(user_id):
    """Create JWT token with expiration"""
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=24),
        'iat': datetime.utcnow(),
        'jti': secrets.token_hex(16)
    }
    return jwt.encode(payload, app.config['JWT_SECRET'], algorithm='HS256')


def verify_jwt_token(token):
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET'], algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        log_security_event('jwt_expired', 'INFO', {'token': 'expired'})
        return None
    except jwt.InvalidTokenError:
        log_security_event('jwt_invalid', 'WARNING', {'token': 'invalid'})
        return None


def require_auth(f):
    """Authentication decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authentication required'}), 401
        
        token = auth_header.split(' ')[1]
        user_id = verify_jwt_token(token)
        
        if not user_id:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        request.current_user_id = user_id
        return f(*args, **kwargs)
    
    return decorated_function


def check_rate_limit(user_id):
    """Check if user is within rate limits"""
    # Implement custom rate limiting per user
    return True


# API Endpoints

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': int(time.time()),
        'version': '1.0.0'
    })


@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    """Get CSRF token"""
    token = generate_csrf_token()
    return jsonify({'csrf_token': token})


@app.route('/api/register', methods=['POST'])
@limiter.limit("5 per hour")
def register():
    """Register new user with security validations"""
    try:
        data = request.get_json()
        
        # Input validation
        email = sanitize_input(data.get('email', ''))
        password = data.get('password', '')
        
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400
        
        if len(password) < 12:
            return jsonify({'error': 'Password must be at least 12 characters'}), 400
        
        # Check password complexity
        if not (re.search(r'[A-Z]', password) and 
                re.search(r'[a-z]', password) and 
                re.search(r'[0-9]', password) and 
                re.search(r'[!@#$%^&*(),.?":{}|<>]', password)):
            return jsonify({'error': 'Password must contain uppercase, lowercase, number, and special character'}), 400
        
        with get_db() as conn:
            cursor = conn.cursor()
            
            # Check if user exists
            cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
            if cursor.fetchone():
                log_security_event('registration_duplicate', 'INFO', {'email': email})
                return jsonify({'error': 'Email already registered'}), 409
            
            # Create user
            password_hash = generate_password_hash(password, method='pbkdf2:sha256:600000')
            verification_token = secrets.token_urlsafe(32)
            
            cursor.execute('''
                INSERT INTO users (email, password_hash, verification_token, created_at)
                VALUES (?, ?, ?, ?)
            ''', (email, password_hash, verification_token, int(time.time())))
            
            user_id = cursor.lastrowid
            conn.commit()
            
            log_security_event('user_registered', 'INFO', {'user_id': user_id, 'email': email})
            
            # TODO: Send verification email
            
            return jsonify({
                'message': 'Registration successful',
                'user_id': user_id,
                'verification_required': True
            }), 201
    
    except Exception as e:
        app.logger.error(f'Registration error: {str(e)}')
        return jsonify({'error': 'Registration failed'}), 500


@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per hour")
def login():
    """Login with account lockout protection"""
    try:
        data = request.get_json()
        email = sanitize_input(data.get('email', ''))
        password = data.get('password', '')
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            user = cursor.fetchone()
            
            if not user:
                log_security_event('login_failed', 'WARNING', {'email': email, 'reason': 'user_not_found'})
                time.sleep(1)  # Prevent timing attacks
                return jsonify({'error': 'Invalid credentials'}), 401
            
            user_id = user['id']
            
            # Check account lockout
            if user['locked_until'] and user['locked_until'] > time.time():
                remaining = int(user['locked_until'] - time.time())
                log_security_event('login_attempt_locked', 'WARNING', {'user_id': user_id, 'remaining': remaining})
                return jsonify({'error': f'Account locked. Try again in {remaining} seconds'}), 403
            
            # Verify password
            if not check_password_hash(user['password_hash'], password):
                # Increment failed attempts
                failed_attempts = user['failed_login_attempts'] + 1
                locked_until = 0
                
                if failed_attempts >= 5:
                    locked_until = int(time.time()) + 900  # 15 minutes lockout
                    log_security_event('account_locked', 'WARNING', {'user_id': user_id, 'attempts': failed_attempts})
                
                cursor.execute('''
                    UPDATE users 
                    SET failed_login_attempts = ?, locked_until = ?
                    WHERE id = ?
                ''', (failed_attempts, locked_until, user_id))
                conn.commit()
                
                log_security_event('login_failed', 'WARNING', {'user_id': user_id, 'attempts': failed_attempts})
                time.sleep(1)  # Prevent timing attacks
                return jsonify({'error': 'Invalid credentials'}), 401
            
            # Successful login - reset failed attempts
            cursor.execute('''
                UPDATE users 
                SET failed_login_attempts = 0, locked_until = 0, last_login = ?
                WHERE id = ?
            ''', (int(time.time()), user_id))
            conn.commit()
            
            # Generate token
            token = create_jwt_token(user_id)
            
            log_security_event('login_success', 'INFO', {'user_id': user_id})
            
            return jsonify({
                'token': token,
                'user_id': user_id,
                'email': user['email']
            }), 200
    
    except Exception as e:
        app.logger.error(f'Login error: {str(e)}')
        return jsonify({'error': 'Login failed'}), 500


@app.route('/api/notifications/subscribe', methods=['POST'])
@require_auth
@limiter.limit("20 per hour")
def subscribe_notification():
    """Subscribe to timeline notifications"""
    try:
        data = request.get_json()
        user_id = request.current_user_id
        
        notification_type = sanitize_input(data.get('type', ''))
        frequency = sanitize_input(data.get('frequency', 'all'))
        
        # Validate notification type
        valid_types = ['timeline_2_4_hours', 'timeline_4_6_hours', 'timeline_tonight', 'timeline_all']
        if notification_type not in valid_types:
            return jsonify({'error': 'Invalid notification type'}), 400
        
        with get_db() as conn:
            cursor = conn.cursor()
            
            # Check if subscription exists
            cursor.execute('''
                SELECT id FROM subscriptions 
                WHERE user_id = ? AND notification_type = ?
            ''', (user_id, notification_type))
            
            existing = cursor.fetchone()
            
            if existing:
                # Update existing
                cursor.execute('''
                    UPDATE subscriptions 
                    SET enabled = 1, frequency = ?
                    WHERE id = ?
                ''', (frequency, existing['id']))
            else:
                # Create new
                cursor.execute('''
                    INSERT INTO subscriptions (user_id, notification_type, frequency, created_at)
                    VALUES (?, ?, ?, ?)
                ''', (user_id, notification_type, frequency, int(time.time())))
            
            conn.commit()
            
            log_security_event('notification_subscribed', 'INFO', {
                'user_id': user_id,
                'type': notification_type
            })
            
            return jsonify({'message': 'Subscription successful'}), 200
    
    except Exception as e:
        app.logger.error(f'Subscribe error: {str(e)}')
        return jsonify({'error': 'Subscription failed'}), 500


@app.route('/api/notifications/unsubscribe', methods=['POST'])
@require_auth
@limiter.limit("20 per hour")
def unsubscribe_notification():
    """Unsubscribe from notifications"""
    try:
        data = request.get_json()
        user_id = request.current_user_id
        notification_type = sanitize_input(data.get('type', ''))
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE subscriptions 
                SET enabled = 0
                WHERE user_id = ? AND notification_type = ?
            ''', (user_id, notification_type))
            conn.commit()
            
            log_security_event('notification_unsubscribed', 'INFO', {
                'user_id': user_id,
                'type': notification_type
            })
            
            return jsonify({'message': 'Unsubscribed successfully'}), 200
    
    except Exception as e:
        app.logger.error(f'Unsubscribe error: {str(e)}')
        return jsonify({'error': 'Unsubscribe failed'}), 500


@app.route('/api/notifications/preferences', methods=['GET'])
@require_auth
def get_preferences():
    """Get user notification preferences"""
    try:
        user_id = request.current_user_id
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT notification_type, enabled, frequency, last_sent
                FROM subscriptions
                WHERE user_id = ?
            ''', (user_id,))
            
            subscriptions = cursor.fetchall()
            
            return jsonify({
                'subscriptions': [dict(row) for row in subscriptions]
            }), 200
    
    except Exception as e:
        app.logger.error(f'Get preferences error: {str(e)}')
        return jsonify({'error': 'Failed to fetch preferences'}), 500


@app.route('/api/notifications/stats', methods=['GET'])
@require_auth
def get_notification_stats():
    """Get notification statistics"""
    try:
        user_id = request.current_user_id
        
        with get_db() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT 
                    notification_type,
                    COUNT(*) as total_sent,
                    SUM(CASE WHEN status = 'delivered' THEN 1 ELSE 0 END) as delivered,
                    MAX(sent_at) as last_sent
                FROM notification_logs
                WHERE user_id = ?
                GROUP BY notification_type
            ''', (user_id,))
            
            stats = cursor.fetchall()
            
            return jsonify({
                'stats': [dict(row) for row in stats]
            }), 200
    
    except Exception as e:
        app.logger.error(f'Get stats error: {str(e)}')
        return jsonify({'error': 'Failed to fetch stats'}), 500


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)  # Never run debug in production
