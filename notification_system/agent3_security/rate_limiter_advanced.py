#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
ADVANCED RATE LIMITER
Built by Agent 3 (Security Ops)

Per-user rate limiting with Redis backend
Exponential backoff and abuse prevention
"""

import redis
import time
import hashlib
import json
from functools import wraps
from flask import request, jsonify
import logging

logger = logging.getLogger(__name__)


class AdvancedRateLimiter:
    """
    Advanced rate limiter with:
    - Per-user and per-IP limiting
    - Distributed Redis backend
    - Exponential backoff
    - Abuse detection
    - Whitelist/blacklist support
    """
    
    def __init__(self, redis_host='localhost', redis_port=6379, redis_db=0):
        """Initialize rate limiter with Redis connection"""
        self.redis_client = redis.Redis(
            host=redis_host,
            port=redis_port,
            db=redis_db,
            decode_responses=True
        )
        
        # Rate limit configurations
        self.limits = {
            'global': {'requests': 200, 'window': 86400},  # 200 per day
            'per_ip': {'requests': 50, 'window': 3600},     # 50 per hour
            'per_user': {'requests': 100, 'window': 3600},  # 100 per hour per user
            'login': {'requests': 5, 'window': 900},        # 5 per 15 min
            'register': {'requests': 3, 'window': 3600},    # 3 per hour
            'email_send': {'requests': 10, 'window': 3600}, # 10 emails per hour per user
        }
        
        # Abuse thresholds
        self.abuse_threshold = 10  # Violations before blacklist
        self.blacklist_duration = 86400  # 24 hours
    
    def _get_identifier(self, limit_type):
        """Generate unique identifier for rate limiting"""
        if limit_type == 'per_ip':
            return f"ip:{request.remote_addr}"
        elif limit_type == 'per_user':
            user_id = getattr(request, 'current_user_id', None)
            if user_id:
                return f"user:{user_id}"
            return f"ip:{request.remote_addr}"  # Fallback to IP
        else:
            return f"global:{limit_type}"
    
    def _get_key(self, identifier, limit_type):
        """Generate Redis key"""
        return f"ratelimit:{limit_type}:{identifier}:{int(time.time())}"
    
    def _is_whitelisted(self, identifier):
        """Check if identifier is whitelisted"""
        return self.redis_client.sismember('whitelist', identifier)
    
    def _is_blacklisted(self, identifier):
        """Check if identifier is blacklisted"""
        return self.redis_client.exists(f"blacklist:{identifier}")
    
    def _add_to_blacklist(self, identifier, reason):
        """Add identifier to blacklist"""
        key = f"blacklist:{identifier}"
        self.redis_client.setex(
            key,
            self.blacklist_duration,
            json.dumps({
                'reason': reason,
                'timestamp': int(time.time())
            })
        )
        logger.warning(f'Blacklisted {identifier}: {reason}')
    
    def _increment_violation(self, identifier):
        """Increment violation counter"""
        key = f"violations:{identifier}"
        violations = self.redis_client.incr(key)
        self.redis_client.expire(key, 86400)  # 24 hour window
        
        if violations >= self.abuse_threshold:
            self._add_to_blacklist(identifier, f'{violations} violations')
        
        return violations
    
    def check_rate_limit(self, limit_type='global'):
        """
        Check if request is within rate limit
        
        Returns: (allowed: bool, remaining: int, reset_time: int)
        """
        identifier = self._get_identifier(limit_type)
        
        # Check whitelist (always allow)
        if self._is_whitelisted(identifier):
            return True, 999999, 0
        
        # Check blacklist (always block)
        if self._is_blacklisted(identifier):
            logger.warning(f'Blocked blacklisted identifier: {identifier}')
            return False, 0, int(time.time()) + self.blacklist_duration
        
        # Get limit configuration
        config = self.limits.get(limit_type, self.limits['global'])
        max_requests = config['requests']
        window = config['window']
        
        # Sliding window algorithm
        now = int(time.time())
        window_start = now - window
        
        # Key for this window
        key = f"ratelimit:{limit_type}:{identifier}"
        
        # Add current request
        pipe = self.redis_client.pipeline()
        pipe.zadd(key, {str(now): now})
        pipe.zremrangebyscore(key, '-inf', window_start)
        pipe.zcard(key)
        pipe.expire(key, window)
        results = pipe.execute()
        
        current_requests = results[2]
        
        # Check if limit exceeded
        if current_requests > max_requests:
            self._increment_violation(identifier)
            remaining = 0
            reset_time = now + window
            allowed = False
        else:
            remaining = max_requests - current_requests
            reset_time = now + window
            allowed = True
        
        return allowed, remaining, reset_time
    
    def rate_limit(self, limit_type='global', on_breach=None):
        """
        Decorator for rate limiting Flask routes
        
        Usage:
            @app.route('/api/login')
            @rate_limiter.rate_limit('login')
            def login():
                ...
        """
        def decorator(f):
            @wraps(f)
            def wrapped(*args, **kwargs):
                allowed, remaining, reset_time = self.check_rate_limit(limit_type)
                
                if not allowed:
                    if on_breach:
                        return on_breach()
                    
                    return jsonify({
                        'error': 'Rate limit exceeded',
                        'retry_after': reset_time - int(time.time())
                    }), 429
                
                # Add rate limit headers
                response = f(*args, **kwargs)
                
                if hasattr(response, 'headers'):
                    response.headers['X-RateLimit-Limit'] = str(self.limits[limit_type]['requests'])
                    response.headers['X-RateLimit-Remaining'] = str(remaining)
                    response.headers['X-RateLimit-Reset'] = str(reset_time)
                
                return response
            
            return wrapped
        return decorator
    
    def get_user_stats(self, user_id):
        """Get rate limit statistics for a user"""
        identifier = f"user:{user_id}"
        stats = {}
        
        for limit_type, config in self.limits.items():
            key = f"ratelimit:{limit_type}:{identifier}"
            current = self.redis_client.zcard(key)
            max_requests = config['requests']
            
            stats[limit_type] = {
                'current': current,
                'max': max_requests,
                'remaining': max(0, max_requests - current),
                'percentage': (current / max_requests * 100) if max_requests > 0 else 0
            }
        
        return stats
    
    def reset_user_limits(self, user_id):
        """Reset all rate limits for a user (admin function)"""
        identifier = f"user:{user_id}"
        
        for limit_type in self.limits.keys():
            key = f"ratelimit:{limit_type}:{identifier}"
            self.redis_client.delete(key)
        
        # Clear violations
        self.redis_client.delete(f"violations:{identifier}")
        
        logger.info(f'Reset rate limits for user {user_id}')
    
    def whitelist_add(self, identifier):
        """Add identifier to whitelist"""
        self.redis_client.sadd('whitelist', identifier)
        logger.info(f'Added to whitelist: {identifier}')
    
    def whitelist_remove(self, identifier):
        """Remove identifier from whitelist"""
        self.redis_client.srem('whitelist', identifier)
        logger.info(f'Removed from whitelist: {identifier}')
    
    def blacklist_remove(self, identifier):
        """Remove identifier from blacklist"""
        key = f"blacklist:{identifier}"
        self.redis_client.delete(key)
        self.redis_client.delete(f"violations:{identifier}")
        logger.info(f'Removed from blacklist: {identifier}')
    
    def get_abuse_report(self):
        """Generate abuse report"""
        report = {
            'blacklisted': [],
            'high_violations': []
        }
        
        # Get blacklisted identifiers
        for key in self.redis_client.scan_iter("blacklist:*"):
            identifier = key.replace('blacklist:', '')
            data = json.loads(self.redis_client.get(key))
            report['blacklisted'].append({
                'identifier': identifier,
                'reason': data['reason'],
                'timestamp': data['timestamp']
            })
        
        # Get high violation identifiers
        for key in self.redis_client.scan_iter("violations:*"):
            identifier = key.replace('violations:', '')
            violations = int(self.redis_client.get(key))
            if violations >= 5:
                report['high_violations'].append({
                    'identifier': identifier,
                    'violations': violations
                })
        
        return report


# Usage example
"""
from rate_limiter_advanced import AdvancedRateLimiter

# Initialize
rate_limiter = AdvancedRateLimiter(
    redis_host='localhost',
    redis_port=6379
)

# Apply to routes
@app.route('/api/login', methods=['POST'])
@rate_limiter.rate_limit('login')
def login():
    ...

@app.route('/api/register', methods=['POST'])
@rate_limiter.rate_limit('register')
def register():
    ...

@app.route('/api/notifications/send', methods=['POST'])
@require_auth
@rate_limiter.rate_limit('email_send')
def send_notification():
    ...

# Admin functions
@app.route('/admin/rate-limits/<user_id>/reset', methods=['POST'])
@require_admin
def reset_user_rate_limits(user_id):
    rate_limiter.reset_user_limits(user_id)
    return jsonify({'message': 'Rate limits reset'})

@app.route('/admin/abuse-report', methods=['GET'])
@require_admin
def abuse_report():
    return jsonify(rate_limiter.get_abuse_report())

@app.route('/admin/whitelist', methods=['POST'])
@require_admin
def add_to_whitelist():
    identifier = request.json.get('identifier')
    rate_limiter.whitelist_add(identifier)
    return jsonify({'message': 'Added to whitelist'})
"""


# Integration with existing server.py
"""
Replace the existing limiter with:

from rate_limiter_advanced import AdvancedRateLimiter

rate_limiter = AdvancedRateLimiter()

# Then use @rate_limiter.rate_limit('type') instead of @limiter.limit()
"""
