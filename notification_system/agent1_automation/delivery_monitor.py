#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
EMAIL DELIVERY MONITORING SYSTEM
Built by Agent 1 (Automation Engineer)

Real-time monitoring of email delivery status
Performance metrics and diagnostics
"""

import sqlite3
import time
import json
from datetime import datetime, timedelta
from contextlib import contextmanager
from collections import defaultdict
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DeliveryMonitor:
    """
    Monitor email delivery performance and health
    
    Features:
    - Real-time delivery tracking
    - Performance metrics (latency, success rate)
    - Queue depth monitoring
    - Failure pattern detection
    - Automated alerting
    """
    
    def __init__(self, db_path='../backend/notifications.db'):
        self.db_path = db_path
        self.metrics = defaultdict(int)
        self.initialize_metrics_table()
    
    @contextmanager
    def get_db(self):
        """Database context manager"""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def initialize_metrics_table(self):
        """Create metrics table if not exists"""
        with self.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS delivery_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    metric_type TEXT NOT NULL,
                    metric_value REAL NOT NULL,
                    timestamp INTEGER NOT NULL,
                    metadata TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS delivery_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    notification_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    priority INTEGER DEFAULT 0,
                    scheduled_time INTEGER NOT NULL,
                    sent_time INTEGER,
                    retry_count INTEGER DEFAULT 0,
                    error_message TEXT,
                    created_at INTEGER NOT NULL
                )
            ''')
            
            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_queue_status 
                ON delivery_queue(status, scheduled_time)
            ''')
            
            conn.commit()
    
    def track_delivery(self, user_id, notification_type, status, latency_ms, error=None):
        """Track email delivery event"""
        with self.get_db() as conn:
            cursor = conn.cursor()
            
            # Update notification log
            cursor.execute('''
                UPDATE notification_logs
                SET status = ?
                WHERE user_id = ? AND notification_type = ?
                ORDER BY sent_at DESC LIMIT 1
            ''', (status, user_id, notification_type))
            
            # Record metrics
            cursor.execute('''
                INSERT INTO delivery_metrics (metric_type, metric_value, timestamp, metadata)
                VALUES (?, ?, ?, ?)
            ''', (
                'delivery_latency',
                latency_ms,
                int(time.time()),
                json.dumps({
                    'notification_type': notification_type,
                    'status': status,
                    'error': error
                })
            ))
            
            conn.commit()
        
        # Update in-memory metrics
        self.metrics[f'{notification_type}_{status}'] += 1
        self.metrics['total_deliveries'] += 1
        
        if status == 'failed':
            logger.error(f'Delivery failed: {notification_type} to user {user_id} - {error}')
    
    def get_delivery_stats(self, hours=24):
        """Get delivery statistics for the last N hours"""
        with self.get_db() as conn:
            cursor = conn.cursor()
            
            cutoff = int(time.time()) - (hours * 3600)
            
            # Overall stats
            cursor.execute('''
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'delivered' THEN 1 ELSE 0 END) as delivered,
                    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
                    SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending
                FROM notification_logs
                WHERE sent_at >= ?
            ''', (cutoff,))
            
            overall = cursor.fetchone()
            
            # Per-type stats
            cursor.execute('''
                SELECT 
                    notification_type,
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'delivered' THEN 1 ELSE 0 END) as delivered,
                    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed
                FROM notification_logs
                WHERE sent_at >= ?
                GROUP BY notification_type
            ''', (cutoff,))
            
            by_type = cursor.fetchall()
            
            # Average latency
            cursor.execute('''
                SELECT AVG(metric_value) as avg_latency
                FROM delivery_metrics
                WHERE metric_type = 'delivery_latency' AND timestamp >= ?
            ''', (cutoff,))
            
            latency = cursor.fetchone()
            
            return {
                'period_hours': hours,
                'overall': dict(overall) if overall else {},
                'by_type': [dict(row) for row in by_type],
                'avg_latency_ms': latency['avg_latency'] if latency and latency['avg_latency'] else 0,
                'success_rate': (overall['delivered'] / overall['total'] * 100) if overall and overall['total'] > 0 else 0
            }
    
    def get_queue_depth(self):
        """Get current queue depth"""
        with self.get_db() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT 
                    status,
                    COUNT(*) as count
                FROM delivery_queue
                GROUP BY status
            ''')
            
            queue = {row['status']: row['count'] for row in cursor.fetchall()}
            
            return {
                'pending': queue.get('pending', 0),
                'processing': queue.get('processing', 0),
                'failed': queue.get('failed', 0),
                'total': sum(queue.values())
            }
    
    def get_failure_patterns(self, limit=10):
        """Identify common failure patterns"""
        with self.get_db() as conn:
            cursor = conn.cursor()
            
            # Get recent failures
            cursor.execute('''
                SELECT 
                    notification_type,
                    COUNT(*) as failure_count,
                    GROUP_CONCAT(DISTINCT ip_address) as affected_ips
                FROM notification_logs
                WHERE status = 'failed'
                AND sent_at >= ?
                GROUP BY notification_type
                ORDER BY failure_count DESC
                LIMIT ?
            ''', (int(time.time()) - 86400, limit))
            
            failures = cursor.fetchall()
            
            return [dict(row) for row in failures]
    
    def get_health_status(self):
        """Get overall system health status"""
        stats = self.get_delivery_stats(1)  # Last hour
        queue = self.get_queue_depth()
        
        # Health indicators
        success_rate = stats['success_rate']
        avg_latency = stats['avg_latency_ms']
        queue_depth = queue['pending']
        
        # Determine health status
        if success_rate >= 95 and avg_latency < 1000 and queue_depth < 100:
            health = 'healthy'
            score = 100
        elif success_rate >= 90 and avg_latency < 2000 and queue_depth < 500:
            health = 'degraded'
            score = 75
        elif success_rate >= 80 and avg_latency < 5000 and queue_depth < 1000:
            health = 'warning'
            score = 50
        else:
            health = 'critical'
            score = 25
        
        return {
            'status': health,
            'score': score,
            'indicators': {
                'success_rate': success_rate,
                'avg_latency_ms': avg_latency,
                'queue_depth': queue_depth
            },
            'timestamp': int(time.time())
        }
    
    def enqueue_notification(self, user_id, notification_type, scheduled_time=None, priority=0):
        """Add notification to delivery queue"""
        if scheduled_time is None:
            scheduled_time = int(time.time())
        
        with self.get_db() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO delivery_queue 
                (user_id, notification_type, status, priority, scheduled_time, created_at)
                VALUES (?, ?, 'pending', ?, ?, ?)
            ''', (user_id, notification_type, priority, scheduled_time, int(time.time())))
            
            queue_id = cursor.lastrowid
            conn.commit()
            
            logger.info(f'Enqueued notification {queue_id}: {notification_type} for user {user_id}')
            return queue_id
    
    def process_queue(self, batch_size=10):
        """Process pending notifications in queue"""
        with self.get_db() as conn:
            cursor = conn.cursor()
            
            # Get pending notifications
            cursor.execute('''
                SELECT * FROM delivery_queue
                WHERE status = 'pending'
                AND scheduled_time <= ?
                ORDER BY priority DESC, scheduled_time ASC
                LIMIT ?
            ''', (int(time.time()), batch_size))
            
            pending = cursor.fetchall()
            
            processed = []
            for item in pending:
                # Mark as processing
                cursor.execute('''
                    UPDATE delivery_queue
                    SET status = 'processing'
                    WHERE id = ?
                ''', (item['id'],))
                conn.commit()
                
                processed.append(dict(item))
            
            return processed
    
    def mark_completed(self, queue_id, status='delivered', error=None):
        """Mark queue item as completed"""
        with self.get_db() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE delivery_queue
                SET status = ?, sent_time = ?, error_message = ?
                WHERE id = ?
            ''', (status, int(time.time()), error, queue_id))
            
            conn.commit()
    
    def retry_failed(self, max_retries=3):
        """Retry failed deliveries"""
        with self.get_db() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM delivery_queue
                WHERE status = 'failed'
                AND retry_count < ?
                AND created_at >= ?
            ''', (max_retries, int(time.time()) - 86400))
            
            failed = cursor.fetchall()
            
            for item in failed:
                cursor.execute('''
                    UPDATE delivery_queue
                    SET status = 'pending', retry_count = retry_count + 1
                    WHERE id = ?
                ''', (item['id'],))
            
            conn.commit()
            
            logger.info(f'Retrying {len(failed)} failed deliveries')
            return len(failed)
    
    def generate_report(self):
        """Generate comprehensive monitoring report"""
        return {
            'health': self.get_health_status(),
            'stats_24h': self.get_delivery_stats(24),
            'stats_1h': self.get_delivery_stats(1),
            'queue': self.get_queue_depth(),
            'failure_patterns': self.get_failure_patterns(),
            'generated_at': datetime.now().isoformat()
        }
    
    def cleanup_old_data(self, days=30):
        """Clean up old metrics data"""
        with self.get_db() as conn:
            cursor = conn.cursor()
            
            cutoff = int(time.time()) - (days * 86400)
            
            cursor.execute('DELETE FROM delivery_metrics WHERE timestamp < ?', (cutoff,))
            cursor.execute('DELETE FROM delivery_queue WHERE created_at < ? AND status != "pending"', (cutoff,))
            
            deleted = cursor.rowcount
            conn.commit()
            
            logger.info(f'Cleaned up {deleted} old records')
            return deleted


# CLI Tool
if __name__ == '__main__':
    import sys
    
    monitor = DeliveryMonitor()
    
    if len(sys.argv) < 2:
        print("Usage: python delivery_monitor.py [stats|health|queue|report|cleanup]")
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == 'stats':
        hours = int(sys.argv[2]) if len(sys.argv) > 2 else 24
        stats = monitor.get_delivery_stats(hours)
        print(json.dumps(stats, indent=2))
    
    elif command == 'health':
        health = monitor.get_health_status()
        print(json.dumps(health, indent=2))
        print(f"\n🟢 System Status: {health['status'].upper()}")
    
    elif command == 'queue':
        queue = monitor.get_queue_depth()
        print(json.dumps(queue, indent=2))
    
    elif command == 'report':
        report = monitor.generate_report()
        print(json.dumps(report, indent=2))
    
    elif command == 'cleanup':
        days = int(sys.argv[2]) if len(sys.argv) > 2 else 30
        deleted = monitor.cleanup_old_data(days)
        print(f"Cleaned up {deleted} old records")
    
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)
