#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Advanced Monitoring & Observability for Agentic System
Real-time metrics, alerts, and visualization
"""

import asyncio
import json
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
from collections import deque
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


@dataclass
class Metric:
    """Single metric measurement"""
    name: str
    value: float
    timestamp: float
    tags: Dict[str, str] = field(default_factory=dict)
    unit: str = ""


@dataclass
class Alert:
    """Alert definition and state"""
    id: str
    name: str
    condition: str
    threshold: float
    severity: str  # 'critical', 'warning', 'info'
    state: str = "ok"  # 'ok', 'firing', 'resolved'
    fired_at: Optional[float] = None
    resolved_at: Optional[float] = None
    message: str = ""


class MetricsCollector:
    """
    Collect and store metrics with time-series support
    """
    
    def __init__(self, retention_seconds: int = 3600):
        self.metrics: Dict[str, deque] = {}
        self.retention_seconds = retention_seconds
        self.aggregates: Dict[str, Dict[str, float]] = {}
        
    def record(self, name: str, value: float, tags: Dict[str, str] = None, unit: str = ""):
        """Record a metric"""
        metric = Metric(
            name=name,
            value=value,
            timestamp=time.time(),
            tags=tags or {},
            unit=unit
        )
        
        if name not in self.metrics:
            self.metrics[name] = deque(maxlen=10000)  # Max 10k points per metric
        
        self.metrics[name].append(metric)
        
        # Clean old metrics
        self._cleanup_old_metrics(name)
    
    def _cleanup_old_metrics(self, metric_name: str):
        """Remove metrics older than retention period"""
        if metric_name not in self.metrics:
            return
        
        cutoff_time = time.time() - self.retention_seconds
        metrics = self.metrics[metric_name]
        
        # Remove old metrics from left
        while metrics and metrics[0].timestamp < cutoff_time:
            metrics.popleft()
    
    def get_latest(self, name: str) -> Optional[Metric]:
        """Get most recent metric value"""
        if name in self.metrics and self.metrics[name]:
            return self.metrics[name][-1]
        return None
    
    def get_range(self, name: str, start_time: float, end_time: float) -> List[Metric]:
        """Get metrics in time range"""
        if name not in self.metrics:
            return []
        
        return [
            m for m in self.metrics[name]
            if start_time <= m.timestamp <= end_time
        ]
    
    def calculate_aggregate(self, name: str, func: str, window_seconds: int = 60) -> float:
        """Calculate aggregate (avg, min, max, sum) over time window"""
        end_time = time.time()
        start_time = end_time - window_seconds
        
        values = [m.value for m in self.get_range(name, start_time, end_time)]
        
        if not values:
            return 0.0
        
        if func == 'avg':
            return sum(values) / len(values)
        elif func == 'min':
            return min(values)
        elif func == 'max':
            return max(values)
        elif func == 'sum':
            return sum(values)
        elif func == 'count':
            return len(values)
        else:
            return 0.0
    
    def get_rate(self, name: str, window_seconds: int = 60) -> float:
        """Calculate rate of change (per second)"""
        end_time = time.time()
        start_time = end_time - window_seconds
        
        metrics = self.get_range(name, start_time, end_time)
        
        if len(metrics) < 2:
            return 0.0
        
        first = metrics[0]
        last = metrics[-1]
        
        time_diff = last.timestamp - first.timestamp
        value_diff = last.value - first.value
        
        if time_diff > 0:
            return value_diff / time_diff
        
        return 0.0


class AlertManager:
    """
    Manage alerts and notifications
    """
    
    def __init__(self, metrics_collector: MetricsCollector):
        self.metrics = metrics_collector
        self.alerts: Dict[str, Alert] = {}
        self.alert_history: List[Alert] = []
        self.notification_callbacks: List[callable] = []
        
    def register_alert(
        self,
        alert_id: str,
        name: str,
        condition: str,
        threshold: float,
        severity: str = "warning"
    ):
        """Register a new alert"""
        alert = Alert(
            id=alert_id,
            name=name,
            condition=condition,
            threshold=threshold,
            severity=severity
        )
        
        self.alerts[alert_id] = alert
        logger.info(f"Registered alert: {name}")
    
    def add_notification_callback(self, callback: callable):
        """Add callback for alert notifications"""
        self.notification_callbacks.append(callback)
    
    async def check_alerts(self):
        """Check all alerts and trigger if conditions met"""
        for alert_id, alert in self.alerts.items():
            await self._evaluate_alert(alert)
    
    async def _evaluate_alert(self, alert: Alert):
        """Evaluate single alert condition"""
        try:
            # Parse condition (e.g., "task_failure_rate > 0.5")
            parts = alert.condition.split()
            if len(parts) != 3:
                return
            
            metric_name, operator, threshold_str = parts
            threshold = float(threshold_str)
            
            # Get current metric value
            current = self.metrics.get_latest(metric_name)
            
            if not current:
                return
            
            # Evaluate condition
            triggered = False
            if operator == '>':
                triggered = current.value > threshold
            elif operator == '<':
                triggered = current.value < threshold
            elif operator == '>=':
                triggered = current.value >= threshold
            elif operator == '<=':
                triggered = current.value <= threshold
            elif operator == '==':
                triggered = current.value == threshold
            
            # Update alert state
            if triggered and alert.state == "ok":
                alert.state = "firing"
                alert.fired_at = time.time()
                alert.message = f"{alert.name}: {metric_name} is {current.value} (threshold: {threshold})"
                
                logger.warning(f"ALERT FIRING: {alert.message}")
                await self._send_notifications(alert)
                
            elif not triggered and alert.state == "firing":
                alert.state = "resolved"
                alert.resolved_at = time.time()
                alert.message = f"{alert.name}: resolved"
                
                logger.info(f"ALERT RESOLVED: {alert.name}")
                await self._send_notifications(alert)
                
                # Archive to history
                self.alert_history.append(alert)
                
                # Reset alert
                alert.state = "ok"
                alert.fired_at = None
                alert.resolved_at = None
                
        except Exception as e:
            logger.error(f"Error evaluating alert {alert.id}: {e}")
    
    async def _send_notifications(self, alert: Alert):
        """Send notifications for alert"""
        for callback in self.notification_callbacks:
            try:
                await callback(alert)
            except Exception as e:
                logger.error(f"Notification callback failed: {e}")


class PerformanceMonitor:
    """
    Monitor system performance and resource usage
    """
    
    def __init__(self, metrics: MetricsCollector):
        self.metrics = metrics
        self.start_time = time.time()
        
    async def collect_system_metrics(self):
        """Collect system-level metrics"""
        while True:
            try:
                # Uptime
                uptime = time.time() - self.start_time
                self.metrics.record("system.uptime_seconds", uptime, unit="seconds")
                
                # Could add: CPU, memory, etc. (would need psutil)
                # For now, recording timestamp
                self.metrics.record("system.timestamp", time.time(), unit="timestamp")
                
            except Exception as e:
                logger.error(f"Error collecting system metrics: {e}")
            
            await asyncio.sleep(10)
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary"""
        uptime = time.time() - self.start_time
        
        return {
            'uptime_seconds': uptime,
            'uptime_formatted': str(timedelta(seconds=int(uptime))),
            'start_time': datetime.fromtimestamp(self.start_time).isoformat()
        }


class AgentActivityTracker:
    """
    Track agent activity and health
    """
    
    def __init__(self, metrics: MetricsCollector):
        self.metrics = metrics
        self.agent_states: Dict[str, Dict[str, Any]] = {}
        
    def record_agent_activity(
        self,
        agent_id: str,
        activity: str,
        metadata: Dict[str, Any] = None
    ):
        """Record agent activity"""
        if agent_id not in self.agent_states:
            self.agent_states[agent_id] = {
                'last_activity': None,
                'activities': deque(maxlen=100)
            }
        
        activity_record = {
            'activity': activity,
            'timestamp': time.time(),
            'metadata': metadata or {}
        }
        
        self.agent_states[agent_id]['last_activity'] = activity_record
        self.agent_states[agent_id]['activities'].append(activity_record)
        
        # Record metrics
        self.metrics.record(
            f"agent.activity.{activity}",
            1.0,
            tags={'agent_id': agent_id}
        )
    
    def get_agent_health(self, agent_id: str) -> Dict[str, Any]:
        """Get agent health status"""
        if agent_id not in self.agent_states:
            return {'status': 'unknown'}
        
        state = self.agent_states[agent_id]
        last_activity = state.get('last_activity')
        
        if not last_activity:
            return {'status': 'idle', 'last_seen': None}
        
        time_since_activity = time.time() - last_activity['timestamp']
        
        # Determine status
        if time_since_activity < 60:
            status = 'active'
        elif time_since_activity < 300:
            status = 'idle'
        else:
            status = 'stale'
        
        return {
            'status': status,
            'last_activity': last_activity['activity'],
            'last_seen': time_since_activity,
            'recent_activities': len(state['activities'])
        }
    
    def get_all_agent_health(self) -> Dict[str, Dict[str, Any]]:
        """Get health for all agents"""
        return {
            agent_id: self.get_agent_health(agent_id)
            for agent_id in self.agent_states.keys()
        }


class TaskMetricsCollector:
    """
    Collect metrics specific to task execution
    """
    
    def __init__(self, metrics: MetricsCollector):
        self.metrics = metrics
        self.task_executions: Dict[str, List[Dict[str, Any]]] = {}
        
    def record_task_start(self, task_id: str, task_name: str, priority: str):
        """Record task start"""
        self.metrics.record(
            "tasks.started",
            1.0,
            tags={'task_name': task_name, 'priority': priority}
        )
        
        if task_id not in self.task_executions:
            self.task_executions[task_id] = []
        
        self.task_executions[task_id].append({
            'event': 'start',
            'timestamp': time.time(),
            'task_name': task_name
        })
    
    def record_task_completion(
        self,
        task_id: str,
        task_name: str,
        duration: float,
        success: bool
    ):
        """Record task completion"""
        # Record completion
        self.metrics.record(
            "tasks.completed" if success else "tasks.failed",
            1.0,
            tags={'task_name': task_name}
        )
        
        # Record duration
        self.metrics.record(
            "tasks.duration_seconds",
            duration,
            tags={'task_name': task_name},
            unit="seconds"
        )
        
        if task_id in self.task_executions:
            self.task_executions[task_id].append({
                'event': 'complete',
                'timestamp': time.time(),
                'task_name': task_name,
                'duration': duration,
                'success': success
            })
    
    def get_task_statistics(self, task_name: str = None) -> Dict[str, Any]:
        """Get task execution statistics"""
        if task_name:
            # Stats for specific task
            executions = [
                exec_list for exec_list in self.task_executions.values()
                if any(e.get('task_name') == task_name for e in exec_list)
            ]
        else:
            # Stats for all tasks
            executions = list(self.task_executions.values())
        
        total = len(executions)
        
        if total == 0:
            return {'total_executions': 0}
        
        # Calculate statistics
        durations = []
        successes = 0
        
        for exec_list in executions:
            for event in exec_list:
                if event['event'] == 'complete':
                    durations.append(event['duration'])
                    if event.get('success'):
                        successes += 1
        
        return {
            'total_executions': total,
            'success_rate': successes / total if total > 0 else 0,
            'average_duration': sum(durations) / len(durations) if durations else 0,
            'min_duration': min(durations) if durations else 0,
            'max_duration': max(durations) if durations else 0
        }


class DashboardGenerator:
    """
    Generate real-time dashboard data
    """
    
    def __init__(
        self,
        metrics: MetricsCollector,
        alerts: AlertManager,
        performance: PerformanceMonitor,
        agent_tracker: AgentActivityTracker,
        task_metrics: TaskMetricsCollector
    ):
        self.metrics = metrics
        self.alerts = alerts
        self.performance = performance
        self.agent_tracker = agent_tracker
        self.task_metrics = task_metrics
    
    def generate_dashboard(self) -> Dict[str, Any]:
        """Generate complete dashboard data"""
        return {
            'timestamp': datetime.now().isoformat(),
            'system': self.performance.get_performance_summary(),
            'agents': self.agent_tracker.get_all_agent_health(),
            'tasks': {
                'statistics': self.task_metrics.get_task_statistics(),
                'rates': {
                    'completion_rate': self.metrics.get_rate('tasks.completed', 60),
                    'failure_rate': self.metrics.get_rate('tasks.failed', 60)
                }
            },
            'alerts': {
                'active': [
                    asdict(alert) for alert in self.alerts.alerts.values()
                    if alert.state == 'firing'
                ],
                'recent_history': [
                    asdict(alert) for alert in self.alerts.alert_history[-10:]
                ]
            },
            'metrics_summary': self._get_metrics_summary()
        }
    
    def _get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of key metrics"""
        summary = {}
        
        for metric_name in self.metrics.metrics.keys():
            latest = self.metrics.get_latest(metric_name)
            if latest:
                summary[metric_name] = {
                    'current': latest.value,
                    'avg_1min': self.metrics.calculate_aggregate(metric_name, 'avg', 60),
                    'max_1min': self.metrics.calculate_aggregate(metric_name, 'max', 60)
                }
        
        return summary
    
    async def save_dashboard(self, filepath: str):
        """Save dashboard to file"""
        dashboard = self.generate_dashboard()
        
        try:
            with open(filepath, 'w') as f:
                json.dump(dashboard, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save dashboard: {e}")
    
    async def continuous_dashboard_update(self, filepath: str, interval_seconds: int = 5):
        """Continuously update dashboard file"""
        while True:
            await self.save_dashboard(filepath)
            await asyncio.sleep(interval_seconds)


# Notification handlers
async def console_notification_handler(alert: Alert):
    """Print alert to console"""
    symbol = "🔴" if alert.severity == "critical" else "⚠️" if alert.severity == "warning" else "ℹ️"
    print(f"\n{symbol} ALERT: {alert.message}")


async def file_notification_handler(alert: Alert):
    """Log alert to file"""
    log_file = Path("output/alerts.log")
    log_file.parent.mkdir(exist_ok=True)
    
    with open(log_file, 'a') as f:
        f.write(f"[{datetime.now().isoformat()}] {alert.severity.upper()}: {alert.message}\n")


# Complete monitoring system setup
def create_monitoring_system():
    """Create complete monitoring system"""
    metrics = MetricsCollector(retention_seconds=3600)
    alerts = AlertManager(metrics)
    performance = PerformanceMonitor(metrics)
    agent_tracker = AgentActivityTracker(metrics)
    task_metrics = TaskMetricsCollector(metrics)
    dashboard = DashboardGenerator(metrics, alerts, performance, agent_tracker, task_metrics)
    
    # Register alerts
    alerts.register_alert(
        "high_failure_rate",
        "High Task Failure Rate",
        "tasks.failed > 5",
        threshold=5.0,
        severity="warning"
    )
    
    alerts.register_alert(
        "agent_stale",
        "Agent Not Responding",
        "agent.heartbeat < 1",
        threshold=1.0,
        severity="critical"
    )
    
    # Add notification handlers
    alerts.add_notification_callback(console_notification_handler)
    alerts.add_notification_callback(file_notification_handler)
    
    return {
        'metrics': metrics,
        'alerts': alerts,
        'performance': performance,
        'agent_tracker': agent_tracker,
        'task_metrics': task_metrics,
        'dashboard': dashboard
    }


if __name__ == "__main__":
    async def demo():
        """Demo monitoring system"""
        system = create_monitoring_system()
        
        metrics = system['metrics']
        task_metrics = system['task_metrics']
        dashboard = system['dashboard']
        
        # Simulate some activity
        for i in range(10):
            task_metrics.record_task_start(f"task_{i}", "demo_task", "high")
            await asyncio.sleep(0.1)
            task_metrics.record_task_completion(f"task_{i}", "demo_task", 0.1, i % 3 != 0)
        
        # Generate dashboard
        dash_data = dashboard.generate_dashboard()
        print(json.dumps(dash_data, indent=2))
    
    asyncio.run(demo())
