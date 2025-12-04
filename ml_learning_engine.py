#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
ML Learning Engine - Self-Learning System for Bug Bounty Automation
Tracks executions, learns patterns, predicts performance, optimizes settings
"""

import json
import os
import time
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import statistics

class ExecutionHistory:
    """Tracks all command executions and outcomes"""
    
    def __init__(self, history_file: str = "output/.ml_learning/execution_history.jsonl"):
        self.history_file = Path(history_file)
        self.history_file.parent.mkdir(parents=True, exist_ok=True)
    
    def log_execution(self, 
                     command: str, 
                     target: str,
                     settings: Dict[str, Any],
                     duration: float,
                     success: bool,
                     results: Dict[str, Any]):
        """Log a command execution with all details"""
        
        execution_id = hashlib.md5(
            f"{command}{target}{time.time()}".encode()
        ).hexdigest()[:12]
        
        record = {
            "execution_id": execution_id,
            "timestamp": datetime.now().isoformat(),
            "command": command,
            "target": target,
            "settings": settings,
            "duration_seconds": duration,
            "success": success,
            "results": results
        }
        
        # Append to JSONL file (idempotent - each line is independent)
        with open(self.history_file, 'a') as f:
            f.write(json.dumps(record) + '\n')
        
        return execution_id
    
    def get_history(self, limit: Optional[int] = None) -> List[Dict]:
        """Retrieve execution history"""
        if not self.history_file.exists():
            return []
        
        history = []
        with open(self.history_file, 'r') as f:
            for line in f:
                if line.strip():
                    history.append(json.loads(line))
        
        if limit:
            return history[-limit:]
        return history
    
    def get_target_history(self, target: str) -> List[Dict]:
        """Get all executions for a specific target"""
        all_history = self.get_history()
        return [h for h in all_history if h.get('target') == target]
    
    def get_command_history(self, command: str) -> List[Dict]:
        """Get all executions for a specific command"""
        all_history = self.get_history()
        return [h for h in all_history if h.get('command') == command]


class PatternRecognizer:
    """Recognizes patterns in execution history and learns optimal configurations"""
    
    def __init__(self, history: ExecutionHistory):
        self.history = history
    
    def find_optimal_settings(self, command: str, target_type: str = "general") -> Dict[str, Any]:
        """Find optimal settings based on successful past executions"""
        
        command_history = self.history.get_command_history(command)
        successful = [h for h in command_history if h.get('success', False)]
        
        if not successful:
            return self._get_default_settings(command)
        
        # Analyze successful executions to find patterns
        settings_performance = {}
        
        for execution in successful:
            settings_key = json.dumps(execution.get('settings', {}), sort_keys=True)
            duration = execution.get('duration_seconds', 0)
            
            if settings_key not in settings_performance:
                settings_performance[settings_key] = []
            settings_performance[settings_key].append(duration)
        
        # Find settings with best average performance
        best_settings = None
        best_avg_duration = float('inf')
        
        for settings_key, durations in settings_performance.items():
            avg_duration = statistics.mean(durations)
            if avg_duration < best_avg_duration:
                best_avg_duration = avg_duration
                best_settings = json.loads(settings_key)
        
        return best_settings or self._get_default_settings(command)
    
    def predict_duration(self, command: str, target: str, settings: Dict[str, Any]) -> float:
        """Predict execution duration based on historical data"""
        
        # Get similar past executions
        target_history = self.history.get_target_history(target)
        if not target_history:
            # Use command history instead
            target_history = self.history.get_command_history(command)
        
        if not target_history:
            return 1800.0  # Default 30 minutes
        
        # Calculate average duration
        durations = [h.get('duration_seconds', 0) for h in target_history if h.get('success')]
        if durations:
            return statistics.median(durations)
        
        return 1800.0
    
    def predict_findings_count(self, target: str) -> Dict[str, int]:
        """Predict expected number of findings by severity"""
        
        target_history = self.history.get_target_history(target)
        
        if not target_history:
            return {"critical": 0, "high": 2, "medium": 5, "low": 10}
        
        # Average findings from past scans
        findings_by_severity = {"critical": [], "high": [], "medium": [], "low": []}
        
        for h in target_history:
            results = h.get('results', {})
            for severity in findings_by_severity.keys():
                count = results.get(f"{severity}_count", 0)
                findings_by_severity[severity].append(count)
        
        # Return median predictions
        predictions = {}
        for severity, counts in findings_by_severity.items():
            if counts:
                predictions[severity] = int(statistics.median(counts))
            else:
                predictions[severity] = 0
        
        return predictions
    
    def _get_default_settings(self, command: str) -> Dict[str, Any]:
        """Default settings for each command type"""
        defaults = {
            "run_pipeline": {
                "RECON_TIMEOUT": 1800,
                "SUBFINDER_THREADS": 50,
                "NUCLEI_RATE_LIMIT": 150,
                "NUCLEI_SEVERITY": "medium,high,critical"
            },
            "run_recon": {
                "RECON_TIMEOUT": 1800,
                "SUBFINDER_THREADS": 50,
                "AMASS_MAX_DNS": 10000
            },
            "run_nuclei": {
                "NUCLEI_RATE_LIMIT": 150,
                "NUCLEI_THREADS": 50,
                "NUCLEI_SEVERITY": "medium,high,critical"
            }
        }
        return defaults.get(command, {})


class AdaptiveOptimizer:
    """Automatically optimizes settings based on system resources and patterns"""
    
    def __init__(self, pattern_recognizer: PatternRecognizer):
        self.recognizer = pattern_recognizer
    
    def optimize_for_speed(self, base_settings: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize settings for maximum speed"""
        optimized = base_settings.copy()
        
        # Aggressive speed settings
        optimized['RECON_TIMEOUT'] = 600
        optimized['SUBFINDER_THREADS'] = 100
        optimized['NUCLEI_RATE_LIMIT'] = 300
        optimized['NUCLEI_SEVERITY'] = 'high,critical'
        optimized['NUCLEI_RETRIES'] = 2
        
        return optimized
    
    def optimize_for_accuracy(self, base_settings: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize settings for maximum accuracy"""
        optimized = base_settings.copy()
        
        # Thorough accuracy settings
        optimized['RECON_TIMEOUT'] = 3600
        optimized['AMASS_MAX_DNS'] = 20000
        optimized['NUCLEI_RATE_LIMIT'] = 50
        optimized['NUCLEI_SEVERITY'] = 'info,low,medium,high,critical'
        optimized['NUCLEI_RETRIES'] = 5
        
        return optimized
    
    def optimize_for_resources(self, base_settings: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize based on available system resources"""
        try:
            import psutil
            total_ram_gb = psutil.virtual_memory().total / (1024**3)
            
            optimized = base_settings.copy()
            
            if total_ram_gb < 10:
                # Low RAM settings
                optimized['SUBFINDER_THREADS'] = 30
                optimized['AMASS_MAX_DNS'] = 5000
                optimized['NUCLEI_THREADS'] = 25
            elif total_ram_gb < 20:
                # Medium RAM settings
                optimized['SUBFINDER_THREADS'] = 50
                optimized['AMASS_MAX_DNS'] = 10000
                optimized['NUCLEI_THREADS'] = 50
            else:
                # High RAM settings
                optimized['SUBFINDER_THREADS'] = 100
                optimized['AMASS_MAX_DNS'] = 20000
                optimized['NUCLEI_THREADS'] = 100
            
            return optimized
        except ImportError:
            # If psutil not available, return base settings
            return base_settings


class LearningEngine:
    """Main learning engine that coordinates all ML components"""
    
    def __init__(self):
        self.history = ExecutionHistory()
        self.recognizer = PatternRecognizer(self.history)
        self.optimizer = AdaptiveOptimizer(self.recognizer)
        self.feedback_file = Path("output/.ml_learning/user_feedback.jsonl")
        self.feedback_file.parent.mkdir(parents=True, exist_ok=True)
    
    def suggest_settings(self, 
                        command: str, 
                        target: str,
                        optimization_goal: str = "balanced") -> Dict[str, Any]:
        """
        Suggest optimal settings based on learning
        
        Args:
            command: Command to run (e.g., 'run_pipeline')
            target: Target domain
            optimization_goal: 'speed', 'accuracy', or 'balanced'
        """
        
        # Get historically optimal settings
        base_settings = self.recognizer.find_optimal_settings(command)
        
        # Apply optimization based on goal
        if optimization_goal == "speed":
            settings = self.optimizer.optimize_for_speed(base_settings)
        elif optimization_goal == "accuracy":
            settings = self.optimizer.optimize_for_accuracy(base_settings)
        else:
            settings = self.optimizer.optimize_for_resources(base_settings)
        
        return settings
    
    def predict_execution(self, command: str, target: str) -> Dict[str, Any]:
        """Predict execution outcome"""
        
        duration = self.recognizer.predict_duration(command, target, {})
        findings = self.recognizer.predict_findings_count(target)
        
        return {
            "estimated_duration_seconds": duration,
            "estimated_duration_human": f"{int(duration/60)} minutes",
            "predicted_findings": findings,
            "confidence": self._calculate_confidence(target)
        }
    
    def record_feedback(self, execution_id: str, feedback: str, rating: int):
        """Record user feedback on execution"""
        record = {
            "execution_id": execution_id,
            "timestamp": datetime.now().isoformat(),
            "feedback": feedback,
            "rating": rating  # 1-5 scale
        }
        
        with open(self.feedback_file, 'a') as f:
            f.write(json.dumps(record) + '\n')
    
    def _calculate_confidence(self, target: str) -> float:
        """Calculate confidence score based on historical data"""
        history = self.history.get_target_history(target)
        
        if not history:
            return 0.3  # Low confidence for new targets
        elif len(history) < 3:
            return 0.6  # Medium confidence
        else:
            return 0.9  # High confidence
    
    def get_learning_stats(self) -> Dict[str, Any]:
        """Get statistics about learning progress"""
        all_history = self.history.get_history()
        
        if not all_history:
            return {
                "total_executions": 0,
                "success_rate": 0.0,
                "avg_duration": 0.0,
                "targets_scanned": 0
            }
        
        successful = [h for h in all_history if h.get('success')]
        durations = [h.get('duration_seconds', 0) for h in successful]
        unique_targets = set(h.get('target') for h in all_history)
        
        return {
            "total_executions": len(all_history),
            "successful_executions": len(successful),
            "success_rate": len(successful) / len(all_history) if all_history else 0,
            "avg_duration_seconds": statistics.mean(durations) if durations else 0,
            "targets_scanned": len(unique_targets),
            "learning_active": True
        }


# CLI Interface
if __name__ == "__main__":
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="ML Learning Engine for Bug Bounty Automation")
    parser.add_argument('action', choices=['suggest', 'predict', 'stats', 'feedback'],
                       help='Action to perform')
    parser.add_argument('--command', help='Command to analyze')
    parser.add_argument('--target', help='Target domain')
    parser.add_argument('--goal', choices=['speed', 'accuracy', 'balanced'], 
                       default='balanced', help='Optimization goal')
    parser.add_argument('--execution-id', help='Execution ID for feedback')
    parser.add_argument('--rating', type=int, choices=[1,2,3,4,5], help='Rating (1-5)')
    parser.add_argument('--comment', help='Feedback comment')
    
    args = parser.parse_args()
    
    engine = LearningEngine()
    
    if args.action == 'suggest':
        if not args.command or not args.target:
            print("Error: --command and --target required for suggest")
            sys.exit(1)
        
        settings = engine.suggest_settings(args.command, args.target, args.goal)
        print(json.dumps(settings, indent=2))
    
    elif args.action == 'predict':
        if not args.command or not args.target:
            print("Error: --command and --target required for predict")
            sys.exit(1)
        
        prediction = engine.predict_execution(args.command, args.target)
        print(json.dumps(prediction, indent=2))
    
    elif args.action == 'stats':
        stats = engine.get_learning_stats()
        print(json.dumps(stats, indent=2))
    
    elif args.action == 'feedback':
        if not args.execution_id or not args.rating:
            print("Error: --execution-id and --rating required for feedback")
            sys.exit(1)
        
        engine.record_feedback(args.execution_id, args.comment or "", args.rating)
        print("Feedback recorded")
