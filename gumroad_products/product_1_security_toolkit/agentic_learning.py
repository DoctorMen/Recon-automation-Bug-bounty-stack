#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Advanced Learning Mechanisms for Agentic System
Machine learning-inspired optimization without external ML libraries
"""

import json
import math
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class ExperienceReplay:
    """Store and replay experiences for learning"""
    state: Dict[str, Any]
    action: str
    reward: float
    next_state: Dict[str, Any]
    timestamp: float


class QLearningTaskScheduler:
    """
    Q-Learning inspired task scheduler
    Learns optimal task ordering and resource allocation
    """
    
    def __init__(self, learning_rate: float = 0.1, discount_factor: float = 0.9):
        self.q_table: Dict[Tuple[str, str], float] = defaultdict(float)
        self.learning_rate = learning_rate
        self.discount_factor = discount_factor
        self.experience_buffer: List[ExperienceReplay] = []
        self.exploration_rate = 0.3  # Epsilon for epsilon-greedy
        
    def get_state_representation(self, task: Any, system_state: Dict) -> str:
        """Convert task and system state to hashable representation"""
        return f"{task.name}_{task.priority.name}_{system_state.get('queue_size', 0)}_{system_state.get('active_agents', 0)}"
    
    def select_action(self, state: str, available_actions: List[str]) -> str:
        """Select action using epsilon-greedy strategy"""
        import random
        
        # Exploration vs exploitation
        if random.random() < self.exploration_rate:
            # Explore: random action
            return random.choice(available_actions)
        else:
            # Exploit: best known action
            q_values = {action: self.q_table[(state, action)] for action in available_actions}
            return max(q_values, key=q_values.get)
    
    def update_q_value(self, state: str, action: str, reward: float, next_state: str, next_actions: List[str]):
        """Update Q-value using Q-learning algorithm"""
        current_q = self.q_table[(state, action)]
        
        # Get max Q-value for next state
        if next_actions:
            max_next_q = max(self.q_table[(next_state, a)] for a in next_actions)
        else:
            max_next_q = 0.0
        
        # Q-learning update rule
        new_q = current_q + self.learning_rate * (
            reward + self.discount_factor * max_next_q - current_q
        )
        
        self.q_table[(state, action)] = new_q
    
    def store_experience(self, experience: ExperienceReplay):
        """Store experience for replay learning"""
        self.experience_buffer.append(experience)
        
        # Keep buffer size manageable
        if len(self.experience_buffer) > 10000:
            self.experience_buffer.pop(0)
    
    def replay_and_learn(self, batch_size: int = 32):
        """Replay random experiences to improve learning"""
        import random
        
        if len(self.experience_buffer) < batch_size:
            return
        
        # Sample random batch
        batch = random.sample(self.experience_buffer, batch_size)
        
        for exp in batch:
            state_str = str(exp.state)
            next_state_str = str(exp.next_state)
            
            # Update Q-value from experience
            self.update_q_value(
                state_str,
                exp.action,
                exp.reward,
                next_state_str,
                []  # No next actions in replay
            )
    
    def decay_exploration(self, min_rate: float = 0.01):
        """Gradually reduce exploration rate"""
        self.exploration_rate = max(min_rate, self.exploration_rate * 0.995)


class BayesianTaskPrioritizer:
    """
    Bayesian-inspired prioritization using observed success rates
    """
    
    def __init__(self):
        # Prior beliefs (alpha, beta for Beta distribution)
        self.priors: Dict[str, Tuple[float, float]] = defaultdict(lambda: (1.0, 1.0))
        
    def update_belief(self, task_type: str, success: bool):
        """Update belief about task success probability"""
        alpha, beta = self.priors[task_type]
        
        if success:
            alpha += 1
        else:
            beta += 1
        
        self.priors[task_type] = (alpha, beta)
    
    def get_success_probability(self, task_type: str) -> float:
        """Get estimated success probability using Beta distribution mean"""
        alpha, beta = self.priors[task_type]
        return alpha / (alpha + beta)
    
    def get_confidence_interval(self, task_type: str, confidence: float = 0.95) -> Tuple[float, float]:
        """Get confidence interval for success probability"""
        alpha, beta = self.priors[task_type]
        
        # Simplified confidence interval (not exact, but good approximation)
        mean = alpha / (alpha + beta)
        variance = (alpha * beta) / ((alpha + beta) ** 2 * (alpha + beta + 1))
        std_dev = math.sqrt(variance)
        
        z_score = 1.96 if confidence == 0.95 else 2.576  # 95% or 99%
        
        lower = max(0, mean - z_score * std_dev)
        upper = min(1, mean + z_score * std_dev)
        
        return (lower, upper)
    
    def prioritize_tasks(self, tasks: List[Any]) -> List[Any]:
        """Prioritize tasks based on success probability and uncertainty"""
        
        scored_tasks = []
        for task in tasks:
            prob = self.get_success_probability(task.name)
            lower, upper = self.get_confidence_interval(task.name)
            
            # UCB (Upper Confidence Bound) score
            uncertainty = upper - lower
            ucb_score = prob + 0.5 * uncertainty  # Bonus for uncertain tasks
            
            scored_tasks.append((ucb_score, task))
        
        # Sort by score (highest first)
        scored_tasks.sort(reverse=True, key=lambda x: x[0])
        
        return [task for _, task in scored_tasks]


class PatternMiningEngine:
    """
    Mine patterns from execution history to predict optimal strategies
    """
    
    def __init__(self):
        self.patterns: Dict[str, Dict[str, Any]] = {}
        self.sequence_counts: Dict[Tuple[str, ...], int] = defaultdict(int)
        
    def mine_sequential_patterns(self, task_sequences: List[List[str]]):
        """Mine frequently occurring task sequences"""
        
        for sequence in task_sequences:
            # Mine patterns of different lengths
            for length in range(2, min(len(sequence) + 1, 6)):
                for i in range(len(sequence) - length + 1):
                    pattern = tuple(sequence[i:i+length])
                    self.sequence_counts[pattern] += 1
        
        # Identify frequent patterns (appear > 3 times)
        frequent_patterns = {
            pattern: count
            for pattern, count in self.sequence_counts.items()
            if count >= 3
        }
        
        return frequent_patterns
    
    def find_optimal_next_task(self, current_sequence: List[str]) -> Optional[str]:
        """Predict optimal next task based on patterns"""
        
        # Look for patterns that match current sequence
        best_match = None
        best_count = 0
        
        for pattern, count in self.sequence_counts.items():
            # Check if pattern starts with our sequence
            if len(pattern) > len(current_sequence):
                pattern_start = pattern[:len(current_sequence)]
                if pattern_start == tuple(current_sequence):
                    if count > best_count:
                        best_count = count
                        best_match = pattern[len(current_sequence)]
        
        return best_match
    
    def extract_conditional_rules(self) -> List[Dict[str, Any]]:
        """Extract if-then rules from patterns"""
        rules = []
        
        for pattern, count in self.sequence_counts.items():
            if len(pattern) >= 2 and count >= 5:
                rule = {
                    'condition': list(pattern[:-1]),
                    'action': pattern[-1],
                    'confidence': count / sum(
                        c for p, c in self.sequence_counts.items()
                        if p[:-1] == pattern[:-1]
                    ),
                    'support': count
                }
                rules.append(rule)
        
        # Sort by confidence
        rules.sort(key=lambda r: r['confidence'], reverse=True)
        
        return rules


class AdaptiveLearningRate:
    """
    Adaptive learning rate that adjusts based on performance
    """
    
    def __init__(self, initial_rate: float = 0.1):
        self.rate = initial_rate
        self.performance_history: List[float] = []
        self.rate_history: List[float] = []
        
    def update(self, performance: float):
        """Update learning rate based on recent performance"""
        self.performance_history.append(performance)
        
        if len(self.performance_history) >= 10:
            # Look at trend over last 10 iterations
            recent = self.performance_history[-10:]
            
            # If improving, keep or slightly decrease rate
            if recent[-1] > recent[0]:
                self.rate *= 0.99
            # If degrading, increase rate to escape local optimum
            else:
                self.rate *= 1.01
            
            # Clamp between bounds
            self.rate = max(0.001, min(0.5, self.rate))
        
        self.rate_history.append(self.rate)
        
        return self.rate


class MetaLearner:
    """
    Meta-learning system that learns how to learn
    Adjusts learning strategies based on domain
    """
    
    def __init__(self):
        self.domain_strategies: Dict[str, Dict[str, Any]] = {}
        self.performance_by_strategy: Dict[str, List[float]] = defaultdict(list)
        
    def register_domain(self, domain_name: str, characteristics: Dict[str, Any]):
        """Register a new domain with its characteristics"""
        self.domain_strategies[domain_name] = {
            'characteristics': characteristics,
            'optimal_strategy': None,
            'strategies_tried': []
        }
    
    def recommend_strategy(self, domain_name: str) -> Dict[str, Any]:
        """Recommend learning strategy for domain"""
        
        if domain_name not in self.domain_strategies:
            return self._default_strategy()
        
        domain = self.domain_strategies[domain_name]
        
        # If we have optimal strategy, use it
        if domain['optimal_strategy']:
            return domain['optimal_strategy']
        
        # Otherwise, recommend based on characteristics
        chars = domain['characteristics']
        
        if chars.get('task_variance', 'low') == 'high':
            # High variance: use more exploration
            return {
                'learning_rate': 0.2,
                'exploration_rate': 0.4,
                'batch_size': 16
            }
        else:
            # Low variance: exploit more
            return {
                'learning_rate': 0.1,
                'exploration_rate': 0.1,
                'batch_size': 32
            }
    
    def _default_strategy(self) -> Dict[str, Any]:
        """Default learning strategy"""
        return {
            'learning_rate': 0.1,
            'exploration_rate': 0.3,
            'batch_size': 32
        }
    
    def update_strategy_performance(self, domain_name: str, strategy_name: str, performance: float):
        """Update performance metrics for strategy"""
        key = f"{domain_name}_{strategy_name}"
        self.performance_by_strategy[key].append(performance)
        
        # Update optimal strategy if this one is best
        if len(self.performance_by_strategy[key]) >= 5:
            avg_perf = sum(self.performance_by_strategy[key][-5:]) / 5
            
            if domain_name in self.domain_strategies:
                domain = self.domain_strategies[domain_name]
                if not domain['optimal_strategy'] or avg_perf > domain.get('best_performance', 0):
                    domain['optimal_strategy'] = strategy_name
                    domain['best_performance'] = avg_perf


class KnowledgeDistillation:
    """
    Distill learned knowledge into simple, fast rules
    """
    
    def __init__(self):
        self.complex_model: Optional[Any] = None
        self.distilled_rules: List[Dict[str, Any]] = []
        
    def distill_from_q_table(self, q_table: Dict[Tuple[str, str], float]) -> List[Dict[str, Any]]:
        """Distill Q-table into simple if-then rules"""
        
        # Group by state
        state_actions: Dict[str, List[Tuple[str, float]]] = defaultdict(list)
        
        for (state, action), q_value in q_table.items():
            state_actions[state].append((action, q_value))
        
        # Extract best action for each state
        rules = []
        for state, actions in state_actions.items():
            best_action = max(actions, key=lambda x: x[1])
            
            rule = {
                'condition': state,
                'action': best_action[0],
                'confidence': best_action[1],
                'type': 'distilled_q_learning'
            }
            rules.append(rule)
        
        self.distilled_rules = rules
        return rules
    
    def export_rules(self, filepath: str):
        """Export distilled rules to file"""
        with open(filepath, 'w') as f:
            json.dump(self.distilled_rules, f, indent=2)
    
    def fast_predict(self, state: str) -> Optional[str]:
        """Fast prediction using distilled rules"""
        for rule in self.distilled_rules:
            if rule['condition'] == state:
                return rule['action']
        return None


class ContinuousLearningSystem:
    """
    Unified continuous learning system combining all approaches
    """
    
    def __init__(self):
        self.q_learner = QLearningTaskScheduler()
        self.bayesian_prioritizer = BayesianTaskPrioritizer()
        self.pattern_miner = PatternMiningEngine()
        self.adaptive_lr = AdaptiveLearningRate()
        self.meta_learner = MetaLearner()
        self.distiller = KnowledgeDistillation()
        
        self.learning_stats = {
            'iterations': 0,
            'total_reward': 0.0,
            'average_performance': 0.0
        }
    
    def learn_from_execution(
        self,
        state: Dict[str, Any],
        action: str,
        reward: float,
        next_state: Dict[str, Any],
        task_type: str,
        success: bool
    ):
        """Learn from single execution"""
        
        # Q-Learning update
        state_repr = self.q_learner.get_state_representation(None, state)
        next_state_repr = self.q_learner.get_state_representation(None, next_state)
        self.q_learner.update_q_value(state_repr, action, reward, next_state_repr, [])
        
        # Bayesian update
        self.bayesian_prioritizer.update_belief(task_type, success)
        
        # Update stats
        self.learning_stats['iterations'] += 1
        self.learning_stats['total_reward'] += reward
        
        # Adaptive learning rate
        performance = reward
        new_lr = self.adaptive_lr.update(performance)
        self.q_learner.learning_rate = new_lr
        
        # Periodic actions
        if self.learning_stats['iterations'] % 100 == 0:
            self._periodic_learning()
    
    def _periodic_learning(self):
        """Perform periodic learning tasks"""
        
        # Experience replay
        self.q_learner.replay_and_learn(batch_size=32)
        
        # Decay exploration
        self.q_learner.decay_exploration()
        
        # Distill knowledge
        self.distiller.distill_from_q_table(self.q_learner.q_table)
        
        logger.info(f"Learning checkpoint: {self.learning_stats}")
    
    def save_state(self, filepath: str):
        """Save learning state"""
        state = {
            'q_table': {f"{k[0]}_{k[1]}": v for k, v in self.q_learner.q_table.items()},
            'bayesian_priors': dict(self.bayesian_prioritizer.priors),
            'patterns': dict(self.pattern_miner.sequence_counts),
            'stats': self.learning_stats
        }
        
        with open(filepath, 'w') as f:
            json.dump(state, f, indent=2)
    
    def load_state(self, filepath: str):
        """Load learning state"""
        try:
            with open(filepath, 'r') as f:
                state = json.load(f)
            
            # Restore Q-table
            for key, value in state.get('q_table', {}).items():
                state_action = tuple(key.split('_', 1))
                self.q_learner.q_table[state_action] = value
            
            # Restore Bayesian priors
            for task_type, prior in state.get('bayesian_priors', {}).items():
                self.bayesian_prioritizer.priors[task_type] = tuple(prior)
            
            # Restore stats
            self.learning_stats = state.get('stats', self.learning_stats)
            
            logger.info("Learning state loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load learning state: {e}")


# Example usage
if __name__ == "__main__":
    # Initialize learning system
    learner = ContinuousLearningSystem()
    
    # Simulate learning from executions
    for i in range(100):
        state = {'queue_size': i % 10, 'active_agents': 3}
        action = f"action_{i % 5}"
        reward = 1.0 if i % 2 == 0 else 0.5
        next_state = {'queue_size': (i + 1) % 10, 'active_agents': 3}
        
        learner.learn_from_execution(
            state, action, reward, next_state,
            task_type=f"task_type_{i % 3}",
            success=i % 2 == 0
        )
    
    # Save learned knowledge
    learner.save_state("learning_state.json")
    
    # Export distilled rules
    learner.distiller.export_rules("distilled_rules.json")
    
    print("Learning complete. State saved.")
