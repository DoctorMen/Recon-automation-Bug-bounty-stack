#!/usr/bin/env python3
"""
Reinforcement Learning Automation System
Automatically applies learning from all vulnerability assessments to improve future performance
"""

import json
import time
import numpy as np
import pickle
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import logging
from collections import defaultdict, deque
import hashlib

# ML/RL libraries
try:
    import sklearn
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, classification_report
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("Warning: sklearn not available. Using simplified learning algorithms.")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ReinforcementLearningAutomation:
    """
    Reinforcement Learning system that automatically learns from vulnerability assessments
    and applies insights to improve future testing performance and accuracy
    """
    
    def __init__(self, learning_data_dir: str = "reinforcement_learning_data"):
        self.learning_data_dir = Path(learning_data_dir)
        self.learning_data_dir.mkdir(exist_ok=True)
        
        # Learning components
        self.vulnerability_patterns = defaultdict(list)
        self.success_patterns = defaultdict(list)
        self.failure_patterns = defaultdict(list)
        self.target_profiles = defaultdict(dict)
        self.technique_effectiveness = defaultdict(float)
        self.platform_optimization = defaultdict(dict)
        
        # ML models (if sklearn available)
        self.vulnerability_predictor = None
        self.success_predictor = None
        self.technique_selector = None
        self.vectorizer = None
        
        # Learning metrics
        self.learning_sessions = 0
        self.total_assessments = 0
        self.successful_predictions = 0
        self.accuracy_history = deque(maxlen=100)
        
        # Load existing learning data
        self._load_learning_data()
        
        logger.info(f"Reinforcement Learning Automation initialized")
        logger.info(f"Learning data directory: {self.learning_data_dir}")
        logger.info(f"Previous learning sessions: {self.learning_sessions}")
        logger.info(f"Sklearn available: {SKLEARN_AVAILABLE}")
    
    def learn_from_assessment(self, assessment_results: Dict, assessment_type: str = "comprehensive") -> Dict:
        """
        Learn from assessment results and update all learning models
        
        Args:
            assessment_results: Complete assessment results dictionary
            assessment_type: Type of assessment (validation, pentest, exploitation, comprehensive)
        
        Returns:
            Learning summary with insights and improvements
        """
        
        logger.info(f"Learning from {assessment_type} assessment...")
        
        learning_session = {
            'session_id': f"RL-{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'assessment_type': assessment_type,
            'target': assessment_results.get('target', 'unknown'),
            'timestamp': datetime.now().isoformat(),
            'learned_patterns': [],
            'updated_models': [],
            'accuracy_improvements': {},
            'recommendations': []
        }
        
        # Extract learning data from assessment
        learning_data = self._extract_learning_data(assessment_results)
        
        # Update vulnerability patterns
        vuln_patterns = self._learn_vulnerability_patterns(learning_data)
        learning_session['learned_patterns'].extend(vuln_patterns)
        
        # Update success/failure patterns
        success_patterns = self._learn_success_patterns(learning_data)
        learning_session['learned_patterns'].extend(success_patterns)
        
        # Update target profiles
        target_profile = self._update_target_profile(learning_data)
        learning_session['updated_models'].append('target_profiles')
        
        # Update technique effectiveness
        technique_updates = self._update_technique_effectiveness(learning_data)
        learning_session['updated_models'].append('technique_effectiveness')
        
        # Update platform optimization
        platform_updates = self._update_platform_optimization(learning_data)
        learning_session['updated_models'].append('platform_optimization')
        
        # Train ML models if data available
        if SKLEARN_AVAILABLE and len(self.vulnerability_patterns) > 10:
            model_updates = self._train_ml_models()
            learning_session['updated_models'].extend(model_updates)
        
        # Generate recommendations
        recommendations = self._generate_learning_recommendations(learning_data)
        learning_session['recommendations'] = recommendations
        
        # Calculate accuracy improvements
        accuracy_improvements = self._calculate_accuracy_improvements()
        learning_session['accuracy_improvements'] = accuracy_improvements
        
        # Save learning session
        self._save_learning_session(learning_session)
        
        # Update metrics
        self.learning_sessions += 1
        self.total_assessments += 1
        
        logger.info(f"Learning session completed: {len(learning_session['learned_patterns'])} patterns learned")
        logger.info(f"Models updated: {learning_session['updated_models']}")
        
        return learning_session
    
    def _extract_learning_data(self, assessment_results: Dict) -> Dict:
        """Extract structured learning data from assessment results"""
        
        learning_data = {
            'target': assessment_results.get('target', ''),
            'assessment_type': assessment_results.get('metadata', {}).get('methodology', 'unknown'),
            'timestamp': assessment_results.get('generated_at', datetime.now().isoformat()),
            'vulnerabilities': [],
            'techniques_used': [],
            'success_metrics': {},
            'platform_performance': {},
            'target_characteristics': {}
        }
        
        # Extract vulnerabilities
        if 'technical_findings' in assessment_results:
            for category, findings in assessment_results['technical_findings'].items():
                if 'vulnerabilities' in findings:
                    for vuln in findings['vulnerabilities']:
                        learning_data['vulnerabilities'].append({
                            'type': vuln.get('type', ''),
                            'severity': vuln.get('severity', ''),
                            'cwe': vuln.get('cwe', ''),
                            'category': category,
                            'technique': vuln.get('exploitation_technique', ''),
                            'success': vuln.get('validation_status') == 'vulnerable'
                        })
        
        # Extract techniques used
        if 'exploitation_analysis' in assessment_results:
            exploitation = assessment_results['exploitation_analysis']
            learning_data['techniques_used'] = exploitation.get('attack_vectors', [])
            
            # Extract countermeasures and bypasses
            learning_data['countermeasures'] = exploitation.get('countermeasures', [])
            learning_data['bypass_techniques'] = exploitation.get('bypass_techniques', [])
        
        # Extract success metrics
        if 'executive_summary' in assessment_results:
            summary = assessment_results['executive_summary']
            learning_data['success_metrics'] = {
                'total_vulnerabilities': summary.get('total_vulnerabilities', 0),
                'critical_findings': len(summary.get('critical_findings', [])),
                'exploitation_potential': summary.get('exploitation_potential', 'low')
            }
        
        # Extract platform performance
        if 'professional_disclosure' in assessment_results:
            disclosure = assessment_results['professional_disclosure']
            for platform, reports in disclosure.items():
                if isinstance(reports, dict) and 'platform_reports' in reports:
                    platform_reports = reports['platform_reports']
                    learning_data['platform_performance'][platform] = {
                        'reports_generated': len(platform_reports),
                        'success_rate': self._calculate_platform_success_rate(platform_reports)
                    }
        
        # Extract target characteristics
        learning_data['target_characteristics'] = self._analyze_target_characteristics(learning_data['target'])
        
        return learning_data
    
    def _learn_vulnerability_patterns(self, learning_data: Dict) -> List[Dict]:
        """Learn patterns from discovered vulnerabilities"""
        
        patterns = []
        
        for vuln in learning_data['vulnerabilities']:
            # Create pattern signature
            pattern_signature = self._create_vulnerability_signature(vuln)
            
            # Update vulnerability patterns
            self.vulnerability_patterns[pattern_signature].append({
                'timestamp': learning_data['timestamp'],
                'target': learning_data['target'],
                'target_type': learning_data['target_characteristics'].get('type', 'unknown'),
                'success': vuln['success'],
                'severity': vuln['severity'],
                'technique': vuln['technique']
            })
            
            patterns.append({
                'type': 'vulnerability_pattern',
                'signature': pattern_signature,
                'success_rate': self._calculate_pattern_success_rate(pattern_signature),
                'recommendation': f"Focus on {vuln['type']} testing for similar targets"
            })
        
        return patterns
    
    def _create_vulnerability_signature(self, vuln: Dict) -> str:
        """Create unique signature for vulnerability pattern"""
        
        signature_components = [
            vuln.get('type', ''),
            vuln.get('severity', ''),
            vuln.get('category', ''),
            vuln.get('cwe', ''),
            vuln.get('technique', '')
        ]
        
        signature = '|'.join(filter(None, signature_components))
        return hashlib.md5(signature.encode()).hexdigest()[:16]
    
    def _calculate_pattern_success_rate(self, pattern_signature: str) -> float:
        """Calculate success rate for a vulnerability pattern"""
        
        pattern_data = self.vulnerability_patterns.get(pattern_signature, [])
        if not pattern_data:
            return 0.0
        
        successful = sum(1 for p in pattern_data if p.get('success', False))
        return successful / len(pattern_data)
    
    def _learn_success_patterns(self, learning_data: Dict) -> List[Dict]:
        """Learn patterns from successful assessments"""
        
        patterns = []
        
        # Analyze successful techniques
        successful_techniques = [
            vuln['technique'] for vuln in learning_data['vulnerabilities']
            if vuln.get('success', False) and vuln.get('technique')
        ]
        
        for technique in successful_techniques:
            self.success_patterns[technique].append({
                'timestamp': learning_data['timestamp'],
                'target': learning_data['target'],
                'target_type': learning_data['target_characteristics'].get('type', 'unknown'),
                'vulnerability_type': next(
                    (v['type'] for v in learning_data['vulnerabilities'] 
                     if v.get('technique') == technique), 'unknown'
                )
            })
            
            patterns.append({
                'type': 'success_pattern',
                'technique': technique,
                'success_count': len(self.success_patterns[technique]),
                'recommendation': f"Prioritize {technique} for similar targets"
            })
        
        # Analyze failure patterns
        failed_techniques = [
            vuln['technique'] for vuln in learning_data['vulnerabilities']
            if not vuln.get('success', False) and vuln.get('technique')
        ]
        
        for technique in failed_techniques:
            self.failure_patterns[technique].append({
                'timestamp': learning_data['timestamp'],
                'target': learning_data['target'],
                'target_type': learning_data['target_characteristics'].get('type', 'unknown'),
                'reason': 'no_vulnerability_found'
            })
        
        return patterns
    
    def _update_target_profile(self, learning_data: Dict) -> Dict:
        """Update target profile based on assessment results"""
        
        target = learning_data['target']
        target_type = learning_data['target_characteristics'].get('type', 'unknown')
        
        if target not in self.target_profiles:
            self.target_profiles[target] = {
                'first_seen': learning_data['timestamp'],
                'assessments': 0,
                'vulnerabilities_found': [],
                'successful_techniques': [],
                'failed_techniques': [],
                'characteristics': learning_data['target_characteristics']
            }
        
        profile = self.target_profiles[target]
        profile['last_seen'] = learning_data['timestamp']
        profile['assessments'] += 1
        
        # Update vulnerabilities found
        for vuln in learning_data['vulnerabilities']:
            if vuln.get('success', False):
                profile['vulnerabilities_found'].append({
                    'type': vuln['type'],
                    'severity': vuln['severity'],
                    'timestamp': learning_data['timestamp']
                })
        
        # Update successful techniques
        successful_techniques = list(set([
            vuln['technique'] for vuln in learning_data['vulnerabilities']
            if vuln.get('success', False) and vuln.get('technique')
        ]))
        profile['successful_techniques'].extend(successful_techniques)
        
        # Update failed techniques
        failed_techniques = list(set([
            vuln['technique'] for vuln in learning_data['vulnerabilities']
            if not vuln.get('success', False) and vuln.get('technique')
        ]))
        profile['failed_techniques'].extend(failed_techniques)
        
        return profile
    
    def _update_technique_effectiveness(self, learning_data: Dict) -> Dict:
        """Update technique effectiveness scores"""
        
        updates = {}
        
        for vuln in learning_data['vulnerabilities']:
            technique = vuln.get('technique')
            if not technique:
                continue
            
            current_effectiveness = self.technique_effectiveness.get(technique, 0.5)
            success = vuln.get('success', False)
            
            # Update using exponential moving average
            alpha = 0.1  # Learning rate
            new_effectiveness = alpha * (1.0 if success else 0.0) + (1 - alpha) * current_effectiveness
            self.technique_effectiveness[technique] = new_effectiveness
            
            updates[technique] = {
                'old_effectiveness': current_effectiveness,
                'new_effectiveness': new_effectiveness,
                'improvement': new_effectiveness - current_effectiveness
            }
        
        return updates
    
    def _update_platform_optimization(self, learning_data: Dict) -> Dict:
        """Update platform-specific optimization strategies"""
        
        updates = {}
        
        for platform, performance in learning_data['platform_performance'].items():
            if platform not in self.platform_optimization:
                self.platform_optimization[platform] = {
                    'total_assessments': 0,
                    'total_reports': 0,
                    'average_success_rate': 0.0,
                    'best_techniques': [],
                    'target_types': defaultdict(int)
                }
            
            platform_data = self.platform_optimization[platform]
            platform_data['total_assessments'] += 1
            platform_data['total_reports'] += performance['reports_generated']
            
            # Update average success rate
            current_avg = platform_data['average_success_rate']
            new_rate = performance['success_rate']
            alpha = 0.1
            platform_data['average_success_rate'] = alpha * new_rate + (1 - alpha) * current_avg
            
            # Update target type distribution
            target_type = learning_data['target_characteristics'].get('type', 'unknown')
            platform_data['target_types'][target_type] += 1
            
            updates[platform] = {
                'assessments': platform_data['total_assessments'],
                'success_rate': platform_data['average_success_rate'],
                'target_types': dict(platform_data['target_types'])
            }
        
        return updates
    
    def _train_ml_models(self) -> List[str]:
        """Train machine learning models for prediction"""
        
        updated_models = []
        
        if not SKLEARN_AVAILABLE:
            return updated_models
        
        try:
            # Prepare training data
            X_train, y_train = self._prepare_training_data()
            
            if len(X_train) < 10:  # Need minimum data for training
                return updated_models
            
            # Train vulnerability predictor
            self.vulnerability_predictor = RandomForestClassifier(n_estimators=100, random_state=42)
            self.vulnerability_predictor.fit(X_train, y_train)
            updated_models.append('vulnerability_predictor')
            
            # Train success predictor
            success_X, success_y = self._prepare_success_training_data()
            if len(success_X) >= 10:
                self.success_predictor = GradientBoostingClassifier(n_estimators=100, random_state=42)
                self.success_predictor.fit(success_X, success_y)
                updated_models.append('success_predictor')
            
            # Train technique selector
            technique_X, technique_y = self._prepare_technique_training_data()
            if len(technique_X) >= 10:
                self.technique_selector = RandomForestClassifier(n_estimators=100, random_state=42)
                self.technique_selector.fit(technique_X, technique_y)
                updated_models.append('technique_selector')
            
        except Exception as e:
            logger.error(f"Error training ML models: {e}")
        
        return updated_models
    
    def _prepare_training_data(self) -> Tuple[List, List]:
        """Prepare training data for vulnerability prediction"""
        
        X = []
        y = []
        
        for pattern_signature, pattern_data in self.vulnerability_patterns.items():
            for instance in pattern_data:
                # Features
                features = [
                    len(instance.get('target', '')),
                    hash(instance.get('target_type', '')) % 1000,
                    hash(instance.get('technique', '')) % 1000,
                    1 if instance.get('success', False) else 0,
                    hash(instance.get('severity', '')) % 100
                ]
                
                X.append(features)
                y.append(1 if instance.get('success', False) else 0)
        
        return X, y
    
    def _prepare_success_training_data(self) -> Tuple[List, List]:
        """Prepare training data for success prediction"""
        
        X = []
        y = []
        
        for technique, technique_data in self.success_patterns.items():
            for instance in technique_data:
                features = [
                    len(instance.get('target', '')),
                    hash(instance.get('target_type', '')) % 1000,
                    hash(technique) % 1000,
                    len(technique_data)  # Technique popularity
                ]
                
                X.append(features)
                y.append(1)  # Success
        
        for technique, technique_data in self.failure_patterns.items():
            for instance in technique_data:
                features = [
                    len(instance.get('target', '')),
                    hash(instance.get('target_type', '')) % 1000,
                    hash(technique) % 1000,
                    len(self.success_patterns.get(technique, []))  # Success count
                ]
                
                X.append(features)
                y.append(0)  # Failure
        
        return X, y
    
    def _prepare_technique_training_data(self) -> Tuple[List, List]:
        """Prepare training data for technique selection"""
        
        X = []
        y = []
        
        for target, profile in self.target_profiles.items():
            if not profile['vulnerabilities_found']:
                continue
            
            target_features = [
                len(target),
                hash(profile['characteristics'].get('type', 'unknown')) % 1000,
                profile['assessments'],
                len(profile['vulnerabilities_found'])
            ]
            
            for technique in profile['successful_techniques']:
                X.append(target_features + [hash(technique) % 1000])
                y.append(technique)
        
        return X, y
    
    def _generate_learning_recommendations(self, learning_data: Dict) -> List[Dict]:
        """Generate recommendations based on learning insights"""
        
        recommendations = []
        
        # Technique recommendations
        top_techniques = sorted(
            self.technique_effectiveness.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        recommendations.append({
            'type': 'technique_prioritization',
            'priority': 'high',
            'recommendation': f"Focus on top techniques: {', '.join([t[0] for t in top_techniques[:3]])}",
            'reasoning': 'These techniques have highest success rates based on historical data'
        })
        
        # Target-specific recommendations
        target_type = learning_data['target_characteristics'].get('type', 'unknown')
        similar_targets = [
            t for t, p in self.target_profiles.items()
            if p['characteristics'].get('type') == target_type and t != learning_data['target']
        ]
        
        if similar_targets:
            # Aggregate successful techniques from similar targets
            similar_techniques = []
            for target in similar_targets[:10]:  # Limit to 10 most similar
                similar_techniques.extend(self.target_profiles[target]['successful_techniques'])
            
            if similar_techniques:
                most_common = max(set(similar_techniques), key=similar_techniques.count)
                recommendations.append({
                    'type': 'target_specific',
                    'priority': 'medium',
                    'recommendation': f"Try {most_common} technique for this target type",
                    'reasoning': f'Successful in {similar_techniques.count(most_common)} similar targets'
                })
        
        # Platform optimization recommendations
        best_platform = max(
            self.platform_optimization.items(),
            key=lambda x: x[1]['average_success_rate'],
            default=(None, {'average_success_rate': 0})
        )
        
        if best_platform[0] and best_platform[1]['average_success_rate'] > 0.7:
            recommendations.append({
                'type': 'platform_optimization',
                'priority': 'medium',
                'recommendation': f"Prioritize {best_platform[0]} for submissions",
                'reasoning': f"Highest success rate: {best_platform[1]['average_success_rate']:.1%}"
            })
        
        # Improvement recommendations
        if learning_data['success_metrics']['total_vulnerabilities'] == 0:
            recommendations.append({
                'type': 'improvement',
                'priority': 'high',
                'recommendation': 'Consider alternative testing approaches',
                'reasoning': 'No vulnerabilities found in current assessment'
            })
        
        return recommendations
    
    def _calculate_accuracy_improvements(self) -> Dict:
        """Calculate accuracy improvements over time"""
        
        improvements = {}
        
        if len(self.accuracy_history) > 1:
            recent_accuracy = list(self.accuracy_history)[-10:]
            if len(recent_accuracy) >= 2:
                old_avg = sum(recent_accuracy[:5]) / len(recent_accuracy[:5])
                new_avg = sum(recent_accuracy[5:]) / len(recent_accuracy[5:])
                improvements['prediction_accuracy'] = {
                    'previous_average': old_avg,
                    'current_average': new_avg,
                    'improvement': new_avg - old_avg
                }
        
        return improvements
    
    def predict_vulnerabilities(self, target: str, target_characteristics: Dict = None) -> Dict:
        """
        Predict likely vulnerabilities for a target based on learned patterns
        
        Args:
            target: Target URL or domain
            target_characteristics: Optional target characteristics
        
        Returns:
            Prediction results with confidence scores
        """
        
        logger.info(f"Predicting vulnerabilities for: {target}")
        
        if target_characteristics is None:
            target_characteristics = self._analyze_target_characteristics(target)
        
        predictions = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'predictions': [],
            'confidence_scores': {},
            'recommended_techniques': [],
            'success_probability': 0.0
        }
        
        # Find similar targets
        similar_targets = self._find_similar_targets(target, target_characteristics)
        
        # Aggregate vulnerabilities from similar targets
        vulnerability_predictions = defaultdict(float)
        technique_predictions = defaultdict(float)
        
        for similar_target, similarity_score in similar_targets[:10]:  # Top 10 similar
            profile = self.target_profiles.get(similar_target, {})
            
            # Predict vulnerabilities
            for vuln in profile['vulnerabilities_found']:
                vulnerability_predictions[vuln['type']] += similarity_score * 0.1
            
            # Predict techniques
            for technique in profile['successful_techniques']:
                technique_predictions[technique] += similarity_score * 0.1
        
        # Add ML predictions if available
        if SKLEARN_AVAILABLE and self.vulnerability_predictor:
            ml_predictions = self._ml_predict_vulnerabilities(target, target_characteristics)
            for vuln_type, confidence in ml_predictions.items():
                vulnerability_predictions[vuln_type] += confidence * 0.3
        
        # Normalize predictions
        total_vuln_score = sum(vulnerability_predictions.values())
        if total_vuln_score > 0:
            for vuln_type in vulnerability_predictions:
                vulnerability_predictions[vuln_type] /= total_vuln_score
        
        total_tech_score = sum(technique_predictions.values())
        if total_tech_score > 0:
            for technique in technique_predictions:
                technique_predictions[technique] /= total_tech_score
        
        # Format predictions
        predictions['predictions'] = [
            {
                'vulnerability_type': vuln_type,
                'probability': score,
                'confidence': min(score * 2, 1.0)  # Boost confidence
            }
            for vuln_type, score in sorted(vulnerability_predictions.items(), key=lambda x: x[1], reverse=True)
            if score > 0.1
        ]
        
        predictions['recommended_techniques'] = [
            {
                'technique': technique,
                'probability': score,
                'confidence': min(score * 2, 1.0)
            }
            for technique, score in sorted(technique_predictions.items(), key=lambda x: x[1], reverse=True)
            if score > 0.1
        ]
        
        # Calculate overall success probability
        if predictions['predictions']:
            predictions['success_probability'] = max(p['probability'] for p in predictions['predictions'])
        
        return predictions
    
    def _find_similar_targets(self, target: str, characteristics: Dict) -> List[Tuple[str, float]]:
        """Find targets similar to the given target"""
        
        similar_targets = []
        
        for existing_target, profile in self.target_profiles.items():
            similarity_score = self._calculate_target_similarity(target, characteristics, existing_target, profile['characteristics'])
            
            if similarity_score > 0.1:  # Minimum similarity threshold
                similar_targets.append((existing_target, similarity_score))
        
        return sorted(similar_targets, key=lambda x: x[1], reverse=True)
    
    def _calculate_target_similarity(self, target1: str, char1: Dict, target2: str, char2: Dict) -> float:
        """Calculate similarity between two targets"""
        
        similarity = 0.0
        
        # Domain similarity
        domain1 = target1.replace('https://', '').replace('http://', '').split('/')[0]
        domain2 = target2.replace('https://', '').replace('http://', '').split('/')[0]
        
        if domain1 == domain2:
            similarity += 0.8
        elif domain1.split('.')[-2:] == domain2.split('.')[-2:]:  # Same TLD and SLD
            similarity += 0.4
        
        # Target type similarity
        type1 = char1.get('type', 'unknown')
        type2 = char2.get('type', 'unknown')
        
        if type1 == type2:
            similarity += 0.2
        
        return similarity
    
    def _analyze_target_characteristics(self, target: str) -> Dict:
        """Analyze target characteristics for learning"""
        
        characteristics = {
            'type': 'unknown',
            'domain': '',
            'subdomain_count': 0,
            'uses_https': target.startswith('https://'),
            'port': 443 if target.startswith('https://') else 80
        }
        
        # Extract domain
        domain = target.replace('https://', '').replace('http://', '').split('/')[0]
        characteristics['domain'] = domain
        
        # Count subdomains
        parts = domain.split('.')
        if len(parts) > 2:
            characteristics['subdomain_count'] = len(parts) - 2
        
        # Classify target type
        if 'api' in domain.lower():
            characteristics['type'] = 'api'
        elif 'admin' in domain.lower() or 'console' in domain.lower():
            characteristics['type'] = 'admin'
        elif 'shop' in domain.lower() or 'store' in domain.lower():
            characteristics['type'] = 'ecommerce'
        elif 'blog' in domain.lower():
            characteristics['type'] = 'blog'
        else:
            characteristics['type'] = 'website'
        
        return characteristics
    
    def _ml_predict_vulnerabilities(self, target: str, characteristics: Dict) -> Dict:
        """Use ML models to predict vulnerabilities"""
        
        if not SKLEARN_AVAILABLE or not self.vulnerability_predictor:
            return {}
        
        try:
            # Create features for prediction
            features = [
                len(target),
                hash(characteristics.get('type', 'unknown')) % 1000,
                characteristics.get('subdomain_count', 0),
                1 if characteristics.get('uses_https', False) else 0,
                characteristics.get('port', 80)
            ]
            
            # Predict
            prediction = self.vulnerability_predictor.predict_proba([features])[0]
            
            # Map to vulnerability types (simplified)
            vulnerability_types = ['xss', 'sql_injection', 'csrf', 'buffer_overflow', 'format_string']
            
            if len(prediction) == len(vulnerability_types):
                return dict(zip(vulnerability_types, prediction))
        
        except Exception as e:
            logger.error(f"ML prediction error: {e}")
        
        return {}
    
    def optimize_assessment_strategy(self, target: str, assessment_type: str = "comprehensive") -> Dict:
        """
        Optimize assessment strategy based on learned patterns
        
        Args:
            target: Target URL or domain
            assessment_type: Type of assessment to optimize
        
        Returns:
            Optimized assessment strategy with prioritized techniques
        """
        
        logger.info(f"Optimizing {assessment_type} assessment strategy for: {target}")
        
        # Get predictions
        predictions = self.predict_vulnerabilities(target)
        
        # Get target characteristics
        characteristics = self._analyze_target_characteristics(target)
        
        # Base strategy
        strategy = {
            'target': target,
            'assessment_type': assessment_type,
            'timestamp': datetime.now().isoformat(),
            'predicted_vulnerabilities': predictions['predictions'],
            'recommended_techniques': predictions['recommended_techniques'],
            'success_probability': predictions['success_probability'],
            'optimization_score': 0.0,
            'prioritized_phases': [],
            'resource_allocation': {},
            'expected_duration': 'standard',
            'confidence_level': 'medium'
        }
        
        # Optimize based on assessment type
        if assessment_type == "validation":
            strategy = self._optimize_validation_strategy(strategy, predictions)
        elif assessment_type == "pentest":
            strategy = self._optimize_pentest_strategy(strategy, predictions)
        elif assessment_type == "exploitation":
            strategy = self._optimize_exploitation_strategy(strategy, predictions)
        elif assessment_type == "comprehensive":
            strategy = self._optimize_comprehensive_strategy(strategy, predictions)
        
        # Calculate optimization score
        strategy['optimization_score'] = self._calculate_optimization_score(strategy)
        
        # Set confidence level
        if strategy['optimization_score'] > 0.8:
            strategy['confidence_level'] = 'high'
        elif strategy['optimization_score'] > 0.6:
            strategy['confidence_level'] = 'medium'
        else:
            strategy['confidence_level'] = 'low'
        
        return strategy
    
    def _optimize_validation_strategy(self, strategy: Dict, predictions: Dict) -> Dict:
        """Optimize validation assessment strategy"""
        
        # Prioritize validation techniques
        prioritized_techniques = []
        
        for pred in predictions['predictions'][:5]:  # Top 5 predictions
            vuln_type = pred['vulnerability_type']
            
            if vuln_type == 'xss':
                prioritized_techniques.extend(['reflected_xss', 'stored_xss', 'dom_xss'])
            elif vuln_type == 'csrf':
                prioritized_techniques.extend(['csrf_token_bypass', 'anti_csrf_bypass'])
            elif vuln_type == 'sql_injection':
                prioritized_techniques.extend(['error_based_sql', 'blind_sql', 'time_based_sql'])
            elif vuln_type == 'buffer_overflow':
                prioritized_techniques.extend(['stack_overflow', 'heap_overflow'])
            elif vuln_type == 'format_string':
                prioritized_techniques.extend(['format_string_read', 'format_string_write'])
        
        strategy['prioritized_techniques'] = prioritized_techniques[:10]  # Limit to 10
        
        # Resource allocation
        strategy['resource_allocation'] = {
            'validation_tests': len(strategy['prioritized_techniques']),
            'evidence_collection': 'high',
            'reporting_detail': 'standard'
        }
        
        return strategy
    
    def _optimize_pentest_strategy(self, strategy: Dict, predictions: Dict) -> Dict:
        """Optimize penetration testing strategy"""
        
        # PTES phase prioritization
        phase_priorities = {
            'reconnaissance': 'high' if predictions['success_probability'] > 0.5 else 'medium',
            'vulnerability_analysis': 'high',
            'exploitation': 'medium' if predictions['success_probability'] > 0.7 else 'low',
            'post_exploitation': 'low'
        }
        
        strategy['prioritized_phases'] = [
            phase for phase, priority in sorted(phase_priorities.items(), key=lambda x: x[1], reverse=True)
        ]
        
        # Resource allocation
        strategy['resource_allocation'] = {
            'reconnaissance_depth': 'deep' if phase_priorities['reconnaissance'] == 'high' else 'standard',
            'vulnerability_scanning': 'comprehensive',
            'exploitation_attempts': 'limited' if phase_priorities['exploitation'] == 'low' else 'standard'
        }
        
        return strategy
    
    def _optimize_exploitation_strategy(self, strategy: Dict, predictions: Dict) -> Dict:
        """Optimize exploitation assessment strategy"""
        
        # Focus on high-impact techniques
        exploitation_techniques = []
        
        for pred in predictions['predictions']:
            if pred['vulnerability_type'] in ['buffer_overflow', 'format_string']:
                exploitation_techniques.append({
                    'technique': pred['vulnerability_type'],
                    'priority': 'high',
                    'expected_impact': 'critical'
                })
        
        strategy['exploitation_focus'] = exploitation_techniques
        
        # Resource allocation
        strategy['resource_allocation'] = {
            'memory_analysis': 'deep',
            'shellcode_development': 'standard',
            'countermeasure_analysis': 'comprehensive'
        }
        
        return strategy
    
    def _optimize_comprehensive_strategy(self, strategy: Dict, predictions: Dict) -> Dict:
        """Optimize comprehensive assessment strategy"""
        
        # Combine all optimizations
        strategy = self._optimize_validation_strategy(strategy, predictions)
        strategy = self._optimize_pentest_strategy(strategy, predictions)
        strategy = self._optimize_exploitation_strategy(strategy, predictions)
        
        # Comprehensive resource allocation
        strategy['resource_allocation'] = {
            'validation_tests': 'comprehensive',
            'pentest_phases': 'all',
            'exploitation_depth': 'standard',
            'reporting_detail': 'comprehensive'
        }
        
        # Expected duration
        if predictions['success_probability'] > 0.8:
            strategy['expected_duration'] = 'extended'
        elif predictions['success_probability'] > 0.5:
            strategy['expected_duration'] = 'standard'
        else:
            strategy['expected_duration'] = 'reduced'
        
        return strategy
    
    def _calculate_optimization_score(self, strategy: Dict) -> float:
        """Calculate optimization score for strategy"""
        
        score = 0.0
        
        # Base score from success probability
        score += strategy['success_probability'] * 0.4
        
        # Score from prediction confidence
        if strategy['predicted_vulnerabilities']:
            avg_confidence = sum(p['confidence'] for p in strategy['predicted_vulnerabilities']) / len(strategy['predicted_vulnerabilities'])
            score += avg_confidence * 0.3
        
        # Score from technique recommendations
        if strategy['recommended_techniques']:
            avg_technique_confidence = sum(t['confidence'] for t in strategy['recommended_techniques']) / len(strategy['recommended_techniques'])
            score += avg_technique_confidence * 0.2
        
        # Score from resource allocation efficiency
        resource_score = 0.1  # Base score for having resource allocation
        score += resource_score
        
        return min(score, 1.0)
    
    def apply_learning_to_assessment(self, target: str, assessment_type: str = "comprehensive") -> Dict:
        """
        Apply all learning to optimize and execute assessment
        
        Args:
            target: Target URL or domain
            assessment_type: Type of assessment to execute
        
        Returns:
            Optimized assessment with learning applied
        """
        
        logger.info(f"Applying learning to {assessment_type} assessment for: {target}")
        
        # Get optimized strategy
        strategy = self.optimize_assessment_strategy(target, assessment_type)
        
        # Apply learning to existing frameworks
        applied_learning = {
            'target': target,
            'assessment_type': assessment_type,
            'timestamp': datetime.now().isoformat(),
            'strategy': strategy,
            'learning_applied': [],
            'expected_improvements': {},
            'automated_optimizations': {}
        }
        
        # Apply vulnerability prediction learning
        if strategy['predicted_vulnerabilities']:
            applied_learning['learning_applied'].append({
                'type': 'vulnerability_prediction',
                'description': f"Prioritized {len(strategy['predicted_vulnerabilities'])} likely vulnerabilities",
                'confidence': strategy['confidence_level']
            })
        
        # Apply technique optimization
        if strategy['recommended_techniques']:
            applied_learning['learning_applied'].append({
                'type': 'technique_optimization',
                'description': f"Optimized {len(strategy['recommended_techniques'])} techniques",
                'success_probability': strategy['success_probability']
            })
        
        # Apply resource optimization
        if strategy['resource_allocation']:
            applied_learning['learning_applied'].append({
                'type': 'resource_optimization',
                'description': "Optimized resource allocation based on learning",
                'efficiency_gain': f"{strategy['optimization_score']:.1%}"
            })
        
        # Calculate expected improvements
        applied_learning['expected_improvements'] = {
            'success_rate_increase': f"{strategy['success_probability'] * 100:.1f}%",
            'efficiency_improvement': f"{strategy['optimization_score'] * 100:.1f}%",
            'time_savings': self._estimate_time_savings(strategy),
            'accuracy_improvement': f"{strategy['optimization_score'] * 50:.1f}%"
        }
        
        # Generate automated optimizations
        applied_learning['automated_optimizations'] = {
            'prioritized_vulnerabilities': [p['vulnerability_type'] for p in strategy['predicted_vulnerabilities'][:5]],
            'recommended_techniques': [t['technique'] for t in strategy['recommended_techniques'][:5]],
            'resource_allocation': strategy['resource_allocation'],
            'assessment_duration': strategy['expected_duration']
        }
        
        # Save applied learning
        self._save_applied_learning(applied_learning)
        
        logger.info(f"Learning applied successfully with {len(applied_learning['learning_applied'])} optimizations")
        
        return applied_learning
    
    def _estimate_time_savings(self, strategy: Dict) -> str:
        """Estimate time savings from optimization"""
        
        base_duration = 100  # Base percentage
        
        if strategy['expected_duration'] == 'reduced':
            time_savings = f"{base_duration - 30}%"
        elif strategy['expected_duration'] == 'standard':
            time_savings = f"{base_duration - 10}%"
        else:  # extended
            time_savings = f"{base_duration + 20}%"
        
        return time_savings
    
    def _save_learning_session(self, session: Dict):
        """Save learning session to file"""
        
        session_file = self.learning_data_dir / f"learning_session_{session['session_id']}.json"
        with open(session_file, 'w') as f:
            json.dump(session, f, indent=2, default=str)
    
    def _save_applied_learning(self, applied_learning: Dict):
        """Save applied learning to file"""
        
        applied_file = self.learning_data_dir / f"applied_learning_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(applied_file, 'w') as f:
            json.dump(applied_learning, f, indent=2, default=str)
    
    def _load_learning_data(self):
        """Load existing learning data"""
        
        try:
            # Load vulnerability patterns
            patterns_file = self.learning_data_dir / "vulnerability_patterns.json"
            if patterns_file.exists():
                with open(patterns_file, 'r') as f:
                    data = json.load(f)
                    self.vulnerability_patterns = defaultdict(list, data)
            
            # Load success patterns
            success_file = self.learning_data_dir / "success_patterns.json"
            if success_file.exists():
                with open(success_file, 'r') as f:
                    data = json.load(f)
                    self.success_patterns = defaultdict(list, data)
            
            # Load target profiles
            profiles_file = self.learning_data_dir / "target_profiles.json"
            if profiles_file.exists():
                with open(profiles_file, 'r') as f:
                    self.target_profiles = json.load(f)
            
            # Load technique effectiveness
            effectiveness_file = self.learning_data_dir / "technique_effectiveness.json"
            if effectiveness_file.exists():
                with open(effectiveness_file, 'r') as f:
                    self.technique_effectiveness = json.load(f)
            
            # Load platform optimization
            platform_file = self.learning_data_dir / "platform_optimization.json"
            if platform_file.exists():
                with open(platform_file, 'r') as f:
                    self.platform_optimization = json.load(f)
            
            # Load ML models
            if SKLEARN_AVAILABLE:
                model_file = self.learning_data_dir / "ml_models.pkl"
                if model_file.exists():
                    with open(model_file, 'rb') as f:
                        models = pickle.load(f)
                        self.vulnerability_predictor = models.get('vulnerability_predictor')
                        self.success_predictor = models.get('success_predictor')
                        self.technique_selector = models.get('technique_selector')
            
            # Load metrics
            metrics_file = self.learning_data_dir / "learning_metrics.json"
            if metrics_file.exists():
                with open(metrics_file, 'r') as f:
                    metrics = json.load(f)
                    self.learning_sessions = metrics.get('learning_sessions', 0)
                    self.total_assessments = metrics.get('total_assessments', 0)
                    self.successful_predictions = metrics.get('successful_predictions', 0)
        
        except Exception as e:
            logger.error(f"Error loading learning data: {e}")
    
    def save_learning_data(self):
        """Save all learning data to files"""
        
        try:
            # Save vulnerability patterns
            patterns_file = self.learning_data_dir / "vulnerability_patterns.json"
            with open(patterns_file, 'w') as f:
                json.dump(dict(self.vulnerability_patterns), f, indent=2, default=str)
            
            # Save success patterns
            success_file = self.learning_data_dir / "success_patterns.json"
            with open(success_file, 'w') as f:
                json.dump(dict(self.success_patterns), f, indent=2, default=str)
            
            # Save target profiles
            profiles_file = self.learning_data_dir / "target_profiles.json"
            with open(profiles_file, 'w') as f:
                json.dump(self.target_profiles, f, indent=2, default=str)
            
            # Save technique effectiveness
            effectiveness_file = self.learning_data_dir / "technique_effectiveness.json"
            with open(effectiveness_file, 'w') as f:
                json.dump(self.technique_effectiveness, f, indent=2)
            
            # Save platform optimization
            platform_file = self.learning_data_dir / "platform_optimization.json"
            with open(platform_file, 'w') as f:
                json.dump(self.platform_optimization, f, indent=2, default=str)
            
            # Save ML models
            if SKLEARN_AVAILABLE and any([self.vulnerability_predictor, self.success_predictor, self.technique_selector]):
                model_file = self.learning_data_dir / "ml_models.pkl"
                models = {
                    'vulnerability_predictor': self.vulnerability_predictor,
                    'success_predictor': self.success_predictor,
                    'technique_selector': self.technique_selector
                }
                with open(model_file, 'wb') as f:
                    pickle.dump(models, f)
            
            # Save metrics
            metrics_file = self.learning_data_dir / "learning_metrics.json"
            metrics = {
                'learning_sessions': self.learning_sessions,
                'total_assessments': self.total_assessments,
                'successful_predictions': self.successful_predictions,
                'last_updated': datetime.now().isoformat()
            }
            with open(metrics_file, 'w') as f:
                json.dump(metrics, f, indent=2)
            
            logger.info("Learning data saved successfully")
        
        except Exception as e:
            logger.error(f"Error saving learning data: {e}")
    
    def _calculate_platform_success_rate(self, platform_reports: Dict) -> float:
        """Calculate success rate for platform reports"""
        
        if not platform_reports:
            return 0.0
        
        # Simplified success rate calculation
        # In real implementation, this would track actual acceptance rates
        return 0.75  # Placeholder
    
    def get_learning_summary(self) -> Dict:
        """Get comprehensive learning summary"""
        
        summary = {
            'learning_overview': {
                'total_learning_sessions': self.learning_sessions,
                'total_assessments_learned': self.total_assessments,
                'successful_predictions': self.successful_predictions,
                'learning_accuracy': self.successful_predictions / max(self.total_assessments, 1),
                'last_updated': datetime.now().isoformat()
            },
            'vulnerability_patterns': {
                'total_patterns': len(self.vulnerability_patterns),
                'most_successful_patterns': self._get_most_successful_patterns(5),
                'pattern_distribution': self._get_pattern_distribution()
            },
            'technique_effectiveness': {
                'total_techniques': len(self.technique_effectiveness),
                'top_techniques': sorted(
                    self.technique_effectiveness.items(),
                    key=lambda x: x[1],
                    reverse=True
                )[:10],
                'average_effectiveness': sum(self.technique_effectiveness.values()) / max(len(self.technique_effectiveness), 1)
            },
            'target_profiles': {
                'total_targets': len(self.target_profiles),
                'target_types': self._get_target_type_distribution(),
                'most_vulnerable_targets': self._get_most_vulnerable_targets(5)
            },
            'platform_optimization': {
                'platforms_tracked': len(self.platform_optimization),
                'best_performing_platform': self._get_best_platform(),
                'platform_success_rates': {
                    platform: data.get('average_success_rate', 0)
                    for platform, data in self.platform_optimization.items()
                }
            },
            'ml_models': {
                'models_trained': bool(self.vulnerability_predictor),
                'sklearn_available': SKLEARN_AVAILABLE,
                'prediction_accuracy': self._get_ml_accuracy()
            }
        }
        
        return summary
    
    def _get_most_successful_patterns(self, count: int) -> List[Dict]:
        """Get most successful vulnerability patterns"""
        
        pattern_success_rates = []
        
        for pattern_signature, pattern_data in self.vulnerability_patterns.items():
            success_rate = self._calculate_pattern_success_rate(pattern_signature)
            if len(pattern_data) > 0:  # Only include patterns with data
                pattern_success_rates.append({
                    'signature': pattern_signature,
                    'success_rate': success_rate,
                    'occurrences': len(pattern_data),
                    'latest_success': any(p.get('success', False) for p in pattern_data[-5:])  # Recent success
                })
        
        return sorted(pattern_success_rates, key=lambda x: x['success_rate'], reverse=True)[:count]
    
    def _get_pattern_distribution(self) -> Dict:
        """Get distribution of vulnerability patterns"""
        
        distribution = defaultdict(int)
        
        for pattern_data in self.vulnerability_patterns.values():
            for instance in pattern_data:
                vuln_type = instance.get('vulnerability_type', 'unknown')
                if vuln_type != 'unknown':
                    distribution[vuln_type] += 1
        
        return dict(distribution)
    
    def _get_target_type_distribution(self) -> Dict:
        """Get distribution of target types"""
        
        distribution = defaultdict(int)
        
        for profile in self.target_profiles.values():
            target_type = profile['characteristics'].get('type', 'unknown')
            distribution[target_type] += 1
        
        return dict(distribution)
    
    def _get_most_vulnerable_targets(self, count: int) -> List[Dict]:
        """Get most vulnerable targets"""
        
        target_vulnerabilities = []
        
        for target, profile in self.target_profiles.items():
            vuln_count = len(profile['vulnerabilities_found'])
            if vuln_count > 0:
                target_vulnerabilities.append({
                    'target': target,
                    'vulnerability_count': vuln_count,
                    'assessments': profile['assessments'],
                    'vulnerability_rate': vuln_count / max(profile['assessments'], 1),
                    'latest_assessment': profile.get('last_seen', 'unknown')
                })
        
        return sorted(target_vulnerabilities, key=lambda x: x['vulnerability_rate'], reverse=True)[:count]
    
    def _get_best_platform(self) -> str:
        """Get best performing platform"""
        
        if not self.platform_optimization:
            return 'none'
        
        return max(
            self.platform_optimization.items(),
            key=lambda x: x[1].get('average_success_rate', 0)
        )[0]
    
    def _get_ml_accuracy(self) -> float:
        """Get ML model accuracy"""
        
        if not SKLEARN_AVAILABLE or not self.accuracy_history:
            return 0.0
        
        return sum(self.accuracy_history) / len(self.accuracy_history)

# Usage example and integration
if __name__ == "__main__":
    # Initialize reinforcement learning system
    rl_system = ReinforcementLearningAutomation()
    
    # Example: Learn from existing assessment results
    try:
        # Load recent assessment results
        assessment_files = [
            "enhanced_validation_20251201_083200/comprehensive_assessment_results.json",
            "exploitation_analysis_20251201_083634/complete_exploitation_analysis.json"
        ]
        
        for assessment_file in assessment_files:
            if Path(assessment_file).exists():
                with open(assessment_file, 'r') as f:
                    assessment_results = json.load(f)
                
                # Learn from assessment
                learning_session = rl_system.learn_from_assessment(assessment_results)
                print(f"Learning session completed: {learning_session['session_id']}")
                print(f"Patterns learned: {len(learning_session['learned_patterns'])}")
                print(f"Models updated: {learning_session['updated_models']}")
    
    except Exception as e:
        print(f"Error in example learning: {e}")
    
    # Example: Apply learning to new target
    target = "https://example.com"
    
    # Get optimized strategy
    strategy = rl_system.optimize_assessment_strategy(target, "comprehensive")
    print(f"\nOptimized strategy for {target}:")
    print(f"Success probability: {strategy['success_probability']:.1%}")
    print(f"Optimization score: {strategy['optimization_score']:.1%}")
    print(f"Confidence level: {strategy['confidence_level']}")
    
    # Apply learning to assessment
    applied_learning = rl_system.apply_learning_to_assessment(target, "comprehensive")
    print(f"\nApplied learning optimizations:")
    for optimization in applied_learning['learning_applied']:
        print(f"- {optimization['type']}: {optimization['description']}")
    
    # Get learning summary
    summary = rl_system.get_learning_summary()
    print(f"\nLearning Summary:")
    print(f"Total learning sessions: {summary['learning_overview']['total_learning_sessions']}")
    print(f"Total assessments learned: {summary['learning_overview']['total_assessments_learned']}")
    print(f"Learning accuracy: {summary['learning_overview']['learning_accuracy']:.1%}")
    
    # Save learning data
    rl_system.save_learning_data()
    
    print(f"\nReinforcement learning system ready for automated optimization!")
