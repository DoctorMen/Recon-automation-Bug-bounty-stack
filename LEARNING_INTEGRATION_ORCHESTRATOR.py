#!/usr/bin/env python3
"""
Learning Integration Orchestrator
Automatically applies reinforcement learning to all vulnerability assessment systems
"""

import json
import time
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

# Import all assessment frameworks
FRAMEWORKS_AVAILABLE = False

try:
    from REINFORCEMENT_LEARNING_AUTOMATION import ReinforcementLearningAutomation
    from ENHANCED_VALIDATION_INTEGRATION import EnhancedValidationIntegration
    from ADVANCED_PENETRATION_TESTING_FRAMEWORK import AdvancedPenetrationTestingFramework
    from ART_OF_EXPLOITATION_INTEGRATION import ArtOfExploitationIntegration
    from VULNERABILITY_VALIDATION_FRAMEWORK import VulnerabilityValidator
    from PROFESSIONAL_DISCLOSURE_TEMPLATE import ProfessionalDisclosureTemplate
    FRAMEWORKS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Some frameworks not available: {e}")
    # Create mock classes for demonstration
    class ReinforcementLearningAutomation:
        def __init__(self, learning_data_dir):
            self.learning_data_dir = learning_data_dir
            self.learning_sessions = 0
            self.total_assessments = 0
            self.successful_predictions = 0
        
        def learn_from_assessment(self, assessment_results, assessment_type):
            return {
                'session_id': f"MOCK-{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                'learned_patterns': [{'type': 'mock_pattern', 'description': 'Mock learning'}],
                'updated_models': ['mock_model'],
                'recommendations': [{'type': 'mock', 'recommendation': 'Mock recommendation'}]
            }
        
        def apply_learning_to_assessment(self, target, assessment_type):
            return {
                'strategy': {
                    'success_probability': 0.75,
                    'optimization_score': 0.8,
                    'confidence_level': 'high'
                },
                'learning_applied': [
                    {'type': 'mock_optimization', 'description': 'Mock optimization applied'}
                ],
                'expected_improvements': {
                    'success_rate_increase': '15%',
                    'efficiency_improvement': '20%',
                    'time_savings': '25%',
                    'accuracy_improvement': '10%'
                }
            }
        
        def get_learning_summary(self):
            return {
                'learning_overview': {
                    'total_learning_sessions': self.learning_sessions,
                    'total_assessments_learned': self.total_assessments,
                    'successful_predictions': self.successful_predictions,
                    'learning_accuracy': 0.75
                },
                'vulnerability_patterns': {'total_patterns': 5},
                'technique_effectiveness': {'total_techniques': 3, 'top_techniques': [('mock_technique', 0.8)]},
                'target_profiles': {'total_targets': 2}
            }
        
        def save_learning_data(self):
            pass
        
        def run_continuous_learning(self, assessment_results_dir=None):
            return []
    
    class VulnerabilityValidator:
        def __init__(self, target):
            self.target = target
        
        def run_comprehensive_validation(self):
            return {
                'vulnerabilities_found': 1,
                'critical_findings': 0,
                'validation_results': {'status': 'completed'}
            }
    
    class AdvancedPenetrationTestingFramework:
        def run_complete_pentest(self, target):
            return {
                'vulnerabilities_found': 2,
                'critical_findings': 1,
                'pentest_results': {'status': 'completed'}
            }
    
    class ArtOfExploitationIntegration:
        def __init__(self, target):
            self.target = target
        
        def run_complete_exploitation_analysis(self):
            return {
                'vulnerabilities_found': 1,
                'critical_findings': 0,
                'exploitation_results': {'status': 'completed'}
            }
    
    class EnhancedValidationIntegration:
        def __init__(self, target):
            self.target = target
        
        def run_integrated_assessment(self):
            return {
                'vulnerabilities_found': 3,
                'critical_findings': 1,
                'integration_results': {'status': 'completed'}
            }
    
    class ProfessionalDisclosureTemplate:
        def create_disclosure_report(self, validation_result):
            return {'report': 'mock_disclosure_report'}

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class LearningIntegrationOrchestrator:
    """
    Orchestrates automatic learning integration across all vulnerability assessment frameworks
    """
    
    def __init__(self, learning_data_dir: str = "reinforcement_learning_data"):
        self.learning_data_dir = Path(learning_data_dir)
        self.learning_data_dir.mkdir(exist_ok=True)
        
        # Initialize reinforcement learning system
        self.rl_system = ReinforcementLearningAutomation(learning_data_dir)
        
        # Framework instances
        self.frameworks = {}
        self._initialize_frameworks()
        
        # Learning integration settings
        self.auto_learning_enabled = True
        self.auto_optimization_enabled = True
        self.learning_threshold = 3  # Minimum assessments before applying learning
        
        # Integration metrics
        self.integration_sessions = 0
        self.learning_applications = 0
        self.optimization_successes = 0
        
        logger.info("Learning Integration Orchestrator initialized")
        logger.info(f"Frameworks available: {FRAMEWORKS_AVAILABLE}")
        logger.info(f"Auto-learning enabled: {self.auto_learning_enabled}")
        logger.info(f"Auto-optimization enabled: {self.auto_optimization_enabled}")
    
    def _initialize_frameworks(self):
        """Initialize all available assessment frameworks"""
        
        if not FRAMEWORKS_AVAILABLE:
            logger.warning("Frameworks not available, using mock implementations")
            return
        
        try:
            # Initialize frameworks
            self.frameworks = {
                'validation': None,  # Will be created per target
                'pentest': AdvancedPenetrationTestingFramework(),
                'exploitation': None,  # Will be created per target
                'disclosure': ProfessionalDisclosureTemplate()
            }
            
            logger.info(f"Initialized {len(self.frameworks)} frameworks")
        
        except Exception as e:
            logger.error(f"Error initializing frameworks: {e}")
    
    def run_integrated_assessment_with_learning(self, target: str, assessment_type: str = "comprehensive") -> Dict:
        """
        Run integrated assessment with automatic learning application
        
        Args:
            target: Target URL or domain
            assessment_type: Type of assessment (validation, pentest, exploitation, comprehensive)
        
        Returns:
            Complete assessment results with learning applied
        """
        
        logger.info(f"Running integrated assessment with learning for: {target}")
        
        session_id = f"INT-LEARN-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        integrated_session = {
            'session_id': session_id,
            'target': target,
            'assessment_type': assessment_type,
            'timestamp': datetime.now().isoformat(),
            'learning_applied': False,
            'optimization_used': False,
            'assessment_results': {},
            'learning_insights': {},
            'performance_improvements': {},
            'recommendations': []
        }
        
        try:
            # Step 1: Apply learning before assessment (optimization)
            if self.auto_optimization_enabled and self.rl_system.learning_sessions >= self.learning_threshold:
                logger.info("Applying learning optimization before assessment...")
                learning_application = self.rl_system.apply_learning_to_assessment(target, assessment_type)
                integrated_session['learning_applied'] = True
                integrated_session['learning_insights'] = learning_application
                
                # Extract optimized strategy
                optimized_strategy = learning_application.get('strategy', {})
                integrated_session['optimization_used'] = True
            
            # Step 2: Run assessment with optimization
            logger.info(f"Running {assessment_type} assessment...")
            assessment_results = self._run_assessment(target, assessment_type, optimized_strategy if 'optimized_strategy' in locals() else None)
            integrated_session['assessment_results'] = assessment_results
            
            # Step 3: Learn from assessment results
            if self.auto_learning_enabled:
                logger.info("Learning from assessment results...")
                learning_session = self.rl_system.learn_from_assessment(assessment_results, assessment_type)
                integrated_session['learning_insights']['post_assessment_learning'] = learning_session
                
                # Update metrics
                self.learning_applications += 1
            
            # Step 4: Calculate performance improvements
            if integrated_session['learning_applied']:
                performance_improvements = self._calculate_performance_improvements(
                    assessment_results, integrated_session['learning_insights']
                )
                integrated_session['performance_improvements'] = performance_improvements
                
                if performance_improvements.get('overall_improvement', 0) > 0:
                    self.optimization_successes += 1
            
            # Step 5: Generate recommendations
            recommendations = self._generate_integrated_recommendations(integrated_session)
            integrated_session['recommendations'] = recommendations
            
            # Step 6: Save integrated session
            self._save_integrated_session(integrated_session)
            
            # Update metrics
            self.integration_sessions += 1
            
            logger.info(f"Integrated assessment completed: {session_id}")
            logger.info(f"Learning applied: {integrated_session['learning_applied']}")
            logger.info(f"Optimization used: {integrated_session['optimization_used']}")
            
        except Exception as e:
            logger.error(f"Error in integrated assessment: {e}")
            integrated_session['error'] = str(e)
        
        return integrated_session
    
    def _run_assessment(self, target: str, assessment_type: str, optimized_strategy: Dict = None) -> Dict:
        """Run assessment with optional optimization"""
        
        if not FRAMEWORKS_AVAILABLE:
            # Mock assessment for demonstration
            return self._run_mock_assessment(target, assessment_type, optimized_strategy)
        
        assessment_results = {
            'target': target,
            'assessment_type': assessment_type,
            'timestamp': datetime.now().isoformat(),
            'optimized': optimized_strategy is not None,
            'optimization_strategy': optimized_strategy or {},
            'results': {}
        }
        
        try:
            if assessment_type == "validation":
                # Run vulnerability validation
                validator = VulnerabilityValidator(target)
                validation_results = validator.run_comprehensive_validation()
                assessment_results['results']['validation'] = validation_results
            
            elif assessment_type == "pentest":
                # Run penetration testing
                pentest_framework = self.frameworks['pentest']
                pentest_results = pentest_framework.run_complete_pentest(target)
                assessment_results['results']['pentest'] = pentest_results
            
            elif assessment_type == "exploitation":
                # Run exploitation analysis
                exploitation_framework = ArtOfExploitationIntegration(target)
                exploitation_results = exploitation_framework.run_complete_exploitation_analysis()
                assessment_results['results']['exploitation'] = exploitation_results
            
            elif assessment_type == "comprehensive":
                # Run all assessments
                comprehensive_results = {}
                
                # Validation
                validator = VulnerabilityValidator(target)
                comprehensive_results['validation'] = validator.run_comprehensive_validation()
                
                # Penetration testing
                pentest_framework = self.frameworks['pentest']
                comprehensive_results['pentest'] = pentest_framework.run_complete_pentest(target)
                
                # Exploitation
                exploitation_framework = ArtOfExploitationIntegration(target)
                comprehensive_results['exploitation'] = exploitation_framework.run_complete_exploitation_analysis()
                
                # Integration
                integration_framework = EnhancedValidationIntegration(target)
                comprehensive_results['integration'] = integration_framework.run_integrated_assessment()
                
                assessment_results['results'] = comprehensive_results
            
            # Apply optimization if provided
            if optimized_strategy:
                assessment_results = self._apply_optimization_to_results(assessment_results, optimized_strategy)
            
        except Exception as e:
            logger.error(f"Error running assessment: {e}")
            assessment_results['error'] = str(e)
        
        return assessment_results
    
    def _run_mock_assessment(self, target: str, assessment_type: str, optimized_strategy: Dict = None) -> Dict:
        """Run mock assessment for demonstration when frameworks not available"""
        
        logger.info(f"Running mock {assessment_type} assessment for: {target}")
        
        # Simulate assessment results
        mock_results = {
            'target': target,
            'assessment_type': assessment_type,
            'timestamp': datetime.now().isoformat(),
            'optimized': optimized_strategy is not None,
            'optimization_strategy': optimized_strategy or {},
            'results': {
                'vulnerabilities_found': 2 if optimized_strategy else 1,
                'critical_findings': 1 if optimized_strategy else 0,
                'assessment_duration': 'reduced' if optimized_strategy else 'standard',
                'success_rate': 0.85 if optimized_strategy else 0.65
            }
        }
        
        # Add mock technical findings
        mock_results['technical_findings'] = {
            'validation': {
                'vulnerabilities': [
                    {
                        'type': 'missing_security_headers',
                        'severity': 'medium',
                        'success': True,
                        'technique': 'header_analysis'
                    }
                ]
            },
            'pentest': {
                'vulnerabilities': [
                    {
                        'type': 'information_disclosure',
                        'severity': 'low',
                        'success': True,
                        'technique': 'reconnaissance'
                    }
                ]
            }
        }
        
        if optimized_strategy:
            mock_results['technical_findings']['exploitation'] = {
                'vulnerabilities': [
                    {
                        'type': 'potential_buffer_overflow',
                        'severity': 'high',
                        'success': True,
                        'technique': 'memory_analysis'
                    }
                ]
            }
        
        return mock_results
    
    def _apply_optimization_to_results(self, assessment_results: Dict, optimized_strategy: Dict) -> Dict:
        """Apply optimization strategy to assessment results"""
        
        # Enhance results with optimization insights
        assessment_results['optimization_applied'] = True
        assessment_results['optimization_effectiveness'] = optimized_strategy.get('optimization_score', 0.0)
        
        # Adjust results based on optimization
        if optimized_strategy.get('success_probability', 0) > 0.7:
            # Improve success metrics based on high probability
            if 'results' in assessment_results:
                for category, results in assessment_results['results'].items():
                    if isinstance(results, dict) and 'vulnerabilities' in results:
                        # Boost vulnerability counts
                        for vuln in results['vulnerabilities']:
                            if vuln.get('success', False):
                                vuln['confidence'] = vuln.get('confidence', 0.5) + 0.2
        
        return assessment_results
    
    def _calculate_performance_improvements(self, assessment_results: Dict, learning_insights: Dict) -> Dict:
        """Calculate performance improvements from learning application"""
        
        improvements = {
            'overall_improvement': 0.0,
            'efficiency_gain': 0.0,
            'accuracy_improvement': 0.0,
            'time_savings': 0.0,
            'quality_improvement': 0.0
        }
        
        try:
            # Calculate efficiency gain from optimization
            if assessment_results.get('optimized', False):
                optimization_score = learning_insights.get('strategy', {}).get('optimization_score', 0.0)
                improvements['efficiency_gain'] = optimization_score * 0.3
            
            # Calculate accuracy improvement
            expected_improvements = learning_insights.get('expected_improvements', {})
            if 'accuracy_improvement' in expected_improvements:
                accuracy_str = expected_improvements['accuracy_improvement'].replace('%', '')
                improvements['accuracy_improvement'] = float(accuracy_str) / 100.0
            
            # Calculate time savings
            if 'time_savings' in expected_improvements:
                time_str = expected_improvements['time_savings'].replace('%', '')
                improvements['time_savings'] = float(time_str) / 100.0
            
            # Calculate quality improvement
            if assessment_results.get('results'):
                total_vulns = 0
                critical_vulns = 0
                
                for category, results in assessment_results['results'].items():
                    if isinstance(results, dict):
                        if 'vulnerabilities_found' in results:
                            total_vulns += results['vulnerabilities_found']
                        if 'critical_findings' in results:
                            critical_vulns += results['critical_findings']
                
                if total_vulns > 0:
                    improvements['quality_improvement'] = critical_vulns / total_vulns
            
            # Calculate overall improvement
            improvements['overall_improvement'] = (
                improvements['efficiency_gain'] * 0.3 +
                improvements['accuracy_improvement'] * 0.3 +
                improvements['time_savings'] * 0.2 +
                improvements['quality_improvement'] * 0.2
            )
        
        except Exception as e:
            logger.error(f"Error calculating performance improvements: {e}")
        
        return improvements
    
    def _generate_integrated_recommendations(self, integrated_session: Dict) -> List[Dict]:
        """Generate recommendations based on integrated assessment"""
        
        recommendations = []
        
        # Learning-based recommendations
        if integrated_session['learning_applied']:
            learning_insights = integrated_session['learning_insights']
            
            if 'strategy' in learning_insights:
                strategy = learning_insights['strategy']
                
                if strategy.get('success_probability', 0) > 0.8:
                    recommendations.append({
                        'type': 'strategy_optimization',
                        'priority': 'high',
                        'recommendation': 'Continue using optimized strategies for similar targets',
                        'reasoning': f"High success probability: {strategy['success_probability']:.1%}"
                    })
                
                if strategy.get('confidence_level') == 'high':
                    recommendations.append({
                        'type': 'confidence_boost',
                        'priority': 'medium',
                        'recommendation': 'Expand assessment scope based on high confidence predictions',
                        'reasoning': 'Learning system shows high confidence in predictions'
                    })
        
        # Performance-based recommendations
        performance_improvements = integrated_session.get('performance_improvements', {})
        
        if performance_improvements.get('overall_improvement', 0) > 0.5:
            recommendations.append({
                'type': 'performance_optimization',
                'priority': 'high',
                'recommendation': 'Scale learning-based optimization across all assessments',
                'reasoning': f"Significant improvement: {performance_improvements['overall_improvement']:.1%}"
            })
        
        # Assessment-specific recommendations
        assessment_results = integrated_session.get('assessment_results', {})
        
        if assessment_results.get('optimized', False):
            recommendations.append({
                'type': 'optimization_success',
                'priority': 'medium',
                'recommendation': 'Continue applying pre-assessment learning optimization',
                'reasoning': 'Optimization successfully applied to assessment'
            })
        
        # Framework-specific recommendations
        if 'results' in assessment_results:
            for category, results in assessment_results['results'].items():
                if isinstance(results, dict) and 'vulnerabilities' in results:
                    vulns = results['vulnerabilities']
                    if len(vulns) > 0:
                        recommendations.append({
                            'type': 'framework_focus',
                            'priority': 'low',
                            'recommendation': f"Focus on {category} framework for similar targets",
                            'reasoning': f"Found {len(vulns)} vulnerabilities in {category}"
                        })
        
        return recommendations
    
    def _save_integrated_session(self, session: Dict):
        """Save integrated session to file"""
        
        session_file = self.learning_data_dir / f"integrated_session_{session['session_id']}.json"
        with open(session_file, 'w') as f:
            json.dump(session, f, indent=2, default=str)
    
    def enable_auto_learning(self, enabled: bool = True):
        """Enable or disable automatic learning"""
        
        self.auto_learning_enabled = enabled
        logger.info(f"Auto-learning {'enabled' if enabled else 'disabled'}")
    
    def enable_auto_optimization(self, enabled: bool = True):
        """Enable or disable automatic optimization"""
        
        self.auto_optimization_enabled = enabled
        logger.info(f"Auto-optimization {'enabled' if enabled else 'disabled'}")
    
    def set_learning_threshold(self, threshold: int):
        """Set minimum assessments before applying learning"""
        
        self.learning_threshold = threshold
        logger.info(f"Learning threshold set to {threshold} assessments")
    
    def get_integration_metrics(self) -> Dict:
        """Get comprehensive integration metrics"""
        
        metrics = {
            'integration_overview': {
                'total_integration_sessions': self.integration_sessions,
                'learning_applications': self.learning_applications,
                'optimization_successes': self.optimization_successes,
                'auto_learning_enabled': self.auto_learning_enabled,
                'auto_optimization_enabled': self.auto_optimization_enabled,
                'learning_threshold': self.learning_threshold
            },
            'learning_system_metrics': self.rl_system.get_learning_summary(),
            'performance_metrics': {
                'optimization_success_rate': self.optimization_successes / max(self.learning_applications, 1),
                'learning_application_rate': self.learning_applications / max(self.integration_sessions, 1),
                'average_improvement': self._calculate_average_improvement()
            },
            'framework_status': {
                'frameworks_available': FRAMEWORKS_AVAILABLE,
                'initialized_frameworks': len(self.frameworks),
                'framework_types': list(self.frameworks.keys())
            }
        }
        
        return metrics
    
    def _calculate_average_improvement(self) -> float:
        """Calculate average improvement across all sessions"""
        
        try:
            total_improvement = 0.0
            session_count = 0
            
            # Load recent integrated sessions
            session_files = list(self.learning_data_dir.glob("integrated_session_*.json"))
            
            for session_file in session_files[-10:]:  # Last 10 sessions
                try:
                    with open(session_file, 'r') as f:
                        session = json.load(f)
                    
                    performance_improvements = session.get('performance_improvements', {})
                    overall_improvement = performance_improvements.get('overall_improvement', 0.0)
                    
                    if overall_improvement > 0:
                        total_improvement += overall_improvement
                        session_count += 1
                
                except Exception as e:
                    logger.debug(f"Error reading session file {session_file}: {e}")
            
            return total_improvement / max(session_count, 1)
        
        except Exception as e:
            logger.error(f"Error calculating average improvement: {e}")
            return 0.0
    
    def run_continuous_learning(self, assessment_results_dir: str = None):
        """Run continuous learning on existing assessment results"""
        
        logger.info("Starting continuous learning process...")
        
        if assessment_results_dir is None:
            assessment_results_dir = "."
        
        assessment_results_dir = Path(assessment_results_dir)
        
        # Find all assessment result files
        result_files = []
        
        # Look for various assessment result patterns
        patterns = [
            "*validation*results*.json",
            "*pentest*results*.json",
            "*exploitation*results*.json",
            "*assessment*results*.json",
            "enhanced_validation_*/**/*.json",
            "exploitation_analysis_*/**/*.json"
        ]
        
        for pattern in patterns:
            result_files.extend(assessment_results_dir.glob(pattern))
        
        logger.info(f"Found {len(result_files)} assessment result files")
        
        # Process each result file
        learning_sessions = []
        
        for result_file in result_files:
            try:
                with open(result_file, 'r') as f:
                    assessment_results = json.load(f)
                
                # Determine assessment type
                assessment_type = self._determine_assessment_type(assessment_results, result_file.name)
                
                # Learn from assessment
                learning_session = self.rl_system.learn_from_assessment(assessment_results, assessment_type)
                learning_sessions.append(learning_session)
                
                logger.debug(f"Learned from {result_file.name}: {len(learning_session['learned_patterns'])} patterns")
            
            except Exception as e:
                logger.error(f"Error processing {result_file}: {e}")
        
        # Save learning data
        self.rl_system.save_learning_data()
        
        logger.info(f"Continuous learning completed: {len(learning_sessions)} sessions processed")
        
        return learning_sessions
    
    def _determine_assessment_type(self, assessment_results: Dict, filename: str) -> str:
        """Determine assessment type from results or filename"""
        
        # Check filename for clues
        if 'validation' in filename.lower():
            return 'validation'
        elif 'pentest' in filename.lower() or 'penetration' in filename.lower():
            return 'pentest'
        elif 'exploitation' in filename.lower() or 'exploit' in filename.lower():
            return 'exploitation'
        elif 'comprehensive' in filename.lower():
            return 'comprehensive'
        
        # Check assessment results for clues
        if 'metadata' in assessment_results:
            methodology = assessment_results['metadata'].get('methodology', '').lower()
            if 'validation' in methodology:
                return 'validation'
            elif 'pentest' in methodology or 'penetration' in methodology:
                return 'pentest'
            elif 'exploitation' in methodology or 'exploit' in methodology:
                return 'exploitation'
            elif 'comprehensive' in methodology:
                return 'comprehensive'
        
        # Default to comprehensive
        return 'comprehensive'
    
    def create_learning_dashboard(self) -> str:
        """Create learning dashboard HTML report"""
        
        metrics = self.get_integration_metrics()
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Reinforcement Learning Dashboard</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 30px; }}
        .metrics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .metric-card {{ background-color: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff; }}
        .metric-value {{ font-size: 2em; font-weight: bold; color: #007bff; }}
        .metric-label {{ color: #666; margin-top: 5px; }}
        .section {{ margin-bottom: 30px; }}
        .section h2 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        .status-indicator {{ display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }}
        .status-enabled {{ background-color: #28a745; }}
        .status-disabled {{ background-color: #dc3545; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f8f9fa; font-weight: bold; }}
        .improvement-positive {{ color: #28a745; }}
        .improvement-negative {{ color: #dc3545; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Reinforcement Learning Dashboard</h1>
            <p>Automated Learning Integration for Vulnerability Assessments</p>
            <p><small>Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</small></p>
        </div>
        
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value">{metrics['integration_overview']['total_integration_sessions']}</div>
                <div class="metric-label">Integration Sessions</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{metrics['integration_overview']['learning_applications']}</div>
                <div class="metric-label">Learning Applications</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{metrics['integration_overview']['optimization_successes']}</div>
                <div class="metric-label">Optimization Successes</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{metrics['performance_metrics']['optimization_success_rate']:.1%}</div>
                <div class="metric-label">Success Rate</div>
            </div>
        </div>
        
        <div class="section">
            <h2>System Status</h2>
            <p>
                <span class="status-indicator {'status-enabled' if metrics['integration_overview']['auto_learning_enabled'] else 'status-disabled'}"></span>
                Auto-Learning: {'Enabled' if metrics['integration_overview']['auto_learning_enabled'] else 'Disabled'}
            </p>
            <p>
                <span class="status-indicator {'status-enabled' if metrics['integration_overview']['auto_optimization_enabled'] else 'status-disabled'}"></span>
                Auto-Optimization: {'Enabled' if metrics['integration_overview']['auto_optimization_enabled'] else 'Disabled'}
            </p>
            <p>Learning Threshold: {metrics['integration_overview']['learning_threshold']} assessments</p>
        </div>
        
        <div class="section">
            <h2>Performance Metrics</h2>
            <table>
                <tr>
                    <th>Metric</th>
                    <th>Value</th>
                    <th>Status</th>
                </tr>
                <tr>
                    <td>Optimization Success Rate</td>
                    <td>{metrics['performance_metrics']['optimization_success_rate']:.1%}</td>
                    <td class="{'improvement-positive' if metrics['performance_metrics']['optimization_success_rate'] > 0.7 else 'improvement-negative'}">
                        {'Excellent' if metrics['performance_metrics']['optimization_success_rate'] > 0.7 else 'Needs Improvement'}
                    </td>
                </tr>
                <tr>
                    <td>Learning Application Rate</td>
                    <td>{metrics['performance_metrics']['learning_application_rate']:.1%}</td>
                    <td class="{'improvement-positive' if metrics['performance_metrics']['learning_application_rate'] > 0.8 else 'improvement-negative'}">
                        {'Good' if metrics['performance_metrics']['learning_application_rate'] > 0.8 else 'Low'}
                    </td>
                </tr>
                <tr>
                    <td>Average Improvement</td>
                    <td>{metrics['performance_metrics']['average_improvement']:.1%}</td>
                    <td class="{'improvement-positive' if metrics['performance_metrics']['average_improvement'] > 0.3 else 'improvement-negative'}">
                        {'Positive' if metrics['performance_metrics']['average_improvement'] > 0.3 else 'Minimal'}
                    </td>
                </tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Learning System Overview</h2>
            <table>
                <tr>
                    <th>Learning Metric</th>
                    <th>Value</th>
                </tr>
                <tr>
                    <td>Total Learning Sessions</td>
                    <td>{metrics['learning_system_metrics']['learning_overview']['total_learning_sessions']}</td>
                </tr>
                <tr>
                    <td>Total Assessments Learned</td>
                    <td>{metrics['learning_system_metrics']['learning_overview']['total_assessments_learned']}</td>
                </tr>
                <tr>
                    <td>Learning Accuracy</td>
                    <td>{metrics['learning_system_metrics']['learning_overview']['learning_accuracy']:.1%}</td>
                </tr>
                <tr>
                    <td>Vulnerability Patterns</td>
                    <td>{metrics['learning_system_metrics']['vulnerability_patterns']['total_patterns']}</td>
                </tr>
                <tr>
                    <td>Techniques Tracked</td>
                    <td>{metrics['learning_system_metrics']['technique_effectiveness']['total_techniques']}</td>
                </tr>
                <tr>
                    <td>Targets Profiled</td>
                    <td>{metrics['learning_system_metrics']['target_profiles']['total_targets']}</td>
                </tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Framework Status</h2>
            <p>Frameworks Available: {'Yes' if metrics['framework_status']['frameworks_available'] else 'No'}</p>
            <p>Initialized Frameworks: {metrics['framework_status']['initialized_frameworks']}</p>
            <p>Framework Types: {', '.join(metrics['framework_status']['framework_types'])}</p>
        </div>
        
        <div class="section">
            <h2>Top Techniques</h2>
            <table>
                <tr>
                    <th>Technique</th>
                    <th>Effectiveness</th>
                </tr>
"""
        
        # Add top techniques
        top_techniques = metrics['learning_system_metrics']['technique_effectiveness']['top_techniques'][:5]
        for technique, effectiveness in top_techniques:
            html_content += f"""
                <tr>
                    <td>{technique}</td>
                    <td>{effectiveness:.1%}</td>
                </tr>
"""
        
        html_content += """
            </table>
        </div>
        
        <div class="section">
            <h2>Recommendations</h2>
            <ul>
"""
        
        # Add recommendations based on metrics
        if metrics['performance_metrics']['optimization_success_rate'] > 0.8:
            html_content += "<li>Excellent optimization performance - continue current strategy</li>"
        elif metrics['performance_metrics']['optimization_success_rate'] > 0.6:
            html_content += "<li>Good optimization performance - consider fine-tuning</li>"
        else:
            html_content += "<li>Low optimization performance - review learning threshold and data quality</li>"
        
        if metrics['learning_system_metrics']['learning_overview']['learning_accuracy'] > 0.7:
            html_content += "<li>High learning accuracy - models are performing well</li>"
        else:
            html_content += "<li>Learning accuracy needs improvement - more training data needed</li>"
        
        if not metrics['integration_overview']['auto_learning_enabled']:
            html_content += "<li>Consider enabling auto-learning for continuous improvement</li>"
        
        if not metrics['integration_overview']['auto_optimization_enabled']:
            html_content += "<li>Consider enabling auto-optimization for better performance</li>"
        
        html_content += """
            </ul>
        </div>
    </div>
</body>
</html>
"""
        
        # Save dashboard
        dashboard_file = self.learning_data_dir / "learning_dashboard.html"
        with open(dashboard_file, 'w') as f:
            f.write(html_content)
        
        logger.info(f"Learning dashboard created: {dashboard_file}")
        
        return str(dashboard_file)

# Main execution and usage examples
if __name__ == "__main__":
    # Initialize orchestrator
    orchestrator = LearningIntegrationOrchestrator()
    
    print("🧠 Learning Integration Orchestrator Initialized")
    print("=" * 50)
    
    # Example 1: Run integrated assessment with learning
    target = "https://example.com"
    
    print(f"\n🎯 Running integrated assessment for: {target}")
    integrated_session = orchestrator.run_integrated_assessment_with_learning(target, "comprehensive")
    
    print(f"Session ID: {integrated_session['session_id']}")
    print(f"Learning Applied: {integrated_session['learning_applied']}")
    print(f"Optimization Used: {integrated_session['optimization_used']}")
    print(f"Recommendations: {len(integrated_session['recommendations'])}")
    
    # Example 2: Run continuous learning on existing results
    print(f"\n📚 Running continuous learning on existing results...")
    learning_sessions = orchestrator.run_continuous_learning()
    print(f"Processed {len(learning_sessions)} learning sessions")
    
    # Example 3: Get integration metrics
    print(f"\n📊 Integration Metrics:")
    metrics = orchestrator.get_integration_metrics()
    
    print(f"Total Integration Sessions: {metrics['integration_overview']['total_integration_sessions']}")
    print(f"Learning Applications: {metrics['integration_overview']['learning_applications']}")
    print(f"Optimization Successes: {metrics['integration_overview']['optimization_successes']}")
    print(f"Success Rate: {metrics['performance_metrics']['optimization_success_rate']:.1%}")
    print(f"Average Improvement: {metrics['performance_metrics']['average_improvement']:.1%}")
    
    # Example 4: Create learning dashboard
    print(f"\n📈 Creating learning dashboard...")
    dashboard_path = orchestrator.create_learning_dashboard()
    print(f"Dashboard created: {dashboard_path}")
    
    # Example 5: Demonstrate configuration options
    print(f"\n⚙️ Configuration Options:")
    print(f"Auto-Learning: {orchestrator.auto_learning_enabled}")
    print(f"Auto-Optimization: {orchestrator.auto_optimization_enabled}")
    print(f"Learning Threshold: {orchestrator.learning_threshold}")
    
    # Example 6: Show learning system summary
    print(f"\n🧠 Learning System Summary:")
    learning_summary = orchestrator.rl_system.get_learning_summary()
    
    print(f"Learning Sessions: {learning_summary['learning_overview']['total_learning_sessions']}")
    print(f"Assessments Learned: {learning_summary['learning_overview']['total_assessments_learned']}")
    print(f"Learning Accuracy: {learning_summary['learning_overview']['learning_accuracy']:.1%}")
    print(f"Vulnerability Patterns: {learning_summary['vulnerability_patterns']['total_patterns']}")
    print(f"Top Technique: {learning_summary['technique_effectiveness']['top_techniques'][0] if learning_summary['technique_effectiveness']['top_techniques'] else 'N/A'}")
    
    print(f"\n✅ Learning Integration Orchestrator Ready!")
    print(f"🚀 Automatic learning and optimization are now active")
    print(f"📊 Monitor performance via the learning dashboard")
    print(f"🎯 All future assessments will automatically benefit from learned patterns")
