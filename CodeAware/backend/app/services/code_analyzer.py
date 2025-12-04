#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Core Code Analysis Engine
Analyzes code quality, security, and calculates awareness metrics
"""
import ast
import os
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import radon.complexity as radon_complexity
import radon.metrics as radon_metrics
from radon.raw import analyze as radon_analyze
import subprocess
import json
import logging

logger = logging.getLogger(__name__)


@dataclass
class CodeIssue:
    """Represents a code quality issue"""
    severity: str  # critical, high, medium, low, info
    category: str  # security, bug, code_smell, complexity, style
    message: str
    file_path: str
    line_number: int
    code_snippet: Optional[str] = None
    recommendation: Optional[str] = None


@dataclass
class AnalysisResult:
    """Complete analysis result"""
    quality_score: float
    security_score: float
    maintainability_score: float
    scalability_score: float
    overall_score: float
    
    # Awareness metrics
    actual_skill_level: float
    awareness_gap: float
    dunning_kruger_score: float
    
    # Code metrics
    total_files: int
    total_lines: int
    code_lines: int
    comment_lines: int
    blank_lines: int
    
    # Complexity
    average_complexity: float
    max_complexity: float
    complex_functions_count: int
    
    # Issues
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    info_issues: int
    security_vulnerabilities: int
    
    # Detailed results
    issues: List[CodeIssue]
    metrics_detail: Dict[str, Any]
    learning_recommendations: List[Dict[str, str]]


class CodeAnalyzer:
    """Main code analysis engine"""
    
    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.issues: List[CodeIssue] = []
        self.metrics = {
            'files': {},
            'complexity': [],
            'security': [],
            'patterns': {}
        }
    
    def analyze(self) -> AnalysisResult:
        """Run complete code analysis"""
        logger.info(f"Starting analysis of {self.repo_path}")
        
        # Gather files
        python_files = self._find_python_files()
        js_files = self._find_javascript_files()
        
        # Run analyses
        self._analyze_python_files(python_files)
        self._analyze_javascript_files(js_files)
        self._analyze_security()
        self._analyze_code_patterns()
        
        # Calculate metrics
        result = self._calculate_final_metrics()
        
        logger.info(f"Analysis complete. Overall score: {result.overall_score:.2f}")
        return result
    
    def _find_python_files(self) -> List[str]:
        """Find all Python files in repository"""
        python_files = []
        for root, dirs, files in os.walk(self.repo_path):
            # Skip common ignore directories
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'venv', '__pycache__', '.venv']]
            
            for file in files:
                if file.endswith('.py'):
                    python_files.append(os.path.join(root, file))
        
        return python_files
    
    def _find_javascript_files(self) -> List[str]:
        """Find all JavaScript/TypeScript files"""
        js_files = []
        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'dist', 'build']]
            
            for file in files:
                if file.endswith(('.js', '.jsx', '.ts', '.tsx')):
                    js_files.append(os.path.join(root, file))
        
        return js_files
    
    def _analyze_python_files(self, files: List[str]):
        """Analyze Python code quality"""
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()
                
                # Raw metrics
                raw_metrics = radon_analyze(code)
                self.metrics['files'][file_path] = {
                    'loc': raw_metrics.loc,
                    'lloc': raw_metrics.lloc,
                    'sloc': raw_metrics.sloc,
                    'comments': raw_metrics.comments,
                    'blank': raw_metrics.blank,
                }
                
                # Complexity analysis
                try:
                    complexity = radon_complexity.cc_visit(code)
                    for item in complexity:
                        complexity_score = item.complexity
                        self.metrics['complexity'].append({
                            'file': file_path,
                            'name': item.name,
                            'complexity': complexity_score,
                            'line': item.lineno
                        })
                        
                        # Flag high complexity
                        if complexity_score > 10:
                            self.issues.append(CodeIssue(
                                severity='high' if complexity_score > 15 else 'medium',
                                category='complexity',
                                message=f"Function '{item.name}' has high cyclomatic complexity ({complexity_score})",
                                file_path=file_path,
                                line_number=item.lineno,
                                recommendation="Consider breaking this function into smaller, more focused functions"
                            ))
                except Exception as e:
                    logger.warning(f"Complexity analysis failed for {file_path}: {e}")
                
                # AST-based analysis
                try:
                    tree = ast.parse(code)
                    self._analyze_python_ast(tree, file_path, code)
                except SyntaxError as e:
                    self.issues.append(CodeIssue(
                        severity='critical',
                        category='bug',
                        message=f"Syntax error: {str(e)}",
                        file_path=file_path,
                        line_number=e.lineno or 0
                    ))
                
            except Exception as e:
                logger.error(f"Error analyzing {file_path}: {e}")
    
    def _analyze_python_ast(self, tree: ast.AST, file_path: str, code: str):
        """Analyze Python AST for patterns and issues"""
        lines = code.split('\n')
        
        for node in ast.walk(tree):
            # Detect bare except clauses
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                self.issues.append(CodeIssue(
                    severity='medium',
                    category='code_smell',
                    message="Bare 'except:' clause catches all exceptions",
                    file_path=file_path,
                    line_number=node.lineno,
                    recommendation="Catch specific exceptions instead of using bare except"
                ))
            
            # Detect potential security issues
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    # Dangerous function calls
                    if node.func.id == 'eval':
                        self.issues.append(CodeIssue(
                            severity='critical',
                            category='security',
                            message="Use of 'eval()' is a security risk",
                            file_path=file_path,
                            line_number=node.lineno,
                            recommendation="Avoid eval(). Use ast.literal_eval() or safer alternatives"
                        ))
                    elif node.func.id == 'exec':
                        self.issues.append(CodeIssue(
                            severity='critical',
                            category='security',
                            message="Use of 'exec()' is a security risk",
                            file_path=file_path,
                            line_number=node.lineno,
                            recommendation="Avoid exec(). Refactor to use safer code patterns"
                        ))
            
            # Detect long functions (potential maintainability issue)
            if isinstance(node, ast.FunctionDef):
                # Count lines in function
                if hasattr(node, 'end_lineno') and node.end_lineno:
                    func_lines = node.end_lineno - node.lineno
                    if func_lines > 50:
                        self.issues.append(CodeIssue(
                            severity='low',
                            category='maintainability',
                            message=f"Function '{node.name}' is too long ({func_lines} lines)",
                            file_path=file_path,
                            line_number=node.lineno,
                            recommendation="Consider breaking into smaller functions"
                        ))
                
                # Check for missing docstrings
                if not ast.get_docstring(node):
                    self.issues.append(CodeIssue(
                        severity='info',
                        category='documentation',
                        message=f"Function '{node.name}' missing docstring",
                        file_path=file_path,
                        line_number=node.lineno,
                        recommendation="Add a docstring describing the function's purpose and parameters"
                    ))
    
    def _analyze_javascript_files(self, files: List[str]):
        """Basic JavaScript analysis"""
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()
                
                lines = code.split('\n')
                
                # Count metrics
                total_lines = len(lines)
                code_lines = sum(1 for line in lines if line.strip() and not line.strip().startswith('//'))
                comment_lines = sum(1 for line in lines if line.strip().startswith('//'))
                
                self.metrics['files'][file_path] = {
                    'loc': total_lines,
                    'code': code_lines,
                    'comments': comment_lines,
                }
                
                # Basic pattern detection
                # Detect console.log in production code
                if 'console.log' in code and 'debug' not in file_path.lower():
                    matches = [(i+1, line) for i, line in enumerate(lines) if 'console.log' in line]
                    for line_num, line in matches:
                        self.issues.append(CodeIssue(
                            severity='low',
                            category='code_smell',
                            message="console.log() should be removed from production code",
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=line.strip(),
                            recommendation="Use a proper logging library or remove debug statements"
                        ))
                
                # Detect eval usage
                if 'eval(' in code:
                    self.issues.append(CodeIssue(
                        severity='critical',
                        category='security',
                        message="Use of eval() is a security risk",
                        file_path=file_path,
                        line_number=0,
                        recommendation="Avoid eval(). Find safer alternatives"
                    ))
                
            except Exception as e:
                logger.error(f"Error analyzing {file_path}: {e}")
    
    def _analyze_security(self):
        """Run security-focused analysis"""
        try:
            # Run bandit for Python security issues
            result = subprocess.run(
                ['bandit', '-r', self.repo_path, '-f', 'json'],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0 or result.returncode == 1:  # 1 means issues found
                bandit_results = json.loads(result.stdout)
                for issue in bandit_results.get('results', []):
                    severity_map = {
                        'HIGH': 'high',
                        'MEDIUM': 'medium',
                        'LOW': 'low'
                    }
                    self.issues.append(CodeIssue(
                        severity=severity_map.get(issue.get('issue_severity', 'MEDIUM'), 'medium'),
                        category='security',
                        message=issue.get('issue_text', 'Security issue found'),
                        file_path=issue.get('filename', ''),
                        line_number=issue.get('line_number', 0),
                        code_snippet=issue.get('code', ''),
                        recommendation=issue.get('issue_text', '')
                    ))
        except Exception as e:
            logger.warning(f"Security analysis with bandit failed: {e}")
    
    def _analyze_code_patterns(self):
        """Analyze code patterns that indicate skill level"""
        patterns = {
            'god_class': 0,  # Classes with too many methods
            'long_parameter_list': 0,  # Functions with many parameters
            'duplicate_code': 0,
            'magic_numbers': 0,
            'nested_complexity': 0,
        }
        
        # Check for god classes (>20 methods indicates poor design)
        for file_path in self.metrics['files'].keys():
            if file_path.endswith('.py'):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        code = f.read()
                    tree = ast.parse(code)
                    
                    for node in ast.walk(tree):
                        if isinstance(node, ast.ClassDef):
                            methods = [n for n in node.body if isinstance(n, ast.FunctionDef)]
                            if len(methods) > 20:
                                patterns['god_class'] += 1
                                self.issues.append(CodeIssue(
                                    severity='medium',
                                    category='design',
                                    message=f"Class '{node.name}' has too many methods ({len(methods)})",
                                    file_path=file_path,
                                    line_number=node.lineno,
                                    recommendation="Consider splitting into smaller, focused classes"
                                ))
                except Exception:
                    pass
        
        self.metrics['patterns'] = patterns
    
    def _calculate_awareness_metrics(self, quality_score: float, security_score: float, 
                                    maintainability_score: float) -> tuple:
        """
        Calculate Dunning-Kruger awareness metrics
        
        This is the secret sauce - detecting overconfidence!
        """
        # Calculate actual skill level from code quality
        actual_skill = (quality_score + security_score + maintainability_score) / 3
        
        # Heuristics for perceived skill level (signs of overconfidence)
        overconfidence_indicators = 0
        total_indicators = 0
        
        # Indicator 1: High complexity without comments (thinks code is self-explanatory)
        high_complexity_funcs = [c for c in self.metrics['complexity'] if c['complexity'] > 10]
        if high_complexity_funcs:
            total_indicators += 1
            total_files = len(self.metrics['files'])
            avg_comments = sum(f.get('comments', 0) for f in self.metrics['files'].values()) / max(total_files, 1)
            if avg_comments < 5:  # Less than 5% comments
                overconfidence_indicators += 1
        
        # Indicator 2: Security issues present (unaware of risks)
        security_issues = [i for i in self.issues if i.category == 'security']
        if security_issues:
            total_indicators += 1
            if len(security_issues) > 3:
                overconfidence_indicators += 1
        
        # Indicator 3: No error handling (assumes things won't fail)
        try_catch_count = 0
        for file_path in self.metrics['files'].keys():
            if file_path.endswith('.py'):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        code = f.read()
                    try_catch_count += code.count('try:')
                except:
                    pass
        
        total_indicators += 1
        total_files = len([f for f in self.metrics['files'].keys() if f.endswith('.py')])
        if total_files > 5 and try_catch_count < total_files * 0.3:  # Less than 30% files have error handling
            overconfidence_indicators += 1
        
        # Indicator 4: High complexity + critical issues (overestimates ability)
        critical_issues = [i for i in self.issues if i.severity == 'critical']
        if critical_issues and high_complexity_funcs:
            total_indicators += 1
            overconfidence_indicators += 1
        
        # Indicator 5: Missing documentation (assumes code is obvious)
        doc_issues = [i for i in self.issues if i.category == 'documentation']
        total_indicators += 1
        if len(doc_issues) > len(self.metrics['files']) * 0.5:
            overconfidence_indicators += 1
        
        # Calculate overconfidence factor (0-1)
        overconfidence = overconfidence_indicators / max(total_indicators, 1)
        
        # Perceived skill = actual skill + overconfidence boost
        # People with DK effect think they're better than they are
        perceived_skill = min(100, actual_skill + (overconfidence * 30))
        
        # Awareness gap (positive = overconfident, negative = underconfident)
        awareness_gap = perceived_skill - actual_skill
        
        # Dunning-Kruger score (0-100, higher = more DK effect)
        dunning_kruger_score = min(100, max(0, awareness_gap * 2))
        
        return actual_skill, awareness_gap, dunning_kruger_score
    
    def _generate_learning_recommendations(self, issues: List[CodeIssue]) -> List[Dict[str, str]]:
        """Generate personalized learning recommendations"""
        recommendations = []
        
        # Group issues by category
        category_counts = {}
        for issue in issues:
            category_counts[issue.category] = category_counts.get(issue.category, 0) + 1
        
        # Sort by frequency
        sorted_categories = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)
        
        # Generate recommendations for top issues
        learning_map = {
            'security': {
                'title': 'Secure Coding Practices',
                'description': 'Learn to identify and prevent security vulnerabilities',
                'resources': ['OWASP Top 10', 'Secure Code Review', 'Security Testing']
            },
            'complexity': {
                'title': 'Code Simplification & Refactoring',
                'description': 'Learn to write simpler, more maintainable code',
                'resources': ['Refactoring patterns', 'Clean Code principles', 'SOLID principles']
            },
            'maintainability': {
                'title': 'Maintainable Code Practices',
                'description': 'Learn to write code that\'s easy to maintain and extend',
                'resources': ['Clean Code by Robert Martin', 'Code Complete', 'Pragmatic Programmer']
            },
            'bug': {
                'title': 'Defensive Programming',
                'description': 'Learn to prevent bugs before they happen',
                'resources': ['Error handling best practices', 'Testing strategies', 'Code reviews']
            },
            'documentation': {
                'title': 'Documentation Best Practices',
                'description': 'Learn to write clear, helpful documentation',
                'resources': ['Writing great documentation', 'Docstring standards', 'API documentation']
            },
            'design': {
                'title': 'Software Design Principles',
                'description': 'Learn better software architecture and design',
                'resources': ['Design Patterns', 'Domain-Driven Design', 'System Architecture']
            }
        }
        
        for category, count in sorted_categories[:3]:  # Top 3 categories
            if category in learning_map:
                rec = learning_map[category].copy()
                rec['priority'] = 'high' if count > 10 else 'medium' if count > 5 else 'low'
                rec['issue_count'] = count
                recommendations.append(rec)
        
        return recommendations
    
    def _calculate_final_metrics(self) -> AnalysisResult:
        """Calculate final scores and create result"""
        # Count lines
        total_files = len(self.metrics['files'])
        total_lines = sum(f.get('loc', 0) for f in self.metrics['files'].values())
        code_lines = sum(f.get('lloc', f.get('code', 0)) for f in self.metrics['files'].values())
        comment_lines = sum(f.get('comments', 0) for f in self.metrics['files'].values())
        blank_lines = sum(f.get('blank', 0) for f in self.metrics['files'].values())
        
        # Complexity metrics
        complexities = [c['complexity'] for c in self.metrics['complexity']]
        avg_complexity = sum(complexities) / len(complexities) if complexities else 0
        max_complexity = max(complexities) if complexities else 0
        complex_funcs = len([c for c in complexities if c > 10])
        
        # Count issues by severity
        critical = len([i for i in self.issues if i.severity == 'critical'])
        high = len([i for i in self.issues if i.severity == 'high'])
        medium = len([i for i in self.issues if i.severity == 'medium'])
        low = len([i for i in self.issues if i.severity == 'low'])
        info = len([i for i in self.issues if i.severity == 'info'])
        security_vulns = len([i for i in self.issues if i.category == 'security'])
        
        # Calculate scores (0-100)
        # Quality score based on issues and complexity
        quality_deductions = (critical * 10) + (high * 5) + (medium * 2) + (low * 0.5)
        complexity_penalty = min(20, avg_complexity * 2)
        quality_score = max(0, 100 - quality_deductions - complexity_penalty)
        
        # Security score
        security_deductions = (critical * 15) + (security_vulns * 10)
        security_score = max(0, 100 - security_deductions)
        
        # Maintainability score
        maintainability_deductions = (complex_funcs * 5) + (medium * 1)
        comment_ratio = comment_lines / max(code_lines, 1)
        maintainability_score = max(0, 100 - maintainability_deductions + (comment_ratio * 10))
        
        # Scalability score (based on design patterns and complexity)
        scalability_score = max(0, 100 - (avg_complexity * 3) - (self.metrics['patterns'].get('god_class', 0) * 10))
        
        # Overall score
        overall_score = (quality_score + security_score + maintainability_score + scalability_score) / 4
        
        # Calculate awareness metrics
        actual_skill, awareness_gap, dk_score = self._calculate_awareness_metrics(
            quality_score, security_score, maintainability_score
        )
        
        # Generate learning recommendations
        learning_recs = self._generate_learning_recommendations(self.issues)
        
        return AnalysisResult(
            quality_score=round(quality_score, 2),
            security_score=round(security_score, 2),
            maintainability_score=round(maintainability_score, 2),
            scalability_score=round(scalability_score, 2),
            overall_score=round(overall_score, 2),
            actual_skill_level=round(actual_skill, 2),
            awareness_gap=round(awareness_gap, 2),
            dunning_kruger_score=round(dk_score, 2),
            total_files=total_files,
            total_lines=total_lines,
            code_lines=code_lines,
            comment_lines=comment_lines,
            blank_lines=blank_lines,
            average_complexity=round(avg_complexity, 2),
            max_complexity=max_complexity,
            complex_functions_count=complex_funcs,
            critical_issues=critical,
            high_issues=high,
            medium_issues=medium,
            low_issues=low,
            info_issues=info,
            security_vulnerabilities=security_vulns,
            issues=self.issues,
            metrics_detail=self.metrics,
            learning_recommendations=learning_recs
        )




