"""
Natural Language Processor for AI Workflow Automation Platform
Copyright © 2025. All Rights Reserved.
"""

import re
from typing import Dict, List, Any, Optional

class NLPProcessor:
    """Handles natural language processing for command interpretation"""
    
    def __init__(self):
        self.intent_patterns = {
            'analyze': [
                r'\banalyze\b', r'\bexamine\b', r'\breview\b', 
                r'\baudit\b', r'\bassess\b', r'\bevaluate\b'
            ],
            'optimize': [
                r'\boptimize\b', r'\bimprove\b', r'\benhance\b', 
                r'\bstreamline\b', r'\bmake better\b'
            ],
            'automate': [
                r'\bautomate\b', r'\bautomated\b', r'\bautomatic\b', 
                r'\bcreate workflow\b', r'\bbuild automation\b'
            ],
            'generate': [
                r'\bgenerate\b', r'\bcreate\b', r'\bproduce\b', 
                r'\bmake\b', r'\bbuild\b', r'\bdevelop\b'
            ],
            'monitor': [
                r'\bmonitor\b', r'\bwatch\b', r'\btrack\b', 
                r'\bobserve\b', r'\bkeep an eye on\b'
            ],
            'integrate': [
                r'\bintegrate\b', r'\bconnect\b', r'\blink\b', 
                r'\bcombine\b', r'\bmerge\b'
            ]
        }
        
        self.entity_patterns = {
            'timeframe': {
                'daily': r'\b(daily|every day|each day)\b',
                'weekly': r'\b(weekly|every week|each week)\b',
                'monthly': r'\b(monthly|every month|each month)\b',
                'quarterly': r'\b(quarterly|q[1-4]|quarter)\b',
                'yearly': r'\b(yearly|annually|every year)\b'
            },
            'business_process': {
                'customer_onboarding': r'\bcustomer (onboarding|registration)\b',
                'sales_process': r'\bsales (process|workflow|pipeline)\b',
                'report_generation': r'\b(report generation|generate reports?)\b',
                'data_analysis': r'\b(data analysis|analyze data)\b',
                'compliance_audit': r'\b(compliance (audit|check)|regulatory)\b',
                'inventory_management': r'\binventory (management|control)\b',
                'order_processing': r'\border (processing|fulfillment)\b',
                'support_ticket': r'\bsupport (ticket|system|workflow)\b'
            },
            'metrics': {
                'revenue': r'\brevenue\b',
                'cost': r'\bcost(s?)\b',
                'efficiency': r'\befficiency\b',
                'productivity': r'\bproductivity\b',
                'satisfaction': r'\bsatisfaction\b',
                'conversion': r'\bconversion (rate)?\b',
                'churn': r'\bchurn (rate)?\b',
                'performance': r'\bperformance\b'
            }
        }
    
    async def initialize(self):
        """Initialize the NLP processor"""
        # In a real implementation, this would load models, dictionaries, etc.
        pass
    
    async def extract_intent(self, text: str) -> str:
        """Extract the primary intent from the text"""
        text_lower = text.lower()
        
        intent_scores = {}
        
        for intent, patterns in self.intent_patterns.items():
            score = 0
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    score += 1
            intent_scores[intent] = score
        
        # Return intent with highest score, or 'general' if no matches
        best_intent = max(intent_scores.items(), key=lambda x: x[1])
        return best_intent[0] if best_intent[1] > 0 else 'general'
    
    async def extract_entities(self, text: str) -> Dict[str, Any]:
        """Extract entities from the text"""
        entities = {}
        text_lower = text.lower()
        
        # Extract timeframes
        for timeframe, pattern in self.entity_patterns['timeframe'].items():
            if re.search(pattern, text_lower):
                entities['timeframe'] = timeframe
                break
        
        # Extract business processes
        for process, pattern in self.entity_patterns['business_process'].items():
            if re.search(pattern, text_lower):
                entities['business_process'] = process
                break
        
        # Extract metrics
        found_metrics = []
        for metric, pattern in self.entity_patterns['metrics'].items():
            if re.search(pattern, text_lower):
                found_metrics.append(metric)
        
        if found_metrics:
            entities['metrics'] = found_metrics
        
        # Extract data sources
        data_patterns = [
            'sales data', 'customer data', 'financial data', 'analytics',
            'logs', 'database', 'api', 'spreadsheet', 'reports'
        ]
        
        for data_source in data_patterns:
            if data_source in text_lower:
                entities['data_source'] = data_source
                break
        
        return entities
    
    async def extract_keywords(self, text: str) -> List[str]:
        """Extract important keywords from text"""
        # Simple keyword extraction - in production would use more sophisticated NLP
        words = re.findall(r'\b\w+\b', text.lower())
        
        # Filter out common stop words
        stop_words = {
            'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
            'of', 'with', 'by', 'is', 'are', 'was', 'were', 'be', 'been', 'have',
            'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should'
        }
        
        keywords = [word for word in words if word not in stop_words and len(word) > 2]
        
        # Return unique keywords
        return list(set(keywords))
    
    async def analyze_sentiment(self, text: str) -> str:
        """Analyze sentiment of text (simplified)"""
        positive_words = ['optimize', 'improve', 'enhance', 'streamline', 'success']
        negative_words = ['problem', 'issue', 'error', 'failure', 'broken']
        
        text_lower = text.lower()
        
        positive_count = sum(1 for word in positive_words if word in text_lower)
        negative_count = sum(1 for word in negative_words if word in text_lower)
        
        if positive_count > negative_count:
            return 'positive'
        elif negative_count > positive_count:
            return 'negative'
        else:
            return 'neutral'
