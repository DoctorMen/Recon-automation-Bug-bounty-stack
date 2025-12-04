#!/usr/bin/env python3
"""
ROSSIAN ETHICAL ENGINE - W.D. Ross's Deontological Pluralism for Security Systems
Copyright © 2025 DoctorMen. All Rights Reserved.

Implements Ross's Prima Facie Duties for ethical decision-making in security contexts.
Balances competing moral obligations using practical wisdom.
"""

from enum import Enum
from dataclasses import dataclass
from typing import Dict, List, Optional
import json


class PrimaFacieDuty(Enum):
    """Ross's seven prima facie duties"""
    FIDELITY = "fidelity"              # Keep promises, be truthful
    REPARATION = "reparation"          # Make amends for harm
    GRATITUDE = "gratitude"            # Return favors
    JUSTICE = "justice"                # Fair distribution
    BENEFICENCE = "beneficence"        # Help others
    SELF_IMPROVEMENT = "self_improvement"  # Develop yourself
    NON_MALEFICENCE = "non_maleficence"    # Don't harm


@dataclass
class DutyScore:
    """Score for a prima facie duty in a given context"""
    duty: PrimaFacieDuty
    score: float  # 0.0 to 1.0
    reasoning: str
    weight: float = 1.0  # Context-specific weight


@dataclass
class EthicalDecision:
    """Ethical decision with Ross's framework"""
    action: str
    primary_duty: PrimaFacieDuty
    duty_scores: Dict[PrimaFacieDuty, float]
    reasoning: str
    conflicts: List[str]
    confidence: float


class RossianEthicalEngine:
    """
    Ethical decision engine based on Ross's deontological pluralism.
    
    Evaluates competing prima facie duties and determines actual duty
    through practical wisdom (contextual judgment).
    """
    
    def __init__(self):
        self.duty_weights = {
            PrimaFacieDuty.FIDELITY: 1.0,
            PrimaFacieDuty.REPARATION: 1.0,
            PrimaFacieDuty.GRATITUDE: 0.8,
            PrimaFacieDuty.JUSTICE: 1.0,
            PrimaFacieDuty.BENEFICENCE: 0.9,
            PrimaFacieDuty.SELF_IMPROVEMENT: 0.7,
            PrimaFacieDuty.NON_MALEFICENCE: 1.2  # Highest weight (do no harm)
        }
        
        self.decision_log = []
    
    def evaluate_security_event(self, event_data: dict) -> EthicalDecision:
        """
        Evaluate a security event through lens of Ross's duties.
        
        Args:
            event_data: Dictionary with event context
                - event_type: 'breach', 'scan_request', 'copyright', etc.
                - severity: 0.0 to 1.0
                - user_type: 'owner', 'researcher', 'attacker', 'unknown'
                - has_authorization: bool
                - potential_harm: 0.0 to 1.0
                - potential_benefit: 0.0 to 1.0
        
        Returns:
            EthicalDecision with recommended action
        """
        # Calculate duty scores
        duty_scores = self._calculate_duty_scores(event_data)
        
        # Find conflicts
        conflicts = self._identify_conflicts(duty_scores)
        
        # Resolve using practical wisdom
        decision = self._resolve_duties(duty_scores, conflicts, event_data)
        
        # Log decision
        self.decision_log.append({
            'event': event_data,
            'decision': decision
        })
        
        return decision
    
    def _calculate_duty_scores(self, event: dict) -> Dict[PrimaFacieDuty, DutyScore]:
        """Calculate score for each prima facie duty"""
        scores = {}
        
        # FIDELITY: Duty to keep promises (to system owner, clients)
        fidelity_score = self._assess_fidelity(event)
        scores[PrimaFacieDuty.FIDELITY] = DutyScore(
            duty=PrimaFacieDuty.FIDELITY,
            score=fidelity_score,
            reasoning=f"Duty to protect system owner's interests: {fidelity_score:.2f}",
            weight=self.duty_weights[PrimaFacieDuty.FIDELITY]
        )
        
        # NON_MALEFICENCE: Duty not to harm
        non_maleficence_score = self._assess_non_maleficence(event)
        scores[PrimaFacieDuty.NON_MALEFICENCE] = DutyScore(
            duty=PrimaFacieDuty.NON_MALEFICENCE,
            score=non_maleficence_score,
            reasoning=f"Duty to avoid harming innocent parties: {non_maleficence_score:.2f}",
            weight=self.duty_weights[PrimaFacieDuty.NON_MALEFICENCE]
        )
        
        # JUSTICE: Duty to be fair
        justice_score = self._assess_justice(event)
        scores[PrimaFacieDuty.JUSTICE] = DutyScore(
            duty=PrimaFacieDuty.JUSTICE,
            score=justice_score,
            reasoning=f"Duty to treat all parties fairly: {justice_score:.2f}",
            weight=self.duty_weights[PrimaFacieDuty.JUSTICE]
        )
        
        # BENEFICENCE: Duty to help
        beneficence_score = self._assess_beneficence(event)
        scores[PrimaFacieDuty.BENEFICENCE] = DutyScore(
            duty=PrimaFacieDuty.BENEFICENCE,
            score=beneficence_score,
            reasoning=f"Duty to maximize good outcomes: {beneficence_score:.2f}",
            weight=self.duty_weights[PrimaFacieDuty.BENEFICENCE]
        )
        
        # REPARATION: Duty to make amends
        reparation_score = self._assess_reparation(event)
        scores[PrimaFacieDuty.REPARATION] = DutyScore(
            duty=PrimaFacieDuty.REPARATION,
            score=reparation_score,
            reasoning=f"Duty to fix vulnerabilities and make amends: {reparation_score:.2f}",
            weight=self.duty_weights[PrimaFacieDuty.REPARATION]
        )
        
        return scores
    
    def _assess_fidelity(self, event: dict) -> float:
        """Assess duty of fidelity (to owner, promises, truth)"""
        score = 0.0
        
        # High fidelity duty if protecting owner's system
        if event.get('event_type') == 'breach':
            score += 0.5
        
        # Higher if severity is high
        score += event.get('severity', 0.0) * 0.3
        
        # Lower if user has authorization (keeping promise to researcher)
        if event.get('has_authorization'):
            score -= 0.2
        
        return max(0.0, min(1.0, score))
    
    def _assess_non_maleficence(self, event: dict) -> float:
        """Assess duty not to harm innocent parties"""
        score = 0.0
        
        # High duty if action could harm legitimate user
        potential_harm = event.get('potential_harm', 0.0)
        score += potential_harm * 0.6
        
        # Higher if user might be researcher/innocent
        if event.get('user_type') in ['researcher', 'unknown']:
            score += 0.3
        
        # Lower if clearly malicious
        if event.get('user_type') == 'attacker':
            score = 0.1
        
        return max(0.0, min(1.0, score))
    
    def _assess_justice(self, event: dict) -> float:
        """Assess duty of fair treatment"""
        score = 0.5  # Baseline: always some duty to be fair
        
        # Higher if dealing with authorized researcher
        if event.get('has_authorization'):
            score += 0.3
        
        # Consider if response is proportional
        severity = event.get('severity', 0.0)
        proposed_response = event.get('proposed_response_severity', 0.0)
        
        if abs(severity - proposed_response) > 0.3:
            score += 0.2  # Disproportionate response raises justice concerns
        
        return max(0.0, min(1.0, score))
    
    def _assess_beneficence(self, event: dict) -> float:
        """Assess duty to maximize good / help others"""
        score = 0.0
        
        # Potential benefit to community
        score += event.get('potential_benefit', 0.0) * 0.5
        
        # Learning opportunity (self-improvement aspect)
        if event.get('is_learning_opportunity'):
            score += 0.2
        
        # Vulnerability disclosure benefits community
        if event.get('is_vulnerability_disclosure'):
            score += 0.4
        
        return max(0.0, min(1.0, score))
    
    def _assess_reparation(self, event: dict) -> float:
        """Assess duty to make amends / fix issues"""
        score = 0.0
        
        # Duty to fix if vulnerability found
        if event.get('vulnerability_found'):
            score += 0.6
        
        # Higher if this exposed a weakness in our system
        if event.get('exposed_system_weakness'):
            score += 0.3
        
        return max(0.0, min(1.0, score))
    
    def _identify_conflicts(self, duty_scores: Dict[PrimaFacieDuty, DutyScore]) -> List[str]:
        """Identify conflicting duties"""
        conflicts = []
        
        # Get weighted scores
        weighted = {
            duty: score.score * score.weight 
            for duty, score in duty_scores.items()
        }
        
        # Find high-scoring duties
        high_duties = [duty for duty, score in weighted.items() if score > 0.5]
        
        # Specific conflicts
        if (weighted[PrimaFacieDuty.FIDELITY] > 0.6 and 
            weighted[PrimaFacieDuty.NON_MALEFICENCE] > 0.6):
            conflicts.append(
                "CONFLICT: Fidelity to owner vs Non-maleficence to potential innocent user"
            )
        
        if (weighted[PrimaFacieDuty.JUSTICE] > 0.6 and 
            weighted[PrimaFacieDuty.FIDELITY] > 0.6):
            conflicts.append(
                "CONFLICT: Fair treatment of all vs Strict protection of owner"
            )
        
        if (weighted[PrimaFacieDuty.BENEFICENCE] > 0.6 and 
            weighted[PrimaFacieDuty.FIDELITY] > 0.6):
            conflicts.append(
                "CONFLICT: Community benefit vs Owner protection"
            )
        
        return conflicts
    
    def _resolve_duties(self, duty_scores: Dict[PrimaFacieDuty, DutyScore], 
                       conflicts: List[str], event: dict) -> EthicalDecision:
        """
        Resolve competing duties using practical wisdom.
        
        Ross: The actual duty is the one that, in the situation, 
        has the greatest balance of prima facie rightness over wrongness.
        """
        # Calculate weighted scores
        weighted_scores = {
            duty: score.score * score.weight 
            for duty, score in duty_scores.items()
        }
        
        # Find primary duty (highest weighted score)
        primary_duty = max(weighted_scores, key=weighted_scores.get)
        primary_score = weighted_scores[primary_duty]
        
        # Decision logic based on primary duty
        action, reasoning, confidence = self._determine_action(
            primary_duty, primary_score, weighted_scores, event
        )
        
        return EthicalDecision(
            action=action,
            primary_duty=primary_duty,
            duty_scores=weighted_scores,
            reasoning=reasoning,
            conflicts=conflicts,
            confidence=confidence
        )
    
    def _determine_action(self, primary_duty: PrimaFacieDuty, primary_score: float,
                         all_scores: Dict[PrimaFacieDuty, float], event: dict):
        """Determine specific action based on primary duty"""
        
        # NON_MALEFICENCE is primary (do no harm)
        if primary_duty == PrimaFacieDuty.NON_MALEFICENCE:
            if primary_score > 0.8:
                return (
                    "LOG_ONLY",
                    f"Prima facie duty of non-maleficence ({primary_score:.2f}) is paramount. "
                    "High risk of harming innocent party. Log event but do not alert/block.",
                    0.85
                )
            elif primary_score > 0.6:
                return (
                    "MONITOR_AND_VERIFY",
                    f"Duty of non-maleficence ({primary_score:.2f}) requires caution. "
                    "Monitor behavior before taking action.",
                    0.70
                )
        
        # FIDELITY is primary (protect owner)
        if primary_duty == PrimaFacieDuty.FIDELITY:
            if primary_score > 0.8 and all_scores[PrimaFacieDuty.NON_MALEFICENCE] < 0.3:
                return (
                    "ALERT_IMMEDIATELY",
                    f"Prima facie duty of fidelity ({primary_score:.2f}) to owner is paramount. "
                    "Low risk of false positive. Alert immediately.",
                    0.90
                )
            elif primary_score > 0.6:
                return (
                    "GRADUATED_RESPONSE",
                    f"Duty of fidelity ({primary_score:.2f}) suggests protection, "
                    "but competing duties require measured response.",
                    0.75
                )
        
        # JUSTICE is primary (fairness)
        if primary_duty == PrimaFacieDuty.JUSTICE:
            return (
                "PROPORTIONAL_RESPONSE",
                f"Prima facie duty of justice ({primary_score:.2f}) requires "
                "fair and proportional response to all parties.",
                0.75
            )
        
        # BENEFICENCE is primary (maximize good)
        if primary_duty == PrimaFacieDuty.BENEFICENCE:
            if event.get('is_vulnerability_disclosure'):
                return (
                    "FACILITATE_DISCLOSURE",
                    f"Duty of beneficence ({primary_score:.2f}) to community "
                    "suggests facilitating responsible disclosure.",
                    0.80
                )
        
        # REPARATION is primary (fix issues)
        if primary_duty == PrimaFacieDuty.REPARATION:
            return (
                "FIX_AND_IMPROVE",
                f"Prima facie duty of reparation ({primary_score:.2f}) "
                "requires fixing vulnerabilities and improving system.",
                0.85
            )
        
        # Default: balanced approach
        return (
            "CONTEXTUAL_JUDGMENT_REQUIRED",
            f"Competing duties ({primary_duty.value}: {primary_score:.2f}) "
            "require human judgment for resolution.",
            0.50
        )
    
    def explain_decision(self, decision: EthicalDecision) -> str:
        """Generate human-readable explanation of ethical decision"""
        explanation = f"""
ETHICAL DECISION ANALYSIS (Ross's Deontological Pluralism)
{'='*70}

PRIMARY DUTY: {decision.primary_duty.value.upper()}
RECOMMENDED ACTION: {decision.action}
CONFIDENCE: {decision.confidence:.0%}

REASONING:
{decision.reasoning}

PRIMA FACIE DUTY SCORES:
"""
        for duty, score in sorted(decision.duty_scores.items(), 
                                 key=lambda x: x[1], reverse=True):
            bar = '#' * int(score * 20)
            explanation += f"  {duty.value:20s} [{score:.2f}] {bar}\n"
        
        if decision.conflicts:
            explanation += f"\nCONFLICTING DUTIES:\n"
            for conflict in decision.conflicts:
                explanation += f"  - {conflict}\n"
        
        explanation += f"\n{'='*70}\n"
        
        return explanation


# Example usage functions
def example_breach_analysis():
    """Example: Analyzing a potential security breach"""
    engine = RossianEthicalEngine()
    
    # Scenario: Unauthorized file access, but might be legitimate researcher
    event = {
        'event_type': 'breach',
        'severity': 0.7,
        'user_type': 'unknown',
        'has_authorization': False,
        'potential_harm': 0.6,  # Could be false positive
        'potential_benefit': 0.2,
        'proposed_response_severity': 0.9  # Very aggressive response proposed
    }
    
    decision = engine.evaluate_security_event(event)
    print(engine.explain_decision(decision))
    
    return decision


def example_vulnerability_disclosure():
    """Example: Researcher wants to disclose vulnerability"""
    engine = RossianEthicalEngine()
    
    event = {
        'event_type': 'disclosure_request',
        'severity': 0.9,  # Critical vulnerability
        'user_type': 'researcher',
        'has_authorization': True,
        'potential_harm': 0.1,
        'potential_benefit': 0.9,  # Huge benefit to community
        'is_vulnerability_disclosure': True,
        'vulnerability_found': True
    }
    
    decision = engine.evaluate_security_event(event)
    print(engine.explain_decision(decision))
    
    return decision


def example_copyright_decision():
    """Example: Deciding on copyright for derived work"""
    engine = RossianEthicalEngine()
    
    event = {
        'event_type': 'copyright',
        'severity': 0.5,
        'user_type': 'owner',
        'has_authorization': True,
        'potential_harm': 0.3,  # Might harm open source community
        'potential_benefit': 0.7,  # Educational value
        'is_learning_opportunity': True,
        'exposed_system_weakness': False
    }
    
    decision = engine.evaluate_security_event(event)
    print(engine.explain_decision(decision))
    
    return decision


if __name__ == '__main__':
    print("ROSSIAN ETHICAL ENGINE - Examples\n")
    
    print("\n" + "="*70)
    print("EXAMPLE 1: Potential Security Breach (Unknown User)")
    print("="*70)
    example_breach_analysis()
    
    print("\n" + "="*70)
    print("EXAMPLE 2: Vulnerability Disclosure Request")
    print("="*70)
    example_vulnerability_disclosure()
    
    print("\n" + "="*70)
    print("EXAMPLE 3: Copyright Decision for Educational Content")
    print("="*70)
    example_copyright_decision()
