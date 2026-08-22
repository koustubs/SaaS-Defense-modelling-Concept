#!/usr/bin/env python3
"""
DREAD Model Implementation for Threat Assessment
Implements the DREAD (Damage, Reproducibility, Exploitability, Affected Users, Discoverability) model
"""

from dataclasses import dataclass
from typing import Dict, List, Any
import json

@dataclass
class DREADScore:
    """Data class for DREAD scoring"""
    damage: int  # 0-10: Impact of the damage
    reproducibility: int  # 0-10: Rate of someone being able to exploit the vulnerability
    exploitability: int  # 0-10: Success rate of exploiting the vulnerability
    affected_users: int  # 0-10: Number of affected users
    discoverability: int  # 0-10: Difficulty of discovering the vulnerability
    
    # Weights for each category
    DAMAGE_WEIGHT = 3
    REPRODUCIBILITY_WEIGHT = 1
    EXPLOITABILITY_WEIGHT = 2
    AFFECTED_USERS_WEIGHT = 3
    DISCOVERABILITY_WEIGHT = 2
    
    def calculate_weighted_dread(self) -> float:
        """Calculate weighted DREAD score using the specified weights"""
        weighted_sum = (
            self.damage * self.DAMAGE_WEIGHT +
            self.reproducibility * self.REPRODUCIBILITY_WEIGHT +
            self.exploitability * self.EXPLOITABILITY_WEIGHT +
            self.affected_users * self.AFFECTED_USERS_WEIGHT +
            self.discoverability * self.DISCOVERABILITY_WEIGHT
        )
        total_weight = (
            self.DAMAGE_WEIGHT +
            self.REPRODUCIBILITY_WEIGHT +
            self.EXPLOITABILITY_WEIGHT +
            self.AFFECTED_USERS_WEIGHT +
            self.DISCOVERABILITY_WEIGHT
        )
        return round(weighted_sum / total_weight, 2)
    
    def calculate_normal_dread(self) -> float:
        """Calculate normal DREAD score (simple average)"""
        return round((self.damage + self.reproducibility + self.exploitability + 
                     self.affected_users + self.discoverability) / 5, 2)
    
    def get_severity_level(self, weighted_score: float) -> str:
        """Determine severity level based on weighted DREAD score"""
        if weighted_score >= 8.0:
            return "Critical"
        elif weighted_score >= 6.0:
            return "High"
        elif weighted_score >= 4.0:
            return "Medium"
        else:
            return "Low"

class DREADScorer:
    """DREAD scoring system for threat assessment"""
    
    def __init__(self):
        # Predefined DREAD scores for different threat categories
        self.threat_dread_scores = {
            # Spoofing threats
            "STRIDE-S-001": DREADScore(8, 7, 6, 8, 5),  # Authentication bypass
            "STRIDE-S-002": DREADScore(7, 6, 5, 7, 4),  # Identity verification
            
            # Tampering threats
            "STRIDE-T-001": DREADScore(9, 8, 7, 9, 6),  # Data transmission without encryption
            "STRIDE-T-002": DREADScore(8, 7, 6, 8, 5),  # Input validation missing
            
            # Repudiation threats
            "STRIDE-R-001": DREADScore(6, 8, 7, 6, 3),  # No audit trail
            
            # Information Disclosure threats
            "STRIDE-I-001": DREADScore(7, 6, 5, 7, 4),  # Sensitive data in error messages
            "STRIDE-I-002": DREADScore(8, 7, 6, 8, 5),  # Data without access control
            
            # Denial of Service threats
            "STRIDE-D-001": DREADScore(7, 9, 8, 7, 6),  # No rate limiting
            "STRIDE-D-002": DREADScore(8, 8, 7, 8, 5),  # Resource exhaustion
            
            # Elevation of Privilege threats
            "STRIDE-E-001": DREADScore(9, 7, 6, 8, 5),  # Admin access without authorization
            "STRIDE-E-002": DREADScore(8, 7, 6, 7, 4),  # Session management issues
            
            # SaaS Notes specific threats
            "SAAS-NOTES-001": DREADScore(8, 7, 6, 8, 5),  # Insecure public links
            "SAAS-NOTES-002": DREADScore(7, 6, 5, 7, 4),  # Weak password policy
            "SAAS-NOTES-003": DREADScore(6, 5, 4, 6, 3),  # No email verification
            "SAAS-NOTES-004": DREADScore(8, 7, 6, 7, 5),  # Excessive permissions
            "SAAS-NOTES-005": DREADScore(6, 7, 6, 6, 4),  # No logout feature
            "SAAS-NOTES-006": DREADScore(3, 5, 4, 5, 3),  # No login feedback
            "SAAS-NOTES-007": DREADScore(4, 5, 4, 5, 3),  # No password reset confirmation
            "SAAS-NOTES-008": DREADScore(7, 6, 5, 7, 4),  # No MFA
            "SAAS-NOTES-009": DREADScore(6, 7, 6, 6, 4),  # No account lockout
            "SAAS-NOTES-010": DREADScore(5, 6, 5, 5, 3),  # No password strength indicator
            "SAAS-NOTES-011": DREADScore(6, 7, 6, 6, 4),  # No session timeout
            "SAAS-NOTES-012": DREADScore(5, 6, 5, 5, 3),  # No login attempt tracking
            "SAAS-NOTES-013": DREADScore(4, 5, 4, 4, 3),  # No account recovery option
            "SAAS-NOTES-014": DREADScore(6, 7, 6, 6, 4),  # No data encryption at rest
            "SAAS-NOTES-015": DREADScore(7, 6, 5, 7, 4),  # No secure headers
            "SAAS-NOTES-016": DREADScore(5, 6, 5, 5, 3),  # No CSRF protection
            "SAAS-NOTES-017": DREADScore(4, 5, 4, 4, 3),  # No new device notification
            "SAAS-NOTES-018": DREADScore(6, 7, 6, 6, 4),  # No input sanitization
            "SAAS-NOTES-019": DREADScore(5, 6, 5, 5, 3),  # No output encoding
            "SAAS-NOTES-020": DREADScore(7, 6, 5, 7, 4),  # No secure cookie settings
        }
    
    def get_dread_score(self, rule_id: str) -> DREADScore:
        """Get DREAD score for a specific threat rule"""
        return self.threat_dread_scores.get(rule_id, DREADScore(5, 5, 5, 5, 5))
    
    def calculate_threat_rankings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Calculate DREAD scores and rankings for all findings"""
        ranked_findings = []
        
        for finding in findings:
            rule_id = finding.get('rule_id', '')
            dread_score = self.get_dread_score(rule_id)
            
            weighted_dread = dread_score.calculate_weighted_dread()
            normal_dread = dread_score.calculate_normal_dread()
            severity_level = dread_score.get_severity_level(weighted_dread)
            
            # Add DREAD information to the finding
            finding_with_dread = finding.copy()
            finding_with_dread.update({
                'dread_score': {
                    'damage': dread_score.damage,
                    'reproducibility': dread_score.reproducibility,
                    'exploitability': dread_score.exploitability,
                    'affected_users': dread_score.affected_users,
                    'discoverability': dread_score.discoverability,
                    'weighted_dread': weighted_dread,
                    'normal_dread': normal_dread,
                    'severity_level': severity_level
                },
                'severity': severity_level
            })
            
            ranked_findings.append(finding_with_dread)
        
        # Sort by weighted DREAD score (highest first)
        ranked_findings.sort(key=lambda x: x['dread_score']['weighted_dread'], reverse=True)
        
        # Add ranking and force top 2 to Critical
        for i, finding in enumerate(ranked_findings):
            finding['dread_score']['rank'] = i + 1
            if i < 2:
                finding['severity'] = 'Critical'
                finding['dread_score']['severity_level'] = 'Critical'
        
        return ranked_findings
    
    def get_dread_summary(self, ranked_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics for DREAD scores"""
        if not ranked_findings:
            return {}
        
        total_findings = len(ranked_findings)
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        
        weighted_scores = []
        normal_scores = []
        
        for finding in ranked_findings:
            dread_score = finding['dread_score']
            severity = dread_score['severity_level']
            severity_counts[severity] += 1
            
            weighted_scores.append(dread_score['weighted_dread'])
            normal_scores.append(dread_score['normal_dread'])
        
        return {
            'total_findings': total_findings,
            'severity_distribution': severity_counts,
            'average_weighted_dread': round(sum(weighted_scores) / total_findings, 2),
            'average_normal_dread': round(sum(normal_scores) / total_findings, 2),
            'max_weighted_dread': max(weighted_scores),
            'min_weighted_dread': min(weighted_scores),
            'max_normal_dread': max(normal_scores),
            'min_normal_dread': min(normal_scores)
        } 