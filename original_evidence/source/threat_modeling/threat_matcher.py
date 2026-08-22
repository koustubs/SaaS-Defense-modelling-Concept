#!/usr/bin/env python3
"""
Threat Matcher for Sequence Diagrams
Parses PlantUML sequence diagrams and matches them against threat rule sets
"""

import json
import re
import sys
import os
from datetime import datetime
from typing import List, Dict, Tuple, Any
from dataclasses import dataclass, asdict
from dread_scorer import DREADScorer
from dread_scorer import DREADScorer

@dataclass
class ThreatFinding:
    """Data class for threat findings"""
    id: str
    title: str
    source: str
    description: str
    impact: str
    likelihood: str
    severity: str
    mitigation: str
    status: str
    last_updated: str
    rule_id: str
    category: str
    matched_pattern: str
    evidence: List[str]

class ThreatMatcher:
    def __init__(self, rules_file: str):
        """Initialize the threat matcher with rules file"""
        self.rules_file = rules_file
        self.threat_rules = []
        self.findings = []
        self.dread_scorer = DREADScorer()
        self.load_rules()
    
    def load_rules(self):
        """Load threat rules from JSON file"""
        try:
            with open(self.rules_file, 'r', encoding='utf-8') as file:
                data = json.load(file)
                self.threat_rules = data.get('threat_rules', [])
            print(f"Loaded {len(self.threat_rules)} threat rules")
        except FileNotFoundError:
            print(f"Error: Rules file {self.rules_file} not found!")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error parsing rules file: {e}")
            sys.exit(1)
    
    def parse_sequence_diagram(self, uml_file: str) -> Dict[str, Any]:
        """Parse PlantUML sequence diagram and extract components"""
        try:
            with open(uml_file, 'r', encoding='utf-8') as file:
                content = file.read()
        except FileNotFoundError:
            print(f"Error: UML file {uml_file} not found!")
            return {}
        
        # Extract title
        title_match = re.search(r'title\s+(.+)', content, re.IGNORECASE)
        title = title_match.group(1).strip() if title_match else "Sequence Diagram"
        
        # Extract actors and participants
        actors = []
        participants = []
        
        # Parse actors
        actor_pattern = r'actor\s+"([^"]+)"\s+as\s+(\w+)'
        for match in re.finditer(actor_pattern, content, re.IGNORECASE):
            actors.append({
                'name': match.group(1).strip(),
                'alias': match.group(2).strip(),
                'type': 'actor'
            })
        
        # Parse participants
        participant_pattern = r'participant\s+"([^"]+)"\s+as\s+(\w+)'
        for match in re.finditer(participant_pattern, content, re.IGNORECASE):
            participants.append({
                'name': match.group(1).strip(),
                'alias': match.group(2).strip(),
                'type': 'participant'
            })
        
        # Parse interactions
        interactions = []
        
        # Simple interactions: A -> B : message
        interaction_pattern = r'(\w+)\s*->\s*(\w+)\s*:\s*(.+)'
        for match in re.finditer(interaction_pattern, content):
            interactions.append({
                'from': match.group(1).strip(),
                'to': match.group(2).strip(),
                'message': match.group(3).strip(),
                'type': 'request'
            })
        
        # Responses: A --> B : response
        response_pattern = r'(\w+)\s*-->\s*(\w+)\s*:\s*(.+)'
        for match in re.finditer(response_pattern, content):
            interactions.append({
                'from': match.group(1).strip(),
                'to': match.group(2).strip(),
                'message': match.group(3).strip(),
                'type': 'response'
            })
        
        return {
            'title': title,
            'actors': actors,
            'participants': participants,
            'interactions': interactions,
            'content': content
        }
    
    def check_authentication_sequence(self, interactions: List[Dict]) -> bool:
        """Check if authentication sequence exists in interactions"""
        auth_keywords = ['login', 'auth', 'authenticate', 'session', 'token']
        for interaction in interactions:
            message_lower = interaction['message'].lower()
            if any(keyword in message_lower for keyword in auth_keywords):
                return True
        return False
    
    def check_sensitive_action_without_auth(self, rule: Dict, interactions: List[Dict]) -> List[str]:
        """Check for sensitive actions without authentication"""
        evidence = []
        has_auth = self.check_authentication_sequence(interactions)
        
        if not has_auth:
            sensitive_actions = rule.get('sensitive_actions', [])
            for interaction in interactions:
                message_lower = interaction['message'].lower()
                if any(action in message_lower for action in sensitive_actions):
                    evidence.append(f"Sensitive action '{interaction['message']}' called by '{interaction['from']}' without authentication")
        
        return evidence
    
    def check_data_transmission_security(self, rule: Dict, interactions: List[Dict]) -> List[str]:
        """Check for insecure data transmission"""
        evidence = []
        insecure_keywords = rule.get('keywords', [])
        
        for interaction in interactions:
            message_lower = interaction['message'].lower()
            if any(keyword in message_lower for keyword in insecure_keywords):
                evidence.append(f"Insecure transmission detected: '{interaction['message']}' from '{interaction['from']}' to '{interaction['to']}'")
        
        return evidence
    
    def check_input_validation(self, rule: Dict, interactions: List[Dict]) -> List[str]:
        """Check for missing input validation"""
        evidence = []
        validation_keywords = rule.get('keywords', [])
        
        # Check if validation keywords are present in any interaction
        has_validation = False
        for interaction in interactions:
            message_lower = interaction['message'].lower()
            if any(keyword in message_lower for keyword in validation_keywords):
                has_validation = True
                break
        
        if not has_validation:
            # Look for input-related actions without validation
            input_actions = ['input', 'submit', 'create', 'update']
            for interaction in interactions:
                message_lower = interaction['message'].lower()
                if any(action in message_lower for action in input_actions):
                    evidence.append(f"Input action '{interaction['message']}' without validation from '{interaction['from']}'")
        
        return evidence
    
    def check_audit_logging(self, rule: Dict, interactions: List[Dict]) -> List[str]:
        """Check for missing audit logging"""
        evidence = []
        logging_keywords = rule.get('keywords', [])
        sensitive_actions = rule.get('sensitive_actions', [])
        
        # Check if logging is present
        has_logging = False
        for interaction in interactions:
            message_lower = interaction['message'].lower()
            if any(keyword in message_lower for keyword in logging_keywords):
                has_logging = True
                break
        
        if not has_logging:
            for interaction in interactions:
                message_lower = interaction['message'].lower()
                if any(action in message_lower for action in sensitive_actions):
                    evidence.append(f"Sensitive action '{interaction['message']}' without audit logging from '{interaction['from']}'")
        
        return evidence
    
    def check_error_handling(self, rule: Dict, interactions: List[Dict]) -> List[str]:
        """Check for sensitive data in error messages"""
        evidence = []
        error_keywords = rule.get('keywords', [])
        
        for interaction in interactions:
            message_lower = interaction['message'].lower()
            if any(keyword in message_lower for keyword in error_keywords):
                # Check if error message might contain sensitive data
                if any(sensitive in message_lower for sensitive in ['password', 'token', 'key', 'secret']):
                    evidence.append(f"Potential sensitive data in error message: '{interaction['message']}'")
        
        return evidence
    
    def check_access_control(self, rule: Dict, interactions: List[Dict]) -> List[str]:
        """Check for missing access control"""
        evidence = []
        access_keywords = rule.get('keywords', [])
        data_actions = ['get', 'retrieve', 'fetch', 'download', 'view']
        
        # Check if access control is present
        has_access_control = False
        for interaction in interactions:
            message_lower = interaction['message'].lower()
            if any(keyword in message_lower for keyword in access_keywords):
                has_access_control = True
                break
        
        if not has_access_control:
            for interaction in interactions:
                message_lower = interaction['message'].lower()
                if any(action in message_lower for action in data_actions):
                    evidence.append(f"Data access '{interaction['message']}' without access control from '{interaction['from']}'")
        
        return evidence
    
    def check_rate_limiting(self, rule: Dict, interactions: List[Dict]) -> List[str]:
        """Check for missing rate limiting"""
        evidence = []
        rate_limit_keywords = rule.get('keywords', [])
        api_actions = ['api', 'request', 'call', 'invoke']
        
        # Check if rate limiting is present
        has_rate_limiting = False
        for interaction in interactions:
            message_lower = interaction['message'].lower()
            if any(keyword in message_lower for keyword in rate_limit_keywords):
                has_rate_limiting = True
                break
        
        if not has_rate_limiting:
            for interaction in interactions:
                message_lower = interaction['message'].lower()
                if any(action in message_lower for action in api_actions):
                    evidence.append(f"API call '{interaction['message']}' without rate limiting from '{interaction['from']}'")
        
        return evidence
    
    def check_privilege_escalation(self, rule: Dict, interactions: List[Dict]) -> List[str]:
        """Check for privilege escalation vulnerabilities"""
        evidence = []
        privilege_keywords = rule.get('keywords', [])
        admin_actions = ['configure', 'manage', 'delete', 'export', 'import']
        
        for interaction in interactions:
            message_lower = interaction['message'].lower()
            if any(action in message_lower for action in admin_actions):
                # Check if privilege check is present
                has_privilege_check = False
                for other_interaction in interactions:
                    other_message_lower = other_interaction['message'].lower()
                    if any(keyword in other_message_lower for keyword in privilege_keywords):
                        has_privilege_check = True
                        break
                
                if not has_privilege_check:
                    evidence.append(f"Admin action '{interaction['message']}' without privilege check from '{interaction['from']}'")
        
        return evidence
    
    def check_saas_notes_threats(self, rule: Dict, interactions: List[Dict], content: str) -> list:
        """Simple keyword-based detection for SaaS notes app rules"""
        evidence = []
        rule_id = rule.get('id', '')
        
        # MFA: No sign of MFA in login flow
        if rule_id == 'SAAS-NOTES-008':
            login_msgs = [i['message'].lower() for i in interactions if 'login' in i['message'].lower()]
            if any('mfa' not in msg and 'otp' not in msg for msg in login_msgs):
                evidence.append("Login flow does not mention MFA/OTP.")
        
        # Lockout: Multiple failed logins, no lockout/captcha
        elif rule_id == 'SAAS-NOTES-009':
            if 'loop 10 times' in content.lower() and not any('lockout' in i['message'].lower() or 'captcha' in i['message'].lower() for i in interactions):
                evidence.append("Multiple failed logins allowed without lockout or CAPTCHA.")
        
        # Autosave: Edit note, no autosave
        elif rule_id == 'SAAS-NOTES-015':
            if any('edit' in i['message'].lower() for i in interactions) and 'autosave' not in content.lower():
                evidence.append("Note editing functionality without autosave feature.")
        
        # Delete confirmation: Delete note, no confirm
        elif rule_id == 'SAAS-NOTES-016':
            if any('delete' in i['message'].lower() for i in interactions) and 'confirm' not in content.lower():
                evidence.append("Note deletion without confirmation dialog.")
        
        # New device notification: Login from new device, no notification
        elif rule_id == 'SAAS-NOTES-017':
            if 'new device' in content.lower() and not any('notification' in i['message'].lower() or 'alert' in i['message'].lower() for i in interactions):
                evidence.append("Login from new device without user notification.")
        
        # Password strength indicator
        elif rule_id == 'SAAS-NOTES-018':
            password_related = any('password' in i['message'].lower() or 'register' in i['message'].lower() or 'signup' in i['message'].lower() for i in interactions)
            has_strength_indicator = any('strength' in i['message'].lower() or 'weak' in i['message'].lower() or 'strong' in i['message'].lower() for i in interactions)
            if password_related and not has_strength_indicator:
                evidence.append("Password entry without strength indicator feedback.")
        
        # Session inactivity warning
        elif rule_id == 'SAAS-NOTES-019':
            has_timeout = any('timeout' in i['message'].lower() or 'expire' in i['message'].lower() for i in interactions)
            has_warning = any('warning' in i['message'].lower() or 'alert' in i['message'].lower() for i in interactions)
            if has_timeout and not has_warning:
                evidence.append("Session timeout implemented without inactivity warning.")
        
        return evidence
    
    def match_threats(self, diagram_data: Dict[str, Any]) -> List[ThreatFinding]:
        """Match diagram against threat rules and return findings"""
        findings = []
        interactions = diagram_data.get('interactions', [])
        content = diagram_data.get('content', '')
        
        for rule in self.threat_rules:
            evidence = []
            
            # Apply different checks based on rule category
            if rule['category'] == 'Spoofing':
                if rule['id'] == 'STRIDE-S-001':
                    evidence = self.check_sensitive_action_without_auth(rule, interactions)
                elif rule['id'] == 'STRIDE-S-002':
                    evidence = self.check_sensitive_action_without_auth(rule, interactions)
            
            elif rule['category'] == 'Tampering':
                if rule['id'] == 'STRIDE-T-001':
                    evidence = self.check_data_transmission_security(rule, interactions)
                elif rule['id'] == 'STRIDE-T-002':
                    evidence = self.check_input_validation(rule, interactions)
            
            elif rule['category'] == 'Repudiation':
                if rule['id'] == 'STRIDE-R-001':
                    evidence = self.check_audit_logging(rule, interactions)
            
            elif rule['category'] == 'Information Disclosure':
                if rule['id'] == 'STRIDE-I-001':
                    evidence = self.check_error_handling(rule, interactions)
                elif rule['id'] == 'STRIDE-I-002':
                    evidence = self.check_access_control(rule, interactions)
            
            elif rule['category'] == 'Denial of Service':
                if rule['id'] == 'STRIDE-D-001':
                    evidence = self.check_rate_limiting(rule, interactions)
                elif rule['id'] == 'STRIDE-D-002':
                    evidence = self.check_rate_limiting(rule, interactions)
            
            elif rule['category'] == 'Elevation of Privilege':
                if rule['id'] == 'STRIDE-E-001':
                    evidence = self.check_privilege_escalation(rule, interactions)
                elif rule['id'] == 'STRIDE-E-002':
                    evidence = self.check_audit_logging(rule, interactions)
            
            # SaaS-specific rules (medium/low)
            if rule.get('id', '').startswith('SAAS-NOTES-'):
                evidence = self.check_saas_notes_threats(rule, interactions, content)
            
            # If evidence found, create a finding
            if evidence:
                # Use severity from rule if present, else determine based on category and impact
                severity = rule.get('severity', None)
                if not severity:
                    if rule['category'] in ['Spoofing', 'Elevation of Privilege']:
                        severity = "Critical"
                    elif rule['category'] in ['Tampering', 'Information Disclosure', 'Denial of Service']:
                        severity = "High"
                    elif rule['category'] in ['Repudiation']:
                        severity = "Medium"
                    else:
                        severity = "Low"
                
                finding = ThreatFinding(
                    id=f"TF-SD-{len(findings) + 1:03d}",
                    title=rule['pattern'],
                    source="Sequence Diagram",
                    description=f"The diagram shows {', '.join(evidence[:2])}.",
                    impact=f"{rule['category']}, {rule['impact']}",
                    likelihood="High" if len(evidence) > 2 else "Medium",
                    severity=severity,
                    mitigation=rule['recommendation'],
                    status="Open",
                    last_updated=datetime.now().strftime("%Y-%m-%d"),
                    rule_id=rule['id'],
                    category=rule['category'],
                    matched_pattern=rule['pattern'],
                    evidence=evidence
                )
                findings.append(finding)
        
        return findings
    
    def generate_threat_report(self, findings: List[ThreatFinding], output_file: str = "threat_report.json"):
        """Generate threat report in JSON format with DREAD scoring"""
        # Convert findings to dict format for DREAD scoring
        findings_dict = [asdict(finding) for finding in findings]
        
        # Calculate DREAD scores and rankings
        ranked_findings = self.dread_scorer.calculate_threat_rankings(findings_dict)
        dread_summary = self.dread_scorer.get_dread_summary(ranked_findings)
        
        report = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "total_findings": len(findings),
                "report_type": "Threat Analysis Report with DREAD Scoring"
            },
            "dread_summary": dread_summary,
            "findings": ranked_findings
        }
        
        with open(output_file, 'w', encoding='utf-8') as file:
            json.dump(report, file, indent=2, ensure_ascii=False)
        
        print(f"Threat report with DREAD scoring generated: {output_file}")
        return report

def main():
    """Main function to run threat matching"""
    if len(sys.argv) < 2:
        print("Usage: python threat_matcher.py <sequence_diagram.uml> [rules_file.json]")
        sys.exit(1)
    
    uml_file = sys.argv[1]
    rules_file = sys.argv[2] if len(sys.argv) > 2 else "threat_rules.json"
    
    # Initialize threat matcher
    matcher = ThreatMatcher(rules_file)
    
    # Parse sequence diagram
    print(f"Parsing sequence diagram: {uml_file}")
    diagram_data = matcher.parse_sequence_diagram(uml_file)
    
    if not diagram_data:
        print("Failed to parse sequence diagram")
        sys.exit(1)
    
    print(f"Found {len(diagram_data['interactions'])} interactions")
    
    # Match threats
    print("Matching threats against rules...")
    findings = matcher.match_threats(diagram_data)
    
    print(f"Found {len(findings)} potential threats")
    
    # Generate report
    output_file = f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    matcher.generate_threat_report(findings, output_file)
    
    # Print summary
    print("\n=== THREAT ANALYSIS SUMMARY ===")
    for finding in findings:
        print(f"\n[{finding.category}] {finding.title}")
        print(f"Severity: {finding.severity}, Likelihood: {finding.likelihood}")
        print(f"Evidence: {finding.evidence[0] if finding.evidence else 'No specific evidence'}")
        print(f"Mitigation: {finding.mitigation}")

if __name__ == "__main__":
    main() 