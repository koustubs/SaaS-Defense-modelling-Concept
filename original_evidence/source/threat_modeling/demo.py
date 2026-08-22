#!/usr/bin/env python3
"""
Demo script for Threat Modeling System
Shows various usage examples and configurations
"""

import json
import os
from threat_matcher import ThreatMatcher
from html_report_generator import HTMLReportGenerator

def demo_basic_usage():
    """Demonstrate basic usage of the threat matcher"""
    print("=== Basic Usage Demo ===\n")
    
    # Initialize threat matcher
    matcher = ThreatMatcher("threat_rules.json")
    
    # Parse sequence diagram
    diagram_data = matcher.parse_sequence_diagram("sample_notes_app.uml")
    
    print(f"Analyzing: {diagram_data['title']}")
    print(f"Found {len(diagram_data['interactions'])} interactions")
    
    # Find threats
    findings = matcher.match_threats(diagram_data)
    
    print(f"Identified {len(findings)} potential threats")
    
    # Generate reports
    matcher.generate_threat_report(findings, "demo_threat_report.json")
    
    # Generate HTML report
    generator = HTMLReportGenerator()
    with open("demo_threat_report.json", "r") as f:
        findings_data = json.load(f)
    generator.generate_html_report(findings_data, "demo_threat_report.html")
    
    print("Reports generated: demo_threat_report.json, demo_threat_report.html")

def demo_custom_rules():
    """Demonstrate using custom threat rules"""
    print("\n=== Custom Rules Demo ===\n")
    
    # Create custom rules
    custom_rules = {
        "threat_rules": [
            {
                "id": "CUSTOM-001",
                "category": "Custom",
                "pattern": "Direct database access without service layer",
                "match_condition": "Client directly accesses database",
                "impact": "Bypass business logic, direct data manipulation",
                "recommendation": "Always access data through service layer",
                "applies_to": "Sequence Diagram",
                "keywords": ["database", "db", "direct"],
                "sensitive_actions": ["query", "insert", "update", "delete"]
            }
        ]
    }
    
    # Save custom rules
    with open("custom_rules.json", "w") as f:
        json.dump(custom_rules, f, indent=2)
    
    print("Created custom rules file: custom_rules.json")
    
    # Use custom rules
    matcher = ThreatMatcher("custom_rules.json")
    diagram_data = matcher.parse_sequence_diagram("sample_notes_app.uml")
    findings = matcher.match_threats(diagram_data)
    
    print(f"Custom analysis found {len(findings)} threats")

def demo_threat_statistics():
    """Show threat statistics and categorization"""
    print("\n=== Threat Statistics Demo ===\n")
    
    # Load existing report
    with open("test_threat_report.json", "r") as f:
        findings_data = json.load(f)
    
    findings = findings_data['findings']
    
    # Calculate statistics
    total = len(findings)
    by_category = {}
    by_severity = {}
    
    for finding in findings:
        category = finding['category']
        severity = finding['severity']
        
        by_category[category] = by_category.get(category, 0) + 1
        by_severity[severity] = by_severity.get(severity, 0) + 1
    
    print(f"Total Findings: {total}")
    print("\nBy Category:")
    for category, count in by_category.items():
        print(f"  {category}: {count}")
    
    print("\nBy Severity:")
    for severity, count in by_severity.items():
        print(f"  {severity}: {count}")
    
    # Show critical findings
    critical_findings = [f for f in findings if f['severity'] == 'Critical']
    if critical_findings:
        print(f"\nCritical Findings ({len(critical_findings)}):")
        for finding in critical_findings:
            print(f"  - {finding['title']} ({finding['category']})")

def demo_evidence_analysis():
    """Analyze evidence patterns in findings"""
    print("\n=== Evidence Analysis Demo ===\n")
    
    with open("test_threat_report.json", "r") as f:
        findings_data = json.load(f)
    
    findings = findings_data['findings']
    
    print("Evidence Analysis:")
    for finding in findings:
        print(f"\n{finding['title']} ({finding['category']})")
        print(f"Evidence count: {len(finding['evidence'])}")
        if finding['evidence']:
            print(f"First evidence: {finding['evidence'][0]}")
        
        # Analyze evidence patterns
        api_calls = [e for e in finding['evidence'] if 'API call' in e]
        if api_calls:
            print(f"API-related evidence: {len(api_calls)} items")

def demo_report_comparison():
    """Compare different analysis approaches"""
    print("\n=== Report Comparison Demo ===\n")
    
    # Analyze with different rule sets
    matcher = ThreatMatcher("threat_rules.json")
    diagram_data = matcher.parse_sequence_diagram("sample_notes_app.uml")
    
    # Full analysis
    full_findings = matcher.match_threats(diagram_data)
    matcher.generate_threat_report(full_findings, "full_analysis.json")
    
    # Focus on authentication only
    auth_findings = [f for f in full_findings if 'auth' in f['title'].lower() or 'login' in f['title'].lower()]
    matcher.generate_threat_report(auth_findings, "auth_focused.json")
    
    print(f"Full analysis: {len(full_findings)} findings")
    print(f"Auth-focused: {len(auth_findings)} findings")
    
    # Generate focused HTML report
    generator = HTMLReportGenerator()
    with open("auth_focused.json", "r") as f:
        auth_data = json.load(f)
    generator.generate_html_report(auth_data, "auth_focused_report.html")
    
    print("Generated focused reports: auth_focused.json, auth_focused_report.html")

def main():
    """Run all demos"""
    print("🔒 Threat Modeling System Demo\n")
    print("This demo shows various capabilities of the threat modeling system.\n")
    
    try:
        demo_basic_usage()
        demo_custom_rules()
        demo_threat_statistics()
        demo_evidence_analysis()
        demo_report_comparison()
        
        print("\n=== Demo Complete ===")
        print("Generated files:")
        print("- demo_threat_report.json (basic analysis)")
        print("- demo_threat_report.html (HTML report)")
        print("- custom_rules.json (custom rules example)")
        print("- auth_focused.json (focused analysis)")
        print("- auth_focused_report.html (focused HTML report)")
        
    except Exception as e:
        print(f"Demo error: {e}")

if __name__ == "__main__":
    main() 