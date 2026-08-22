#!/usr/bin/env python3
"""
Demo: Threat Countermeasures and Solutions
=========================================

This demo shows how to use the countermeasures system and displays
all identified threats with their corresponding security solutions.
"""

from countermeasures import ThreatCountermeasures
from countermeasures_report_generator import CountermeasuresReportGenerator
import json


def print_threat_summary():
    """Print a summary of all threats and their countermeasures."""
    print("🛡️  THREAT COUNTERMEASURES SUMMARY")
    print("=" * 50)
    
    countermeasures = ThreatCountermeasures()
    report = countermeasures.generate_countermeasures_report()
    
    print(f"\n📊 Report Summary:")
    print(f"   Total Threats: {report['report_metadata']['total_threats']}")
    print(f"   Total Countermeasures: {report['report_metadata']['total_countermeasures']}")
    
    summary = report['summary']
    print(f"\n🎯 Priority Distribution:")
    print(f"   Critical: {summary['critical_priority']}")
    print(f"   High: {summary['high_priority']}")
    print(f"   Medium: {summary['medium_priority']}")
    print(f"   Low: {summary['low_priority']}")
    
    print(f"\n⚡ Effort Distribution:")
    print(f"   Easy: {summary['easy_effort']}")
    print(f"   Medium: {summary['medium_effort']}")
    print(f"   Hard: {summary['hard_effort']}")
    
    print("\n" + "=" * 50)


def print_detailed_threats():
    """Print detailed information about each threat and its countermeasures."""
    print("\n🔍 DETAILED THREAT ANALYSIS")
    print("=" * 50)
    
    countermeasures = ThreatCountermeasures()
    all_countermeasures = countermeasures.get_all_countermeasures()
    
    for threat_id, threat_cms in all_countermeasures.items():
        if not threat_cms:
            continue
            
        threat_title = threat_cms[0].threat_title
        print(f"\n🎯 {threat_id}: {threat_title}")
        print("-" * 40)
        
        for i, cm in enumerate(threat_cms, 1):
            print(f"\n  {i}. {cm.title}")
            print(f"     Priority: {cm.priority.value}")
            print(f"     Effort: {cm.effort.value}")
            print(f"     Estimated Time: {cm.estimated_time}")
            print(f"     Description: {cm.description}")
            
            print(f"     Implementation Steps ({len(cm.implementation_steps)}):")
            for step in cm.implementation_steps[:3]:  # Show first 3 steps
                print(f"       • {step}")
            if len(cm.implementation_steps) > 3:
                print(f"       • ... and {len(cm.implementation_steps) - 3} more steps")
            
            print(f"     Dependencies ({len(cm.dependencies)}): {', '.join(cm.dependencies)}")
            print(f"     Testing Requirements ({len(cm.testing_requirements)}): {', '.join(cm.testing_requirements[:2])}...")
        
        print()


def show_implementation_roadmap():
    """Show a recommended implementation roadmap."""
    print("\n🗺️  IMPLEMENTATION ROADMAP")
    print("=" * 50)
    
    roadmap = {
        "Week 1 - Critical Security": [
            "TF-SD-003: Resource exhaustion through unlimited operations",
            "TF-SD-004: User can access admin functions without proper authorization",
            "TF-SD-002: No rate limiting on API endpoints",
            "TF-SD-001: Sensitive data exposed in error messages"
        ],
        "Week 2 - Authentication & Sessions": [
            "TF-SD-005: Session management without proper timeout",
            "TF-SD-006: No multi-factor authentication (MFA) option",
            "TF-SD-007: No account lockout after repeated failed logins"
        ],
        "Week 3 - User Experience": [
            "TF-SD-009: No password strength indicator",
            "TF-SD-008: No new device login notification"
        ],
        "Week 4 - Testing & Optimization": [
            "Comprehensive security testing",
            "Performance optimization",
            "Security audit and penetration testing",
            "Documentation and training"
        ]
    }
    
    for week, tasks in roadmap.items():
        print(f"\n📅 {week}")
        print("-" * 30)
        for task in tasks:
            print(f"   • {task}")
    
    print()


def show_quick_wins():
    """Show countermeasures that are easy to implement with high impact."""
    print("\n⚡ QUICK WINS - High Impact, Easy Implementation")
    print("=" * 50)
    
    countermeasures = ThreatCountermeasures()
    all_countermeasures = countermeasures.get_all_countermeasures()
    
    quick_wins = []
    
    for threat_id, threat_cms in all_countermeasures.items():
        for cm in threat_cms:
            if (cm.priority.value in ['Critical', 'High'] and 
                cm.effort.value == 'Easy'):
                quick_wins.append({
                    'threat_id': threat_id,
                    'threat_title': cm.threat_title,
                    'countermeasure': cm.title,
                    'description': cm.description,
                    'estimated_time': cm.estimated_time
                })
    
    for i, win in enumerate(quick_wins, 1):
        print(f"\n{i}. {win['threat_id']}: {win['countermeasure']}")
        print(f"   Threat: {win['threat_title']}")
        print(f"   Time: {win['estimated_time']}")
        print(f"   Description: {win['description']}")
    
    print()


def generate_reports():
    """Generate both HTML and JSON reports."""
    print("\n📄 GENERATING REPORTS")
    print("=" * 50)
    
    # Generate HTML report
    generator = CountermeasuresReportGenerator()
    html_filename = generator.generate_html_report()
    print(f"✅ HTML Report: {html_filename}")
    
    # Generate JSON report
    countermeasures = ThreatCountermeasures()
    json_filename = countermeasures.export_countermeasures_to_json()
    print(f"✅ JSON Report: {json_filename}")
    
    print(f"\n📖 You can now open {html_filename} in your browser to view the interactive report!")
    print()


def main():
    """Main demo function."""
    print("🛡️  THREAT COUNTERMEASURES DEMO")
    print("=" * 50)
    print("This demo shows the comprehensive countermeasures and solutions")
    print("for all threats identified in the threat modeling analysis.\n")
    
    # Show summary
    print_threat_summary()
    
    # Show quick wins
    show_quick_wins()
    
    # Show implementation roadmap
    show_implementation_roadmap()
    
    # Show detailed threats
    print_detailed_threats()
    
    # Generate reports
    generate_reports()
    
    print("\n🎉 Demo completed! Check the generated reports for detailed information.")
    print("\n💡 Next Steps:")
    print("   1. Review the HTML report for interactive countermeasures")
    print("   2. Prioritize implementation based on critical threats")
    print("   3. Start with quick wins for immediate security improvements")
    print("   4. Follow the implementation roadmap for systematic deployment")


if __name__ == "__main__":
    main() 