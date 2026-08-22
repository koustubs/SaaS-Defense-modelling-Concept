#!/usr/bin/env python3
"""
Demo script to test DREAD implementation with existing threat report
"""

import json
import os
from datetime import datetime
from threat_matcher import ThreatMatcher
from html_report_generator import HTMLReportGenerator
from dread_scorer import DREADScorer

def main():
    """Demo the DREAD implementation"""
    print("🎯 DREAD Model Implementation Demo")
    print("=" * 50)
    
    # Initialize components
    matcher = ThreatMatcher("threat_rules.json")
    html_generator = HTMLReportGenerator()
    dread_scorer = DREADScorer()
    
    # Load existing threat report if available
    existing_report = "threat_report_20250708_160013.json"
    if os.path.exists(existing_report):
        print(f"📄 Loading existing threat report: {existing_report}")
        with open(existing_report, 'r', encoding='utf-8') as file:
            existing_data = json.load(file)
        
        # Extract findings and apply DREAD scoring
        findings = existing_data.get('findings', [])
        print(f"🔍 Found {len(findings)} existing threats")
        
        # Calculate DREAD scores and rankings
        ranked_findings = dread_scorer.calculate_threat_rankings(findings)
        dread_summary = dread_scorer.get_dread_summary(ranked_findings)
        
        # Create new report with DREAD data
        new_report_data = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "total_findings": len(findings),
                "report_type": "Threat Analysis Report with DREAD Scoring"
            },
            "dread_summary": dread_summary,
            "findings": ranked_findings
        }
        
        # Save updated report
        output_file = f"threat_report_dread_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w', encoding='utf-8') as file:
            json.dump(new_report_data, file, indent=2, ensure_ascii=False)
        
        print(f"💾 Saved updated report with DREAD scoring: {output_file}")
        
        # Generate HTML report
        html_output = f"threat_report_dread_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        html_generator.generate_html_report(new_report_data, html_output)
        
        # Display DREAD summary
        print("\n📊 DREAD Analysis Summary:")
        print(f"Total Findings: {dread_summary.get('total_findings', 0)}")
        print(f"Average Weighted DREAD: {dread_summary.get('average_weighted_dread', 0)}")
        print(f"Average Normal DREAD: {dread_summary.get('average_normal_dread', 0)}")
        print(f"Max Weighted DREAD: {dread_summary.get('max_weighted_dread', 0)}")
        print(f"Min Weighted DREAD: {dread_summary.get('min_weighted_dread', 0)}")
        
        print("\n🏆 Top 5 Threats by DREAD Score:")
        for i, finding in enumerate(ranked_findings[:5]):
            dread_score = finding.get('dread_score', {})
            print(f"{i+1}. {finding.get('title', 'Unknown')}")
            print(f"   Weighted DREAD: {dread_score.get('weighted_dread', 0)}")
            print(f"   Normal DREAD: {dread_score.get('normal_dread', 0)}")
            print(f"   Severity: {dread_score.get('severity_level', 'Unknown')}")
            print()
        
        print(f"📈 HTML report generated: {html_output}")
        
    else:
        print("❌ No existing threat report found. Please run threat analysis first.")
        print("Usage: python threat_matcher.py <sequence_diagram.uml>")

if __name__ == "__main__":
    main() 