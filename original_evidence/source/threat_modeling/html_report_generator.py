#!/usr/bin/env python3
"""
HTML Report Generator for Threat Analysis
Creates beautiful, interactive HTML reports from threat findings
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Any
from countermeasures import ThreatCountermeasures

class HTMLReportGenerator:
    def __init__(self):
        self.css_styles = """
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background: #1a1a1a;
            color: #e0e0e0;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            background: #23232b;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 30px;
        }
        .header h1 {
            color: #e0e0e0;
            margin-bottom: 10px;
        }
        .summary-cards {
            display: flex;
            justify-content: center;
            gap: 20px;
            flex-wrap: wrap;
            margin-bottom: 40px;
        }
        .dread-summary {
            background: #23232b;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.15);
        }
        .dread-metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        .dread-metric {
            background: #1a1a1a;
            padding: 15px;
            border-radius: 10px;
            text-align: center;
        }
        .dread-score {
            font-size: 1.5em;
            font-weight: bold;
            color: #4dd0e1;
        }
        .dread-label {
            color: #b0b0b0;
            font-size: 0.9em;
            margin-top: 5px;
        }
        .dread-summary {
            background: #23232b;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.15);
        }
        .dread-metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        .dread-metric {
            background: #1a1a1a;
            padding: 15px;
            border-radius: 10px;
            text-align: center;
        }
        .dread-score {
            font-size: 1.5em;
            font-weight: bold;
            color: #4dd0e1;
        }
        .dread-label {
            color: #b0b0b0;
            font-size: 0.9em;
            margin-top: 5px;
        }
        .summary-card {
            background: #23232b;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.15);
            text-align: center;
            min-width: 150px;
            transition: transform 0.3s ease;
        }
        .summary-card:hover {
            transform: translateY(-5px);
        }
        .summary-number {
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }
        .critical { color: #e57373; }
        .high { color: #ffb74d; }
        .medium { color: #fff176; }
        .low { color: #4dd0e1; }
        .summary-label {
            color: #b0b0b0;
            font-size: 0.9em;
        }
        .findings-section {
            background: #2d2d2d;
            border-radius: 8px;
            padding: 20px;
            margin-top: 20px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
        }
        .section-header {
            background: #394666;
            color: #e0e0e0;
            padding: 16px;
            border-radius: 8px;
            font-size: 1.3em;
            font-weight: bold;
            margin-bottom: 20px;
        }
        .filters {
            padding: 10px 0;
        }
        .filter-buttons {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .filter-btn {
            background: #394666;
            color: #e0e0e0;
            border: none;
            padding: 8px 16px;
            border-radius: 5px;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        .filter-btn:hover {
            background: #4a5d8f;
        }
        .filter-btn.active {
            background: #4a5d8f;
        }
        .finding-card {
            background: #1a1a1a;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 15px;
            border: 1px solid #394666;
        }
        .dread-scores {
            display: flex;
            gap: 10px;
            margin: 10px 0;
            flex-wrap: wrap;
        }
        .dread-badge {
            background: #394666;
            color: #e0e0e0;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
        }
        .dread-breakdown {
            background: #23232b;
            border-radius: 5px;
            padding: 10px;
            margin: 10px 0;
        }
        .dread-breakdown h4 {
            color: #4dd0e1;
            margin-bottom: 10px;
        }
        .dread-item {
            display: flex;
            justify-content: space-between;
            margin: 5px 0;
            color: #b0b0b0;
        }
        .dread-scores {
            display: flex;
            gap: 10px;
            margin: 10px 0;
            flex-wrap: wrap;
        }
        .dread-badge {
            background: #394666;
            color: #e0e0e0;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
        }
        .dread-breakdown {
            background: #23232b;
            border-radius: 5px;
            padding: 10px;
            margin: 10px 0;
        }
        .dread-breakdown h4 {
            color: #4dd0e1;
            margin-bottom: 10px;
        }
        .dread-item {
            display: flex;
            justify-content: space-between;
            margin: 5px 0;
            color: #b0b0b0;
        }
        .finding-header {
            cursor: pointer;
        }
        .meta-item {
            display: inline-block;
            margin-right: 15px;
            color: #b0b0b0;
            font-size: 0.95em;
        }
        .severity-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            margin-right: 10px;
            color: #1a1a1a;
        }
        .severity-critical { background: #8f4a4a; }
        .severity-high { background: #8f6e4a; }
        .severity-medium { background: #6e8f4a; }
        .severity-low { background: #4a8f8f; }
        .finding-title {
            font-size: 1.1em;
            font-weight: bold;
            margin: 10px 0;
            color: #e0e0e0;
        }
        .finding-details {
            color: #b0b0b0;
            font-size: 0.9em;
        }
        .evidence-list {
            margin: 10px 0;
            padding-left: 20px;
            color: #b0b0b0;
        }
        .evidence-item {
            margin: 5px 0;
        }
        .mitigation-box {
            background: #23232b;
            border: 1px solid #4a8f8f;
            border-radius: 5px;
            padding: 15px;
            margin-top: 15px;
        }
        .mitigation-box h4 {
            color: #4a8f8f;
            margin-bottom: 10px;
        }
        @media (max-width: 768px) {
            .stat-card {
                min-width: 120px;
            }
            .summary-cards {
                flex-direction: column;
                gap: 10px;
            }
        }
        """
        self.js_scripts = self._get_js_scripts()
    
    def _generate_dread_summary_html(self, dread_summary: Dict[str, Any]) -> str:
        """Generate HTML for DREAD summary section"""
        if not dread_summary:
            return ""
        
        return f"""
                <div class="dread-summary">
                    <h2>🎯 DREAD Model Analysis</h2>
                    <p>Threat assessment using the DREAD (Damage, Reproducibility, Exploitability, Affected Users, Discoverability) model with weighted scoring.</p>
                    
                    <div class="dread-metrics">
                        <div class="dread-metric">
                            <div class="dread-score">{dread_summary.get('average_weighted_dread', 0)}</div>
                            <div class="dread-label">Avg Weighted DREAD</div>
                        </div>
                        <div class="dread-metric">
                            <div class="dread-score">{dread_summary.get('average_normal_dread', 0)}</div>
                            <div class="dread-label">Avg Normal DREAD</div>
                        </div>
                        <div class="dread-metric">
                            <div class="dread-score">{dread_summary.get('max_weighted_dread', 0)}</div>
                            <div class="dread-label">Max Weighted DREAD</div>
                        </div>
                        <div class="dread-metric">
                            <div class="dread-score">{dread_summary.get('min_weighted_dread', 0)}</div>
                            <div class="dread-label">Min Weighted DREAD</div>
                        </div>
                    </div>
                    
                    <div style="margin-top: 20px;">
                        <h4>DREAD Weights:</h4>
                        <ul style="color: #b0b0b0; margin: 10px 0;">
                            <li><strong>Damage:</strong> Weight 3 - Impact of the damage</li>
                            <li><strong>Reproducibility:</strong> Weight 1 - Rate of exploitation</li>
                            <li><strong>Exploitability:</strong> Weight 2 - Success rate of exploitation</li>
                            <li><strong>Affected Users:</strong> Weight 3 - Number of affected users</li>
                            <li><strong>Discoverability:</strong> Weight 2 - Difficulty of discovering vulnerability</li>
                        </ul>
                    </div>
                </div>
        """
    
    def _generate_dread_scores_html(self, finding: Dict[str, Any]) -> str:
        """Generate HTML for DREAD scores in finding cards"""
        dread_score = finding.get('dread_score', {})
        if not dread_score:
            return ""
        
        return f"""
                        <div class="dread-scores">
                            <div class="dread-badge">Rank #{dread_score.get('rank', 'N/A')}</div>
                            <div class="dread-badge">Weighted DREAD: {dread_score.get('weighted_dread', 0)}</div>
                            <div class="dread-badge">Normal DREAD: {dread_score.get('normal_dread', 0)}</div>
                            <div class="dread-badge">Severity: {dread_score.get('severity_level', 'Unknown')}</div>
                        </div>
                        
                        <div class="dread-breakdown">
                            <h4>DREAD Breakdown:</h4>
                            <div class="dread-item">
                                <span>Damage:</span>
                                <span>{dread_score.get('damage', 0)}/10</span>
                            </div>
                            <div class="dread-item">
                                <span>Reproducibility:</span>
                                <span>{dread_score.get('reproducibility', 0)}/10</span>
                            </div>
                            <div class="dread-item">
                                <span>Exploitability:</span>
                                <span>{dread_score.get('exploitability', 0)}/10</span>
                            </div>
                            <div class="dread-item">
                                <span>Affected Users:</span>
                                <span>{dread_score.get('affected_users', 0)}/10</span>
                            </div>
                            <div class="dread-item">
                                <span>Discoverability:</span>
                                <span>{dread_score.get('discoverability', 0)}/10</span>
                            </div>
                        </div>
        """
    
    def _get_css_styles(self) -> str:
        """Get CSS styles for the report"""
        return """
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                line-height: 1.6;
                margin: 0;
                padding: 20px;
                background: #1a1a1a;
                color: #e0e0e0;
            }

            .container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
            }

            h1 {
                text-align: center;
                color: #e0e0e0;
                margin-bottom: 40px;
            }

            .stats-container {
                display: flex;
                justify-content: center;
                gap: 20px;
                flex-wrap: wrap;
                margin-bottom: 40px;
            }

            .stat-card {
                background: #2d2d2d;
                border-radius: 8px;
                padding: 20px;
                min-width: 150px;
                text-align: center;
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
            }

            .stat-number {
                font-size: 2.5em;
                font-weight: bold;
                margin: 10px 0;
            }

            .stat-label {
                color: #b0b0b0;
                font-size: 0.9em;
            }

            .findings-section {
                background: #2d2d2d;
                border-radius: 8px;
                padding: 20px;
                margin-top: 20px;
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
            }

            .findings-header {
                display: flex;
                align-items: center;
                margin-bottom: 20px;
                padding: 10px;
                background: #394666;
                border-radius: 5px;
                color: #e0e0e0;
            }

            .filter-container {
                display: flex;
                gap: 10px;
                margin: 20px 0;
                flex-wrap: wrap;
            }

            .filter-btn {
                background: #394666;
                color: #e0e0e0;
                border: none;
                padding: 8px 16px;
                border-radius: 5px;
                cursor: pointer;
                transition: background-color 0.3s;
            }

            .filter-btn:hover {
                background: #4a5d8f;
            }

            .filter-btn.active {
                background: #4a5d8f;
            }

            .finding-card {
                background: #1a1a1a;
                border-radius: 5px;
                padding: 15px;
                margin-bottom: 15px;
                border: 1px solid #394666;
            }

            .severity-badge {
                display: inline-block;
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 0.8em;
                font-weight: bold;
                margin-right: 10px;
                color: #1a1a1a;
            }

            .severity-critical { background: #8f4a4a; }
            .severity-high { background: #8f6e4a; }
            .severity-medium { background: #6e8f4a; }
            .severity-low { background: #4a8f8f; }

            .finding-title {
                font-size: 1.1em;
                font-weight: bold;
                margin: 10px 0;
                color: #e0e0e0;
            }

            .finding-details {
                color: #b0b0b0;
                font-size: 0.9em;
            }

            .evidence-list {
                margin: 10px 0;
                padding-left: 20px;
                color: #b0b0b0;
            }

            .evidence-item {
                margin: 5px 0;
            }

            @media (max-width: 768px) {
                .stat-card {
                    min-width: 120px;
                }
            }
        </style>
        """
    
    def _get_js_scripts(self) -> str:
        """Get JavaScript for interactivity"""
        return """
        <script>
            function toggleFinding(findingId) {
                const content = document.getElementById('finding-content-' + findingId);
                content.classList.toggle('show');
            }
            
            function filterFindings(category) {
                const findings = document.querySelectorAll('.finding-card');
                const buttons = document.querySelectorAll('.filter-btn');
                
                // Update active button
                buttons.forEach(btn => btn.classList.remove('active'));
                event.target.classList.add('active');
                
                findings.forEach(finding => {
                    const findingCategory = finding.getAttribute('data-category');
                    if (category === 'all' || findingCategory === category) {
                        finding.style.display = 'block';
                    } else {
                        finding.style.display = 'none';
                    }
                });
            }
            
            function exportReport() {
                const reportContent = document.documentElement.outerHTML;
                const blob = new Blob([reportContent], { type: 'text/html' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'threat_report_' + new Date().toISOString().split('T')[0] + '.html';
                a.click();
                URL.revokeObjectURL(url);
            }
        </script>
        """
    
    def _get_diagram_html(self, threat_title: str) -> str:
        """Return HTML for the diagram image if a matching file is found for the threat title."""
        # Mapping from threat title to diagram filename
        diagram_map = {
            "Resource exhaustion through unlimited operations": "DoS Mitigation via adaptive rate limiting.png",
            "User can access admin functions without proper authorization": "RBAC Enforcement for Admin Action Restriction.png",
            "No rate limiting on API endpoints": "resource quota enforcement.png",
            "Session management without proper timeout": "session timeout enforcement.png",
            "Sensitive data exposed in error messages": "secure error handling.png",
            "No multi-factor authentication (MFA) option": "MFA.png",
            "No account lockout after repeated failed logins": "Account Lockout and CAPTCHA.png",
            "No password strength indicator": "password strength feedback.png",
        }
        filename = diagram_map.get(threat_title)
        if not filename:
            return ""
        # Check if file exists in the current directory
        if os.path.exists(filename):
            return f'<div class="content-section"><h5>🖼️ Diagram</h5><img src="{filename}" alt="Diagram for {threat_title}" style="max-width:100%;border-radius:8px;margin:10px 0;box-shadow:0 2px 8px #000;"/></div>'
        return ""
    
    def generate_html_report(self, findings_data: Dict[str, Any], output_file: str = "threat_report.html") -> str:
        """Generate HTML report from findings data"""
        
        # Extract data
        metadata = findings_data.get('report_metadata', {})
        findings = findings_data.get('findings', [])
        dread_summary = findings_data.get('dread_summary', {})
        
        # Calculate statistics
        total_findings = len(findings)
        critical_count = sum(1 for f in findings if f.get('severity') == 'Critical')
        high_count = sum(1 for f in findings if f.get('severity') == 'High')
        medium_count = sum(1 for f in findings if f.get('severity') == 'Medium')
        low_count = sum(1 for f in findings if f.get('severity') == 'Low')
        
        # Group findings by category
        categories = {}
        for finding in findings:
            category = finding.get('category', 'Unknown')
            if category not in categories:
                categories[category] = []
            categories[category].append(finding)
        
        # Generate HTML content
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Threat Analysis Report</title>
            <style>{self.css_styles}</style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Threat Analysis Report</h1>
                </div>
                
                <div class="summary-cards">
                    <div class="summary-card">
                        <div class="summary-number">{total_findings}</div>
                        <div class="summary-label">Total Findings</div>
                    </div>
                    <div class="summary-card">
                        <div class="summary-number critical">{critical_count}</div>
                        <div class="summary-label">Critical</div>
                    </div>
                    <div class="summary-card">
                        <div class="summary-number high">{high_count}</div>
                        <div class="summary-label">High</div>
                    </div>
                    <div class="summary-card">
                        <div class="summary-number medium">{medium_count}</div>
                        <div class="summary-label">Medium</div>
                    </div>
                    <div class="summary-card">
                        <div class="summary-number low">{low_count}</div>
                        <div class="summary-label">Low</div>
                    </div>
                </div>
                
                {self._generate_dread_summary_html(dread_summary)}
                
                <div class="findings-section">
                    <div class="section-header">
                        📋 Threat Findings
                    </div>
                    
                    <div class="filters">
                        <div class="filter-buttons">
                            <button class="filter-btn active" onclick="filterFindings('all')">All ({total_findings})</button>
        """
        
        # Add category filter buttons
        for category, category_findings in categories.items():
            html_content += f"""
                            <button class="filter-btn" onclick="filterFindings('{category}')">{category} ({len(category_findings)})</button>
            """
        
        html_content += """
                        </div>
                    </div>
        """
        
        # Generate finding cards
        threat_countermeasures = ThreatCountermeasures()
        for i, finding in enumerate(findings):
            severity_class = f"severity-{finding.get('severity', 'medium').lower()}"
            category = finding.get('category', 'Unknown')
            threat_id = finding.get('id', None)
            
            html_content += f"""
                <div class=\"finding-card\" data-category=\"{category}\">\n
                    <div class=\"finding-header\" onclick=\"toggleFinding({i})\">\n                        <span class=\"play-icon\" id=\"play-icon-{i}\">▶</span>\n                        <div class=\"finding-title\">{finding.get('title', 'Unknown Threat')}</div>\n                        <div class=\"finding-meta\">\n                            <div class=\"meta-item\">\n                                <span class=\"severity-badge {severity_class}\">{finding.get('severity', 'Medium')}</span>\n                            </div>\n                            <div class=\"meta-item\">\n                                <strong>Category:</strong> {category}\n                            </div>\n                            <div class=\"meta-item\">\n                                <strong>Likelihood:</strong> {finding.get('likelihood', 'Unknown')}\n                            </div>\n                            <div class=\"meta-item\">\n                                <strong>Rule ID:</strong> {finding.get('rule_id', 'Unknown')}\n                            </div>\n                            <div class=\"meta-item\">\n                                <strong>Status:</strong> {finding.get('status', 'Open')}\n                            </div>\n                        </div>\n                    </div>\n
                    <div class=\"finding-content\" id=\"finding-content-{i}\" style=\"display:none;\">\n
                        <div class=\"subsection-header\" onclick=\"toggleSubsection('finding', {i})\">\n                            <span class=\"play-icon\" id=\"play-icon-finding-{i}\">▶</span>\n                            <span class=\"subsection-title\">Threat Finding</span>\n                        </div>\n                        <div class=\"subsection-content\" id=\"subsection-finding-{i}\" style=\"display:none;\">\n                            {self._generate_dread_scores_html(finding)}\n                            <div class=\"finding-section\">\n                                <h5>Description</h5>\n                                <p>{finding.get('description', 'No description available')}</p>\n                            </div>\n                            <div class=\"finding-section\">\n                                <h5>Impact</h5>\n                                <p>{finding.get('impact', 'Impact not specified')}</p>\n                            </div>\n                            <div class=\"finding-section\">\n                                <h5>Evidence</h5>\n                                <ul class=\"evidence-list\">\n            """
            
            evidence = finding.get('evidence', [])
            if evidence:
                for item in evidence:
                    html_content += f"<li class=\"evidence-item\">{item}</li>\n"
            else:
                html_content += "<li class=\"evidence-item\">No specific evidence available</li>\n"
            html_content += f"""
                                </ul>\n                            </div>\n                        </div>\n
                        <div class=\"subsection-header\" onclick=\"toggleSubsection('countermeasures', {i})\">\n                            <span class=\"play-icon\" id=\"play-icon-countermeasures-{i}\">▶</span>\n                            <span class=\"subsection-title\">Countermeasures & Solutions</span>\n                        </div>\n                        <div class=\"subsection-content\" id=\"subsection-countermeasures-{i}\" style=\"display:none;\">\n            """
            countermeasures = threat_countermeasures.get_countermeasures_for_threat(threat_id) if threat_id else []
            if countermeasures:
                for cm in countermeasures:
                    html_content += f"""
<div class=\"countermeasure-card\">
  <div class=\"countermeasure-header\">
    <div class=\"countermeasure-title\">{cm.title}</div>
    <div class=\"countermeasure-meta\">
      <span class=\"priority-badge\">{cm.priority.value}</span>
      <span class=\"effort-badge\">{cm.effort.value}</span>
      <span style=\"color: #b0b0b0; font-size: 0.9em;\">{cm.estimated_time}</span>
    </div>
  </div>
  <div class=\"countermeasure-content\">
    <div class=\"content-section\"><h5>📋 Description</h5><p>{cm.description}</p></div>
    <div class=\"content-section\"><h5>🔧 Implementation Steps</h5><ol class=\"steps-list\">{''.join(f'<li>{step}</li>' for step in cm.implementation_steps)}</ol></div>
    <div class=\"content-section\"><h5>📦 Dependencies</h5><ul class=\"requirements-list\">{''.join(f'<li>{dep}</li>' for dep in cm.dependencies)}</ul></div>
    {self._get_diagram_html(cm.threat_title)}
  </div>
</div>
"""
            else:
                html_content += "<p>No detailed countermeasures available for this threat.</p>"
            html_content += "</div>"  # end countermeasures subsection-content
            html_content += "</div>"  # end finding-content
            html_content += "</div>"  # end finding-card
        
        html_content += """
                </div>
            </div>
            
            """ + self.js_scripts + """
        <style>
        .play-icon {
            font-size: 1.2em;
            margin-right: 10px;
            cursor: pointer;
            vertical-align: middle;
        }
        .subsection-header {
            background: #23232b;
            color: #e0e0e0;
            padding: 10px 15px;
            border-radius: 8px;
            margin: 20px 0 0 0;
            font-weight: bold;
            display: flex;
            align-items: center;
            cursor: pointer;
        }
        .subsection-title {
            font-size: 1.1em;
        }
        .subsection-content {
            margin-bottom: 20px;
            margin-left: 20px;
        }
        </style>
        <script>
        function toggleFinding(idx) {
            var content = document.getElementById('finding-content-' + idx);
            var icon = document.getElementById('play-icon-' + idx);
            if (content.style.display === 'none' || content.style.display === '') {
                content.style.display = 'block';
                if (icon) icon.textContent = '▼';
            } else {
                content.style.display = 'none';
                if (icon) icon.textContent = '▶';
            }
        }
        function toggleSubsection(type, idx) {
            var content = document.getElementById('subsection-' + type + '-' + idx);
            var icon = document.getElementById('play-icon-' + type + '-' + idx);
            if (content.style.display === 'none' || content.style.display === '') {
                content.style.display = 'block';
                if (icon) icon.textContent = '▼';
            } else {
                content.style.display = 'none';
                if (icon) icon.textContent = '▶';
            }
        }
        </script>
        </body>
        </html>
        """
        
        # Write to file
        with open(output_file, 'w', encoding='utf-8') as file:
            file.write(html_content)
        
        print(f"HTML report generated: {output_file}")
        return output_file

def main():
    """Main function to generate HTML report from JSON findings"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python html_report_generator.py <threat_report.json> [output.html]")
        sys.exit(1)
    
    json_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "threat_report.html"
    
    if not os.path.exists(json_file):
        print(f"Error: JSON file {json_file} not found!")
        sys.exit(1)
    
    # Load JSON data
    with open(json_file, 'r', encoding='utf-8') as file:
        findings_data = json.load(file)
    
    # Generate HTML report
    generator = HTMLReportGenerator()
    generator.generate_html_report(findings_data, output_file)

if __name__ == "__main__":
    main() 