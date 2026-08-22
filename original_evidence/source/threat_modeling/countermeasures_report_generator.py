#!/usr/bin/env python3
"""
Countermeasures HTML Report Generator
====================================

Generates beautiful HTML reports for threat countermeasures and solutions.
"""

import json
from datetime import datetime
from typing import Dict, List, Any
from countermeasures import ThreatCountermeasures


class CountermeasuresReportGenerator:
    """Generates HTML reports for countermeasures."""
    
    def __init__(self):
        self.countermeasures = ThreatCountermeasures()
    
    def generate_html_report(self, output_file: str = None) -> str:
        """Generate a comprehensive HTML report for countermeasures."""
        
        import os
        if output_file is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join("threat_modeling", f"countermeasures_report_{timestamp}.html")
        
        report_data = self.countermeasures.generate_countermeasures_report()
        
        html_content = self._generate_html_content(report_data)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_file
    
    def _generate_html_content(self, report_data: Dict[str, Any]) -> str:
        """Generate the HTML content for the countermeasures report."""
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Countermeasures Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background: #1a1a1a;
            color: #e0e0e0;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}
        .header {{
            background: #23232b;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #e0e0e0;
            margin-bottom: 10px;
            font-size: 2.5em;
        }}
        .header p {{
            color: #b0b0b0;
            font-size: 1.1em;
        }}
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        .summary-card {{
            background: #23232b;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.15);
            text-align: center;
            transition: transform 0.3s ease;
        }}
        .summary-card:hover {{
            transform: translateY(-5px);
        }}
        .summary-number {{
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }}
        .critical {{ color: #e57373; }}
        .high {{ color: #ffb74d; }}
        .medium {{ color: #fff176; }}
        .low {{ color: #4dd0e1; }}
        .easy {{ color: #81c784; }}
        .hard {{ color: #f06292; }}
        .summary-label {{
            color: #b0b0b0;
            font-size: 0.9em;
        }}
        .threat-section {{
            background: #2d2d2d;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
        }}
        .threat-header {{
            background: #394666;
            color: #e0e0e0;
            padding: 16px;
            border-radius: 8px;
            font-size: 1.3em;
            font-weight: bold;
            margin-bottom: 20px;
            cursor: pointer;
            transition: background-color 0.3s;
        }}
        .threat-header:hover {{
            background: #4a5d8f;
        }}
        .threat-header::after {{
            content: '▼';
            float: right;
            transition: transform 0.3s;
        }}
        .threat-header.collapsed::after {{
            transform: rotate(-90deg);
        }}
        .countermeasure-card {{
            background: #1a1a1a;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid #394666;
        }}
        .countermeasure-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        .countermeasure-title {{
            font-size: 1.2em;
            font-weight: bold;
            color: #4dd0e1;
        }}
        .countermeasure-meta {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}
        .priority-badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .priority-critical {{ background: #e57373; color: #000; }}
        .priority-high {{ background: #ffb74d; color: #000; }}
        .priority-medium {{ background: #fff176; color: #000; }}
        .priority-low {{ background: #4dd0e1; color: #000; }}
        .effort-badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .effort-easy {{ background: #81c784; color: #000; }}
        .effort-medium {{ background: #ffb74d; color: #000; }}
        .effort-hard {{ background: #f06292; color: #000; }}
        .countermeasure-content {{
            margin-top: 15px;
        }}
        .content-section {{
            margin-bottom: 15px;
        }}
        .content-section h4 {{
            color: #4dd0e1;
            margin-bottom: 8px;
        }}
        .steps-list, .examples-list, .requirements-list {{
            background: #23232b;
            border-radius: 5px;
            padding: 15px;
            margin: 10px 0;
        }}
        .steps-list li, .examples-list li, .requirements-list li {{
            margin-bottom: 8px;
            color: #b0b0b0;
        }}
        .code-block {{
            background: #1a1a1a;
            border: 1px solid #394666;
            border-radius: 5px;
            padding: 15px;
            margin: 10px 0;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            color: #e0e0e0;
        }}
        .filters {{
            padding: 10px 0;
            margin-bottom: 20px;
        }}
        .filter-buttons {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}
        .filter-btn {{
            background: #394666;
            color: #e0e0e0;
            border: none;
            padding: 8px 16px;
            border-radius: 5px;
            cursor: pointer;
            transition: background-color 0.3s;
        }}
        .filter-btn:hover {{
            background: #4a5d8f;
        }}
        .filter-btn.active {{
            background: #4a5d8f;
        }}
        .hidden {{
            display: none;
        }}
        .implementation-timeline {{
            background: #23232b;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }}
        .timeline-item {{
            display: flex;
            align-items: center;
            margin-bottom: 15px;
            padding: 10px;
            background: #1a1a1a;
            border-radius: 5px;
        }}
        .timeline-number {{
            background: #4dd0e1;
            color: #000;
            width: 30px;
            height: 30px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            margin-right: 15px;
        }}
        .timeline-content {{
            flex: 1;
        }}
        .timeline-title {{
            font-weight: bold;
            color: #e0e0e0;
            margin-bottom: 5px;
        }}
        .timeline-details {{
            color: #b0b0b0;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Threat Countermeasures Report</h1>
            <p>Comprehensive security solutions and implementation guidance for identified threats</p>
            <p><strong>Generated:</strong> {report_data['report_metadata']['generated_at']}</p>
        </div>

        <div class="summary-cards">
            <div class="summary-card">
                <div class="summary-number">{report_data['report_metadata']['total_countermeasures']}</div>
                <div class="summary-label">Total Countermeasures</div>
            </div>
            <div class="summary-card">
                <div class="summary-number critical">{report_data['summary']['critical_priority']}</div>
                <div class="summary-label">Critical Priority</div>
            </div>
            <div class="summary-card">
                <div class="summary-number high">{report_data['summary']['high_priority']}</div>
                <div class="summary-label">High Priority</div>
            </div>
            <div class="summary-card">
                <div class="summary-number medium">{report_data['summary']['medium_priority']}</div>
                <div class="summary-label">Medium Priority</div>
            </div>
            <div class="summary-card">
                <div class="summary-number low">{report_data['summary']['low_priority']}</div>
                <div class="summary-label">Low Priority</div>
            </div>
            <div class="summary-card">
                <div class="summary-number easy">{report_data['summary']['easy_effort']}</div>
                <div class="summary-label">Easy Implementation</div>
            </div>
            <div class="summary-card">
                <div class="summary-number medium">{report_data['summary']['medium_effort']}</div>
                <div class="summary-label">Medium Effort</div>
            </div>
            <div class="summary-card">
                <div class="summary-number hard">{report_data['summary']['hard_effort']}</div>
                <div class="summary-label">Hard Implementation</div>
            </div>
        </div>

        <div class="filters">
            <h3>Filter Countermeasures</h3>
            <div class="filter-buttons">
                <button class="filter-btn active" onclick="filterCountermeasures('all')">All</button>
                <button class="filter-btn" onclick="filterCountermeasures('critical')">Critical Priority</button>
                <button class="filter-btn" onclick="filterCountermeasures('high')">High Priority</button>
                <button class="filter-btn" onclick="filterCountermeasures('medium')">Medium Priority</button>
                <button class="filter-btn" onclick="filterCountermeasures('low')">Low Priority</button>
                <button class="filter-btn" onclick="filterCountermeasures('easy')">Easy Effort</button>
                <button class="filter-btn" onclick="filterCountermeasures('hard')">Hard Effort</button>
            </div>
        </div>

        <div class="implementation-timeline">
            <h3>🚀 Recommended Implementation Timeline</h3>
            <div class="timeline-item">
                <div class="timeline-number">1</div>
                <div class="timeline-content">
                    <div class="timeline-title">Week 1: Critical Security Measures</div>
                    <div class="timeline-details">Implement rate limiting, RBAC, and secure error handling</div>
                </div>
            </div>
            <div class="timeline-item">
                <div class="timeline-number">2</div>
                <div class="timeline-content">
                    <div class="timeline-title">Week 2: Authentication & Session Security</div>
                    <div class="timeline-details">Add MFA, session management, and account lockout</div>
                </div>
            </div>
            <div class="timeline-item">
                <div class="timeline-number">3</div>
                <div class="timeline-content">
                    <div class="timeline-title">Week 3: User Experience & Monitoring</div>
                    <div class="timeline-details">Password strength indicators, device notifications, and monitoring</div>
                </div>
            </div>
            <div class="timeline-item">
                <div class="timeline-number">4</div>
                <div class="timeline-content">
                    <div class="timeline-title">Week 4: Testing & Optimization</div>
                    <div class="timeline-details">Comprehensive testing, performance optimization, and security audits</div>
                </div>
            </div>
        </div>
"""
        
        # Add threat sections
        for threat_id, threat_data in report_data["threat_countermeasures"].items():
            html += self._generate_threat_section(threat_id, threat_data)
        
        html += """
        <script>
            function toggleThreat(threatId) {
                const content = document.getElementById('threat-content-' + threatId);
                const header = document.getElementById('threat-header-' + threatId);
                
                if (content.style.display === 'none') {
                    content.style.display = 'block';
                    header.classList.remove('collapsed');
                } else {
                    content.style.display = 'none';
                    header.classList.add('collapsed');
                }
            }
            
            function filterCountermeasures(filter) {
                const buttons = document.querySelectorAll('.filter-btn');
                buttons.forEach(btn => btn.classList.remove('active'));
                event.target.classList.add('active');
                
                const countermeasures = document.querySelectorAll('.countermeasure-card');
                countermeasures.forEach(cm => {
                    const priority = cm.querySelector('.priority-badge').textContent.toLowerCase();
                    const effort = cm.querySelector('.effort-badge').textContent.toLowerCase();
                    
                    if (filter === 'all' || 
                        (filter === 'critical' && priority === 'critical') ||
                        (filter === 'high' && priority === 'high') ||
                        (filter === 'medium' && priority === 'medium') ||
                        (filter === 'low' && priority === 'low') ||
                        (filter === 'easy' && effort === 'easy') ||
                        (filter === 'hard' && effort === 'hard')) {
                        cm.style.display = 'block';
                    } else {
                        cm.style.display = 'none';
                    }
                });
            }
            
            // Initialize collapsed state
            document.addEventListener('DOMContentLoaded', function() {
                const threatHeaders = document.querySelectorAll('.threat-header');
                threatHeaders.forEach(header => {
                    header.classList.add('collapsed');
                    const threatId = header.id.replace('threat-header-', '');
                    const content = document.getElementById('threat-content-' + threatId);
                    if (content) {
                        content.style.display = 'none';
                    }
                });
            });
        </script>
    </div>
</body>
</html>
"""
        
        return html
    
    def _generate_threat_section(self, threat_id: str, threat_data: Dict[str, Any]) -> str:
        """Generate HTML section for a specific threat and its countermeasures."""
        
        # Get threat title from first countermeasure
        threat_title = threat_data["countermeasures"][0]["threat_title"] if threat_data["countermeasures"] else "Unknown Threat"
        
        html = f"""
        <div class="threat-section">
            <div class="threat-header" id="threat-header-{threat_id}" onclick="toggleThreat('{threat_id}')">
                {threat_id}: {threat_title}
            </div>
            <div class="threat-content" id="threat-content-{threat_id}">
"""
        
        for cm in threat_data["countermeasures"]:
            html += self._generate_countermeasure_card(cm)
        
        html += """
            </div>
        </div>
"""
        
        return html
    
    def _generate_countermeasure_card(self, cm: Dict[str, Any]) -> str:
        """Generate HTML card for a countermeasure."""
        
        priority_class = f"priority-{cm['priority'].value.lower()}"
        effort_class = f"effort-{cm['effort'].value.lower()}"

        # Diagram mapping (threat title to diagram file)
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
        diagram_file = diagram_map.get(cm['threat_title'])
        diagram_html = ""
        if diagram_file:
            diagram_html = f'''
                <div class="content-section">
                    <h4>🖼️ Diagram</h4>
                    <img src="threat_modeling/{diagram_file}" alt="Diagram for {cm['threat_title']}" style="max-width:100%;border-radius:8px;box-shadow:0 2px 8px #0003;">
                </div>
            '''

        html = f"""
        <div class="countermeasure-card">
            <div class="countermeasure-header">
                <div class="countermeasure-title">{cm['title']}</div>
                <div class="countermeasure-meta">
                    <span class="priority-badge {priority_class}">{cm['priority']}</span>
                    <span class="effort-badge {effort_class}">{cm['effort']}</span>
                    <span style="color: #b0b0b0; font-size: 0.9em;">{cm['estimated_time']}</span>
                </div>
            </div>
            <div class="countermeasure-content">
                <div class="content-section">
                    <h4>📋 Description</h4>
                    <p>{cm['description']}</p>
                </div>
                {diagram_html}
                <div class="content-section">
                    <h4>🔧 Implementation Steps</h4>
                    <ol class="steps-list">
        """
        for step in cm['implementation_steps']:
            html += f"<li>{step}</li>\n"
        html += """
                    </ol>
                </div>
        """
        if cm['code_examples']:
            html += """
                <div class="content-section">
                    <h4>💻 Code Examples</h4>
            """
            for example in cm['code_examples']:
                html += f'<div class="code-block">{example}</div>\n'
            html += "</div>\n"
        html += f"""
                <div class="content-section">
                    <h4>📦 Dependencies</h4>
                    <ul class="requirements-list">
        """
        for dep in cm['dependencies']:
            html += f"<li>{dep}</li>\n"
        html += """
                    </ul>
                </div>
            </div>
        </div>
        """
        return html


def main():
    """Main function to generate countermeasures report."""
    generator = CountermeasuresReportGenerator()
    
    filename = generator.generate_html_report()
    print(f"Countermeasures HTML report generated: {filename}")
    # Also generate JSON report in threat_modeling folder
    countermeasures = ThreatCountermeasures()
    import os
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    json_filename = os.path.join("threat_modeling", f"countermeasures_report_{timestamp}.json")
    countermeasures.export_countermeasures_to_json(json_filename)
    print(f"Countermeasures JSON report generated: {json_filename}")


if __name__ == "__main__":
    main() 