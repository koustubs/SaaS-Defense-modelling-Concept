#!/usr/bin/env python3
"""
PlantUML Sequence Diagram Parser and HTML Report Generator
Simple tool to parse PlantUML sequence diagrams and generate HTML reports
"""

import re
import sys
import os
from datetime import datetime
from typing import List, Dict, Tuple

# Add import for PlantUML rendering
try:
    from plantuml import PlantUML
except ImportError:
    PlantUML = None

class PlantUMLParser:
    def __init__(self, uml_file_path: str):
        self.uml_file_path = uml_file_path
        self.content = ""
        self.title = ""
        self.actors = []
        self.participants = []
        self.interactions = []
        self.sections = []
        self.diagram_image_path = None
        
    def read_uml_file(self):
        """Read the PlantUML file content"""
        try:
            with open(self.uml_file_path, 'r', encoding='utf-8') as file:
                self.content = file.read()
            return True
        except FileNotFoundError:
            print(f"Error: File {self.uml_file_path} not found!")
            return False
        except Exception as e:
            print(f"Error reading file: {e}")
            return False
    
    def parse_title(self):
        """Extract title from PlantUML"""
        title_match = re.search(r'title\s+(.+)', self.content, re.IGNORECASE)
        if title_match:
            self.title = title_match.group(1).strip()
        else:
            self.title = "Sequence Diagram Analysis"
    
    def parse_actors(self):
        """Extract actors from PlantUML"""
        actor_pattern = r'actor\s+"([^"]+)"\s+as\s+(\w+)'
        actors = re.findall(actor_pattern, self.content, re.IGNORECASE)
        for actor_name, actor_alias in actors:
            self.actors.append({
                'name': actor_name.strip(),
                'alias': actor_alias.strip(),
                'type': 'actor'
            })
    
    def parse_participants(self):
        """Extract participants from PlantUML"""
        participant_pattern = r'participant\s+"([^"]+)"\s+as\s+(\w+)'
        participants = re.findall(participant_pattern, self.content, re.IGNORECASE)
        for participant_name, participant_alias in participants:
            self.participants.append({
                'name': participant_name.strip(),
                'alias': participant_alias.strip(),
                'type': 'participant'
            })
    
    def parse_interactions(self):
        """Extract interactions from PlantUML"""
        # Pattern for simple interactions: A -> B : message
        interaction_pattern = r'(\w+)\s*->\s*(\w+)\s*:\s*(.+)'
        interactions = re.findall(interaction_pattern, self.content)
        
        for from_entity, to_entity, message in interactions:
            self.interactions.append({
                'from': from_entity.strip(),
                'to': to_entity.strip(),
                'message': message.strip(),
                'type': 'request'
            })
        
        # Pattern for responses: A --> B : response
        response_pattern = r'(\w+)\s*-->\s*(\w+)\s*:\s*(.+)'
        responses = re.findall(response_pattern, self.content)
        
        for from_entity, to_entity, message in responses:
            self.interactions.append({
                'from': from_entity.strip(),
                'to': to_entity.strip(),
                'message': message.strip(),
                'type': 'response'
            })
    
    def parse_sections(self):
        """Extract sections from PlantUML"""
        section_pattern = r'==\s*(.+?)\s*=='
        sections = re.findall(section_pattern, self.content)
        self.sections = [section.strip() for section in sections]
    
    def render_uml_image(self, output_path=None):
        """Render the PlantUML diagram to an image using the PlantUML server."""
        if PlantUML is None:
            print("[WARN] plantuml package not installed. Skipping diagram rendering.")
            return None
        server = PlantUML(url="http://www.plantuml.com/plantuml/img/")
        tmp_file = "temp_diagram.puml"
        with open(tmp_file, "w", encoding="utf-8") as f:
            f.write(self.content)
        if not output_path:
            base = os.path.splitext(os.path.basename(self.uml_file_path))[0]
            output_path = f"{base}_diagram.png"
        try:
            server.processes_file(tmp_file, outfile=output_path)
            self.diagram_image_path = output_path
            print(f"Diagram saved as: {output_path}")
            os.remove(tmp_file)
            return output_path
        except Exception as e:
            print(f"[WARN] Could not render diagram: {e}")
            return None
    
    def parse(self):
        """Main parsing method"""
        if not self.read_uml_file():
            return False
        
        self.parse_title()
        self.parse_actors()
        self.parse_participants()
        self.parse_interactions()
        self.parse_sections()
        # Render diagram image
        self.render_uml_image()
        
        return True
    
    def generate_html_report(self, output_file: str = "sequence_diagram_report.html"):
        """Generate HTML report"""
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.title} - Analysis Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            text-align: center;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            border-left: 4px solid #3498db;
            padding-left: 15px;
            margin-top: 30px;
        }}
        .summary {{
            background: #ecf0f1;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 15px;
        }}
        .summary-item {{
            background: white;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .summary-number {{
            font-size: 2em;
            font-weight: bold;
            color: #3498db;
        }}
        .summary-label {{
            color: #7f8c8d;
            font-size: 0.9em;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #3498db;
            color: white;
            font-weight: bold;
        }}
        tr:nth-child(even) {{
            background-color: #f8f9fa;
        }}
        tr:hover {{
            background-color: #e3f2fd;
        }}
        .interaction-type {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .request {{
            background-color: #e8f5e8;
            color: #2e7d32;
        }}
        .response {{
            background-color: #fff3e0;
            color: #ef6c00;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #7f8c8d;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{self.title}</h1>
        <img src="{self.diagram_image_path}" alt="Sequence Diagram" style="max-width:100%; border:1px solid #ccc; border-radius:8px; box-shadow:0 2px 8px rgba(0,0,0,0.08);">\n</div>\n'
        
        <div class="summary">
            <h2>📊 Analysis Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="summary-number">{len(self.actors)}</div>
                    <div class="summary-label">Actors</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">{len(self.participants)}</div>
                    <div class="summary-label">Participants</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">{len(self.interactions)}</div>
                    <div class="summary-label">Interactions</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">{len(self.sections)}</div>
                    <div class="summary-label">Sections</div>
                </div>
            </div>
        </div>

        <h2>🎭 Actors</h2>
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Alias</th>
                    <th>Type</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for actor in self.actors:
            display_name = actor['name'].replace('\\n', ' / ').replace('\n', ' / ')
            html_content += f"""
                <tr>
                    <td>{display_name}</td>
                    <td><code>{actor['alias']}</code></td>
                    <td>{actor['type'].title()}</td>
                </tr>
"""
        
        html_content += """
            </tbody>
        </table>

        <h2>🏢 Participants</h2>
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Alias</th>
                    <th>Type</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for participant in self.participants:
            display_name = participant['name'].replace('\\n', ' / ').replace('\n', ' / ')
            html_content += f"""
                <tr>
                    <td>{display_name}</td>
                    <td><code>{participant['alias']}</code></td>
                    <td>{participant['type'].title()}</td>
                </tr>
"""
        
        html_content += """
            </tbody>
        </table>

        <h2>🔄 Interactions</h2>
        <table>
            <thead>
                <tr>
                    <th>From</th>
                    <th>To</th>
                    <th>Message</th>
                    <th>Type</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for interaction in self.interactions:
            html_content += f"""
                <tr>
                    <td><code>{interaction['from']}</code></td>
                    <td><code>{interaction['to']}</code></td>
                    <td>{interaction['message']}</td>
                    <td><span class="interaction-type {interaction['type']}">{interaction['type'].title()}</span></td>
                </tr>
"""
        
        html_content += """
            </tbody>
        </table>

        <h2>📑 Sections</h2>
        <ul>
"""
        
        for section in self.sections:
            html_content += f"""
            <li>{section}</li>
"""
        
        html_content += f"""
        </ul>

        <div class="footer">
            <p>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Source: {self.uml_file_path}</p>
        </div>
    </div>
</body>
</html>
"""
        
        try:
            with open(output_file, 'w', encoding='utf-8') as file:
                file.write(html_content)
            print(f"HTML report generated successfully: {output_file}")
            return True
        except Exception as e:
            print(f"❌ Error generating HTML report: {e}")
            return False

def main():
    """Main function"""
    if len(sys.argv) != 2:
        print("Usage: python plantuml_parser.py <plantuml_file>")
        print("Example: python plantuml_parser.py sequence_diagram.uml")
        sys.exit(1)
    
    uml_file = sys.argv[1]
    
    if not os.path.exists(uml_file):
        print(f"Error: File '{uml_file}' not found!")
        sys.exit(1)
    
    # Create parser instance
    parser = PlantUMLParser(uml_file)
    
    # Parse the PlantUML file
    print(f"Parsing PlantUML file: {uml_file}")
    if not parser.parse():
        print("❌ Failed to parse PlantUML file!")
        sys.exit(1)
    
    # Generate HTML report
    output_file = f"{os.path.splitext(uml_file)[0]}_report.html"
    print(f"Generating HTML report: {output_file}")
    
    if parser.generate_html_report(output_file):
        print("Report generation completed successfully!")
        print(f"Open {output_file} in your web browser to view the report.")
    else:
        print("❌ Report generation failed!")
        sys.exit(1)

if __name__ == "__main__":
    main() 