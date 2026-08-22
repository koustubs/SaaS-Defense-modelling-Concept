# PlantUML Sequence Diagram Parser

A simple Python tool to parse PlantUML sequence diagrams and generate beautiful HTML reports.

## Features

- 📊 **Parse PlantUML sequence diagrams** - Extracts actors, participants, interactions, and sections
- 📄 **Generate HTML reports** - Creates clean, responsive HTML reports with analysis
- 🎨 **Modern UI** - Beautiful, professional-looking reports with CSS styling
- 📈 **Summary statistics** - Quick overview of diagram components
- 🔍 **Detailed analysis** - Tables showing all extracted information

## Usage

### Basic Usage

```bash
python plantuml_parser.py <plantuml_file>
```

### Example

```bash
python plantuml_parser.py sample_sequence.uml
```

This will generate `sample_sequence_report.html` in the same directory.

## What the Parser Extracts

1. **Title** - The diagram title
2. **Actors** - External actors (users, systems)
3. **Participants** - Internal system components
4. **Interactions** - All message exchanges between components
5. **Sections** - Logical groupings of interactions

## Supported PlantUML Elements

- `actor` declarations
- `participant` declarations  
- `->` and `-->` message arrows
- `==` section dividers
- `title` declarations

## Output

The tool generates an HTML file with:

- 📊 **Summary Dashboard** - Overview statistics
- 🎭 **Actors Table** - All external actors
- 🏢 **Participants Table** - All system components
- 🔄 **Interactions Table** - All message exchanges
- 📑 **Sections List** - Logical groupings

## Requirements

- Python 3.6+
- No external dependencies (uses only standard library)

## Example Report

The generated HTML report includes:
- Responsive design that works on desktop and mobile
- Color-coded interaction types (requests vs responses)
- Professional styling with hover effects
- Timestamp and source file information

## File Structure

```
├── plantuml_parser.py    # Main parser script
├── sample_sequence.uml   # Example PlantUML file
├── README.md            # This file
└── sample_sequence_report.html  # Generated report (after running)
```

## Quick Start

1. Save your PlantUML sequence diagram as a `.uml` file
2. Run: `python plantuml_parser.py your_diagram.uml`
3. Open the generated HTML file in your web browser

That's it! You'll have a beautiful, professional report of your sequence diagram analysis. 