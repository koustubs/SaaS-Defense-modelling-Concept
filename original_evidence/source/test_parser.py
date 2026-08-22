#!/usr/bin/env python3
"""
Test script for PlantUML Parser
Demonstrates the parser functionality with a simple example
"""

from plantuml_parser import PlantUMLParser
import os

def test_parser():
    """Test the parser with the sample file"""
    print("🧪 Testing PlantUML Parser")
    print("=" * 50)
    
    # Test file
    test_file = "sample_sequence.uml"
    
    if not os.path.exists(test_file):
        print(f"❌ Test file {test_file} not found!")
        return False
    
    # Create parser instance
    parser = PlantUMLParser(test_file)
    
    # Parse the file
    print(f"📖 Parsing {test_file}...")
    if not parser.parse():
        print("❌ Parsing failed!")
        return False
    
    # Display parsed information
    print(f"\n📊 Parsing Results:")
    print(f"   Title: {parser.title}")
    print(f"   Actors: {len(parser.actors)}")
    print(f"   Participants: {len(parser.participants)}")
    print(f"   Interactions: {len(parser.interactions)}")
    print(f"   Sections: {len(parser.sections)}")
    
    print(f"\n🎭 Actors found:")
    for actor in parser.actors:
        print(f"   - {actor['name']} (alias: {actor['alias']})")
    
    print(f"\n🏢 Participants found:")
    for participant in parser.participants:
        print(f"   - {participant['name']} (alias: {participant['alias']})")
    
    print(f"\n📑 Sections found:")
    for i, section in enumerate(parser.sections, 1):
        print(f"   {i}. {section}")
    
    print(f"\n🔄 Sample interactions:")
    for i, interaction in enumerate(parser.interactions[:5], 1):
        print(f"   {i}. {interaction['from']} -> {interaction['to']}: {interaction['message']}")
    
    if len(parser.interactions) > 5:
        print(f"   ... and {len(parser.interactions) - 5} more interactions")
    
    # Generate test report
    test_output = "test_report.html"
    print(f"\n📄 Generating test report: {test_output}")
    if parser.generate_html_report(test_output):
        print("✅ Test report generated successfully!")
        print(f"📂 Open {test_output} in your browser to view the report")
    else:
        print("❌ Test report generation failed!")
        return False
    
    print("\n🎉 All tests passed!")
    return True

if __name__ == "__main__":
    test_parser() 