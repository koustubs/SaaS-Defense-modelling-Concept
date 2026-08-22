"""Context-aware PlantUML threat analysis for the portfolio reference project."""

from .analyzer import analyze_diagram, analyze_text
from .exceptions import ThreatAnalyzerError
from .parser import parse_plantuml, parse_plantuml_text
from .reporting import render_html, render_json, write_html, write_json
from .rules import load_rule_set, load_threat_register

__version__ = "1.1.0"

__all__ = [
    "ThreatAnalyzerError",
    "analyze_diagram",
    "analyze_text",
    "load_rule_set",
    "load_threat_register",
    "parse_plantuml",
    "parse_plantuml_text",
    "render_html",
    "render_json",
    "write_html",
    "write_json",
]
