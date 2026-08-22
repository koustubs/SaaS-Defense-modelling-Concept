"""Command-line adapter; library functions remain exception based."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from .analyzer import ANALYZER_VERSION, analyze_diagram
from .exceptions import ThreatAnalyzerError
from .reporting import render_json, write_html, write_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="threat_analyzer")
    parser.add_argument("--version", action="version", version=ANALYZER_VERSION)
    commands = parser.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser(
        "analyze",
        help="analyze a supported PlantUML sequence diagram",
    )
    analyze.add_argument("diagram", type=Path)
    analyze.add_argument(
        "--rules",
        type=Path,
        default=Path("config/threat_rules.json"),
        help="validated JSON rules (default: config/threat_rules.json)",
    )
    analyze.add_argument(
        "--register",
        type=Path,
        help="threat register (default: threat_register.json beside the rules)",
    )
    analyze.add_argument("--json", type=Path, dest="json_path")
    analyze.add_argument("--html", type=Path, dest="html_path")
    return parser


def run(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = analyze_diagram(args.diagram, args.rules, args.register)
        if args.json_path is not None:
            write_json(report, args.json_path)
        if args.html_path is not None:
            write_html(report, args.html_path)
        if args.json_path is None and args.html_path is None:
            sys.stdout.write(render_json(report))
        else:
            destinations = [
                str(path) for path in (args.json_path, args.html_path) if path is not None
            ]
            print(
                f"Analyzed {len(report.observations)} diagram observation(s); wrote "
                + ", ".join(destinations)
            )
        return 0
    except ThreatAnalyzerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def main() -> int:
    return run()
