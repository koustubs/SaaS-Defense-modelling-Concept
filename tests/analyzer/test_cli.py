from __future__ import annotations

import json
from pathlib import Path

from threat_analyzer.cli import run

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_cli_analyze_writes_json_and_html(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    diagram = tmp_path / "flow.puml"
    diagram.write_text(
        """@startuml
actor User as U
participant API
U -> API : GET /api/notes
@enduml
""",
        encoding="utf-8",
    )
    json_path = tmp_path / "out" / "report.json"
    html_path = tmp_path / "out" / "report.html"

    result = run(
        [
            "analyze",
            str(diagram),
            "--rules",
            str(PROJECT_ROOT / "config" / "threat_rules.json"),
            "--json",
            str(json_path),
            "--html",
            str(html_path),
        ]
    )

    assert result == 0
    assert json.loads(json_path.read_text(encoding="utf-8"))["schema_version"] == "1.1"
    assert html_path.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert "Analyzed" in capsys.readouterr().out
