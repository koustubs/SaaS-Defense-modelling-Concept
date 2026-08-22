from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from threat_analyzer.analyzer import analyze_text
from threat_analyzer.models import ThreatRegister
from threat_analyzer.reporting import render_html, render_json, write_json
from threat_analyzer.rules import load_rule_set, load_threat_register, parse_rule_set

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RULES = load_rule_set(PROJECT_ROOT / "config" / "threat_rules.json")
REGISTER = load_threat_register(PROJECT_ROOT / "config" / "threat_register.json")


def test_html_escapes_diagram_rule_register_evidence_and_warning_fields() -> None:
    malicious_rule = parse_rule_set(
        {
            "schema_version": "1.0",
            "rules": [
                {
                    "id": "RULE-TM-010-ESCAPE",
                    "threat_id": "TM-010",
                    "title": '<img src=x onerror="rule()">',
                    "detector": "explicit_evidence",
                    "match_terms": ["database error"],
                    "control_terms": [],
                    "control_scope": "none",
                    "evidence_statement": "<strong>unsafe evidence</strong>",
                }
            ],
        }
    )
    entries = tuple(
        replace(
            entry,
            affected_asset='<a href="bad">register asset</a>',
            scenario="register & scenario",
            preconditions="<details open>register precondition</details>",
            planned_or_demonstrated_control="<button>unsafe control</button>",
        )
        if entry.id == "TM-010"
        else entry
        for entry in REGISTER.entries
    )
    malicious_register = ThreatRegister(
        schema_version=REGISTER.schema_version,
        matrix=REGISTER.matrix,
        entries=entries,
    )
    report = analyze_text(
        """@startuml
title <svg/onload=diagram()>
actor User
participant API
User -> API : database error <script>alert(1)</script>
!include <iframe>
@enduml
""",
        rule_set=malicious_rule,
        threat_register=malicious_register,
        source='<source onmouseover="source()">',
    )

    html = render_html(report)

    assert "<script>alert(1)</script>" not in html
    assert "<svg/onload=diagram()>" not in html
    assert '<img src=x onerror="rule()">' not in html
    assert '<a href="bad">register asset</a>' not in html
    assert "<details open>register precondition</details>" not in html
    assert "<button>unsafe control</button>" not in html
    assert "<strong>unsafe evidence</strong>" not in html
    assert "!include <iframe>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;svg/onload=diagram()&gt;" in html
    assert "&lt;strong&gt;unsafe evidence&lt;/strong&gt;" in html
    assert "!include &lt;iframe&gt;" in html
    assert "register &amp; scenario" in html
    assert "&lt;details open&gt;register precondition&lt;/details&gt;" in html
    assert "&lt;button&gt;unsafe control&lt;/button&gt;" in html


def test_json_is_versioned_and_deterministic_without_timestamps() -> None:
    content = """@startuml
actor User as U
participant API
U -> API : GET /api/notes
@enduml
"""
    first = analyze_text(
        content,
        rule_set=RULES,
        threat_register=REGISTER,
        source="stable/source.puml",
    )
    second = analyze_text(
        content,
        rule_set=RULES,
        threat_register=REGISTER,
        source="stable/source.puml",
    )

    first_json = render_json(first)
    assert first_json == render_json(second)
    assert "generated_at" not in first_json
    assert "timestamp" not in first_json
    decoded = json.loads(first_json)
    assert decoded["schema_version"] == "1.1"
    assert decoded["report_type"] == "plantuml-threat-analysis"
    assert decoded["risk_matrix"]["Medium"]["High"] == "High"
    assert len(decoded["threat_register"]) == 21
    assert all("severity" not in item for item in decoded["observations"])


def test_report_write_is_atomic_and_leaves_no_temp_file(tmp_path: Path) -> None:
    report = analyze_text(
        "@startuml\nactor User\n@enduml\n",
        rule_set=RULES,
        threat_register=REGISTER,
    )
    output = tmp_path / "nested" / "report.json"

    assert write_json(report, output) == output
    assert output.read_text(encoding="utf-8") == render_json(report)
    assert list(output.parent.glob(".report.json.*.tmp")) == []
