from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from threat_analyzer.analyzer import analyze_text
from threat_analyzer.exceptions import RuleSchemaError, ThreatRegisterSchemaError
from threat_analyzer.rules import (
    load_rule_set,
    load_threat_register,
    parse_rule_set,
    parse_threat_register,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _valid_rule() -> dict[str, object]:
    return {
        "id": "RULE-TM-002-TEST",
        "threat_id": "TM-002",
        "title": "Test rule",
        "detector": "missing_contextual_control",
        "match_terms": ["sensitive action"],
        "control_terms": ["validate session"],
        "control_scope": "connected_section_prior",
        "evidence_statement": "A contextual control is not modeled.",
    }


def test_repository_rules_and_register_are_valid_and_stably_sorted() -> None:
    rules = load_rule_set(PROJECT_ROOT / "config" / "threat_rules.json")
    register = load_threat_register(PROJECT_ROOT / "config" / "threat_register.json")

    assert len(rules.rules) == 11
    assert [item.id for item in rules.rules] == sorted(item.id for item in rules.rules)
    assert [item.id for item in register.entries] == [f"TM-{index:03d}" for index in range(1, 22)]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda rule: rule.pop("evidence_statement"),
        lambda rule: rule.update({"unexpected": "schema drift"}),
        lambda rule: rule.update({"id": "unstable id"}),
        lambda rule: rule.update({"id": "RULE-TM-003-MISMATCH"}),
        lambda rule: rule.update({"control_terms": []}),
    ],
)
def test_invalid_rule_schema_is_rejected(mutation) -> None:  # type: ignore[no-untyped-def]
    rule = _valid_rule()
    mutation(rule)

    with pytest.raises(RuleSchemaError):
        parse_rule_set({"schema_version": "1.0", "rules": [rule]})


def test_duplicate_rule_ids_are_rejected() -> None:
    rule = _valid_rule()
    with pytest.raises(RuleSchemaError, match="duplicate ID"):
        parse_rule_set({"schema_version": "1.0", "rules": [rule, deepcopy(rule)]})


def test_register_rejects_severity_that_disagrees_with_matrix() -> None:
    payload = json.loads(
        (PROJECT_ROOT / "config" / "threat_register.json").read_text(encoding="utf-8")
    )
    payload["threats"][0]["overall_severity"] = "Critical"

    with pytest.raises(ThreatRegisterSchemaError, match="matrix result"):
        parse_threat_register(payload)


def test_generic_database_error_is_not_sensitive_detail_evidence() -> None:
    rules = load_rule_set(PROJECT_ROOT / "config" / "threat_rules.json")
    register = load_threat_register(PROJECT_ROOT / "config" / "threat_register.json")

    generic = analyze_text(
        "@startuml\nparticipant DB\nparticipant API\nDB --> API : Database error\n@enduml\n",
        rule_set=rules,
        threat_register=register,
    )
    detailed = analyze_text(
        "@startuml\nparticipant DB\nparticipant API\n"
        "DB --> API : Database error with sensitive field detail\n@enduml\n",
        rule_set=rules,
        threat_register=register,
    )

    assert all(item.threat_id != "TM-010" for item in generic.observations)
    assert any(item.threat_id == "TM-010" for item in detailed.observations)
