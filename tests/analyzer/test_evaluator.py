from __future__ import annotations

from pathlib import Path

from threat_analyzer.analyzer import analyze_text
from threat_analyzer.reporting import report_to_dict
from threat_analyzer.rules import load_threat_register, parse_rule_set

PROJECT_ROOT = Path(__file__).resolve().parents[2]
REGISTER = load_threat_register(PROJECT_ROOT / "config" / "threat_register.json")


def _rule_set(
    *,
    threat_id: str = "TM-002",
    detector: str = "missing_contextual_control",
    match_terms: list[str] | None = None,
    control_terms: list[str] | None = None,
    scope: str = "connected_section_prior",
) -> object:
    return parse_rule_set(
        {
            "schema_version": "1.0",
            "rules": [
                {
                    "id": f"RULE-{threat_id}-TEST",
                    "threat_id": threat_id,
                    "title": "Context test",
                    "detector": detector,
                    "match_terms": (match_terms if match_terms is not None else ["export request"]),
                    "control_terms": (
                        control_terms if control_terms is not None else ["validate session"]
                    ),
                    "control_scope": scope,
                    "evidence_statement": "The expected contextual control is not modeled.",
                }
            ],
        }
    )


def test_control_in_another_section_does_not_globally_protect_flow() -> None:
    report = analyze_text(
        """@startuml
actor User as U
participant Auth
participant API
== Login ==
U -> Auth : Validate session
== Export ==
U -> API : Export request
@enduml
""",
        rule_set=_rule_set(),  # type: ignore[arg-type]
        threat_register=REGISTER,
    )

    assert len(report.observations) == 1
    assert report.observations[0].evidence[0].section == "Export"
    assert "not proof" in report.observations[0].evidence[0].reason


def test_connected_prior_control_protects_only_its_local_flow() -> None:
    protected = analyze_text(
        """@startuml
actor User as U
participant API
== Export ==
U -> API : Export request after validate session
@enduml
""",
        rule_set=_rule_set(),  # type: ignore[arg-type]
        threat_register=REGISTER,
    )
    unrelated = analyze_text(
        """@startuml
actor User as U
participant API
participant Auth
participant Other
== Export ==
Other -> Auth : Validate session
U -> API : Export request
@enduml
""",
        rule_set=_rule_set(),  # type: ignore[arg-type]
        threat_register=REGISTER,
    )

    assert protected.observations == ()
    assert len(unrelated.observations) == 1


def test_connected_control_can_follow_a_participant_path_but_negation_cannot() -> None:
    query_rule = _rule_set(match_terms=["query notes"])
    protected = analyze_text(
        """@startuml
actor User as U
participant Gateway
participant Auth
participant Notes
participant DB
== Listing ==
U -> Gateway : GET notes
Gateway -> Auth : Validate session
Auth --> Gateway : Valid
Gateway -> Notes : Forward request
Notes -> DB : Query notes
@enduml
""",
        rule_set=query_rule,  # type: ignore[arg-type]
        threat_register=REGISTER,
    )
    negated = analyze_text(
        """@startuml
actor User as U
participant API
== Export ==
U -> API : No validate session step
U -> API : Export request
@enduml
""",
        rule_set=_rule_set(),  # type: ignore[arg-type]
        threat_register=REGISTER,
    )

    assert protected.observations == ()
    assert len(negated.observations) == 1


def test_shared_service_does_not_join_separate_actor_initiated_flows() -> None:
    report = analyze_text(
        """@startuml
actor Alice
actor Bob
participant API
participant Auth
participant Export
== Combined section ==
Alice -> API : Start Alice request
API -> Auth : Validate session
Auth --> API : Valid
Bob -> API : Start Bob request
API -> Export : Export request
@enduml
""",
        rule_set=_rule_set(),  # type: ignore[arg-type]
        threat_register=REGISTER,
    )

    assert len(report.observations) == 1
    assert report.observations[0].evidence[0].excerpt.endswith("Export request")


def test_note_targeted_at_unrelated_participant_does_not_protect_trigger() -> None:
    report = analyze_text(
        """@startuml
actor User
participant API
participant Other
== Export ==
User -> API : Export request
note right of Other: Validate session
@enduml
""",
        rule_set=_rule_set(scope="attached"),  # type: ignore[arg-type]
        threat_register=REGISTER,
    )

    assert len(report.observations) == 1


def test_repeated_section_name_does_not_share_controls_across_occurrences() -> None:
    report = analyze_text(
        """@startuml
actor User as U
participant API
== Export ==
U -> API : Validate session
== Export ==
U -> API : Export request
@enduml
""",
        rule_set=_rule_set(),  # type: ignore[arg-type]
        threat_register=REGISTER,
    )

    assert len(report.observations) == 1


def test_unvalidated_observations_are_not_assigned_scenario_severity() -> None:
    rules = parse_rule_set(
        {
            "schema_version": "1.0",
            "rules": [
                {
                    "id": "RULE-TM-010-ERROR",
                    "threat_id": "TM-010",
                    "title": "Error gap",
                    "detector": "explicit_evidence",
                    "match_terms": ["error gap"],
                    "control_terms": [],
                    "control_scope": "none",
                    "evidence_statement": "Error detail is modeled.",
                },
                {
                    "id": "RULE-TM-006-ADMIN",
                    "threat_id": "TM-006",
                    "title": "Admin gap",
                    "detector": "explicit_evidence",
                    "match_terms": ["admin gap"],
                    "control_terms": [],
                    "control_scope": "none",
                    "evidence_statement": "An administrative gap is modeled.",
                },
            ],
        }
    )
    report = analyze_text(
        """@startuml
actor User
' admin gap
' admin gap repeated
' error gap
@enduml
""",
        rule_set=rules,
        threat_register=REGISTER,
    )

    assert [item.threat_id for item in report.observations] == ["TM-006", "TM-010"]
    assert len(report.observations[0].evidence) == 2
    serialized = report_to_dict(report)
    assert "by_severity" not in serialized["summary"]
    assert "findings" not in serialized
    assert all("severity" not in item for item in serialized["observations"])
    assert all(item["status"] == "Needs validation" for item in serialized["observations"])
