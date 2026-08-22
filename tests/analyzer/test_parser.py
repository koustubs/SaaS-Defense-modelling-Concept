from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from threat_analyzer.exceptions import DiagramReadError
from threat_analyzer.models import InteractionKind, ParticipantKind
from threat_analyzer.parser import parse_plantuml, parse_plantuml_text


def test_parses_participants_requests_responses_and_evidence_lines() -> None:
    content = """@startuml
title Notes flow
actor "User" as U
participant "API" as API
participant DB
== Read ==
U -> API : GET /notes
API -> DB : Query owner notes
DB --> API : Rows
note right: Ownership enforced
API --> U : Notes
@enduml
"""

    diagram = parse_plantuml_text(content, source="read.puml")

    assert diagram.title == "Notes flow"
    assert [(item.alias, item.kind) for item in diagram.participants] == [
        ("U", ParticipantKind.ACTOR),
        ("API", ParticipantKind.PARTICIPANT),
        ("DB", ParticipantKind.PARTICIPANT),
    ]
    assert [item.kind for item in diagram.interactions] == [
        InteractionKind.REQUEST,
        InteractionKind.REQUEST,
        InteractionKind.RESPONSE,
        InteractionKind.RESPONSE,
    ]
    assert [item.number for item in diagram.interactions] == [1, 2, 3, 4]
    assert diagram.interactions[0].line_number == 7
    assert diagram.interactions[2].sender == "DB"
    assert diagram.interactions[2].receiver == "API"
    assert diagram.annotations[0].line_number == 10
    assert diagram.annotations[0].interaction_number == 3
    assert diagram.annotations[0].participants == ()
    assert diagram.warnings == ()


def test_note_targets_are_preserved_for_context_matching() -> None:
    diagram = parse_plantuml_text(
        """@startuml
participant API
participant DB
API -> DB : Query
note right of API: Checked
note over API, DB
Shared context
end note
@enduml
"""
    )

    assert [item.participants for item in diagram.annotations] == [("API",), ("API", "DB")]


def test_preserves_source_order_and_warns_on_unsupported_syntax() -> None:
    content = """@startuml
participant Zed as Z
actor Alice as A
!include unreviewed-library.puml
loop twice
A -> Z : First
Z --> A : Second
end
@enduml
"""

    first = parse_plantuml_text(content)
    second = parse_plantuml_text(content)

    assert first == second
    assert [item.alias for item in first.participants] == ["Z", "A"]
    assert [item.message for item in first.interactions] == ["First", "Second"]
    assert first.interactions[0].blocks[0].kind == "loop"
    assert [(item.code, item.line_number) for item in first.warnings] == [("UNSUPPORTED_SYNTAX", 4)]


def test_reverse_arrow_is_normalized_to_actual_sender() -> None:
    diagram = parse_plantuml_text(
        """@startuml
participant Client
participant API
Client <-- API : Response
@enduml
"""
    )

    interaction = diagram.interactions[0]
    assert interaction.sender == "API"
    assert interaction.receiver == "Client"
    assert interaction.kind is InteractionKind.RESPONSE


def test_file_source_digest_uses_exact_bytes_including_crlf(tmp_path: Path) -> None:
    raw_content = b"@startuml\r\nactor User\r\n@enduml\r\n"
    source = tmp_path / "windows-lines.puml"
    source.write_bytes(raw_content)

    diagram = parse_plantuml(source)

    assert diagram.source_sha256 == hashlib.sha256(raw_content).hexdigest()


def test_missing_diagram_raises_typed_library_exception(tmp_path: Path) -> None:
    with pytest.raises(DiagramReadError, match="Cannot read diagram"):
        parse_plantuml(tmp_path / "missing.puml")
