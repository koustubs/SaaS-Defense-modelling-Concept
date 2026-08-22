"""Parser for a documented, warning-oriented subset of PlantUML sequences."""

from __future__ import annotations

import hashlib
import re
from dataclasses import replace
from pathlib import Path

from .exceptions import DiagramReadError
from .models import (
    Annotation,
    Block,
    Diagram,
    Interaction,
    InteractionKind,
    ParseWarning,
    Participant,
    ParticipantKind,
    Section,
)

_DECLARATION_RE = re.compile(
    r"^\s*(?P<kind>actor|participant|boundary|control|entity|database|collections|queue)\s+"
    r'(?:(?:"(?P<quoted>(?:\\.|[^"])*)")|(?P<bare>[A-Za-z_][\w.$:-]*))'
    r"(?:\s+as\s+(?P<alias>[A-Za-z_][\w.$:-]*))?\s*$",
    re.IGNORECASE,
)
_INTERACTION_RE = re.compile(
    r"^\s*(?P<left>[A-Za-z_][\w.$:-]*)\s*"
    r"(?P<arrow>-->>|->>|-->|->|<<--|<--|<<-|<-)\s*"
    r"(?P<right>[A-Za-z_][\w.$:-]*)\s*:\s*(?P<message>.+?)\s*$"
)
_SECTION_RE = re.compile(r"^\s*==\s*(?P<name>.*?)\s*==\s*$")
_TITLE_RE = re.compile(r"^\s*title(?:\s+|:\s*)(?P<title>.+?)\s*$", re.IGNORECASE)
_NOTE_POSITION = (
    r"(?:(?:left|right)(?:\s+of\s+(?P<side_target>[\w.$:-]+))?"
    r"|over(?:\s+(?P<over_targets>[\w.$:-]+(?:\s*,\s*[\w.$:-]+)?))?)"
)
_SINGLE_NOTE_RE = re.compile(
    rf"^\s*note\s+{_NOTE_POSITION}\s*:\s*(?P<text>.+?)\s*$",
    re.IGNORECASE,
)
_BLOCK_NOTE_RE = re.compile(rf"^\s*note\s+{_NOTE_POSITION}\s*$", re.IGNORECASE)
_BLOCK_START_RE = re.compile(
    r"^\s*(?P<kind>alt|opt|loop|group|par|critical|break)\b\s*(?P<label>.*?)\s*$",
    re.IGNORECASE,
)
_SUPPORTED_DIRECTIVE_RE = re.compile(
    r"^\s*(?:activate|deactivate|destroy|create|autonumber|newpage|hide\s+footbox|"
    r"skinparam\b.*|scale\b.*|header\b.*|footer\b.*)\s*$",
    re.IGNORECASE,
)


def _clean_quoted_name(value: str) -> str:
    return value.replace(r"\"", '"').replace(r"\\", "\\")


def _warning(code: str, message: str, line_number: int, source_text: str) -> ParseWarning:
    return ParseWarning(
        code=code,
        message=message,
        line_number=line_number,
        source_text=source_text.strip(),
    )


def _note_participants(match: re.Match[str]) -> tuple[str, ...]:
    targets = match.group("side_target") or match.group("over_targets") or ""
    return tuple(part.strip() for part in targets.split(",") if part.strip())


def parse_plantuml(path: str | Path) -> Diagram:
    """Read and parse a PlantUML sequence diagram from ``path``.

    Unsupported non-empty lines are retained as warnings. File and decoding
    failures raise :class:`DiagramReadError`; no reusable function exits the
    process.
    """

    source_path = Path(path)
    try:
        raw_content = source_path.read_bytes()
        content = raw_content.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise DiagramReadError(source_path, str(exc)) from exc
    diagram = parse_plantuml_text(content, source=source_path.as_posix())
    return replace(
        diagram,
        source_sha256=hashlib.sha256(raw_content).hexdigest(),
    )


def parse_plantuml_text(content: str, *, source: str = "<memory>") -> Diagram:
    """Parse the supported PlantUML subset from an in-memory string."""

    participants: list[Participant] = []
    interactions: list[Interaction] = []
    sections: list[Section] = []
    annotations: list[Annotation] = []
    warnings: list[ParseWarning] = []
    aliases: set[str] = set()
    block_stack: list[Block] = []
    current_section: str | None = None
    current_section_number: int | None = None
    title = ""
    saw_start = False
    saw_end = False
    lines = content.splitlines()
    line_index = 0

    while line_index < len(lines):
        raw_line = lines[line_index]
        line_number = line_index + 1
        stripped = raw_line.strip()
        line_index += 1

        if not stripped:
            continue
        if stripped.lower().startswith("@startuml"):
            if saw_start:
                warnings.append(
                    _warning(
                        "DUPLICATE_START",
                        "Repeated @startuml directive",
                        line_number,
                        raw_line,
                    )
                )
            saw_start = True
            continue
        if stripped.lower() == "@enduml":
            saw_end = True
            continue

        title_match = _TITLE_RE.match(raw_line)
        if title_match:
            title = title_match.group("title").strip()
            continue

        declaration = _DECLARATION_RE.match(raw_line)
        if declaration:
            declared_name = declaration.group("quoted") or declaration.group("bare") or ""
            name = _clean_quoted_name(declared_name)
            alias = declaration.group("alias") or declaration.group("bare") or name
            if alias in aliases:
                warnings.append(
                    _warning(
                        "DUPLICATE_ALIAS",
                        f"Alias '{alias}' was already declared; the first declaration is retained",
                        line_number,
                        raw_line,
                    )
                )
                continue
            aliases.add(alias)
            kind = (
                ParticipantKind.ACTOR
                if declaration.group("kind").casefold() == "actor"
                else ParticipantKind.PARTICIPANT
            )
            participants.append(
                Participant(alias=alias, name=name, kind=kind, line_number=line_number)
            )
            continue

        section_match = _SECTION_RE.match(raw_line)
        if section_match:
            current_section = section_match.group("name").strip()
            current_section_number = len(sections) + 1
            sections.append(
                Section(
                    number=current_section_number,
                    name=current_section,
                    line_number=line_number,
                )
            )
            continue

        interaction_match = _INTERACTION_RE.match(raw_line)
        if interaction_match:
            left = interaction_match.group("left")
            right = interaction_match.group("right")
            arrow = interaction_match.group("arrow")
            sender, receiver = (right, left) if arrow.startswith("<") else (left, right)
            interaction = Interaction(
                number=len(interactions) + 1,
                sender=sender,
                receiver=receiver,
                message=interaction_match.group("message").strip(),
                arrow=arrow,
                kind=(InteractionKind.RESPONSE if "--" in arrow else InteractionKind.REQUEST),
                line_number=line_number,
                section=current_section,
                section_number=current_section_number,
                blocks=tuple(block_stack),
            )
            interactions.append(interaction)
            for endpoint in (left, right):
                if endpoint not in aliases:
                    warnings.append(
                        _warning(
                            "UNDECLARED_PARTICIPANT",
                            f"Interaction references undeclared alias '{endpoint}'",
                            line_number,
                            raw_line,
                        )
                    )
            continue

        single_note = _SINGLE_NOTE_RE.match(raw_line)
        if single_note:
            annotations.append(
                Annotation(
                    text=single_note.group("text").strip(),
                    line_number=line_number,
                    section=current_section,
                    section_number=current_section_number,
                    interaction_number=interactions[-1].number if interactions else None,
                    participants=_note_participants(single_note),
                    kind="note",
                )
            )
            continue

        block_note = _BLOCK_NOTE_RE.match(raw_line)
        if block_note:
            note_lines: list[str] = []
            found_end = False
            while line_index < len(lines):
                candidate = lines[line_index]
                line_index += 1
                if candidate.strip().casefold() == "end note":
                    found_end = True
                    break
                note_lines.append(candidate.strip())
            if not found_end:
                warnings.append(
                    _warning(
                        "UNCLOSED_NOTE",
                        "Block note is missing 'end note'",
                        line_number,
                        raw_line,
                    )
                )
            annotations.append(
                Annotation(
                    text="\n".join(part for part in note_lines if part),
                    line_number=line_number,
                    section=current_section,
                    section_number=current_section_number,
                    interaction_number=interactions[-1].number if interactions else None,
                    participants=_note_participants(block_note),
                    kind="note",
                )
            )
            continue

        if stripped.startswith("'"):
            annotations.append(
                Annotation(
                    text=stripped[1:].strip(),
                    line_number=line_number,
                    section=current_section,
                    section_number=current_section_number,
                    interaction_number=interactions[-1].number if interactions else None,
                    participants=(),
                    kind="comment",
                )
            )
            continue

        block_start = _BLOCK_START_RE.match(raw_line)
        if block_start:
            block_stack.append(
                Block(
                    kind=block_start.group("kind").casefold(),
                    label=block_start.group("label").strip(),
                    line_number=line_number,
                )
            )
            continue
        if re.match(r"^\s*else\b", raw_line, re.IGNORECASE):
            if not block_stack:
                warnings.append(
                    _warning(
                        "UNMATCHED_ELSE",
                        "'else' has no open control block",
                        line_number,
                        raw_line,
                    )
                )
            continue
        if stripped.casefold() == "end":
            if block_stack:
                block_stack.pop()
            else:
                warnings.append(
                    _warning(
                        "UNMATCHED_END",
                        "'end' has no open control block",
                        line_number,
                        raw_line,
                    )
                )
            continue
        if _SUPPORTED_DIRECTIVE_RE.match(raw_line):
            continue

        warnings.append(
            _warning(
                "UNSUPPORTED_SYNTAX",
                "Line is outside the supported PlantUML sequence subset",
                line_number,
                raw_line,
            )
        )

    if not saw_start:
        warnings.append(_warning("MISSING_START", "Diagram has no @startuml directive", 1, ""))
    if not saw_end:
        warnings.append(
            _warning("MISSING_END", "Diagram has no @enduml directive", max(len(lines), 1), "")
        )
    for block in block_stack:
        warnings.append(
            _warning(
                "UNCLOSED_BLOCK",
                f"Control block '{block.kind}' is not closed",
                block.line_number,
                block.label,
            )
        )

    return Diagram(
        source=source,
        source_sha256=hashlib.sha256(content.encode("utf-8")).hexdigest(),
        title=title,
        participants=tuple(participants),
        interactions=tuple(interactions),
        sections=tuple(sections),
        annotations=tuple(annotations),
        warnings=tuple(warnings),
    )
