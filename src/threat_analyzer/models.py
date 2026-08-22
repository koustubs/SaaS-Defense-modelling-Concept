"""Immutable typed models shared by parsing, evaluation, and reporting."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class StringEnum(StrEnum):
    """String-valued enum with stable JSON-friendly values."""


class ParticipantKind(StringEnum):
    ACTOR = "actor"
    PARTICIPANT = "participant"


class InteractionKind(StringEnum):
    REQUEST = "request"
    RESPONSE = "response"


class Classification(StringEnum):
    SECURITY = "security"
    PRIVACY = "privacy"
    RESILIENCE = "resilience"
    USABILITY = "usability"


class Rating(StringEnum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class Severity(StringEnum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class DetectorKind(StringEnum):
    EXPLICIT_EVIDENCE = "explicit_evidence"
    MISSING_CONTEXTUAL_CONTROL = "missing_contextual_control"


class ControlScope(StringEnum):
    NONE = "none"
    SAME_SECTION = "same_section"
    SAME_SECTION_PRIOR = "same_section_prior"
    CONNECTED_SECTION = "connected_section"
    CONNECTED_SECTION_PRIOR = "connected_section_prior"
    ATTACHED = "attached"


@dataclass(frozen=True, slots=True)
class Participant:
    alias: str
    name: str
    kind: ParticipantKind
    line_number: int


@dataclass(frozen=True, slots=True)
class Section:
    number: int
    name: str
    line_number: int


@dataclass(frozen=True, slots=True)
class Block:
    kind: str
    label: str
    line_number: int


@dataclass(frozen=True, slots=True)
class Interaction:
    number: int
    sender: str
    receiver: str
    message: str
    arrow: str
    kind: InteractionKind
    line_number: int
    section: str | None
    section_number: int | None
    blocks: tuple[Block, ...] = ()


@dataclass(frozen=True, slots=True)
class Annotation:
    text: str
    line_number: int
    section: str | None
    section_number: int | None
    interaction_number: int | None
    participants: tuple[str, ...]
    kind: str


@dataclass(frozen=True, slots=True)
class ParseWarning:
    code: str
    message: str
    line_number: int
    source_text: str


@dataclass(frozen=True, slots=True)
class Diagram:
    source: str
    source_sha256: str
    title: str
    participants: tuple[Participant, ...]
    interactions: tuple[Interaction, ...]
    sections: tuple[Section, ...]
    annotations: tuple[Annotation, ...]
    warnings: tuple[ParseWarning, ...]

    @property
    def actors(self) -> tuple[Participant, ...]:
        return tuple(item for item in self.participants if item.kind is ParticipantKind.ACTOR)

    @property
    def system_participants(self) -> tuple[Participant, ...]:
        return tuple(item for item in self.participants if item.kind is ParticipantKind.PARTICIPANT)


@dataclass(frozen=True, slots=True)
class ThreatRule:
    id: str
    threat_id: str
    title: str
    detector: DetectorKind
    match_terms: tuple[str, ...]
    control_terms: tuple[str, ...]
    control_scope: ControlScope
    evidence_statement: str


@dataclass(frozen=True, slots=True)
class RuleSet:
    schema_version: str
    rules: tuple[ThreatRule, ...]


@dataclass(frozen=True, slots=True)
class ThreatRegisterEntry:
    id: str
    classification: Classification
    stride_category: str
    affected_asset: str
    scenario: str
    preconditions: str
    trust_boundary: str
    evidence_source: str
    likelihood: Rating
    impact: Rating
    overall_severity: Severity
    existing_control: str
    planned_or_demonstrated_control: str
    residual_risk: str
    validation_method: str
    status: str


@dataclass(frozen=True, slots=True)
class ThreatRegister:
    schema_version: str
    matrix: dict[str, dict[str, str]]
    entries: tuple[ThreatRegisterEntry, ...]


@dataclass(frozen=True, slots=True)
class Evidence:
    line_number: int
    interaction_number: int | None
    section: str | None
    excerpt: str
    reason: str


@dataclass(frozen=True, slots=True)
class Observation:
    id: str
    rule_id: str
    threat_id: str
    title: str
    classification: Classification
    status: str
    evidence_basis: str
    evidence: tuple[Evidence, ...]


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    schema_version: str
    analyzer_version: str
    rules_schema_version: str
    register_schema_version: str
    risk_matrix: dict[str, dict[str, str]]
    source: str
    source_sha256: str
    title: str
    warnings: tuple[ParseWarning, ...]
    register_entries: tuple[ThreatRegisterEntry, ...]
    observations: tuple[Observation, ...]
