"""Context-aware evaluation of diagram evidence against validated rules."""

from __future__ import annotations

import re
from collections.abc import Iterable

from .exceptions import AnalysisConfigurationError
from .models import (
    Annotation,
    ControlScope,
    DetectorKind,
    Diagram,
    Evidence,
    Interaction,
    InteractionKind,
    Observation,
    RuleSet,
    ThreatRegister,
    ThreatRegisterEntry,
    ThreatRule,
)


def _contains_term(text: str, terms: Iterable[str]) -> bool:
    normalized = text.casefold()
    return any(term.casefold() in normalized for term in terms)


def _contains_positive_control(text: str, terms: Iterable[str]) -> bool:
    """Match a control term while rejecting nearby explicit negation."""

    normalized = text.casefold()
    for term in terms:
        for match in re.finditer(re.escape(term.casefold()), normalized):
            prefix = normalized[max(0, match.start() - 64) : match.start()]
            suffix = normalized[match.end() : match.end() + 48]
            negated_before = re.search(
                r"\b(?:no|not|without|missing|lacks?|absent|skip|skipped)\b"
                r"[^.!?;\n]{0,48}$",
                prefix,
            )
            negated_after = re.match(
                r"[^.!?;\n]{0,24}\b(?:not\s+(?:shown|present|performed)|"
                r"absent|missing|skipped)\b",
                suffix,
            )
            if negated_before is None and negated_after is None:
                return True
    return False


def _annotation_evidence(annotation: Annotation, rule: ThreatRule) -> Evidence:
    return Evidence(
        line_number=annotation.line_number,
        interaction_number=annotation.interaction_number,
        section=annotation.section,
        excerpt=annotation.text,
        reason=(
            f"{rule.evidence_statement} This is diagram evidence only; it does not "
            "confirm the deployed implementation state."
        ),
    )


def _interaction_evidence(interaction: Interaction, rule: ThreatRule, *, missing: bool) -> Evidence:
    reason = rule.evidence_statement
    if missing:
        reason += (
            f" No qualifying control appears in the rule's '{rule.control_scope.value}' "
            "scope. Absence from this diagram is a review signal, not proof that the "
            "implementation lacks the control."
        )
    else:
        reason += " This is diagram evidence only; it does not confirm implementation state."
    return Evidence(
        line_number=interaction.line_number,
        interaction_number=interaction.number,
        section=interaction.section,
        excerpt=(
            f"{interaction.sender} {interaction.arrow} {interaction.receiver}: "
            f"{interaction.message}"
        ),
        reason=reason,
    )


def _explicit_evidence(diagram: Diagram, rule: ThreatRule) -> tuple[Evidence, ...]:
    evidence: list[Evidence] = []
    for interaction in diagram.interactions:
        if _contains_term(interaction.message, rule.match_terms):
            evidence.append(_interaction_evidence(interaction, rule, missing=False))
    for annotation in diagram.annotations:
        if _contains_term(annotation.text, rule.match_terms):
            evidence.append(_annotation_evidence(annotation, rule))
    return _deduplicate_evidence(evidence)


def _interactions_connected(
    diagram: Diagram,
    left: Interaction,
    right: Interaction,
    *,
    prior_only: bool,
) -> bool:
    """Check participant connectivity within one actor-initiated flow."""

    actor_aliases = {item.alias for item in diagram.actors}
    flow_numbers: dict[int, int] = {}
    flow_number = 0
    previous_section: int | None = None
    for interaction in diagram.interactions:
        if interaction.section_number != previous_section:
            flow_number = 0
            previous_section = interaction.section_number
        if interaction.kind is InteractionKind.REQUEST and interaction.sender in actor_aliases:
            flow_number += 1
        flow_numbers[interaction.number] = flow_number

    right_flow = flow_numbers[right.number]
    if flow_numbers[left.number] != right_flow:
        return False

    adjacency: dict[str, set[str]] = {}
    for interaction in diagram.interactions:
        if interaction.section_number != right.section_number:
            continue
        if flow_numbers[interaction.number] != right_flow:
            continue
        if prior_only and interaction.line_number > right.line_number:
            continue
        adjacency.setdefault(interaction.sender, set()).add(interaction.receiver)
        adjacency.setdefault(interaction.receiver, set()).add(interaction.sender)

    targets = {right.sender, right.receiver}
    pending = [left.sender, left.receiver]
    visited: set[str] = set()
    while pending:
        participant = pending.pop()
        if participant in targets:
            return True
        if participant in visited:
            continue
        visited.add(participant)
        pending.extend(adjacency.get(participant, ()) - visited)
    return False


def _annotation_applies_to(annotation: Annotation, interaction: Interaction) -> bool:
    return not annotation.participants or bool(
        set(annotation.participants) & {interaction.sender, interaction.receiver}
    )


def _qualifying_control_exists(
    diagram: Diagram,
    trigger: Interaction,
    rule: ThreatRule,
) -> bool:
    if _contains_positive_control(trigger.message, rule.control_terms):
        return True

    scope = rule.control_scope
    attached_annotations = tuple(
        annotation
        for annotation in diagram.annotations
        if annotation.interaction_number == trigger.number
        and _annotation_applies_to(annotation, trigger)
    )
    if any(
        _contains_positive_control(annotation.text, rule.control_terms)
        for annotation in attached_annotations
    ):
        return True
    if scope is ControlScope.ATTACHED:
        return False

    prior_only = scope in {
        ControlScope.SAME_SECTION_PRIOR,
        ControlScope.CONNECTED_SECTION_PRIOR,
    }
    connected_only = scope in {
        ControlScope.CONNECTED_SECTION,
        ControlScope.CONNECTED_SECTION_PRIOR,
    }
    for candidate in diagram.interactions:
        if candidate.section_number != trigger.section_number:
            continue
        if prior_only and candidate.line_number > trigger.line_number:
            continue
        if connected_only and not _interactions_connected(
            diagram,
            candidate,
            trigger,
            prior_only=prior_only,
        ):
            continue
        if _contains_positive_control(candidate.message, rule.control_terms):
            return True

    interactions_by_number = {item.number: item for item in diagram.interactions}
    for annotation in diagram.annotations:
        if annotation.section_number != trigger.section_number:
            continue
        if prior_only and annotation.line_number > trigger.line_number:
            continue
        if connected_only:
            attached_to = interactions_by_number.get(annotation.interaction_number or -1)
            if (
                attached_to is None
                or not _annotation_applies_to(annotation, attached_to)
                or not _interactions_connected(
                    diagram,
                    attached_to,
                    trigger,
                    prior_only=prior_only,
                )
            ):
                continue
        if _contains_positive_control(annotation.text, rule.control_terms):
            return True
    return False


def _missing_contextual_control(diagram: Diagram, rule: ThreatRule) -> tuple[Evidence, ...]:
    evidence = [
        _interaction_evidence(interaction, rule, missing=True)
        for interaction in diagram.interactions
        if _contains_term(interaction.message, rule.match_terms)
        and not _qualifying_control_exists(diagram, interaction, rule)
    ]
    return _deduplicate_evidence(evidence)


def _deduplicate_evidence(items: Iterable[Evidence]) -> tuple[Evidence, ...]:
    unique: dict[tuple[int, int | None, str], Evidence] = {}
    for item in items:
        unique[(item.line_number, item.interaction_number, item.excerpt)] = item
    return tuple(
        sorted(
            unique.values(),
            key=lambda item: (
                item.line_number,
                item.interaction_number if item.interaction_number is not None else -1,
                item.excerpt,
            ),
        )
    )


def _make_observation(
    rule: ThreatRule,
    register_entry: ThreatRegisterEntry,
    evidence: tuple[Evidence, ...],
) -> Observation:
    return Observation(
        id=f"OBS-{rule.id.removeprefix('RULE-')}",
        rule_id=rule.id,
        threat_id=rule.threat_id,
        title=rule.title,
        classification=register_entry.classification,
        status="Needs validation",
        evidence_basis="diagram-indicator",
        evidence=evidence,
    )


def evaluate_rules(
    diagram: Diagram,
    rule_set: RuleSet,
    threat_register: ThreatRegister,
) -> tuple[Observation, ...]:
    """Evaluate each rule and return stable, deterministically ordered observations."""

    entries = {entry.id: entry for entry in threat_register.entries}
    missing_ids = sorted({rule.threat_id for rule in rule_set.rules} - entries.keys())
    if missing_ids:
        raise AnalysisConfigurationError(
            "Rules reference threat IDs absent from the register: " + ", ".join(missing_ids)
        )

    observations: list[Observation] = []
    for rule in rule_set.rules:
        if rule.detector is DetectorKind.EXPLICIT_EVIDENCE:
            evidence = _explicit_evidence(diagram, rule)
        else:
            evidence = _missing_contextual_control(diagram, rule)
        if evidence:
            observations.append(_make_observation(rule, entries[rule.threat_id], evidence))
    return tuple(sorted(observations, key=lambda item: (item.threat_id, item.rule_id, item.id)))
