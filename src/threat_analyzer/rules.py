"""Load and strictly validate analyzer rules and the modern threat register."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .exceptions import (
    RuleSchemaError,
    RuleSetReadError,
    ThreatRegisterReadError,
    ThreatRegisterSchemaError,
)
from .models import (
    Classification,
    ControlScope,
    DetectorKind,
    Rating,
    RuleSet,
    Severity,
    ThreatRegister,
    ThreatRegisterEntry,
    ThreatRule,
)
from .scoring import RISK_MATRIX, score_risk

RULE_SCHEMA_VERSION = "1.0"
REGISTER_SCHEMA_VERSION = "1.0"
_RULE_ID_RE = re.compile(r"^RULE-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
_THREAT_ID_RE = re.compile(r"^TM-\d{3}$")
_STRIDE_CATEGORIES = {
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
}
_REGISTER_STATUSES = {
    "Open",
    "Planned",
    "Partially demonstrated",
    "Demonstrated",
    "Needs validation",
    "Accepted",
}


def _load_json_file(
    path: Path,
    error_factory: Callable[[Path, str], Exception],
) -> Any:
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise error_factory(path, str(exc)) from exc
    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        detail = f"invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        raise error_factory(path, detail) from exc


def _require_object(
    value: object,
    location: str,
    error_type: type[RuleSchemaError] | type[ThreatRegisterSchemaError],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise error_type(location, "expected an object")
    return value


def _require_exact_keys(
    value: dict[str, Any],
    expected: set[str],
    location: str,
    error_type: type[RuleSchemaError] | type[ThreatRegisterSchemaError],
) -> None:
    missing = sorted(expected - value.keys())
    unknown = sorted(value.keys() - expected)
    if missing:
        raise error_type(location, f"missing required keys: {', '.join(missing)}")
    if unknown:
        raise error_type(location, f"unknown keys: {', '.join(unknown)}")


def _require_text(
    value: object,
    location: str,
    error_type: type[RuleSchemaError] | type[ThreatRegisterSchemaError],
) -> str:
    if not isinstance(value, str) or not value.strip():
        raise error_type(location, "expected a non-empty string")
    return value.strip()


def _require_terms(value: object, location: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise RuleSchemaError(location, "expected an array of strings")
    terms: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        term = _require_text(item, f"{location}[{index}]", RuleSchemaError)
        normalized = term.casefold()
        if normalized in seen:
            raise RuleSchemaError(location, f"duplicate term: {term}")
        seen.add(normalized)
        terms.append(term)
    return tuple(terms)


def load_rule_set(path: str | Path) -> RuleSet:
    """Load a UTF-8 JSON rule set and reject schema drift or invalid IDs."""

    rule_path = Path(path)
    payload = _load_json_file(rule_path, RuleSetReadError)
    return parse_rule_set(payload)


def parse_rule_set(payload: object) -> RuleSet:
    root = _require_object(payload, "$", RuleSchemaError)
    _require_exact_keys(root, {"schema_version", "rules"}, "$", RuleSchemaError)
    version = _require_text(root["schema_version"], "$.schema_version", RuleSchemaError)
    if version != RULE_SCHEMA_VERSION:
        raise RuleSchemaError(
            "$.schema_version",
            f"expected '{RULE_SCHEMA_VERSION}', got '{version}'",
        )
    raw_rules = root["rules"]
    if not isinstance(raw_rules, list):
        raise RuleSchemaError("$.rules", "expected an array")

    expected_keys = {
        "id",
        "threat_id",
        "title",
        "detector",
        "match_terms",
        "control_terms",
        "control_scope",
        "evidence_statement",
    }
    parsed: list[ThreatRule] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(raw_rules):
        location = f"$.rules[{index}]"
        raw_rule = _require_object(item, location, RuleSchemaError)
        _require_exact_keys(raw_rule, expected_keys, location, RuleSchemaError)
        rule_id = _require_text(raw_rule["id"], f"{location}.id", RuleSchemaError)
        if not _RULE_ID_RE.fullmatch(rule_id):
            raise RuleSchemaError(f"{location}.id", "expected stable ID like RULE-TM-001-NAME")
        if rule_id in seen_ids:
            raise RuleSchemaError(f"{location}.id", f"duplicate ID '{rule_id}'")
        seen_ids.add(rule_id)
        threat_id = _require_text(raw_rule["threat_id"], f"{location}.threat_id", RuleSchemaError)
        if not _THREAT_ID_RE.fullmatch(threat_id):
            raise RuleSchemaError(f"{location}.threat_id", "expected ID like TM-001")
        if not rule_id.startswith(f"RULE-{threat_id}-"):
            raise RuleSchemaError(
                f"{location}.id",
                f"rule ID must begin with 'RULE-{threat_id}-'",
            )
        detector_text = _require_text(raw_rule["detector"], f"{location}.detector", RuleSchemaError)
        scope_text = _require_text(
            raw_rule["control_scope"], f"{location}.control_scope", RuleSchemaError
        )
        try:
            detector = DetectorKind(detector_text)
        except ValueError as exc:
            raise RuleSchemaError(
                f"{location}.detector",
                f"unsupported detector '{detector_text}'",
            ) from exc
        try:
            scope = ControlScope(scope_text)
        except ValueError as exc:
            raise RuleSchemaError(
                f"{location}.control_scope",
                f"unsupported scope '{scope_text}'",
            ) from exc
        match_terms = _require_terms(raw_rule["match_terms"], f"{location}.match_terms")
        control_terms = _require_terms(raw_rule["control_terms"], f"{location}.control_terms")
        if not match_terms:
            raise RuleSchemaError(f"{location}.match_terms", "at least one term is required")
        if detector is DetectorKind.EXPLICIT_EVIDENCE:
            if control_terms or scope is not ControlScope.NONE:
                raise RuleSchemaError(
                    location,
                    "explicit_evidence requires empty control_terms and control_scope 'none'",
                )
        elif not control_terms or scope is ControlScope.NONE:
            raise RuleSchemaError(
                location,
                "missing_contextual_control requires control terms and a contextual scope",
            )
        parsed.append(
            ThreatRule(
                id=rule_id,
                threat_id=threat_id,
                title=_require_text(raw_rule["title"], f"{location}.title", RuleSchemaError),
                detector=detector,
                match_terms=match_terms,
                control_terms=control_terms,
                control_scope=scope,
                evidence_statement=_require_text(
                    raw_rule["evidence_statement"],
                    f"{location}.evidence_statement",
                    RuleSchemaError,
                ),
            )
        )
    return RuleSet(schema_version=version, rules=tuple(sorted(parsed, key=lambda rule: rule.id)))


def load_threat_register(path: str | Path) -> ThreatRegister:
    """Load and validate the machine-readable modern threat register."""

    register_path = Path(path)
    payload = _load_json_file(register_path, ThreatRegisterReadError)
    return parse_threat_register(payload)


def parse_threat_register(payload: object) -> ThreatRegister:
    root = _require_object(payload, "$", ThreatRegisterSchemaError)
    _require_exact_keys(
        root,
        {"schema_version", "risk_matrix", "threats"},
        "$",
        ThreatRegisterSchemaError,
    )
    version = _require_text(root["schema_version"], "$.schema_version", ThreatRegisterSchemaError)
    if version != REGISTER_SCHEMA_VERSION:
        raise ThreatRegisterSchemaError(
            "$.schema_version",
            f"expected '{REGISTER_SCHEMA_VERSION}', got '{version}'",
        )
    if root["risk_matrix"] != RISK_MATRIX:
        raise ThreatRegisterSchemaError(
            "$.risk_matrix",
            "matrix must match the documented qualitative likelihood-impact matrix",
        )
    raw_entries = root["threats"]
    if not isinstance(raw_entries, list):
        raise ThreatRegisterSchemaError("$.threats", "expected an array")

    expected_keys = {
        "id",
        "classification",
        "stride_category",
        "affected_asset",
        "scenario",
        "preconditions",
        "trust_boundary",
        "evidence_source",
        "likelihood",
        "impact",
        "overall_severity",
        "existing_control",
        "planned_or_demonstrated_control",
        "residual_risk",
        "validation_method",
        "status",
    }
    parsed: list[ThreatRegisterEntry] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(raw_entries):
        location = f"$.threats[{index}]"
        raw_entry = _require_object(item, location, ThreatRegisterSchemaError)
        _require_exact_keys(raw_entry, expected_keys, location, ThreatRegisterSchemaError)
        entry_id = _require_text(raw_entry["id"], f"{location}.id", ThreatRegisterSchemaError)
        if not _THREAT_ID_RE.fullmatch(entry_id):
            raise ThreatRegisterSchemaError(f"{location}.id", "expected ID like TM-001")
        if entry_id in seen_ids:
            raise ThreatRegisterSchemaError(f"{location}.id", f"duplicate ID '{entry_id}'")
        seen_ids.add(entry_id)

        classification_text = _require_text(
            raw_entry["classification"],
            f"{location}.classification",
            ThreatRegisterSchemaError,
        )
        likelihood_text = _require_text(
            raw_entry["likelihood"], f"{location}.likelihood", ThreatRegisterSchemaError
        )
        impact_text = _require_text(
            raw_entry["impact"], f"{location}.impact", ThreatRegisterSchemaError
        )
        severity_text = _require_text(
            raw_entry["overall_severity"],
            f"{location}.overall_severity",
            ThreatRegisterSchemaError,
        )
        try:
            classification = Classification(classification_text)
            likelihood = Rating(likelihood_text)
            impact = Rating(impact_text)
            severity = Severity(severity_text)
        except ValueError as exc:
            raise ThreatRegisterSchemaError(location, f"unsupported enum value: {exc}") from exc
        expected_severity = score_risk(likelihood, impact)
        if severity is not expected_severity:
            raise ThreatRegisterSchemaError(
                f"{location}.overall_severity",
                f"matrix result for {likelihood.value}/{impact.value} is {expected_severity.value}",
            )
        stride = _require_text(
            raw_entry["stride_category"],
            f"{location}.stride_category",
            ThreatRegisterSchemaError,
        )
        if stride not in _STRIDE_CATEGORIES:
            raise ThreatRegisterSchemaError(
                f"{location}.stride_category", f"unsupported STRIDE category '{stride}'"
            )
        status = _require_text(raw_entry["status"], f"{location}.status", ThreatRegisterSchemaError)
        if status not in _REGISTER_STATUSES:
            raise ThreatRegisterSchemaError(f"{location}.status", f"unsupported status '{status}'")
        parsed.append(
            ThreatRegisterEntry(
                id=entry_id,
                classification=classification,
                stride_category=stride,
                affected_asset=_require_text(
                    raw_entry["affected_asset"],
                    f"{location}.affected_asset",
                    ThreatRegisterSchemaError,
                ),
                scenario=_require_text(
                    raw_entry["scenario"], f"{location}.scenario", ThreatRegisterSchemaError
                ),
                preconditions=_require_text(
                    raw_entry["preconditions"],
                    f"{location}.preconditions",
                    ThreatRegisterSchemaError,
                ),
                trust_boundary=_require_text(
                    raw_entry["trust_boundary"],
                    f"{location}.trust_boundary",
                    ThreatRegisterSchemaError,
                ),
                evidence_source=_require_text(
                    raw_entry["evidence_source"],
                    f"{location}.evidence_source",
                    ThreatRegisterSchemaError,
                ),
                likelihood=likelihood,
                impact=impact,
                overall_severity=severity,
                existing_control=_require_text(
                    raw_entry["existing_control"],
                    f"{location}.existing_control",
                    ThreatRegisterSchemaError,
                ),
                planned_or_demonstrated_control=_require_text(
                    raw_entry["planned_or_demonstrated_control"],
                    f"{location}.planned_or_demonstrated_control",
                    ThreatRegisterSchemaError,
                ),
                residual_risk=_require_text(
                    raw_entry["residual_risk"],
                    f"{location}.residual_risk",
                    ThreatRegisterSchemaError,
                ),
                validation_method=_require_text(
                    raw_entry["validation_method"],
                    f"{location}.validation_method",
                    ThreatRegisterSchemaError,
                ),
                status=status,
            )
        )
    return ThreatRegister(
        schema_version=version,
        matrix={key: dict(value) for key, value in RISK_MATRIX.items()},
        entries=tuple(sorted(parsed, key=lambda entry: entry.id)),
    )
