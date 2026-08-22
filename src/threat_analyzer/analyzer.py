"""Reusable orchestration functions for deterministic diagram analysis."""

from __future__ import annotations

from pathlib import Path

from .evaluator import evaluate_rules
from .models import AnalysisReport, Observation, ParseWarning, RuleSet, ThreatRegister
from .parser import parse_plantuml, parse_plantuml_text
from .rules import load_rule_set, load_threat_register

ANALYZER_VERSION = "1.1.0"
REPORT_SCHEMA_VERSION = "1.1"


def _build_report(
    *,
    diagram_source: str,
    source_sha256: str,
    title: str,
    warnings: tuple[ParseWarning, ...],
    rule_set: RuleSet,
    threat_register: ThreatRegister,
    observations: tuple[Observation, ...],
) -> AnalysisReport:
    return AnalysisReport(
        schema_version=REPORT_SCHEMA_VERSION,
        analyzer_version=ANALYZER_VERSION,
        rules_schema_version=rule_set.schema_version,
        register_schema_version=threat_register.schema_version,
        risk_matrix={key: dict(value) for key, value in threat_register.matrix.items()},
        source=diagram_source,
        source_sha256=source_sha256,
        title=title,
        warnings=warnings,
        register_entries=threat_register.entries,
        observations=observations,
    )


def analyze_diagram(
    diagram_path: str | Path,
    rules_path: str | Path,
    register_path: str | Path | None = None,
) -> AnalysisReport:
    """Analyze a diagram file using validated rules and a modern threat register.

    When ``register_path`` is omitted, ``threat_register.json`` beside the rule
    file is used. This keeps the documented CLI concise without relying on the
    process working directory.
    """

    resolved_rules = Path(rules_path)
    resolved_register = (
        Path(register_path)
        if register_path is not None
        else resolved_rules.with_name("threat_register.json")
    )
    diagram = parse_plantuml(diagram_path)
    rule_set = load_rule_set(resolved_rules)
    threat_register = load_threat_register(resolved_register)
    observations = evaluate_rules(diagram, rule_set, threat_register)
    return _build_report(
        diagram_source=diagram.source,
        source_sha256=diagram.source_sha256,
        title=diagram.title,
        warnings=diagram.warnings,
        rule_set=rule_set,
        threat_register=threat_register,
        observations=observations,
    )


def analyze_text(
    content: str,
    *,
    rule_set: RuleSet,
    threat_register: ThreatRegister,
    source: str = "<memory>",
) -> AnalysisReport:
    """Analyze in-memory PlantUML without filesystem or process side effects."""

    diagram = parse_plantuml_text(content, source=source)
    observations = evaluate_rules(diagram, rule_set, threat_register)
    return _build_report(
        diagram_source=diagram.source,
        source_sha256=diagram.source_sha256,
        title=diagram.title,
        warnings=diagram.warnings,
        rule_set=rule_set,
        threat_register=threat_register,
        observations=observations,
    )
