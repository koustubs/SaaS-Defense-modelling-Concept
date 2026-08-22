"""Deterministic JSON and safely escaped HTML report rendering."""

from __future__ import annotations

import json
import tempfile
from html import escape
from pathlib import Path
from typing import Any

from .exceptions import ReportWriteError
from .models import AnalysisReport, Observation, ParseWarning, ThreatRegisterEntry


def _register_entry_dict(entry: ThreatRegisterEntry) -> dict[str, str]:
    return {
        "id": entry.id,
        "classification": entry.classification.value,
        "stride_category": entry.stride_category,
        "affected_asset": entry.affected_asset,
        "scenario": entry.scenario,
        "preconditions": entry.preconditions,
        "trust_boundary": entry.trust_boundary,
        "evidence_source": entry.evidence_source,
        "likelihood": entry.likelihood.value,
        "impact": entry.impact.value,
        "overall_severity": entry.overall_severity.value,
        "existing_control": entry.existing_control,
        "planned_or_demonstrated_control": entry.planned_or_demonstrated_control,
        "residual_risk": entry.residual_risk,
        "validation_method": entry.validation_method,
        "status": entry.status,
    }


def _warning_dict(warning: ParseWarning) -> dict[str, str | int]:
    return {
        "code": warning.code,
        "line_number": warning.line_number,
        "message": warning.message,
        "source_text": warning.source_text,
    }


def _observation_dict(observation: Observation) -> dict[str, Any]:
    return {
        "id": observation.id,
        "rule_id": observation.rule_id,
        "threat_id": observation.threat_id,
        "title": observation.title,
        "classification": observation.classification.value,
        "status": observation.status,
        "evidence_basis": observation.evidence_basis,
        "evidence": [
            {
                "line_number": item.line_number,
                "interaction_number": item.interaction_number,
                "section": item.section,
                "excerpt": item.excerpt,
                "reason": item.reason,
            }
            for item in observation.evidence
        ],
    }


def report_to_dict(report: AnalysisReport) -> dict[str, Any]:
    """Convert a report to its documented versioned JSON shape."""

    classification_order = ("security", "privacy", "resilience", "usability")
    return {
        "schema_version": report.schema_version,
        "report_type": "plantuml-threat-analysis",
        "analyzer_version": report.analyzer_version,
        "source": {
            "path": report.source,
            "sha256": report.source_sha256,
            "title": report.title,
        },
        "rule_schema_version": report.rules_schema_version,
        "threat_register_schema_version": report.register_schema_version,
        "risk_matrix": report.risk_matrix,
        "summary": {
            "diagram_observations": len(report.observations),
            "register_entries": len(report.register_entries),
            "warnings": len(report.warnings),
            "by_classification": {
                value: sum(item.classification.value == value for item in report.observations)
                for value in classification_order
            },
        },
        "parser_warnings": [_warning_dict(item) for item in report.warnings],
        "threat_register": [_register_entry_dict(item) for item in report.register_entries],
        "observations": [_observation_dict(item) for item in report.observations],
        "interpretation": (
            "Observations are diagram-derived review indicators. A missing control in a diagram "
            "is not confirmation that the implementation lacks that control. Scenario ratings "
            "remain in the threat register and are not assigned to unvalidated observations."
        ),
    }


def render_json(report: AnalysisReport) -> str:
    """Render stable JSON with no timestamp or environment-dependent metadata."""

    return (
        json.dumps(
            report_to_dict(report),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def _h(value: object) -> str:
    return escape(str(value), quote=True)


def _observation_html(observation: Observation) -> str:
    evidence_rows = "".join(
        "<tr>"
        f"<td>{item.line_number}</td>"
        f"<td>{_h(item.interaction_number if item.interaction_number is not None else '—')}</td>"
        f"<td>{_h(item.section or 'Unsectioned')}</td>"
        f"<td><code>{_h(item.excerpt)}</code></td>"
        f"<td>{_h(item.reason)}</td>"
        "</tr>"
        for item in observation.evidence
    )
    return (
        f'<article class="observation" id="{_h(observation.id)}">'
        f"<h3>{_h(observation.id)} — {_h(observation.title)}</h3>"
        "<dl>"
        f"<dt>Threat</dt><dd>{_h(observation.threat_id)}</dd>"
        f"<dt>Rule</dt><dd>{_h(observation.rule_id)}</dd>"
        f"<dt>Classification</dt><dd>{_h(observation.classification.value)}</dd>"
        f"<dt>Status</dt><dd>{_h(observation.status)}</dd>"
        f"<dt>Evidence basis</dt><dd>{_h(observation.evidence_basis)}</dd>"
        "</dl>"
        "<table><thead><tr><th>Line</th><th>Interaction</th><th>Section</th>"
        f"<th>Excerpt</th><th>Interpretation</th></tr></thead><tbody>{evidence_rows}</tbody></table>"
        "</article>"
    )


def _register_html(entry: ThreatRegisterEntry) -> str:
    return (
        f'<article class="register-entry" id="{_h(entry.id)}">'
        f"<h3>{_h(entry.id)} — {_h(entry.scenario)}</h3>"
        "<dl>"
        f"<dt>Classification</dt><dd>{_h(entry.classification.value)}</dd>"
        f"<dt>STRIDE</dt><dd>{_h(entry.stride_category)}</dd>"
        f"<dt>Affected asset</dt><dd>{_h(entry.affected_asset)}</dd>"
        f"<dt>Preconditions</dt><dd>{_h(entry.preconditions)}</dd>"
        f"<dt>Trust boundary</dt><dd>{_h(entry.trust_boundary)}</dd>"
        f"<dt>Evidence source</dt><dd>{_h(entry.evidence_source)}</dd>"
        f"<dt>Likelihood / impact</dt><dd>{_h(entry.likelihood.value)} / "
        f"{_h(entry.impact.value)}</dd>"
        f"<dt>Severity</dt><dd>{_h(entry.overall_severity.value)}</dd>"
        f"<dt>Existing control</dt><dd>{_h(entry.existing_control)}</dd>"
        "<dt>Planned or demonstrated control</dt>"
        f"<dd>{_h(entry.planned_or_demonstrated_control)}</dd>"
        f"<dt>Residual risk</dt><dd>{_h(entry.residual_risk)}</dd>"
        f"<dt>Validation</dt><dd>{_h(entry.validation_method)}</dd>"
        f"<dt>Status</dt><dd>{_h(entry.status)}</dd>"
        "</dl></article>"
    )


def _risk_matrix_html(report: AnalysisReport) -> str:
    ratings = ("Low", "Medium", "High")
    rows = "".join(
        "<tr>"
        f"<th>{_h(likelihood)}</th>"
        + "".join(f"<td>{_h(report.risk_matrix[likelihood][impact])}</td>" for impact in ratings)
        + "</tr>"
        for likelihood in ratings
    )
    return (
        "<table><thead><tr><th>Likelihood / impact</th>"
        + "".join(f"<th>{_h(impact)}</th>" for impact in ratings)
        + f"</tr></thead><tbody>{rows}</tbody></table>"
    )


def render_html(report: AnalysisReport) -> str:
    """Render standalone HTML, escaping every diagram-, rule-, and register-derived field."""

    observation_html = "".join(_observation_html(item) for item in report.observations)
    if not observation_html:
        observation_html = "<p>No configured rule produced a diagram observation.</p>"
    warning_html = (
        "".join(
            "<li>"
            f"Line {warning.line_number}: <strong>{_h(warning.code)}</strong> — "
            f"{_h(warning.message)} <code>{_h(warning.source_text)}</code>"
            "</li>"
            for warning in report.warnings
        )
        or "<li>None</li>"
    )
    register_html = "".join(_register_html(item) for item in report.register_entries)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{_h(report.title or "Threat analysis")}</title>
  <style>
    body {{ color: #172033; background: #f5f7fa; font: 16px/1.5 system-ui, sans-serif; margin: 0; }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 2rem; }}
    h1, h2, h3 {{ line-height: 1.2; }}
    .notice {{ background: #fff7d6; border-left: 4px solid #9b7200; padding: 1rem; }}
    .observation {{
      background: white; border: 1px solid #d9dee8; border-radius: .4rem;
      margin: 1rem 0; padding: 1rem;
    }}
    .register-entry {{
      background: white; border: 1px solid #d9dee8; border-radius: .4rem;
      margin: 1rem 0; padding: 1rem;
    }}
    dl {{ display: grid; grid-template-columns: minmax(9rem, 1fr) 4fr; gap: .35rem 1rem; }}
    dt {{ font-weight: 650; }} dd {{ margin: 0; }}
    .table-wrap {{ overflow-x: auto; }}
    table {{ border-collapse: collapse; width: 100%; background: white; }}
    th, td {{ border: 1px solid #d9dee8; padding: .55rem; text-align: left; vertical-align: top; }}
    th {{ background: #e9edf4; }} code {{ white-space: pre-wrap; overflow-wrap: anywhere; }}
  </style>
</head>
<body><main>
  <h1>{_h(report.title or "Threat analysis")}</h1>
  <p><strong>Source:</strong> {_h(report.source)}<br>
  <strong>SHA-256:</strong> <code>{_h(report.source_sha256)}</code><br>
  <strong>Report schema:</strong> {_h(report.schema_version)}</p>
  <p class="notice">
    Observations are diagram-derived review indicators. A missing control in a diagram
    is not confirmation that the implementation lacks that control. Scenario ratings
    remain in the threat register and are not assigned to unvalidated observations.
  </p>
  <h2>Diagram observations ({len(report.observations)})</h2>
  {observation_html}
  <h2>Parser warnings ({len(report.warnings)})</h2><ul>{warning_html}</ul>
  <h2>Qualitative risk matrix</h2>
  <div class="table-wrap">{_risk_matrix_html(report)}</div>
  <h2>Modern threat register ({len(report.register_entries)})</h2>
  {register_html}
</main></body></html>
"""


def _write(path: str | Path, content: str) -> Path:
    output_path = Path(path)
    temporary_path: Path | None = None
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(content)
            temporary.flush()
        temporary_path.replace(output_path)
    except OSError as exc:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
        raise ReportWriteError(output_path, str(exc)) from exc
    return output_path


def write_json(report: AnalysisReport, path: str | Path) -> Path:
    return _write(path, render_json(report))


def write_html(report: AnalysisReport, path: str | Path) -> Path:
    return _write(path, render_html(report))
