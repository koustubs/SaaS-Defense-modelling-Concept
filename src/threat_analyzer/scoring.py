"""Qualitative likelihood-impact scoring used by the modern register."""

from __future__ import annotations

from .models import Rating, Severity

RISK_MATRIX: dict[str, dict[str, str]] = {
    Rating.LOW.value: {
        Rating.LOW.value: Severity.LOW.value,
        Rating.MEDIUM.value: Severity.LOW.value,
        Rating.HIGH.value: Severity.MEDIUM.value,
    },
    Rating.MEDIUM.value: {
        Rating.LOW.value: Severity.LOW.value,
        Rating.MEDIUM.value: Severity.MEDIUM.value,
        Rating.HIGH.value: Severity.HIGH.value,
    },
    Rating.HIGH.value: {
        Rating.LOW.value: Severity.MEDIUM.value,
        Rating.MEDIUM.value: Severity.HIGH.value,
        Rating.HIGH.value: Severity.CRITICAL.value,
    },
}


def score_risk(likelihood: Rating, impact: Rating) -> Severity:
    """Return the matrix result; ranking and finding count never affect severity."""

    return Severity(RISK_MATRIX[likelihood.value][impact.value])
