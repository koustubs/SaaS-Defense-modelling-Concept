"""Typed exceptions raised by the reusable threat-analyzer library."""

from __future__ import annotations

from pathlib import Path


class ThreatAnalyzerError(Exception):
    """Base class for expected analyzer failures."""


class DiagramReadError(ThreatAnalyzerError):
    """A diagram could not be read as UTF-8 text."""

    def __init__(self, path: Path, detail: str) -> None:
        self.path = path
        self.detail = detail
        super().__init__(f"Cannot read diagram '{path}': {detail}")


class RuleSetReadError(ThreatAnalyzerError):
    """A rule-set file could not be read or decoded."""

    def __init__(self, path: Path, detail: str) -> None:
        self.path = path
        self.detail = detail
        super().__init__(f"Cannot read rule set '{path}': {detail}")


class RuleSchemaError(ThreatAnalyzerError):
    """A rule set does not conform to the supported schema."""

    def __init__(self, location: str, detail: str) -> None:
        self.location = location
        self.detail = detail
        super().__init__(f"Invalid rule schema at {location}: {detail}")


class ThreatRegisterReadError(ThreatAnalyzerError):
    """A threat-register file could not be read or decoded."""

    def __init__(self, path: Path, detail: str) -> None:
        self.path = path
        self.detail = detail
        super().__init__(f"Cannot read threat register '{path}': {detail}")


class ThreatRegisterSchemaError(ThreatAnalyzerError):
    """A threat register does not conform to the supported schema."""

    def __init__(self, location: str, detail: str) -> None:
        self.location = location
        self.detail = detail
        super().__init__(f"Invalid threat-register schema at {location}: {detail}")


class AnalysisConfigurationError(ThreatAnalyzerError):
    """Rules and the threat register are individually valid but incompatible."""


class ReportWriteError(ThreatAnalyzerError):
    """A deterministic report could not be written."""

    def __init__(self, path: Path, detail: str) -> None:
        self.path = path
        self.detail = detail
        super().__init__(f"Cannot write report '{path}': {detail}")
