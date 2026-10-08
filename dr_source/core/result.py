"""Public result snapshots without execution services or persistence identifiers."""

import os
from dataclasses import dataclass, field
from typing import Tuple

from dr_source.api import Vulnerability
from dr_source.core.diagnostics import (
    ResolutionDiagnostic,
    ResolutionOriginSummary,
    ResolutionSummary,
    _summarize_resolution_events,
    _summarize_resolution_origins,
)


@dataclass(frozen=True)
class ScanMetrics:
    """Selected files include failed/skipped work; duration is observational.

    Duration retains Scanner's timing boundaries and does not affect equality.
    This is not a count of successfully analyzed files.
    """

    files_selected: int
    duration_seconds: float = field(compare=False)


def _copy_finding(finding: Vulnerability) -> Vulnerability:
    return Vulnerability(
        vulnerability_type=finding.vulnerability_type,
        message=finding.message,
        severity=finding.severity,
        file_path=finding.file_path,
        line_number=finding.line_number,
        plugin_name=finding.plugin_name,
        trace=list(finding.trace),
    )


def _finding_order(finding: Vulnerability) -> tuple:
    return (
        os.path.normpath(finding.file_path), finding.line_number,
        finding.vulnerability_type, finding.message, finding.severity,
        finding.plugin_name, tuple(finding.trace),
        # Distinguish equal normalized paths without changing stored paths.
        finding.file_path,
    )


@dataclass(frozen=True)
class ScanResult:
    """Frozen containers with detached, still-mutable Vulnerability payloads.

    Construction copies findings and their trace lists, then sorts presentation
    order without deduplicating or changing which findings Scanner selected.
    Caller edits to a finding stay in this result but cannot affect Scanner.
    Equality is value-based (excluding duration), not scan identity or a cache
    key. No execution services or persistence identifiers are included.
    """

    findings: Tuple[Vulnerability, ...]
    diagnostics: Tuple[ResolutionDiagnostic, ...]
    metrics: ScanMetrics

    __hash__ = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "findings", tuple(sorted(
            (_copy_finding(finding) for finding in self.findings), key=_finding_order,
        )))
        object.__setattr__(self, "diagnostics", tuple(self.diagnostics))

    @property
    def resolution_summary(self) -> ResolutionSummary:
        """Outcomes of recorded resolver probes, not all application calls."""
        return _summarize_resolution_events(self.diagnostics)

    @property
    def resolution_origin_summary(self) -> ResolutionOriginSummary:
        """Attempt evidence; fallback probes do not imply external ownership."""
        return _summarize_resolution_origins(self.diagnostics)
