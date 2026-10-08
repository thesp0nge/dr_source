"""Scan-owned observations of project resolution; never resolution decisions."""

import os
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Iterable, Optional, Tuple

from dr_source.core.project_index import SymbolId
from dr_source.core.resolution import ResolutionReason, ResolutionStatus

ResolutionSite = Tuple[str, str, Optional[int], Optional[int], Optional[int], Optional[int], str]


class ResolutionOrigin(Enum):
    """Evidence for attempting project resolution, independent of its outcome."""

    EXPLICIT_PROJECT_BINDING = "explicit_project_binding"
    CANDIDATE_BACKED = "candidate_backed"
    FALLBACK_PROBE = "fallback_probe"


@dataclass(frozen=True)
class ResolutionDiagnostic:
    """Immutable call-site evidence. Candidate order is supplied by the resolver.

    Origin describes attempt evidence, independently of status/reason, and is
    payload rather than source-site identity. Conflicting origins are errors.

    Positions span the complete call expression: one-based lines and zero-based
    UTF-8 byte columns, with an exclusive end. Genuinely unavailable coordinates
    remain None; identity then uses the available coordinates without inventing
    a node identifier. Such fallback identities can still collide, so conflicting
    decisions remain errors.
    Paths use the same lexical normalization as SymbolId, without resolving
    symlinks or changing the caller's absolute/relative path basis.
    """

    language: str
    file_path: str
    line: Optional[int]
    column: Optional[int]
    call_name: str
    status: ResolutionStatus
    reason: ResolutionReason
    origin: ResolutionOrigin
    candidates: Tuple[SymbolId, ...] = ()
    end_line: Optional[int] = None
    end_column: Optional[int] = None

    def __post_init__(self) -> None:
        if not self.file_path:
            raise ValueError("A resolution diagnostic requires a source file")
        if not isinstance(self.status, ResolutionStatus) or not isinstance(self.reason, ResolutionReason):
            raise TypeError("Diagnostic status and reason must use resolution enums")
        if not isinstance(self.origin, ResolutionOrigin):
            raise TypeError("Diagnostic origin must use ResolutionOrigin")
        if not isinstance(self.candidates, tuple) or any(
            not isinstance(candidate, SymbolId) for candidate in self.candidates
        ):
            raise TypeError("Diagnostic candidates must be a tuple of SymbolId values")
        object.__setattr__(self, "file_path", os.path.normpath(self.file_path))

    @property
    def identity(self) -> ResolutionSite:
        return (self.language, self.file_path, self.line, self.column,
                self.end_line, self.end_column, self.call_name)


@dataclass(frozen=True)
class ResolutionSummary:
    total_project_resolution_sites: int
    resolved: int
    unresolved: int
    ambiguous: int
    unsupported: int


@dataclass(frozen=True)
class ResolutionOriginSummary:
    """An orthogonal decomposition of the same sites counted by ResolutionSummary."""

    total_project_resolution_sites: int
    explicit_project_binding: int
    candidate_backed: int
    fallback_probe: int

    @property
    def project_evidenced_sites(self) -> int:
        return self.explicit_project_binding + self.candidate_backed


class ResolutionDiagnosticConflict(ValueError):
    """A source site produced inconsistent decisions within one scan."""


class ScanDiagnostics:
    """One collector per scan, with stable decisions required for each site."""

    def __init__(self) -> None:
        self._resolution_events: Dict[ResolutionSite, ResolutionDiagnostic] = {}

    def record_resolution(self, event: ResolutionDiagnostic) -> None:
        existing = self._resolution_events.get(event.identity)
        if existing is not None and existing != event:
            raise ResolutionDiagnosticConflict(f"Conflicting resolution diagnostics for {event.identity!r}")
        self._resolution_events[event.identity] = event

    def resolution_events(self) -> Tuple[ResolutionDiagnostic, ...]:
        # Tag nullable coordinates so None and numeric positions never compare.
        return tuple(sorted(self._resolution_events.values(), key=lambda event: (
            event.language, event.file_path,
            (event.line is not None, event.line),
            (event.column is not None, event.column),
            (event.end_line is not None, event.end_line),
            (event.end_column is not None, event.end_column), event.call_name,
        )))

    def summary(self) -> ResolutionSummary:
        return _summarize_resolution_events(self._resolution_events.values())

    def origin_summary(self) -> ResolutionOriginSummary:
        return _summarize_resolution_origins(self._resolution_events.values())


def _summarize_resolution_events(events: Iterable[ResolutionDiagnostic]) -> ResolutionSummary:
    """Pure reduction shared by collectors and detached scan results."""
    counts = {status: 0 for status in ResolutionStatus}
    total = 0
    for event in events:
        counts[event.status] += 1
        total += 1
    return ResolutionSummary(
        total,
        counts[ResolutionStatus.RESOLVED], counts[ResolutionStatus.UNRESOLVED],
        counts[ResolutionStatus.AMBIGUOUS], counts[ResolutionStatus.UNSUPPORTED],
    )


def _summarize_resolution_origins(events: Iterable[ResolutionDiagnostic]) -> ResolutionOriginSummary:
    """An independent decomposition of the same recorded event population."""
    counts = {origin: 0 for origin in ResolutionOrigin}
    total = 0
    for event in events:
        counts[event.origin] += 1
        total += 1
    return ResolutionOriginSummary(
        total,
        counts[ResolutionOrigin.EXPLICIT_PROJECT_BINDING],
        counts[ResolutionOrigin.CANDIDATE_BACKED],
        counts[ResolutionOrigin.FALLBACK_PROBE],
    )
