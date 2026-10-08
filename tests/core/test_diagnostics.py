from dataclasses import FrozenInstanceError, replace

import pytest

from dr_source.core.diagnostics import ResolutionDiagnostic, ResolutionDiagnosticConflict, ResolutionSummary, ScanDiagnostics, ResolutionOrigin, ResolutionOriginSummary
from dr_source.core.project_index import ProjectIndex
from dr_source.core.resolution import ResolutionReason, ResolutionStatus


def event(**changes):
    values = dict(language="python", file_path="src/./app.py", line=10,
                  column=0, end_line=10, end_column=9, call_name="execute", status=ResolutionStatus.UNRESOLVED,
                  reason=ResolutionReason.NO_CANDIDATES, candidates=(),
                  origin=ResolutionOrigin.FALLBACK_PROBE)
    values.update(changes)
    return ResolutionDiagnostic(**values)


def test_event_immutable_normalized_identity_and_equality():
    diagnostic = event()
    assert diagnostic.identity == ("python", "src/app.py", 10, 0, 10, 9, "execute")
    assert diagnostic == event(file_path="src/sub/../app.py")
    assert hash(diagnostic) == hash(event(file_path="src/app.py"))
    with pytest.raises(FrozenInstanceError):
        diagnostic.line = 20
    for field, value in (("language", "java"), ("file_path", "other.py"),
                         ("line", None), ("column", None), ("end_line", None),
                         ("end_column", None), ("call_name", "other")):
        assert replace(diagnostic, **{field: value}).identity != diagnostic.identity
    changed = replace(diagnostic, status=ResolutionStatus.UNSUPPORTED,
                      reason=ResolutionReason.UNSUPPORTED_CALL_FORM)
    assert changed.identity == diagnostic.identity
    assert changed != diagnostic


def test_event_rejects_mutable_candidates_and_missing_file():
    with pytest.raises(TypeError):
        event(candidates=[])
    with pytest.raises(TypeError):
        event(candidates=(object(),))
    with pytest.raises(ValueError):
        event(file_path="")


def test_empty_summary_and_immutable_exposure():
    collector = ScanDiagnostics()
    assert collector.resolution_events() == ()
    assert collector.summary() == ResolutionSummary(0, 0, 0, 0, 0)
    with pytest.raises(FrozenInstanceError):
        collector.summary().resolved = 1


def test_status_counts_deduplication_and_order():
    events = [event(line=None), event(line=1, column=None, status=ResolutionStatus.RESOLVED,
              reason=ResolutionReason.NONE),
              event(line=1, column=0, status=ResolutionStatus.AMBIGUOUS,
                    reason=ResolutionReason.MULTIPLE_CANDIDATES),
              event(line=2, status=ResolutionStatus.UNSUPPORTED,
                    reason=ResolutionReason.UNSUPPORTED_BINDING)]
    forward, reverse = ScanDiagnostics(), ScanDiagnostics()
    for diagnostic in events:
        forward.record_resolution(diagnostic)
        forward.record_resolution(diagnostic)
    for diagnostic in reversed(events):
        reverse.record_resolution(diagnostic)
    assert forward.resolution_events() == reverse.resolution_events() == tuple(events)
    assert forward.summary() == reverse.summary() == ResolutionSummary(4, 1, 1, 1, 1)
    snapshot = forward.resolution_events()
    forward.record_resolution(event(line=99))
    assert len(snapshot) == 4


def test_ambiguous_candidate_identities_preserve_resolver_order():
    index = ProjectIndex()
    index.register_function("execute", "z.py", object(), "python")
    index.register_function("execute", "a.py", object(), "python")
    other = ProjectIndex()
    other.register_function("execute", "a.py", object(), "python")
    other.register_function("execute", "z.py", object(), "python")
    resolution = index.resolve_unique("execute", "python")
    assert resolution.candidates == other.resolve_unique("execute", "python").candidates
    diagnostic = event(status=resolution.status, reason=resolution.reason,
                       candidates=resolution.candidates)
    collector = ScanDiagnostics()
    collector.record_resolution(diagnostic)
    assert collector.resolution_events()[0].candidates == resolution.candidates
    assert tuple(symbol.file_path for symbol in diagnostic.candidates) == ("a.py", "z.py")
    with pytest.raises(FrozenInstanceError):
        diagnostic.candidates[0].name = "changed"


@pytest.mark.parametrize("reverse", [False, True])
def test_conflicting_same_site_is_rejected_in_either_order(reverse):
    events = [event(), event(status=ResolutionStatus.UNSUPPORTED,
                            reason=ResolutionReason.UNSUPPORTED_CALL_FORM)]
    if reverse:
        events.reverse()
    collector = ScanDiagnostics()
    collector.record_resolution(events[0])
    with pytest.raises(ResolutionDiagnosticConflict, match="Conflicting resolution diagnostics"):
        collector.record_resolution(events[1])
    assert collector.resolution_events() == (events[0],)


@pytest.mark.parametrize("ends", [((10, 9), (10, 15)), ((10, 9), (11, 9))])
def test_same_start_different_end_remains_distinct_and_order_independent(ends):
    events = tuple(event(end_line=line, end_column=column) for line, column in ends)
    collectors = (ScanDiagnostics(), ScanDiagnostics())
    for collector, ordered in zip(collectors, (events, reversed(events))):
        for diagnostic in ordered:
            collector.record_resolution(diagnostic)
            collector.record_resolution(diagnostic)
        assert collector.summary() == ResolutionSummary(2, 0, 2, 0, 0)
    assert collectors[0].resolution_events() == collectors[1].resolution_events() == events
    assert events[0].identity != events[1].identity


def test_missing_end_coordinates_use_deterministic_none_fallback():
    missing = event(end_line=None, end_column=None)
    partial = event(end_line=10, end_column=None)
    complete = event()
    assert missing.identity == ("python", "src/app.py", 10, 0, None, None, "execute")
    collector = ScanDiagnostics()
    for diagnostic in (complete, partial, missing, missing):
        collector.record_resolution(diagnostic)
    assert collector.resolution_events() == (missing, partial, complete)
    assert collector.summary() == ResolutionSummary(3, 0, 3, 0, 0)
    with pytest.raises(ResolutionDiagnosticConflict):
        collector.record_resolution(replace(missing, status=ResolutionStatus.UNSUPPORTED,
                                            reason=ResolutionReason.UNSUPPORTED_CALL_FORM))


def test_exact_full_span_duplicate_counts_once():
    diagnostic = event()
    collector = ScanDiagnostics()
    collector.record_resolution(diagnostic)
    collector.record_resolution(diagnostic)
    assert collector.resolution_events() == (diagnostic,)
    assert collector.summary() == ResolutionSummary(1, 0, 1, 0, 0)


@pytest.mark.parametrize("reverse", [False, True])
def test_origin_conflict_preserves_source_identity(reverse):
    first = event()
    second = replace(first, origin=ResolutionOrigin.EXPLICIT_PROJECT_BINDING)
    assert first.identity == second.identity
    if reverse:
        first, second = second, first
    collector = ScanDiagnostics()
    collector.record_resolution(first)
    collector.record_resolution(replace(first))
    assert collector.resolution_events() == (first,)
    with pytest.raises(ResolutionDiagnosticConflict):
        collector.record_resolution(second)
    assert collector.resolution_events() == (first,)


def test_origin_enum_validation_and_immutability():
    with pytest.raises(TypeError, match="origin"):
        event(origin="fallback_probe")
    with pytest.raises(FrozenInstanceError):
        event().origin = ResolutionOrigin.CANDIDATE_BACKED


def test_origin_summary_is_immutable_and_orthogonal_to_status():
    collector = ScanDiagnostics()
    assert collector.origin_summary() == ResolutionOriginSummary(0, 0, 0, 0)
    for line, (origin, status, reason) in enumerate([
        (ResolutionOrigin.EXPLICIT_PROJECT_BINDING, ResolutionStatus.RESOLVED, ResolutionReason.NONE),
        (ResolutionOrigin.EXPLICIT_PROJECT_BINDING, ResolutionStatus.UNRESOLVED, ResolutionReason.EXPLICIT_TARGET_NOT_FOUND),
        (ResolutionOrigin.EXPLICIT_PROJECT_BINDING, ResolutionStatus.UNSUPPORTED, ResolutionReason.UNSUPPORTED_BINDING),
        (ResolutionOrigin.CANDIDATE_BACKED, ResolutionStatus.RESOLVED, ResolutionReason.NONE),
        (ResolutionOrigin.CANDIDATE_BACKED, ResolutionStatus.AMBIGUOUS, ResolutionReason.MULTIPLE_CANDIDATES),
        (ResolutionOrigin.FALLBACK_PROBE, ResolutionStatus.UNRESOLVED, ResolutionReason.NO_CANDIDATES),
    ], start=1):
        diagnostic = event(line=line, origin=origin, status=status, reason=reason)
        collector.record_resolution(diagnostic)
        collector.record_resolution(diagnostic)
    summary = collector.origin_summary()
    assert summary == ResolutionOriginSummary(6, 3, 2, 1)
    assert summary.project_evidenced_sites == 5
    assert summary.total_project_resolution_sites == (
        summary.explicit_project_binding + summary.candidate_backed + summary.fallback_probe
    )
    outcomes = collector.summary()
    assert outcomes == ResolutionSummary(6, 2, 2, 1, 1)
    assert outcomes.total_project_resolution_sites == summary.total_project_resolution_sites == (
        outcomes.resolved + outcomes.unresolved + outcomes.ambiguous + outcomes.unsupported
    )
    with pytest.raises(FrozenInstanceError):
        summary.candidate_backed = 0
