from dataclasses import FrozenInstanceError, asdict, fields, replace
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dr_source.api import AnalyzerPlugin, Vulnerability
from dr_source.core.diagnostics import (
    ResolutionDiagnostic, ResolutionDiagnosticConflict, ResolutionOrigin,
    ResolutionOriginSummary, ResolutionSummary,
)
from dr_source.core.resolution import ResolutionReason, ResolutionStatus
from dr_source.core.result import ScanMetrics, ScanResult
from dr_source.core.scanner import Scanner
from dr_source.core.utils import TimeoutException
from dr_source.plugins.python.plugin import PythonAstAnalyzer


def finding(**changes):
    values = dict(vulnerability_type="TEST", message="message", severity="HIGH",
                  file_path="app.py", line_number=1, plugin_name="test", trace=["source", "sink"])
    values.update(changes)
    return Vulnerability(**values)


def diagnostic(line=1, **changes):
    values = dict(language="python", file_path="app.py", line=line, column=0,
                  end_line=line, end_column=9, call_name="missing",
                  status=ResolutionStatus.UNRESOLVED, reason=ResolutionReason.NO_CANDIDATES,
                  origin=ResolutionOrigin.FALLBACK_PROBE)
    values.update(changes)
    return ResolutionDiagnostic(**values)


def test_metrics_and_result_equality_ignore_duration_only():
    first = ScanMetrics(2, 1.0)
    second = ScanMetrics(2, 8.5)
    assert first == second
    assert first != ScanMetrics(3, 1.0)
    result = ScanResult((finding(),), (diagnostic(),), first)
    assert result == ScanResult((finding(),), (diagnostic(),), second)
    assert result != replace(result, metrics=ScanMetrics(3, 1.0))
    assert result != replace(result, findings=(finding(message="different"),))
    assert result != replace(result, diagnostics=(diagnostic(line=2),))
    with pytest.raises(TypeError):
        hash(result)


def test_frozen_containers_and_exact_public_fields():
    result = ScanResult((finding(),), (diagnostic(),), ScanMetrics(1, 0.5))
    assert {field.name for field in fields(ScanResult)} == {"findings", "diagnostics", "metrics"}
    assert {field.name for field in fields(ScanMetrics)} == {"files_selected", "duration_seconds"}
    assert isinstance(result.findings, tuple)
    assert isinstance(result.diagnostics, tuple)
    for name in ("findings", "diagnostics", "metrics", "resolution_summary", "resolution_origin_summary"):
        with pytest.raises(FrozenInstanceError):
            setattr(result, name, None)
    with pytest.raises(FrozenInstanceError):
        result.metrics.files_selected = 2
    with pytest.raises(FrozenInstanceError):
        result.metrics.duration_seconds = 2.0
    with pytest.raises(TypeError):
        result.findings[0] = finding()
    with pytest.raises(TypeError):
        result.diagnostics[0] = diagnostic(line=2)


@pytest.mark.parametrize("early, late", [
    ({"file_path": "a.py"}, {"file_path": "z.py"}),
    ({"line_number": 1}, {"line_number": 2}),
    ({"vulnerability_type": "A"}, {"vulnerability_type": "Z"}),
    ({"message": "a"}, {"message": "z"}),
    ({"severity": "HIGH"}, {"severity": "LOW"}),
    ({"plugin_name": "a"}, {"plugin_name": "z"}),
    ({"trace": ["a", "z"]}, {"trace": ["z", "a"]}),
    # Normalize the sort key without rewriting the actual payload path.
    ({"file_path": "a/../b.py"}, {"file_path": "c.py"}),
    # Equal normalized keys need a stable raw-path tie breaker.
    ({"file_path": "./app.py"}, {"file_path": "app.py"}),
])
def test_canonical_presentation_order_uses_finding_values(early, late):
    a, z = finding(**early), finding(**late)
    forward = ScanResult((a, z), (), ScanMetrics(1, 0.0))
    reverse = ScanResult((z, a), (), ScanMetrics(1, 0.0))
    assert forward.findings == reverse.findings == (a, z)
    assert forward.findings[0].file_path == a.file_path


def test_constructor_detaches_input_containers_and_finding_payloads():
    original = finding()
    input_findings, input_diagnostics = [original], [diagnostic()]
    result = ScanResult(input_findings, input_diagnostics, ScanMetrics(1, 0.0))
    original.trace.append("later")
    input_findings.clear()
    input_diagnostics.clear()
    assert result.findings == (finding(),)
    assert result.diagnostics == (diagnostic(),)
    assert result.findings[0] is not original
    assert result.findings[0].trace is not original.trace


class ControlledAnalyzer(AnalyzerPlugin):
    name = "Controlled analyzer"

    def __init__(self, behavior=None):
        self.behavior = behavior or (lambda path: [finding(file_path=path)])

    def get_supported_extensions(self):
        return [".py"]

    def analyze(self, file_path):
        return self.behavior(file_path)


def scanner_with(monkeypatch, target, plugin, database=None):
    def load(scanner):
        scanner.extension_map = {".py": [plugin]}
    monkeypatch.setattr(Scanner, "load_plugins", load)
    if database is not None:
        monkeypatch.setattr("dr_source.core.scanner.ScanDatabase", lambda **kwargs: database)
    return Scanner(str(target))


@pytest.fixture
def real_scan(monkeypatch, tmp_path):
    factory = Path(__file__).resolve().parents[2] / "dr_source" / "config" / "knowledge_base.yaml"
    monkeypatch.setattr(
        "dr_source.core.knowledge_base.KnowledgeBaseLoader._get_default_search_paths",
        lambda self, explicit_path=None: [str(factory)],
    )
    source = "from flask import request\nimport os\nvalue = request.args.get('cmd')\nos.system(value)\n"
    for filename in ("z.py", "a.py"):
        (tmp_path / filename).write_text(source)
    scanner = scanner_with(monkeypatch, tmp_path, PythonAstAnalyzer())
    return scanner, scanner.scan()


def test_real_scanner_return_findings_metrics_and_sqlite_parity(real_scan):
    scanner, result = real_scan
    assert isinstance(result, ScanResult)
    assert isinstance(result.metrics, ScanMetrics)
    assert result.metrics.files_selected == scanner.num_files_analyzed == 2
    assert result.metrics.duration_seconds == scanner.scan_duration
    assert len(result.findings) == len(scanner.all_findings) == 2
    assert [Path(f.file_path).name for f in result.findings] == ["a.py", "z.py"]
    assert all(f.vulnerability_type == "COMMAND_INJECTION (AST Taint)" and f.line_number == 4 for f in result.findings)
    assert sorted((asdict(f) for f in result.findings), key=lambda f: f["file_path"]) == sorted(
        (asdict(f) for f in scanner.all_findings), key=lambda f: f["file_path"])
    assert isinstance(scanner.scan_id, int) and scanner.scan_id > 0
    stored = scanner.db.get_vulnerabilities_for_scan(scanner.scan_id)
    assert len(stored) == len(result.findings)
    for row in stored:
        expected = next(f for f in scanner.all_findings if f.file_path == row["file"])
        assert row == dict(file=expected.file_path, vuln_type=expected.vulnerability_type,
                           match=expected.message, line=expected.line_number, severity=expected.severity,
                           plugin_name=expected.plugin_name, trace=expected.trace)


def test_real_scanner_findings_are_isolated_in_both_directions(real_scan):
    scanner, result = real_scan
    result_finding = result.findings[0]
    legacy = next(f for f in scanner.all_findings if f.file_path == result_finding.file_path)
    assert result_finding == legacy
    assert result_finding is not legacy
    assert result_finding.trace is not legacy.trace
    legacy_before = asdict(legacy)
    result_finding.message = "caller edit"
    result_finding.trace.append("caller trace")
    assert asdict(legacy) == legacy_before
    result_before = asdict(result_finding)
    legacy.message = "legacy edit"
    legacy.trace.append("legacy trace")
    assert asdict(result_finding) == result_before
    # Payloads intentionally remain mutable and retain caller edits across reads.
    assert result.findings[0] is result_finding


def test_real_scanner_diagnostics_and_summaries_are_snapshot_values(real_scan):
    scanner, result = real_scan
    assert result.diagnostics == scanner.diagnostics.resolution_events()
    assert result.diagnostics
    assert result.resolution_summary == scanner.diagnostics.summary()
    assert result.resolution_origin_summary == scanner.diagnostics.origin_summary()
    snapshot = result.diagnostics
    summary = result.resolution_summary
    scanner.diagnostics.record_resolution(diagnostic(line=99))
    assert result.diagnostics == snapshot
    assert result.resolution_summary == summary
    assert len(scanner.diagnostics.resolution_events()) == len(snapshot) + 1


def test_summary_derivation_preserves_status_and_origin_decompositions(monkeypatch, tmp_path):
    (tmp_path / "app.py").write_text("pass\n")
    events = [
        diagnostic(1, status=ResolutionStatus.RESOLVED, reason=ResolutionReason.NONE,
                   origin=ResolutionOrigin.EXPLICIT_PROJECT_BINDING),
        diagnostic(2, reason=ResolutionReason.EXPLICIT_TARGET_NOT_FOUND,
                   origin=ResolutionOrigin.EXPLICIT_PROJECT_BINDING),
        diagnostic(3, status=ResolutionStatus.UNSUPPORTED, reason=ResolutionReason.UNSUPPORTED_BINDING,
                   origin=ResolutionOrigin.EXPLICIT_PROJECT_BINDING),
        diagnostic(4, status=ResolutionStatus.RESOLVED, reason=ResolutionReason.NONE,
                   origin=ResolutionOrigin.CANDIDATE_BACKED),
        diagnostic(5, status=ResolutionStatus.AMBIGUOUS, reason=ResolutionReason.MULTIPLE_CANDIDATES,
                   origin=ResolutionOrigin.CANDIDATE_BACKED),
        diagnostic(6),
    ]
    class RecordingAnalyzer(ControlledAnalyzer):
        def prepare(self, context):
            self.context = context

        def analyze(self, file_path):
            for event in events + events:
                self.context.diagnostics.record_resolution(event)
            return []
    scanner = scanner_with(monkeypatch, tmp_path, RecordingAnalyzer())
    result = scanner.scan()
    assert result.diagnostics == tuple(events)
    assert result.resolution_summary == scanner.diagnostics.summary() == ResolutionSummary(6, 2, 2, 1, 1)
    origins = result.resolution_origin_summary
    assert origins == scanner.diagnostics.origin_summary() == ResolutionOriginSummary(6, 3, 2, 1)
    assert origins.project_evidenced_sites == 5
    assert origins.total_project_resolution_sites == (
        origins.explicit_project_binding + origins.candidate_backed + origins.fallback_probe)
    status = result.resolution_summary
    assert status.total_project_resolution_sites == status.resolved + status.unresolved + status.ambiguous + status.unsupported


def test_result_order_is_independent_of_real_scan_traversal(monkeypatch, real_scan):
    original, first_result = real_scan
    root = original.target_path
    legacy_order = [Path(f.file_path).name for f in original.all_findings]
    def walk(path):
        yield path, [], list(reversed(legacy_order))
    monkeypatch.setattr("dr_source.core.scanner.os.walk", walk)
    second = scanner_with(monkeypatch, root, PythonAstAnalyzer())
    second_result = second.scan()
    second_legacy_order = [Path(f.file_path).name for f in second.all_findings]
    assert second_legacy_order == list(reversed(legacy_order))
    assert second_legacy_order != legacy_order
    assert first_result.findings == second_result.findings
    assert [Path(f.file_path).name for f in second_result.findings] == ["a.py", "z.py"]


@pytest.mark.parametrize("reverse", [False, True])
def test_first_wins_selection_and_legacy_order_are_unchanged(monkeypatch, tmp_path, reverse):
    (tmp_path / "app.py").write_text("pass\n")
    a = finding(file_path="z.py", plugin_name="first", severity="HIGH", trace=["first"])
    b = replace(a, plugin_name="second", severity="LOW", trace=["second"])
    order = [b, a] if reverse else [a, b]
    order += [finding(file_path="a.py")]
    scanner = scanner_with(monkeypatch, tmp_path, ControlledAnalyzer(lambda path: order))
    result = scanner.scan()
    assert scanner.all_findings == [order[0], order[2]]
    assert result.findings == (order[2], order[0])
    assert result.findings[1].trace == order[0].trace


@pytest.mark.parametrize("unsupported_file", [False, True])
def test_empty_scan_preserves_database_lifecycle(monkeypatch, tmp_path, unsupported_file):
    if unsupported_file:
        (tmp_path / "notes.md").write_text("not selected\n")
    database = MagicMock()
    database.start_scan.return_value = 123
    scanner = scanner_with(monkeypatch, tmp_path, ControlledAnalyzer(), database)
    result = scanner.scan()
    assert result == ScanResult((), (), ScanMetrics(0, result.metrics.duration_seconds))
    assert result.metrics.files_selected == scanner.num_files_analyzed == 0
    assert result.metrics.duration_seconds == scanner.scan_duration
    assert result.resolution_summary == ResolutionSummary(0, 0, 0, 0, 0)
    assert result.resolution_origin_summary == ResolutionOriginSummary(0, 0, 0, 0)
    assert scanner.scan_id == 123
    database.start_scan.assert_called_once_with()
    database.store_vulnerabilities.assert_not_called()
    database.update_scan_summary.assert_called_once_with(
        123, num_vulnerabilities=0, num_files_analyzed=0, scan_duration=scanner.scan_duration)


@pytest.mark.parametrize("error", [RuntimeError("plugin failed"), TimeoutException("timeout"), KeyboardInterrupt()])
def test_selected_metric_includes_failed_analysis(monkeypatch, tmp_path, error):
    (tmp_path / "app.py").write_text("pass\n")
    def fail(path):
        raise error
    scanner = scanner_with(monkeypatch, tmp_path, ControlledAnalyzer(fail))
    result = scanner.scan()
    assert result.findings == ()
    assert result.metrics.files_selected == scanner.num_files_analyzed == 1


@pytest.mark.parametrize("stage", ["start_scan", "update_scan_summary"])
def test_fatal_database_failures_escape_without_result(monkeypatch, tmp_path, stage):
    database = MagicMock()
    getattr(database, stage).side_effect = RuntimeError(stage)
    scanner = scanner_with(monkeypatch, tmp_path, ControlledAnalyzer(), database)
    with pytest.raises(RuntimeError, match=stage):
        scanner.scan()


def test_logged_storage_failure_still_returns_snapshot(monkeypatch, tmp_path, caplog):
    (tmp_path / "app.py").write_text("pass\n")
    database = MagicMock()
    database.store_vulnerabilities.side_effect = RuntimeError("storage failed")
    scanner = scanner_with(monkeypatch, tmp_path, ControlledAnalyzer(), database)
    result = scanner.scan()
    assert len(result.findings) == len(scanner.all_findings) == 1
    assert "Failed to store vulnerabilities" in caplog.text
    database.update_scan_summary.assert_called_once()


@pytest.mark.parametrize("error", [ResolutionDiagnosticConflict("conflict"), KeyboardInterrupt()])
def test_fatal_analysis_failures_escape_without_partial_result(monkeypatch, tmp_path, error):
    (tmp_path / "app.py").write_text("pass\n")
    def fail(path):
        raise error
    database = MagicMock()
    scanner = scanner_with(monkeypatch, tmp_path, ControlledAnalyzer(fail), database)
    # Preserve the current double-interrupt fatal boundary.
    if isinstance(error, KeyboardInterrupt):
        scanner.last_interrupt_time = 100.0
        monkeypatch.setattr("dr_source.core.scanner.time.time", lambda: scanner.last_interrupt_time)
    with pytest.raises(type(error)):
        scanner.scan()
    database.update_scan_summary.assert_not_called()



def test_persistence_call_order_and_existing_timer_boundaries(monkeypatch, tmp_path):
    (tmp_path / "app.py").write_text("pass\n")
    database = MagicMock()
    database.start_scan.return_value = 123
    scanner = scanner_with(monkeypatch, tmp_path, ControlledAnalyzer(), database)
    start, end = 100.0, 107.25
    clock = MagicMock(side_effect=[start, end])
    monkeypatch.setattr("dr_source.core.scanner.time.time", clock)
    def start_scan():
        assert clock.call_count == 0
        return 123
    def store(scan_id, rows):
        assert clock.call_count == 1
        assert scan_id == 123
        assert rows == [dict(file=str(tmp_path / "app.py"), vuln_type="TEST", match="message",
                             line=1, severity="HIGH", plugin_name="test", trace="source -> sink")]
    def summary(*args, **kwargs):
        assert clock.call_count == 2
    database.start_scan.side_effect = start_scan
    database.store_vulnerabilities.side_effect = store
    database.update_scan_summary.side_effect = summary
    result = scanner.scan()
    assert [call[0] for call in database.method_calls] == [
        "start_scan", "store_vulnerabilities", "update_scan_summary"]
    assert scanner.scan_id == 123
    assert result.metrics.duration_seconds == scanner.scan_duration == end - start
    database.update_scan_summary.assert_called_once_with(
        123, num_vulnerabilities=len(result.findings), num_files_analyzed=1, scan_duration=end - start)
