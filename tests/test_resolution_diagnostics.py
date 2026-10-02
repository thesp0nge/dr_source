"""Observe existing lookup boundaries without expanding their call domain."""

from collections import Counter
from pathlib import Path

import pytest

from dr_source.core.diagnostics import ResolutionDiagnostic, ResolutionDiagnosticConflict, ResolutionSummary
from dr_source.core.resolution import ResolutionReason, ResolutionStatus
from dr_source.core.scanner import Scanner
from dr_source.plugins.python.plugin import PythonAstAnalyzer
from dr_source.plugins.python.taint_visitor import PythonTaintVisitor
from dr_source.plugins.java.plugin import JavaAstAnalyzer
from dr_source.plugins.java.taint_visitor import TaintVisitor
from dr_source.plugins.javascript.plugin import JavaScriptAstAnalyzer
from dr_source.plugins.javascript.taint_visitor import JavaScriptTaintVisitor


LANGUAGES = {
    "python": (PythonAstAnalyzer, PythonTaintVisitor, ".py", "request.args", "os.system", "escape"),
    "java": (JavaAstAnalyzer, TaintVisitor, ".java", "getParameter", "executeQuery", "escapeSql"),
    "javascript": (JavaScriptAstAnalyzer, JavaScriptTaintVisitor, ".js", "req.query", "cp.exec", "escape"),
}


class SingleRuleKnowledge:
    """Isolate one existing visitor model so exact denominators are testable."""
    rules = {"TEST_FLOW": {}}

    def __init__(self, language):
        self.language = language

    def get_all_vuln_types(self):
        return self.rules.keys()

    def get_detector_rules(self, category):
        return {"severity": "HIGH"}

    def get_lang_ast_sources(self, category, language):
        return [LANGUAGES[language][3]]

    def get_lang_ast_sinks(self, category, language):
        return [LANGUAGES[language][4]]

    def get_lang_ast_sanitizers(self, category, language):
        return [LANGUAGES[language][5]]


def scan_project(monkeypatch, root, language, *, real_knowledge=False, reverse=False, before_scan=None):
    analyzer_class, _, extension, *_ = LANGUAGES[language]
    def load(scanner):
        plugin = analyzer_class()
        if not real_knowledge:
            plugin.kb = SingleRuleKnowledge(language)
        scanner.extension_map = {extension: [plugin]}
    monkeypatch.setattr(Scanner, "load_plugins", load)
    scanner = Scanner(str(root))
    # Reverse both indexing and analysis over identical source paths.
    original_walk = __import__("os").walk
    def walk(path):
        for directory, dirs, files in original_walk(path):
            yield directory, dirs, sorted(files, reverse=reverse)
    with monkeypatch.context() as scoped:
        scoped.setattr("dr_source.core.scanner.os.walk", walk)
        if before_scan:
            before_scan(scanner)
        scanner.scan()
    summary = scanner.diagnostics.summary()
    assert summary.total_project_resolution_sites == (
        summary.resolved + summary.unresolved + summary.ambiguous + summary.unsupported
    )
    return scanner


def write(root, filename, source):
    (root / filename).write_text(source, encoding="utf-8")


def programs(language, call="projectTarget"):
    if language == "python":
        return f"{call}('constant')\n", "def projectTarget(value):\n    return value\n", (1, 0)
    if language == "java":
        return (f'class App {{\n    void route() {{ helper.{call}("constant"); }}\n}}\n',
                "class Service { void projectTarget(String value) {} }\n", (2, 19))
    return f"{call}('constant');\n", "function projectTarget(value) { return value; }\n", (1, 0)


@pytest.mark.parametrize("language", LANGUAGES)
@pytest.mark.parametrize("status", [ResolutionStatus.RESOLVED, ResolutionStatus.AMBIGUOUS,
                                    ResolutionStatus.UNRESOLVED])
def test_scanner_records_exact_existing_project_outcome(monkeypatch, tmp_path, language, status):
    extension = LANGUAGES[language][2]
    caller, target, position = programs(language)
    write(tmp_path, "app" + extension, caller)
    if status is not ResolutionStatus.UNRESOLVED:
        write(tmp_path, "service_a" + extension, target)
    if status is ResolutionStatus.AMBIGUOUS:
        write(tmp_path, "service_b" + extension, target)
    scanner = scan_project(monkeypatch, tmp_path, language)
    events = scanner.diagnostics.resolution_events()
    assert len(events) == 1
    event = events[0]
    expression = 'helper.projectTarget("constant")' if language == "java" else "projectTarget('constant')"
    end = (position[0], position[1] + len(expression.encode("utf-8")))
    assert event.identity == (language, str(tmp_path / ("app" + extension)), *position, *end, "projectTarget")
    expected = scanner.project_index.resolve_unique("projectTarget", language)
    assert (event.status, event.reason, event.candidates) == (expected.status, expected.reason, expected.candidates)
    counts = {ResolutionStatus.RESOLVED: (1, 0, 0, 0),
              ResolutionStatus.AMBIGUOUS: (0, 0, 1, 0),
              ResolutionStatus.UNRESOLVED: (0, 1, 0, 0)}
    assert scanner.diagnostics.summary() == ResolutionSummary(1, *counts[status])
    assert scanner.all_findings == []
    if status is ResolutionStatus.AMBIGUOUS:
        assert [Path(candidate.file_path).name for candidate in event.candidates] == [
            "service_a" + extension, "service_b" + extension]
        other = scan_project(monkeypatch, tmp_path, language, reverse=True)
        assert other.diagnostics.resolution_events() == events


@pytest.mark.parametrize("imports, name, target, status, reason", [
    ("from service import projectTarget", "projectTarget", True, ResolutionStatus.RESOLVED, ResolutionReason.NONE),
    ("import service", "service.projectTarget", True, ResolutionStatus.RESOLVED, ResolutionReason.NONE),
    ("from service import projectTarget", "projectTarget", False, ResolutionStatus.UNRESOLVED, ResolutionReason.EXPLICIT_TARGET_NOT_FOUND),
    ("from service import projectTarget as run", "run", True, ResolutionStatus.UNSUPPORTED, ResolutionReason.UNSUPPORTED_BINDING),
    ("import service as svc", "svc.projectTarget", True, ResolutionStatus.UNSUPPORTED, ResolutionReason.UNSUPPORTED_BINDING),
])
def test_python_import_events_copy_decision(monkeypatch, tmp_path, imports, name, target, status, reason):
    write(tmp_path, "app.py", f"{imports}\n{name}('constant')\n")
    write(tmp_path, "service.py", programs("python")[1] if target else "value = 1\n")
    scanner = scan_project(monkeypatch, tmp_path, "python")
    event, = scanner.diagnostics.resolution_events()
    assert event.identity == ("python", str(tmp_path / "app.py"), 2, 0,
                              2, len(f"{name}('constant')"), name)
    assert event.status is status
    assert event.reason is reason
    if status is ResolutionStatus.RESOLVED:
        assert event.candidates == tuple(d.symbol_id for d in scanner.project_index.find_candidates("projectTarget", "python"))
    else:
        assert event.candidates == ()
    assert scanner.all_findings == []


def test_javascript_dotted_member_remains_exact_unresolved_lookup(monkeypatch, tmp_path):
    write(tmp_path, "app.js", "service.projectTarget('constant');\n")
    write(tmp_path, "service.js", programs("javascript")[1])
    scanner = scan_project(monkeypatch, tmp_path, "javascript")
    event, = scanner.diagnostics.resolution_events()
    assert event.call_name == "service.projectTarget"
    assert event.status is ResolutionStatus.UNRESOLVED
    assert event.reason is ResolutionReason.NO_CANDIDATES
    assert event.candidates == ()


RECURSIVE = {
    "python": {
        "app.py": "from service import projectTarget\nvalue = request.args\nprojectTarget(value)\nprojectTarget(value)\n",
        "service.py": "from helper import leafTarget\ndef projectTarget(value):\n    leafTarget(value)\n",
        "helper.py": "def leafTarget(value):\n    os.system(value)\n",
    },
    "java": {
        "app.java": 'class App { void route() { String password = "x";\n    helper.projectTarget(password); helper.projectTarget(password); } }\n',
        "service.java": "class Service { void projectTarget(String value) {\n    helper.leafTarget(value); } }\n",
        "helper.java": "class Helper { void leafTarget(String value) { stmt.executeQuery(value); } }\n",
    },
    "javascript": {
        "app.js": "const value = req.query.cmd;\nprojectTarget(value);\nprojectTarget(value);\n",
        "service.js": "function projectTarget(value) {\n    leafTarget(value);\n}\n",
        "helper.js": "function leafTarget(value) { cp.exec(value); }\n",
    },
}


@pytest.mark.parametrize("language", LANGUAGES)
def test_recursive_visitors_share_context_file_and_deduplicate(monkeypatch, tmp_path, language):
    for filename, source in RECURSIVE[language].items():
        write(tmp_path, filename, source)
    visitor_class = LANGUAGES[language][1]
    original_init = visitor_class.__init__
    visitors = []
    def init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        visitors.append(self)
    monkeypatch.setattr(visitor_class, "__init__", init)
    attempts = []
    def observe(scanner):
        original_record = scanner.diagnostics.record_resolution
        def record(event):
            attempts.append(event)
            original_record(event)
        monkeypatch.setattr(scanner.diagnostics, "record_resolution", record)
    scanner = scan_project(monkeypatch, tmp_path, language, before_scan=observe)
    extension = LANGUAGES[language][2]
    events = scanner.diagnostics.resolution_events()
    assert scanner.diagnostics.summary() == ResolutionSummary(3, 3, 0, 0, 0)
    assert [Path(event.file_path).name for event in events] == ["app" + extension, "app" + extension, "service" + extension]
    assert [event.call_name for event in events] == ["projectTarget", "projectTarget", "leafTarget"]
    assert [(event.line, event.column) for event in events] == {
        "python": [(3, 0), (4, 0), (3, 4)],
        "java": [(2, 4), (2, 36), (2, 4)],
        "javascript": [(2, 0), (3, 0), (2, 4)],
    }[language]
    assert Counter(event.identity for event in attempts)[events[-1].identity] >= 3
    contextual = [visitor for visitor in visitors if visitor.analysis_context is not None]
    assert all(visitor.analysis_context is scanner.analysis_context for visitor in contextual)
    assert all(visitor.analysis_context.diagnostics is scanner.diagnostics for visitor in contextual)
    assert any(visitor.depth > 0 and visitor.current_file == str(tmp_path / ("service" + extension)) for visitor in contextual)
    assert any(visitor.depth > 1 and visitor.current_file == str(tmp_path / ("helper" + extension)) for visitor in contextual)
    assert scanner.all_findings
    assert all(any("in helper" + extension in step for step in finding.trace) for finding in scanner.all_findings)
    other = scan_project(monkeypatch, tmp_path, language, reverse=True)
    assert other.diagnostics.resolution_events() == events
    assert other.diagnostics.summary() == scanner.diagnostics.summary()
    assert other.all_findings == scanner.all_findings


@pytest.mark.parametrize("language, source", [
    ("python", "def local(value):\n    return value\nvalue = request.args\nlocal(value)\nos.system(value)\n"),
    ("java", 'class App { void local(String value) {} void route() { String password = "x"; local(password); stmt.executeQuery(password); jdbcTemplate.query(password); } }\n'),
    ("javascript", "function local(value) { return value; }\nconst value = req.query.cmd;\nlocal(value); cp.exec(value);\n"),
])
def test_local_known_sink_and_noncall_sources_are_not_counted(monkeypatch, tmp_path, language, source):
    write(tmp_path, "app" + LANGUAGES[language][2], source)
    scanner = scan_project(monkeypatch, tmp_path, language)
    assert scanner.diagnostics.resolution_events() == ()
    assert scanner.diagnostics.summary() == ResolutionSummary(0, 0, 0, 0, 0)
    assert scanner.all_findings  # Existing sink handling still works.


@pytest.mark.parametrize("language, source, names", [
    ("python", "value = request.args.get('cmd')\nclean = escape(value)\nprint(clean)\n", ["request.args.get", "escape", "print"]),
    ("java", 'class App { void route() { String value = request.getParameter("cmd"); String clean = StringEscapeUtils.escapeSql(value); System.out.println(clean); } }\n', ["getParameter", "escapeSql", "println"]),
    ("javascript", "const value = req.query.cmd;\nconst clean = escape(value);\nconsole.log(clean);\n", ["escape", "console.log"]),
])
def test_existing_external_source_and_sanitizer_lookup_is_characterized(monkeypatch, tmp_path, language, source, names):
    write(tmp_path, "app" + LANGUAGES[language][2], source)
    scanner = scan_project(monkeypatch, tmp_path, language)
    events = scanner.diagnostics.resolution_events()
    assert [event.call_name for event in events] == names
    assert all(event.status is ResolutionStatus.UNRESOLVED for event in events)
    assert all(event.reason is ResolutionReason.NO_CANDIDATES for event in events)
    assert scanner.diagnostics.summary() == ResolutionSummary(len(names), 0, len(names), 0, 0)
    assert scanner.all_findings == []


@pytest.mark.parametrize("language", LANGUAGES)
def test_conflicting_diagnostics_propagate_through_plugin_and_scanner(monkeypatch, tmp_path, language):
    write(tmp_path, "app" + LANGUAGES[language][2], programs(language)[0])
    def reject(scanner):
        line, column = programs(language)[2]
        scanner.diagnostics.record_resolution(ResolutionDiagnostic(
            language, str(tmp_path / ("app" + LANGUAGES[language][2])),
            line, column, "projectTarget", ResolutionStatus.UNSUPPORTED,
            ResolutionReason.UNSUPPORTED_CALL_FORM,
            end_line=line, end_column=column + len(
                'helper.projectTarget("constant")' if language == "java" else "projectTarget('constant')"
            ),
        ))
    with pytest.raises(ResolutionDiagnosticConflict, match="Conflicting resolution diagnostics"):
        scan_project(monkeypatch, tmp_path, language, before_scan=reject)


@pytest.mark.parametrize("language", LANGUAGES)
@pytest.mark.parametrize("scenario", ["recursive", "existing_fixture"])
def test_real_rules_findings_identical_with_and_without_recording(monkeypatch, tmp_path, language, scenario):
    if scenario == "recursive":
        for filename, source in RECURSIVE[language].items():
            write(tmp_path, filename, source)
        root = tmp_path
    else:
        root = Path(__file__).parent / "test_code" / "inter_file" / language
    scanner = scan_project(monkeypatch, root, language, real_knowledge=True)
    assert scanner.diagnostics.resolution_events()
    monkeypatch.setattr(LANGUAGES[language][1], "_record_resolution_diagnostic", lambda *args: None)
    control = scan_project(monkeypatch, root, language, real_knowledge=True)
    if scenario == "existing_fixture":
        assert scanner.all_findings
    assert control.diagnostics.resolution_events() == ()
    assert scanner.all_findings == control.all_findings


@pytest.mark.parametrize("language, prefix, suffix", [
    ("python", "label = 'é'; ", "projectTarget('constant')\n"),
    ("java", 'class App { void route() { String label = "é"; ', 'helper.projectTarget("constant"); } }\n'),
    ("javascript", "const label = 'é'; ", "projectTarget('constant');\n"),
])
def test_call_columns_are_zero_based_utf8_bytes(monkeypatch, tmp_path, language, prefix, suffix):
    write(tmp_path, "app" + LANGUAGES[language][2], prefix + suffix)
    scanner = scan_project(monkeypatch, tmp_path, language)
    event, = scanner.diagnostics.resolution_events()
    assert event.line == 1
    assert event.column == len(prefix.encode("utf-8"))
    assert event.end_line == 1
    expression = suffix.split(";")[0].rstrip("\n")
    assert event.end_column == len((prefix + expression).encode("utf-8"))
    assert event.status is ResolutionStatus.UNRESOLVED


@pytest.mark.parametrize("language", LANGUAGES)
def test_visitor_context_requires_source_file_and_consistent_index(tmp_path, language):
    from dr_source.core.context import AnalysisContext
    from dr_source.core.diagnostics import ScanDiagnostics
    from dr_source.core.project_index import ProjectIndex

    context = AnalysisContext(ProjectIndex(str(tmp_path)), str(tmp_path), ScanDiagnostics())
    visitor_class = LANGUAGES[language][1]
    args = ([], [], []) if language == "python" else ([], [], [], b"")
    with pytest.raises(ValueError, match="current source file"):
        visitor_class(*args, analysis_context=context)
    with pytest.raises(ValueError, match="index must match"):
        visitor_class(*args, analysis_context=context, current_file="app",
                      project_index=ProjectIndex())


@pytest.mark.parametrize("language, source, start, end", [
    ("python", "missing(\n    'é'\n)\n", (1, 0), (3, 1)),
    ("javascript", "missing(\n    'é'\n);\n", (1, 0), (3, 1)),
    ("java", 'class App { void route() {\n    helper.missing(\n        "é"\n    );\n} }\n', (2, 4), (4, 5)),
])
def test_multiline_call_span_uses_complete_expression(monkeypatch, tmp_path, language, source, start, end):
    write(tmp_path, "app" + LANGUAGES[language][2], source)
    scanner = scan_project(monkeypatch, tmp_path, language)
    event, = scanner.diagnostics.resolution_events()
    assert (event.line, event.column) == start
    assert (event.end_line, event.end_column) == end
    assert event.status is ResolutionStatus.UNRESOLVED


def test_python_ast_without_end_positions_records_fallback(monkeypatch, tmp_path):
    import ast
    from dr_source.core.context import AnalysisContext
    from dr_source.core.diagnostics import ScanDiagnostics
    from dr_source.core.project_index import ProjectIndex

    context = AnalysisContext(ProjectIndex(str(tmp_path)), str(tmp_path), ScanDiagnostics())
    visitor = PythonTaintVisitor([], [], [], analysis_context=context,
                                 current_file=str(tmp_path / "app.py"), structural_analysis=False)
    tree = ast.parse("missing()")
    tree.body[0].value.end_lineno = None
    tree.body[0].value.end_col_offset = None
    visitor.visit(tree)
    visitor.visit(tree)
    event, = context.diagnostics.resolution_events()
    assert event.identity == ("python", str(tmp_path / "app.py"), 1, 0, None, None, "missing")
    assert context.diagnostics.summary() == ResolutionSummary(1, 0, 1, 0, 0)
