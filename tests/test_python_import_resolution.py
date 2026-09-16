"""Regression tests for minimal Python import-aware resolution."""

import ast
import logging
from pathlib import Path

import pytest

from dr_source.core.project_index import ProjectIndex
from dr_source.core.scanner import Scanner
from dr_source.core.resolution import ResolutionReason, ResolutionStatus
from dr_source.plugins.python.plugin import PythonAstAnalyzer
from dr_source.plugins.python.project_context import PythonProjectContext
from dr_source.plugins.python.taint_visitor import PythonTaintVisitor


@pytest.fixture
def scan_python_project(tmp_path, monkeypatch):
    def load_python_plugin(scanner):
        scanner.extension_map = {".py": [PythonAstAnalyzer()]}

    monkeypatch.setattr(Scanner, "load_plugins", load_python_plugin)

    def scan(import_statement, call_expression, duplicate=True, target_vulnerable=True, duplicate_target=False):
        project = tmp_path / "project"
        project.mkdir()
        target_code = "import os\ndef execute(value):\n    os.system(value)\n" if target_vulnerable else "def execute(value):\n    return value\n"
        sibling_code = "import os\ndef execute(value):\n    os.system(value)\n" if not target_vulnerable else "def execute(value):\n    return value\n"
        if duplicate_target:
            target_code += "\ndef execute(value):\n    os.system(value)\n"
        (project / "service_a.py").write_text(
            target_code,
            encoding="utf-8",
        )
        if duplicate:
            (project / "service_b.py").write_text(
                sibling_code, encoding="utf-8"
            )
        (project / "app.py").write_text(
            f"{import_statement}\n"
            "from flask import request\n"
            "\n"
            "def endpoint():\n"
            "    value = request.args.get('cmd')\n"
            f"    {call_expression}\n",
            encoding="utf-8",
        )
        scanner = Scanner(str(project))
        scanner.scan()
        return scanner

    return scan


@pytest.mark.parametrize(
    "import_statement, call_expression, lookup_name",
    [
        pytest.param(
            "from service_a import execute", "execute(value)", "execute",
            id="from-import-selects-module",
        ),
        pytest.param(
            "import service_a", "service_a.execute(value)", "service_a.execute",
            id="qualified-module-call-selects-module",
        ),
        pytest.param(
            "from service_a import execute as run", "run(value)", "run",
            id="from-import-alias-remains-unresolved",
        ),
        pytest.param(
            "import service_a as svc", "svc.execute(value)", "svc.execute",
            id="module-alias-remains-unresolved",
        ),
    ],
)
def test_import_syntax_resolves_or_rejects_conservatively(
    scan_python_project, caplog, import_statement, call_expression, lookup_name
):
    visitor = PythonTaintVisitor([], [], [], structural_analysis=False)
    call = ast.parse(call_expression, mode="eval").body
    assert visitor._get_full_call_name(call) == lookup_name

    with caplog.at_level(logging.WARNING):
        scanner = scan_python_project(import_statement, call_expression)
    project = Path(scanner.target_path)
    definitions = scanner.project_index.find_candidates("execute", language="python")
    assert [item.file_path for item in definitions] == [
        str(project / "service_a.py"), str(project / "service_b.py")
    ]
    assert scanner.num_files_analyzed == 3
    assert not any(record.levelno >= logging.ERROR for record in caplog.records)
    diagnostics = [message for message in caplog.messages if "Ambiguous function" in message]
    if lookup_name in {"execute", "service_a.execute"}:
        assert len(scanner.all_findings) == 1
        assert scanner.all_findings[0].file_path == str(project / "app.py")
        assert "service_a.py" in scanner.all_findings[0].trace[-1]
        assert not diagnostics
    else:
        assert scanner.all_findings == []
        assert scanner.project_index.find_candidates(lookup_name, "python") == []
        assert scanner.project_index.find_function(lookup_name, language="python") is None
        assert diagnostics == []


@pytest.mark.parametrize("import_statement", ["", "from service_a import execute"])
def test_unique_bare_function_flow_works_without_import_binding(
    scan_python_project, caplog, import_statement
):
    """The same finding with or without an import is a name-lookup control."""
    with caplog.at_level(logging.WARNING):
        scanner = scan_python_project(import_statement, "execute(value)", duplicate=False)
    project = Path(scanner.target_path)
    target = scanner.project_index.find_function("execute", language="python")
    assert target.file_path == str(project / "service_a.py")
    assert scanner.num_files_analyzed == 2
    assert len(scanner.all_findings) == 1
    finding = scanner.all_findings[0]
    assert finding.vulnerability_type == "COMMAND_INJECTION (AST Taint)"
    assert finding.plugin_name == "Python AST Analyzer"
    assert finding.file_path == str(project / "app.py")
    assert "sink 'os.system'" in finding.message
    assert finding.trace == [
        "Tainted by request.args.get at line 5",
        "Passed to execute() in service_a.py at line 6",
    ]
    assert not any(record.levelno >= logging.WARNING for record in caplog.records)


def test_module_names_are_derived_from_conventional_project_paths(tmp_path):
    from dr_source.plugins.python.project_context import PythonProjectContext

    (tmp_path / "service_a.py").write_text("", encoding="utf-8")
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "pkg" / "service_a.py").write_text("", encoding="utf-8")
    context = PythonProjectContext(str(tmp_path))
    assert context.module_for_file(str(tmp_path / "service_a.py")) == "service_a"
    assert context.module_for_file(str(tmp_path / "pkg" / "service_a.py")) == "pkg.service_a"
    assert context.module_for_file(str(tmp_path / "pkg" / "__init__.py")) == "pkg"


def test_recursive_simulation_switches_to_callee_import_context(tmp_path, monkeypatch):
    def load_python_plugin(scanner):
        scanner.extension_map = {".py": [PythonAstAnalyzer()]}

    monkeypatch.setattr(Scanner, "load_plugins", load_python_plugin)
    (tmp_path / "app.py").write_text(
        "from service import execute\n"
        "from flask import request\n"
        "def endpoint():\n"
        "    value = request.args.get('cmd')\n"
        "    execute(value)\n", encoding="utf-8"
    )
    (tmp_path / "service.py").write_text(
        "from helper import sink_func\n"
        "def execute(value):\n"
        "    sink_func(value)\n", encoding="utf-8"
    )
    (tmp_path / "helper.py").write_text(
        "import os\n"
        "def sink_func(value):\n"
        "    os.system(value)\n", encoding="utf-8"
    )
    scanner = Scanner(str(tmp_path))
    scanner.scan()
    assert len(scanner.all_findings) == 1
    finding = scanner.all_findings[0]
    assert finding.file_path == str(tmp_path / "app.py")
    assert any("in service.py" in step for step in finding.trace)
    assert any("in helper.py" in step for step in finding.trace)


@pytest.mark.parametrize(
    "import_statement, call_expression",
    [
        ("from service_a import execute", "execute(value)"),
        ("import service_a", "service_a.execute(value)"),
    ],
)
def test_supported_import_never_selects_vulnerable_sibling(
    scan_python_project, import_statement, call_expression
):
    scanner = scan_python_project(
        import_statement,
        call_expression,
        target_vulnerable=False,
    )
    assert scanner.all_findings == []


def test_imported_module_with_multiple_same_name_definitions_remains_ambiguous(
    scan_python_project, caplog
):
    with caplog.at_level(logging.WARNING, logger="dr_source.plugins.python.taint_visitor"):
        scanner = scan_python_project(
            "from service_a import execute", "execute(value)", duplicate_target=True
        )
    assert scanner.all_findings == []
    assert any("Ambiguous or unresolved Python symbol 'execute'" in message for message in caplog.messages)


def _direct_python_resolution(tmp_path, imports, call, service_sources):
    tmp_path.mkdir()
    app_path = tmp_path / "app.py"
    app_path.write_text(imports + "\n" + call + "\n", encoding="utf-8")
    index = ProjectIndex(str(tmp_path))
    context = PythonProjectContext(str(tmp_path))
    for filename, source in {"app.py": imports, **service_sources}.items():
        path = tmp_path / filename
        if filename != "app.py":
            path.write_text(source, encoding="utf-8")
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        context.register_file(str(path), tree)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                index.register_function(node.name, str(path), node, "python", declaration_position=(node.lineno, node.col_offset))
    visitor = PythonTaintVisitor(
        [], [], [], index, current_file=str(app_path), python_context=context,
        structural_analysis=False,
    )
    return visitor, ast.parse(call, mode="eval").body


def test_python_project_resolution_returns_structured_outcomes(tmp_path):
    cases = [
        ("", "execute(value)", {"service_a.py": "def execute(value):\n    return value\n"}, ResolutionStatus.RESOLVED, ResolutionReason.NONE),
        ("", "execute(value)", {
            "service_a.py": "def execute(value):\n    return value\n",
            "service_b.py": "def execute(value):\n    return value\n",
        }, ResolutionStatus.AMBIGUOUS, ResolutionReason.MULTIPLE_CANDIDATES),
        ("from service_a import execute", "execute(value)", {"service_a.py": "def execute(value):\n    return value\n"}, ResolutionStatus.RESOLVED, ResolutionReason.NONE),
        ("from service_a import execute", "execute(value)", {"service_a.py": "value = 1\n"}, ResolutionStatus.UNRESOLVED, ResolutionReason.EXPLICIT_TARGET_NOT_FOUND),
        ("import service_a", "service_a.execute(value)", {"service_a.py": "def execute(value):\n    return value\n"}, ResolutionStatus.RESOLVED, ResolutionReason.NONE),
        ("from service_a import execute as run", "run(value)", {"service_a.py": "def execute(value):\n    return value\n"}, ResolutionStatus.UNSUPPORTED, ResolutionReason.UNSUPPORTED_BINDING),
        ("import service_a as svc", "svc.execute(value)", {"service_a.py": "def execute(value):\n    return value\n"}, ResolutionStatus.UNSUPPORTED, ResolutionReason.UNSUPPORTED_BINDING),
        ("", "missing(value)", {"service_a.py": "value = 1\n"}, ResolutionStatus.UNRESOLVED, ResolutionReason.NO_CANDIDATES),
    ]
    for index, (imports, call, sources, status, reason) in enumerate(cases):
        visitor, node = _direct_python_resolution(tmp_path / str(index), imports, call, sources)
        result = visitor._resolve_project_call(node)
        assert result.status is status
        assert result.reason is reason
        if status is ResolutionStatus.RESOLVED:
            assert result.symbol is not None
        else:
            assert result.symbol is None


def test_python_project_resolution_ambiguity_is_registration_order_independent(tmp_path):
    results = []
    for index, names in enumerate((("service_a.py", "service_b.py"), ("service_b.py", "service_a.py"))):
        root = tmp_path / str(index)
        root.mkdir()
        index_obj = ProjectIndex(str(root))
        context = PythonProjectContext(str(root))
        app = root / "app.py"
        app.write_text("", encoding="utf-8")
        context.register_file(str(app), ast.parse(""))
        for name in names:
            path = root / name
            path.write_text("def execute(value):\n    return value\n", encoding="utf-8")
            tree = ast.parse(path.read_text(encoding="utf-8"))
            context.register_file(str(path), tree)
            node = tree.body[0]
            index_obj.register_function("execute", str(path), node, "python", declaration_position=(1, 0))
        visitor = PythonTaintVisitor([], [], [], index_obj, current_file=str(app), python_context=context, structural_analysis=False)
        result = visitor._resolve_project_call(ast.parse("execute(value)", mode="eval").body)
        results.append(result)
    assert results[0].status is results[1].status is ResolutionStatus.AMBIGUOUS
    assert results[0].reason is results[1].reason is ResolutionReason.MULTIPLE_CANDIDATES
    assert [Path(symbol.file_path).name for symbol in results[0].candidates] == [
        Path(symbol.file_path).name for symbol in results[1].candidates
    ]
