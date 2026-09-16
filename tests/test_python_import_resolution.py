"""Regression tests for minimal Python import-aware resolution."""

import ast
import logging
from pathlib import Path

import pytest

from dr_source.core.scanner import Scanner
from dr_source.plugins.python.plugin import PythonAstAnalyzer
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
