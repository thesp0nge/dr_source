"""Passing characterizations of Phase 2, not guarantees for Phase 3.

Future from-import and qualified-call resolution should find the service_a flow
despite service_b.execute. Today the former is ambiguous and the latter is
unresolved. Alias cases document missing bindings, not proposed alias support.
See docs/python-import-resolution-investigation.md for future expectations.
"""

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

    def scan(import_statement, call_expression, duplicate=True):
        project = tmp_path / "project"
        project.mkdir()
        (project / "service_a.py").write_text(
            "import os\ndef execute(value):\n    os.system(value)\n",
            encoding="utf-8",
        )
        if duplicate:
            (project / "service_b.py").write_text(
                "def execute(value):\n    return value\n", encoding="utf-8"
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
            id="from-import-remains-ambiguous",
        ),
        pytest.param(
            "import service_a", "service_a.execute(value)", "service_a.execute",
            id="qualified-module-call-remains-unresolved",
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
def test_import_syntax_does_not_bind_project_candidates(
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
    # Characterization: the valid service_a flow is currently lost, not safe.
    assert scanner.all_findings == []

    diagnostics = [message for message in caplog.messages if "Ambiguous function" in message]
    if lookup_name == "execute":
        assert scanner.project_index.find_candidates(lookup_name, "python") == definitions
        assert diagnostics
        assert all("Ambiguous function 'execute': 2 candidates" in message for message in diagnostics)
        assert all("language=python" in message for message in diagnostics)
        assert all("inter-file analysis skipped" in message for message in diagnostics)
        assert all("service_a.py" in message and "service_b.py" in message for message in diagnostics)
    else:
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
