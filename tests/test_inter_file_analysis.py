import unittest
import os
import logging
import pytest
from dr_source.core.project_index import ProjectIndex
from dr_source.core.scanner import Scanner
from dr_source.logging import setup_logging
from dr_source.plugins.java.plugin import JavaAstAnalyzer
from dr_source.plugins.javascript.plugin import JavaScriptAstAnalyzer
from dr_source.plugins.python.plugin import PythonAstAnalyzer

class TestInterFileAnalysis(unittest.TestCase):
    def setUp(self):
        setup_logging(debug=True)
        self.base_dir = os.path.join(os.path.dirname(__file__), "test_code", "inter_file")

    def test_python_inter_file_flow(self):
        target = os.path.join(self.base_dir, "python")
        scanner = Scanner(target)
        scanner.scan()
        
        findings = [f for f in scanner.all_findings if "vulnerable_execute" in f.message or "os.system" in f.message]
        self.assertGreater(len(findings), 0, "Failed to detect cross-file Python vulnerability")
        
        vuln = findings[0]
        has_cross_file_trace = any("in inter_file_utils.py" in step for step in vuln.trace)
        self.assertTrue(has_cross_file_trace, f"Trace missing cross-file info: {vuln.trace}")

    def test_java_inter_file_flow(self):
        target = os.path.join(self.base_dir, "java")
        scanner = Scanner(target)
        scanner.scan()
        
        findings = [f for f in scanner.all_findings if "runQuery" in f.message or "executeQuery" in f.message]
        self.assertGreater(len(findings), 0, "Failed to detect cross-file Java vulnerability")
        
        vuln = findings[0]
        has_cross_file_trace = any("in DatabaseHelper.java" in step for step in vuln.trace)
        self.assertTrue(has_cross_file_trace, f"Trace missing cross-file info: {vuln.trace}")

    def test_javascript_inter_file_flow(self):
        target = os.path.join(self.base_dir, "javascript")
        scanner = Scanner(target)
        scanner.scan()
        
        findings = [f for f in scanner.all_findings if "runCommand" in f.message or "exec" in f.message]
        self.assertGreater(len(findings), 0, "Failed to detect cross-file JavaScript vulnerability")
        
        vuln = findings[0]
        has_cross_file_trace = any("in db.js" in step for step in vuln.trace)
        self.assertTrue(has_cross_file_trace, f"Trace missing cross-file info: {vuln.trace}")

@pytest.mark.parametrize(
    "analyzer_class, filename, language, code, positions",
    [
        (
            PythonAstAnalyzer, "service.py", "python",
            "def execute(value):\n    pass\n\ndef execute(value):\n    pass\n",
            [(1, 0), (4, 0)],
        ),
        (
            JavaAstAnalyzer, "Service.java", "java",
            "class A {\n"
            "    void execute(String value) {}\n"
            "    void execute(int value) {}\n"
            "}\n"
            "class B {\n"
            "    void execute(String value) {}\n"
            "}\n",
            [(2, 4), (3, 4), (6, 4)],
        ),
        (
            JavaScriptAstAnalyzer, "service.js", "javascript",
            "function execute(value) {}\n"
            "function outer() {\n"
            "    function execute(value) {}\n"
            "}\n",
            [(1, 0), (3, 4)],
        ),
    ],
    ids=["python-redefinitions", "java-classes-and-overloads", "javascript-nested"],
)
def test_frontend_preserves_same_file_declarations(
    tmp_path, analyzer_class, filename, language, code, positions
):
    source = tmp_path / filename
    source.write_text(code, encoding="utf-8")
    index = ProjectIndex()
    analyzer_class().index(str(source), index)

    candidates = index.find_candidates("execute", language)
    assert [item.symbol_id.declaration_position for item in candidates] == positions
    assert all(item.file_path == str(source) for item in candidates)
    assert all(item.symbol_id.owner is None for item in candidates)
    assert all(item.symbol_id.signature is None for item in candidates)
    if language == "python":
        assert [item.node.lineno for item in candidates] == [line for line, _ in positions]
    else:
        assert all(item.node["code"] == code.encode("utf-8") for item in candidates)
    assert index.find_function("execute") is None


def test_scanner_reports_ambiguous_cross_file_target(tmp_path, monkeypatch, caplog):
    def load_python_plugin(scanner):
        scanner.extension_map = {".py": [PythonAstAnalyzer()]}

    monkeypatch.setattr(Scanner, "load_plugins", load_python_plugin)
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "def route():\n"
        "    value = request.args.get('cmd')\n"
        "    execute(value)\n",
        encoding="utf-8",
    )
    vulnerable = tmp_path / "vulnerable.py"
    vulnerable.write_text(
        "import os\ndef execute(value):\n    os.system(value)\n", encoding="utf-8"
    )
    unique_scan = Scanner(str(tmp_path))
    unique_scan.scan()
    assert any(
        "os.system" in finding.message
        and any("in vulnerable.py" in step for step in finding.trace)
        for finding in unique_scan.all_findings
    )

    safe = tmp_path / "safe.py"
    safe.write_text("def execute(value):\n    return value\n", encoding="utf-8")
    ambiguous_scan = Scanner(str(tmp_path))
    with caplog.at_level(logging.WARNING, logger="dr_source.core.project_index"):
        ambiguous_scan.scan()

    assert [
        item.file_path for item in ambiguous_scan.project_index.find_candidates("execute")
    ] == [str(safe), str(vulnerable)]
    assert ambiguous_scan.all_findings == []
    assert "Ambiguous function 'execute': 2 candidates" in caplog.text
    assert "inter-file analysis skipped" in caplog.text
    assert str(safe) in caplog.text
    assert str(vulnerable) in caplog.text


def test_java_ambiguous_project_target_is_not_simulated(tmp_path, monkeypatch, caplog):
    def load_java_plugin(scanner):
        scanner.extension_map = {".java": [JavaAstAnalyzer()]}

    monkeypatch.setattr(Scanner, "load_plugins", load_java_plugin)
    (tmp_path / "Caller.java").write_text(
        "import javax.servlet.http.HttpServletRequest;\n"
        "import java.sql.Connection;\n"
        "class Caller {\n"
        "    void doGet(HttpServletRequest request, Connection conn) throws Exception {\n"
        "        String id = request.getParameter(\"id\");\n"
        "        String sql = \"SELECT * FROM users WHERE id = \" + id;\n"
        "        helper.runQuery(sql, conn);\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    for filename in ("DatabaseHelper.java", "OtherHelper.java"):
        (tmp_path / filename).write_text(
            "import java.sql.Statement;\n"
            "import java.sql.Connection;\n"
            "class Helper {\n"
            "    void runQuery(String query, Connection conn) throws Exception {\n"
            "        Statement stmt = conn.createStatement();\n"
            "        stmt.executeQuery(query);\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )

    with caplog.at_level(logging.WARNING):
        scanner = Scanner(str(tmp_path))
        scanner.scan()

    assert len(scanner.project_index.find_candidates("runQuery", language="java")) == 2
    assert scanner.all_findings == []
    assert "Ambiguous function 'runQuery': 2 candidates" in caplog.text


def test_javascript_ambiguous_project_target_is_not_simulated(tmp_path, monkeypatch, caplog):
    def load_javascript_plugin(scanner):
        scanner.extension_map = {".js": [JavaScriptAstAnalyzer()]}

    monkeypatch.setattr(Scanner, "load_plugins", load_javascript_plugin)
    (tmp_path / "app.js").write_text(
        "const value = req.query.cmd;\n"
        "runCommand(value);\n",
        encoding="utf-8",
    )
    helper_code = (
        "const cp = require('child_process');\n"
        "function runCommand(value) { cp.exec(value); }\n"
    )
    (tmp_path / "commands_a.js").write_text(helper_code, encoding="utf-8")
    (tmp_path / "commands_b.js").write_text(helper_code, encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        scanner = Scanner(str(tmp_path))
        scanner.scan()

    assert len(scanner.project_index.find_candidates("runCommand", language="javascript")) == 2
    assert scanner.all_findings == []
    assert "Ambiguous function 'runCommand': 2 candidates" in caplog.text


@pytest.mark.parametrize(
    "language, foreign_language",
    [
        ("python", "javascript"),
        ("python", "java"),
        ("java", "python"),
        ("javascript", "python"),
    ],
)
def test_scanner_isolates_cross_language_targets(
    tmp_path, monkeypatch, caplog, language, foreign_language
):
    programs = {
        "python": (
            PythonAstAnalyzer, ".py",
            "from flask import request\n"
            "value = request.args.get('cmd')\n"
            "execute(value)\n",
            "import os\ndef execute(value):\n    os.system(value)\n",
            "def execute(value):\n    return value\n",
        ),
        "java": (
            JavaAstAnalyzer, ".java",
            "class App {\n"
            "    void route(HttpServletRequest request, Connection conn) {\n"
            "        String value = request.getParameter(\"id\");\n"
            "        helper.execute(value, conn);\n"
            "    }\n"
            "}\n",
            "class Helper {\n"
            "    void execute(String value, Connection conn) {\n"
            "        Statement stmt = conn.createStatement();\n"
            "        stmt.executeQuery(value);\n"
            "    }\n"
            "}\n",
            "class Safe { void execute(String value, Connection conn) {} }\n",
        ),
        "javascript": (
            JavaScriptAstAnalyzer, ".js",
            "const value = req.query.cmd;\nexecute(value);\n",
            "const cp = require('child_process');\n"
            "function execute(value) { cp.exec(value); }\n",
            "function execute(value) { return value; }\n",
        ),
    }
    analyzer_class, extension, caller_code, target_code, safe_code = programs[language]
    foreign_class, foreign_extension, _, _, foreign_code = programs[foreign_language]
    # Java/JS model "execute" itself as a sink; use their existing inter-file
    # fixture names so this test specifically exercises global call simulation.
    name = {"python": "execute", "java": "runQuery", "javascript": "runCommand"}[language]
    caller_code, target_code, safe_code, foreign_code = [
        code.replace("execute(", name + "(")
        for code in (caller_code, target_code, safe_code, foreign_code)
    ]

    def load_plugins(scanner):
        scanner.extension_map = {
            extension: [analyzer_class()],
            foreign_extension: [foreign_class()],
        }

    monkeypatch.setattr(Scanner, "load_plugins", load_plugins)
    caller = tmp_path / ("app" + extension)
    target = tmp_path / ("helper" + extension)
    caller.write_text(caller_code, encoding="utf-8")
    target.write_text(target_code, encoding="utf-8")
    unique_scan = Scanner(str(tmp_path))
    unique_scan.scan()
    assert unique_scan.all_findings
    assert all(finding.file_path == str(caller) for finding in unique_scan.all_findings)
    assert all(
        any(f"Passed to {name}() in {target.name}" in step for step in finding.trace)
        for finding in unique_scan.all_findings
    )

    foreign = tmp_path / ("foreign" + foreign_extension)
    foreign.write_text(foreign_code, encoding="utf-8")
    caplog.clear()
    mixed_scan = Scanner(str(tmp_path))
    with caplog.at_level(logging.WARNING, logger="dr_source.core.project_index"):
        mixed_scan.scan()
    assert len(mixed_scan.project_index.find_candidates(name)) == 2
    assert [
        item.file_path for item in mixed_scan.project_index.find_candidates(name, language)
    ] == [str(target)]
    # Before Phase 2 this is empty: legacy lookup rejects both-language candidates.
    assert mixed_scan.all_findings == unique_scan.all_findings
    assert not any(f"Ambiguous function {name!r}" in message for message in caplog.messages)

    safe = tmp_path / ("safe" + extension)
    safe.write_text(safe_code, encoding="utf-8")
    caplog.clear()
    ambiguous_scan = Scanner(str(tmp_path))
    with caplog.at_level(logging.WARNING, logger="dr_source.core.project_index"):
        ambiguous_scan.scan()
    assert ambiguous_scan.all_findings == []
    messages = [message for message in caplog.messages if f"Ambiguous function {name!r}" in message]
    assert messages
    assert all("2 candidates" in message and f"language={language}" in message for message in messages)
    assert all(str(target) in message and str(safe) in message for message in messages)
    assert all(str(foreign) not in message for message in messages)


if __name__ == "__main__":
    unittest.main()
