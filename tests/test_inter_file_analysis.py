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


if __name__ == "__main__":
    unittest.main()
