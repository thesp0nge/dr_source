import unittest
import os
from dr_source.api import Vulnerability
from dr_source.plugins.python.plugin import PythonAstAnalyzer

# Get the absolute path to the 'tests' directory
TEST_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST_FILE_SIMPLE = os.path.join(TEST_DIR, "test_code", "python", "vulnerable.py")
TEST_FILE_COMPLEX = os.path.join(
    TEST_DIR, "test_code", "python", "complex_vulnerable_app.py"
)


class TestPythonAstAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = PythonAstAnalyzer()

    def test_plugin_identification(self):
        self.assertEqual(self.analyzer.name, "Python AST Analyzer")
        self.assertIn(".py", self.analyzer.get_supported_extensions())

    def test_finds_command_injection_simple(self):
        findings = self.analyzer.analyze(TEST_FILE_SIMPLE)
        self.assertIsInstance(findings, list)
        self.assertGreater(len(findings), 0, "No findings returned")
        vuln = findings[0]
        self.assertEqual(vuln.vulnerability_type, "COMMAND_INJECTION (AST Taint)")
        self.assertEqual(vuln.severity, "CRITICAL")
        self.assertEqual(vuln.line_number, 16)  # From vulnerable.py

    def test_finds_propagated_command_injection(self):
        """
        Tests taint propagation through a Binary Operation (e.g., "str" + tainted_var).
        """
        findings = self.analyzer.analyze(TEST_FILE_COMPLEX)
        self.assertIsInstance(findings, list)

        cmd_vulns = [
            f
            for f in findings
            if f.vulnerability_type == "COMMAND_INJECTION (AST Taint)"
        ]
        self.assertGreater(len(cmd_vulns), 0, "No Command Injection finding returned")

        vuln = cmd_vulns[0]
        self.assertEqual(vuln.severity, "CRITICAL")
        self.assertEqual(vuln.line_number, 34)

    def test_finds_sqli_via_fstring(self):
        """
        Tests taint propagation into an f-string (ast.JoinedStr).
        """
        findings = self.analyzer.analyze(TEST_FILE_COMPLEX)
        self.assertIsInstance(findings, list)

        sql_vulns = [
            f for f in findings if f.vulnerability_type == "SQL_INJECTION (AST Taint)"
        ]
        self.assertGreater(len(sql_vulns), 0, "No SQL Injection finding returned")

        vuln = sql_vulns[0]
        self.assertEqual(vuln.severity, "HIGH")
        self.assertEqual(vuln.line_number, 16)
