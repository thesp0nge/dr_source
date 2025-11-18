# File: tests/plugins/test_java_ast_analyzer.py
import unittest
import os
from dr_source.api import Vulnerability, Severity

# TDD: This import will fail until we create the plugin.py file
from dr_source.plugins.java.plugin import JavaAstAnalyzer

# --- IMPORTANT ---
# You need to point this to your existing test code files
# (e.g., the vulnerable Sqli.java you use in other tests)
TEST_CODE_DIR = "tests/test_code/java/"  # Adapt this path if needed


class TestJavaAstAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = JavaAstAnalyzer()
        self.vulnerable_file = os.path.join(
            TEST_CODE_DIR, "Sqli.java"
        )  # Adapt file name
        self.safe_file = os.path.join(TEST_CODE_DIR, "Safe.java")  # Adapt file name

    def test_plugin_metadata(self):
        """Tests the plugin's name and supported extensions."""
        self.assertEqual(self.analyzer.name, "Java AST Analyzer (Tree-sitter)")
        self.assertIn(".java", self.analyzer.get_supported_extensions())

    def test_sql_injection_finding(self):
        """
        This test REPLACES test_ast_sql_injection_taint.py.
        It tests the same logic but through the new plugin API.
        """
        findings = self.analyzer.analyze(self.vulnerable_file)

        self.assertIsInstance(findings, list)
        self.assertGreater(len(findings), 0, "No findings returned for vulnerable file")

        # Check the finding
        vuln = findings[0]
        self.assertIsInstance(vuln, Vulnerability)
        self.assertEqual(vuln.vulnerability_type, "SQL_INJECTION (AST Taint)")
        self.assertEqual(vuln.file_path, self.vulnerable_file)
        self.assertEqual(vuln.severity, "HIGH")
        self.assertEqual(vuln.plugin_name, "Java AST Analyzer (Tree-sitter)")
        # self.assertEqual(vuln.line_number, 15) # Be specific if you can

    def test_no_finding_in_safe_file(self):
        """Ensures we don't get false positives."""
        findings = self.analyzer.analyze(self.safe_file)
        self.assertEqual(len(findings), 0, "Found issues in a safe file")
