import unittest
import os
from dr_source.api import Vulnerability

# TDD: This import will fail until we create the plugin
from dr_source.plugins.javascript.plugin import JavaScriptAstAnalyzer

# Get the absolute path to the 'tests' directory
TEST_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST_FILE_JS = os.path.join(
    TEST_DIR, "test_code", "javascript", "vulnerable_express.js"
)


class TestJavaScriptAstAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = JavaScriptAstAnalyzer()

    def test_plugin_identification(self):
        """Tests the plugin's metadata."""
        self.assertEqual(self.analyzer.name, "JavaScript AST Analyzer (Tree-sitter)")
        self.assertIn(".js", self.analyzer.get_supported_extensions())

    def test_finds_rce_via_eval(self):
        """
        Tests taint flow through request.query to the eval() sink.
        """
        findings = self.analyzer.analyze(TEST_FILE_JS)

        self.assertIsInstance(findings, list)
        self.assertGreater(len(findings), 0, "No findings returned for RCE test")

        vuln = findings[0]
        self.assertEqual(vuln.vulnerability_type, "COMMAND_INJECTION (AST Taint)")
        self.assertEqual(vuln.severity, "CRITICAL")
        self.assertEqual(vuln.line_number, 8)

        self.assertIn("req.query", vuln.trace[0])
        self.assertEqual(
            vuln.message.split("'")[1], "eval", "Sink name should be eval in message."
        )
