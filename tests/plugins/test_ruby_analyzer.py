import unittest
import os
from dr_source.plugins.ruby.plugin import RubyAstAnalyzer

# Get the absolute path to the 'tests' directory
TEST_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST_FILE = os.path.join(TEST_DIR, "test_code", "ruby", "vulnerable.rb")

class TestRubyAstAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = RubyAstAnalyzer()

    def test_plugin_identification(self):
        self.assertEqual(self.analyzer.name, "Ruby AST Analyzer (Tree-sitter)")
        self.assertIn(".rb", self.analyzer.get_supported_extensions())

    def test_finds_vulnerabilities(self):
        findings = self.analyzer.analyze(TEST_FILE)
        self.assertIsInstance(findings, list)
        
        # SQL Injection at line 5
        sqli = [f for f in findings if "SQL_INJECTION" in f.vulnerability_type]
        self.assertGreater(len(sqli), 0, "No SQL Injection found")
        self.assertEqual(sqli[0].line_number, 5)

        # Command Injection at line 9
        cmd = [f for f in findings if "COMMAND_INJECTION" in f.vulnerability_type]
        self.assertGreater(len(cmd), 0, "No Command Injection found")
        self.assertEqual(cmd[0].line_number, 9)

    def test_constant_propagation_ignores_safe_call(self):
        findings = self.analyzer.analyze(TEST_FILE)
        # The safe command is at line 13.
        safe_cmd = [f for f in findings if f.line_number == 13]
        self.assertEqual(len(safe_cmd), 0, "Safe call at line 13 should have been ignored")
