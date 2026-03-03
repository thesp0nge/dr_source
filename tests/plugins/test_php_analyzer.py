import unittest
import os
from dr_source.plugins.php.plugin import PHPAstAnalyzer

# Get the absolute path to the 'tests' directory
TEST_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST_FILE = os.path.join(TEST_DIR, "test_code", "php", "vulnerable.php")

class TestPHPAstAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = PHPAstAnalyzer()

    def test_plugin_identification(self):
        self.assertEqual(self.analyzer.name, "PHP AST Analyzer (Tree-sitter)")
        self.assertIn(".php", self.analyzer.get_supported_extensions())

    def test_finds_vulnerabilities(self):
        findings = self.analyzer.analyze(TEST_FILE)
        self.assertIsInstance(findings, list)
        
        # SQL Injection at line 7
        sqli = [f for f in findings if "SQL_INJECTION" in f.vulnerability_type]
        self.assertGreater(len(sqli), 0, "No SQL Injection found")
        self.assertEqual(sqli[0].line_number, 7)

        # Command Injection at line 11
        cmd = [f for f in findings if "COMMAND_INJECTION" in f.vulnerability_type]
        self.assertGreater(len(cmd), 0, "No Command Injection found")
        self.assertEqual(cmd[0].line_number, 11)

        # XSS at line 15
        xss = [f for f in findings if "XSS" in f.vulnerability_type]
        self.assertGreater(len(xss), 0, "No XSS found")
        self.assertEqual(xss[0].line_number, 15)

    def test_constant_propagation_ignores_safe_query(self):
        findings = self.analyzer.analyze(TEST_FILE)
        # The safe query is at line 21. 
        # If it's NOT in the findings, constant propagation worked.
        safe_sqli = [f for f in findings if f.line_number == 21]
        self.assertEqual(len(safe_sqli), 0, "Safe query at line 21 should have been ignored")
