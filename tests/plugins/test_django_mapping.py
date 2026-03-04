import unittest
import os
from dr_source.plugins.python.plugin import PythonAstAnalyzer

# Get the absolute path to the 'tests' directory
TEST_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST_FILE = os.path.join(TEST_DIR, "test_code", "python", "django_views.py")

class TestDjangoMapping(unittest.TestCase):
    def setUp(self):
        self.analyzer = PythonAstAnalyzer()

    def test_finds_vulnerabilities_in_django_views(self):
        """
        Tests that the 'request' parameter in Django views is correctly identified 
        as a source and taint is propagated through attribute access.
        """
        findings = self.analyzer.analyze(TEST_FILE)
        self.assertIsInstance(findings, list)
        
        # 1. Check for SQL Injection at line 14
        sqli = [f for f in findings if "SQL_INJECTION" in f.vulnerability_type]
        self.assertGreater(len(sqli), 0, "Django SQL Injection not found")
        self.assertEqual(sqli[0].line_number, 14)
        
        # 2. Check for XSS at lines 16 and 22
        xss = [f for f in findings if "XSS" in f.vulnerability_type]
        self.assertGreaterEqual(len(xss), 2, "Django XSS findings not found")
        
        xss_lines = [f.line_number for f in xss]
        self.assertIn(16, xss_lines)
        self.assertIn(22, xss_lines)
        
        # Check trace for attribute access specifically for the subscript one (line 22)
        subscript_xss = [f for f in xss if f.line_number == 22][0]
        full_trace = " ".join(subscript_xss.trace)
        # We accept either attribute access or general framework taint
        self.assertTrue("Accessed attribute" in full_trace or "Accessed subscript" in full_trace or "request" in full_trace)

    def test_django_constant_propagation(self):
        findings = self.analyzer.analyze(TEST_FILE)
        # Safe HttpResponse at line 26 should be ignored
        safe_xss = [f for f in findings if f.line_number == 26]
        self.assertEqual(len(safe_xss), 0, "Safe Django HttpResponse should be ignored")
