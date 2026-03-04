import unittest
import os
from dr_source.plugins.python.plugin import PythonAstAnalyzer

# Get the absolute path to the 'tests' directory
TEST_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST_FILE = os.path.join(TEST_DIR, "test_code", "python", "fastapi_app.py")

class TestFastAPIMapping(unittest.TestCase):
    def setUp(self):
        self.analyzer = PythonAstAnalyzer()

    def test_finds_vulnerabilities_in_fastapi_endpoints(self):
        """
        Tests that FastAPI parameters are correctly identified as sources
        and lead to findings in GET and POST routes.
        """
        findings = self.analyzer.analyze(TEST_FILE)
        self.assertIsInstance(findings, list)
        
        sqli = [f for f in findings if "SQL_INJECTION" in f.vulnerability_type]
        # We expect 2 SQL injections:
        # 1. line 11 (search route)
        # 2. line 23 (update route via f-string)
        self.assertGreaterEqual(len(sqli), 2, "FastAPI SQL Injections not found")
        
        lines = [f.line_number for f in sqli]
        self.assertIn(11, lines)
        self.assertIn(23, lines)
        
        full_trace = " ".join(sqli[0].trace)
        self.assertTrue("Tainted parameter query" in full_trace or "Tainted by framework annotation" in full_trace)
