import unittest
import os
from dr_source.plugins.java.plugin import JavaAstAnalyzer

# Get the absolute path to the 'tests' directory
TEST_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST_FILE = os.path.join(TEST_DIR, "test_code", "java", "SpringController.java")

class TestSpringMapping(unittest.TestCase):
    def setUp(self):
        self.analyzer = JavaAstAnalyzer()

    def test_finds_vulnerability_with_annotation_source(self):
        """
        Tests that @RequestParam is correctly identified as a source
        and leads to a SQL Injection finding.
        """
        findings = self.analyzer.analyze(TEST_FILE)
        self.assertIsInstance(findings, list)
        
        sqli = [f for f in findings if "SQL_INJECTION" in f.vulnerability_type]
        self.assertGreater(len(sqli), 0, "SQL Injection from @RequestParam not found")
        
        vuln = sqli[0]
        self.assertEqual(vuln.line_number, 17)
        full_trace = " ".join(vuln.trace)
        self.assertTrue("SpringBootMapper" in full_trace or "framework annotation" in full_trace)
