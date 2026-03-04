import unittest
import os
from dr_source.plugins.java.plugin import JavaAstAnalyzer

# Get the absolute path to the 'tests' directory
TEST_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST_FILE = os.path.join(TEST_DIR, "test_code", "java", "LegacyAndHibernate.java")

class TestJavaExtraFrameworks(unittest.TestCase):
    def setUp(self):
        self.analyzer = JavaAstAnalyzer()

    def test_finds_servlet_and_hibernate_vulnerabilities(self):
        """
        Tests that Servlet sources and Hibernate sinks are correctly detected.
        """
        findings = self.analyzer.analyze(TEST_FILE)
        self.assertIsInstance(findings, list)
        
        # 1. Check for XSS in Servlet
        xss = [f for f in findings if "XSS" in f.vulnerability_type]
        self.assertGreater(len(xss), 0, "XSS from Servlet getParameter not found")
        self.assertEqual(xss[0].line_number, 20)

        # 2. Check for SQL Injection in Hibernate
        sqli = [f for f in findings if "SQL_INJECTION" in f.vulnerability_type]
        self.assertGreater(len(sqli), 0, "SQL Injection from Hibernate createQuery not found")
        
        # We expect it at line 30 (createQuery(hql))
        hibernate_sqli = [f for f in sqli if f.line_number == 30]
        self.assertGreater(len(hibernate_sqli), 0, "Hibernate SQLi at line 30 not found")

    def test_hibernate_constant_propagation(self):
        findings = self.analyzer.analyze(TEST_FILE)
        # Safe call at line 34 should be ignored
        safe_sqli = [f for f in findings if f.line_number == 34]
        self.assertEqual(len(safe_sqli), 0, "Safe Hibernate query at line 34 should be ignored")
