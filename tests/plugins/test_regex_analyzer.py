import unittest
import os
from dr_source.api import Vulnerability

from dr_source.plugins.regex.plugin import RegexAnalyzer

# Get the absolute path to the 'tests' directory
TEST_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TEST_FILE_CONFIG = os.path.join(TEST_DIR, "test_code", "misc", "vulnerable_config.ini")
TEST_FILE_JAVA = os.path.join(TEST_DIR, "test_code", "java", "RegexSqli.java")

TEST_FILE_PYTHON_LURE = os.path.join(TEST_DIR, "test_code", "python", "regex_lure.py")


class TestRegexAnalyzer(unittest.TestCase):
    def setUp(self):
        # This analyzer loads the *real* knowledge base
        self.analyzer = RegexAnalyzer()

    def test_plugin_identification(self):
        """Tests the plugin's metadata."""
        self.assertEqual(self.analyzer.name, "General Regex Analyzer")
        # It should scan all files
        self.assertIn(".*", self.analyzer.get_supported_extensions())

    def test_finds_hardcoded_password(self):
        """
        Tests that the plugin loads regex rules from the KB
        and finds a hardcoded password.
        """
        findings = self.analyzer.analyze(TEST_FILE_CONFIG)

        self.assertIsInstance(findings, list)
        self.assertGreater(len(findings), 0, "No findings were returned")

        # Check that we found the password
        found_types = {f.vulnerability_type for f in findings}
        self.assertIn("HARDCODED_PASSWORD", found_types)

        # Check the finding content
        pwd_finding = next(
            f
            for f in findings
            if f.vulnerability_type == "HARDCODED_PASSWORD" and "password" in f.message
        )
        self.assertEqual(pwd_finding.severity, "HIGH")
        self.assertEqual(pwd_finding.line_number, 3)  # Line 3 in the test file

    def test_finds_java_regex_vulnerability(self):
        """
        Tests that the plugin loads language-specific regex rules
        and finds a Java SQLi vulnerability.
        """
        findings = self.analyzer.analyze(TEST_FILE_JAVA)

        self.assertIsInstance(findings, list)
        print("\n--- Findings for RegexSqli.java ---")
        if not findings:
            print("No findings returned.")
        for f in findings:
            print(f"  Line {f.line_number}: {f.message}")
        print("-------------------------------------")
        self.assertGreater(len(findings), 0, "No findings were returned")

        # Check that we found the SQL Injection
        found_types = {f.vulnerability_type for f in findings}
        self.assertIn("SQL_INJECTION", found_types)

        # Check the finding content
        sqli_finding = next(
            f
            for f in findings
            if f.vulnerability_type == "SQL_INJECTION" and "JAVA-SQLI-002" in f.message
        )
        self.assertEqual(sqli_finding.severity, "HIGH")
        self.assertEqual(sqli_finding.line_number, 7)  # Line 7 in the new test file
        self.assertIn(
            "JAVA-SQLI-002", sqli_finding.message
        )  # Check for the specific rule ID

    def test_java_rules_do_not_run_on_python_files(self):
        """
        Tests that language-specific rules (Java) are NOT run
        against files of a different language (Python).
        This proves our optimization is working.
        """
        findings = self.analyzer.analyze(TEST_FILE_PYTHON_LURE)

        # We expect ZERO findings, because the only vulnerable string
        # in this file is from a Java rule, which should not be run.
        self.assertEqual(
            len(findings),
            0,
            f"Found findings in a .py file using Java rules: {findings}",
        )
