import unittest
import os
import json
from unittest.mock import patch, MagicMock

from dr_source.api import Vulnerability
from dr_source.plugins.dependency.plugin import DependencyAnalyzer

TEST_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST_FILE_REQS = os.path.join(TEST_DIR, "test_code", "deps", "requirements.txt")
TEST_FILE_POM = os.path.join(TEST_DIR, "test_code", "deps", "pom.xml")

# Mock Data for Python
MOCK_PIP_AUDIT_JSON = """
[
  {
    "name": "requests",
    "version": "2.19.0",
    "vulns": [
      {
        "id": "PYSEC-2018-19",
        "description": "Vulnerability in requests"
      }
    ]
  }
]
"""

# Mock Data for Java (OSV API response)
MOCK_OSV_RESPONSE = {
    "vulns": [{"id": "GHSA-jfh8-c2jp-5v3q", "summary": "Log4j 2 Remote Code Execution"}]
}


class TestDependencyAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = DependencyAnalyzer()

    def test_plugin_identification(self):
        self.assertEqual(self.analyzer.name, "Dependency Analyzer")
        self.assertIn(".txt", self.analyzer.get_supported_extensions())
        self.assertIn(".xml", self.analyzer.get_supported_extensions())

    @patch("subprocess.run")
    def test_finds_vulnerable_python_package(self, mock_run):
        # ... (Previous Python test logic) ...
        mock_process = MagicMock()
        mock_process.stdout = MOCK_PIP_AUDIT_JSON
        mock_run.return_value = mock_process

        findings = self.analyzer.analyze(TEST_FILE_REQS)

        self.assertGreater(len(findings), 0)
        vuln = findings[0]
        self.assertEqual(vuln.vulnerability_type, "VULNERABLE_DEPENDENCY")
        self.assertIn("requests==2.19.0", vuln.message)

    @patch("urllib.request.urlopen")
    def test_finds_vulnerable_java_package(self, mock_urlopen):
        """
        Tests that the plugin parses pom.xml and queries OSV correctly.
        """
        # --- Arrange ---
        # Create a mock response object for urllib
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps(MOCK_OSV_RESPONSE).encode("utf-8")

        # Set the context manager return value
        mock_urlopen.return_value.__enter__.return_value = mock_response

        # --- Act ---
        findings = self.analyzer.analyze(TEST_FILE_POM)

        # --- Assert ---
        self.assertGreater(len(findings), 0, "No findings for vulnerable pom.xml")

        vuln = findings[0]
        self.assertEqual(vuln.vulnerability_type, "VULNERABLE_DEPENDENCY")
        self.assertEqual(vuln.severity, "HIGH")
        self.assertIn("log4j-core", vuln.message)
        self.assertIn("GHSA-jfh8-c2jp-5v3q", vuln.message)
