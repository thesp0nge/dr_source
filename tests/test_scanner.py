import unittest
import os
from unittest.mock import patch, MagicMock, call
from typing import List

# Import the API
from dr_source.api import AnalyzerPlugin, Vulnerability

# Import the class we are testing
from dr_source.core.scanner import Scanner

# Define a path to our existing test files
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_FILE_JAVA = os.path.join(TEST_DIR, "test_code", "java", "Sqli.java")


# --- 1. Create a Mock Plugin Class (Unchanged) ---
class MockAnalyzer(AnalyzerPlugin):
    """A fake plugin for the test to discover."""

    @property
    def name(self) -> str:
        return "Mock Analyzer"

    def get_supported_extensions(self) -> List[str]:
        return [".java"]

    analyze = MagicMock(
        return_value=[
            Vulnerability(
                vulnerability_type="MOCK_VULN",
                message="Found a mock vulnerability",
                severity="HIGH",  # Note: severity is not in the default DB
                file_path=TEST_FILE_JAVA,
                line_number=10,
                plugin_name="Mock Analyzer",
            )
        ]
    )


class TestScanner(unittest.TestCase):
    # --- 2. Mock Plugin Discovery AND the ScanDatabase ---
    @patch("dr_source.core.scanner.ScanDatabase")  # Patch the *real* DB class
    @patch(
        "importlib.metadata.entry_points",
        return_value=[MagicMock(load=lambda: MockAnalyzer)],
    )
    def test_scanner_runs_full_lifecycle(self, mock_entry_points, mock_ScanDatabase):
        """
        Tests that the scanner:
        1. Initializes the ScanDatabase correctly.
        2. Follows the full scan lifecycle (start, store, update).
        3. Correctly converts dataclasses to dictionaries for the DB.
        """
        # --- Arrange ---
        # Get the mock *instance* of the database
        mock_db_instance = mock_ScanDatabase.return_value
        # Make start_scan() return a fake scan_id
        mock_db_instance.start_scan.return_value = 123

        MockAnalyzer.analyze.reset_mock()

        # Initialize the scanner
        scanner = Scanner(TEST_DIR)

        # --- Act ---
        scanner.scan()

        # --- Assert ---
        # 1. Check DB was initialized correctly
        mock_ScanDatabase.assert_called_with(project_name=TEST_DIR)

        # 2. Check plugin discovery
        mock_entry_points.assert_called_with(group="dr_source.plugins")

        # 3. Check plugin was called
        # We walk more than just the .java file, so we check for *any* call
        MockAnalyzer.analyze.assert_any_call(TEST_FILE_JAVA)

        # 4. Check that the *full scan lifecycle* was followed
        mock_db_instance.start_scan.assert_called_once()
        mock_db_instance.store_vulnerabilities.assert_called_once()
        mock_db_instance.update_scan_summary.assert_called_once()

        # 5. Check the data *sent to the database*
        #    (This is the most important check)

        # Get the arguments from the store_vulnerabilities call
        store_call_args = mock_db_instance.store_vulnerabilities.call_args[0]

        # Arg 1: scan_id
        self.assertEqual(store_call_args[0], 123)

        # Arg 2: list of vulnerability dictionaries
        stored_vulns_list = store_call_args[1]
        self.assertEqual(len(stored_vulns_list), 3)

        # Check the dictionary content
        stored_vuln_dict = stored_vulns_list[0]
        self.assertIsInstance(stored_vuln_dict, dict)
        self.assertEqual(stored_vuln_dict["vuln_type"], "MOCK_VULN")
        self.assertEqual(stored_vuln_dict["file"], TEST_FILE_JAVA)
        self.assertEqual(stored_vuln_dict["match"], "Found a mock vulnerability")
        self.assertEqual(stored_vuln_dict["line"], 10)

        # 6. Check the final summary
        # Get the full 'call' object (which has .args and .kwargs)
        summary_call = mock_db_instance.update_scan_summary.call_args

        # Check the positional argument (scan_id)
        self.assertEqual(summary_call.args[0], 123)

        # Check the keyword arguments
        self.assertEqual(summary_call.kwargs["num_vulnerabilities"], 3)
        self.assertGreater(summary_call.kwargs["num_files_analyzed"], 0)
        self.assertGreater(summary_call.kwargs["scan_duration"], 0)
