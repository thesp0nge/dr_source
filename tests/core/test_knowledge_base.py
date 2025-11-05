import unittest
from unittest.mock import patch, mock_open
import logging
import os
import yaml
from typing import Dict, Any

# The class we are testing
from dr_source.core.knowledge_base import KnowledgeBaseLoader

# --- Mock Data ---
MOCK_KB_YAML = """
SQL_INJECTION:
  description: "SQL Injection"
  cwe: "CWE-89"
  language_specific:
    java:
      ast_sources:
        - "request.getParameter"
"""
MOCK_BAD_YAML = "SQL_INJECTION: [unterminated list"


# --- Test Case ---
class TestKnowledgeBaseLoader(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)

    def tearDown(self):
        logging.disable(logging.NOTSET)

    @patch("platformdirs.site_config_dir")
    @patch("platformdirs.user_config_dir")
    @patch("os.path.exists")
    @patch("builtins.open", new_callable=mock_open, read_data=MOCK_KB_YAML)
    def test_01_load_from_in_package_default(
        # --- FIX: This is the correct (innermost-to-outermost) argument order ---
        self,
        mock_file,
        mock_exists,
        mock_user_dir,
        mock_site_dir,
    ):
        """
        Tests the default case: No custom config exists,
        so it loads the in-package file.
        """
        # --- Arrange ---
        # Now these variables correctly map to the mocks:
        # mock_user_dir is patch('...user_config_dir')
        # mock_exists is patch('os.path.exists')

        mock_user_dir.return_value = "/mock/user/config/dr_source"
        mock_site_dir.return_value = "/mock/system/config/dr_source"

        app_in_package_path_fragment = "dr_source/core/../config/knowledge_base.yaml"

        def exists_side_effect(path):
            if path.startswith("/mock/user") or path.startswith("/mock/system"):
                return False
            if path.endswith(app_in_package_path_fragment):
                return True
            return False

        # Assign the side effect to the correct mock
        mock_exists.side_effect = exists_side_effect

        # --- Act ---
        kb = KnowledgeBaseLoader(config_path=None)

        # --- Assert ---
        self.assertIn("SQL_INJECTION", kb.rules)
        self.assertEqual(kb.rules["SQL_INJECTION"]["cwe"], "CWE-89")

        called_path = mock_file.call_args[0][0]
        self.assertTrue(called_path.endswith(app_in_package_path_fragment))

    @patch("platformdirs.site_config_dir")
    @patch("platformdirs.user_config_dir")
    @patch("os.path.exists")
    @patch("builtins.open", new_callable=mock_open, read_data=MOCK_KB_YAML)
    def test_02_load_from_explicit_path(
        # --- FIX: Correct argument order ---
        self,
        mock_file,
        mock_exists,
        mock_user_dir,
        mock_site_dir,
    ):
        """
        Tests that an explicit 'config_path' is loaded first.
        """
        # --- Arrange ---
        explicit_path = "/explicit/custom_kb.yaml"
        # mock_exists is the correct mock
        mock_exists.return_value = True

        # --- Act ---
        kb = KnowledgeBaseLoader(config_path=explicit_path)

        # --- Assert ---
        self.assertIn("SQL_INJECTION", kb.rules)
        # mock_file is the correct mock
        mock_file.assert_called_with(explicit_path, "r")

    @patch("platformdirs.site_config_dir")
    @patch("platformdirs.user_config_dir")
    @patch("os.path.exists")
    @patch("builtins.open", new_callable=mock_open)
    def test_03_priority_user_over_default(
        # --- FIX: Correct argument order ---
        self,
        mock_file,
        mock_exists,
        mock_user_dir,
        mock_site_dir,
    ):
        """
        Tests the priority: User config is loaded *instead of* the default.
        """
        # --- Arrange ---
        user_config_file = "/mock/user/config/dr_source/knowledge_base.yaml"
        app_in_package_path_fragment = "dr_source/core/../config/knowledge_base.yaml"

        # These return values are now assigned to the correct mocks
        mock_user_dir.return_value = "/mock/user/config/dr_source"
        mock_site_dir.return_value = "/mock/system/config/dr_source"
        mock_exists.return_value = True

        def open_side_effect(path, mode):
            if path == user_config_file:
                return mock_open(read_data="USER_CONFIG: true").return_value
            else:
                return mock_open(read_data="DEFAULT_CONFIG: true").return_value

        # Assign side effect to the correct mock
        mock_file.side_effect = open_side_effect

        # --- Act ---
        kb = KnowledgeBaseLoader(config_path=None)

        # --- Assert ---
        self.assertIn("USER_CONFIG", kb.rules)
        self.assertNotIn("DEFAULT_CONFIG", kb.rules)

        mock_file.assert_called_with(user_config_file, "r")
        for call in mock_file.call_args_list:
            self.assertFalse(call[0][0].endswith(app_in_package_path_fragment))

    # --- These tests were unaffected and should be correct ---

    @patch("os.path.exists", return_value=False)
    @patch("logging.Logger.warning")
    def test_04_no_file_found(self, mock_log_warning, mock_exists):
        """
        Tests that a warning is logged if no config file is found.
        """
        # --- Act ---
        kb = KnowledgeBaseLoader(config_path=None)

        # --- Assert ---
        self.assertEqual(kb.rules, {})
        mock_log_warning.assert_called_with(
            "No knowledge base file was found or loaded. "
            "The tool will run with no rules."
        )

    @patch("os.path.exists", return_value=True)
    @patch("builtins.open", new_callable=mock_open, read_data=MOCK_BAD_YAML)
    @patch("logging.Logger.error")
    def test_05_malformed_yaml_file(self, mock_log_error, mock_file, mock_exists):
        """
        Tests that an error is logged if the YAML file is corrupt.
        """
        # --- Arrange ---
        explicit_path = "/explicit/bad_kb.yaml"

        # --- Act ---
        kb = KnowledgeBaseLoader(config_path=explicit_path)

        # --- Assert ---
        self.assertEqual(kb.rules, {})
        mock_log_error.assert_called_once()
        self.assertIn("Error loading knowledge base", mock_log_error.call_args[0][0])

    def test_06_get_methods_with_loaded_rules(self):
        """
        Tests the various 'get' helper methods against a pre-loaded KB.
        """
        # --- Arrange ---
        kb = KnowledgeBaseLoader(config_path="/dev/null")
        kb.rules = yaml.safe_load(MOCK_KB_YAML)

        # --- Act & Assert ---
        sql_rules = kb.get_detector_rules("SQL_INJECTION")
        self.assertEqual(sql_rules["cwe"], "CWE-89")

        gen_regex = kb.get_general_regex("SQL_INJECTION")
        self.assertEqual(gen_regex, [])

        java_regex = kb.get_lang_regex("SQL_INJECTION", "java")
        self.assertEqual(java_regex, [])

        java_sources = kb.get_lang_ast_sources("SQL_INJECTION", "java")
        self.assertEqual(java_sources, ["request.getParameter"])

        missing_sinks = kb.get_lang_ast_sinks("SQL_INJECTION", "python")
        self.assertEqual(missing_sinks, [])

        missing_rules = kb.get_detector_rules("MISSING_VULN")
        self.assertEqual(missing_rules, {})


if __name__ == "__main__":
    unittest.main()
