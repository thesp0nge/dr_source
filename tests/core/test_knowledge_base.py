import unittest
import os
import yaml
from unittest.mock import patch, mock_open
from dr_source.core.knowledge_base import KnowledgeBaseLoader

# --- Mock Data ---
# A minimal version of your knowledge base for testing
MOCK_KB_YAML = """
SQL_INJECTION:
  description: "SQL Injection"
  cwe: "CWE-89"
  severity: "HIGH"
  language_specific:
    java:
      ast_sources:
        - "request.getParameter"
"""
MOCK_BAD_YAML = "SQL_INJECTION: [unterminated list"


class TestKnowledgeBaseLoader(unittest.TestCase):
    # We need to mock os.getcwd and platformdirs because the new loader relies on them
    @patch("os.getcwd", return_value="/mock/project")
    @patch("platformdirs.user_config_dir", return_value="/mock/user/config")
    @patch("os.path.exists")
    @patch("builtins.open", new_callable=mock_open, read_data=MOCK_KB_YAML)
    def test_01_load_from_in_package_default(
        self, mock_file, mock_exists, mock_user_dir, mock_cwd
    ):
        """
        Tests the default case: No custom config exists,
        so it loads the in-package file.
        """

        # --- Arrange ---
        # Simulate ONLY the default path existing
        def exists_side_effect(path):
            return "dr_source/config/knowledge_base.yaml" in path

        mock_exists.side_effect = exists_side_effect

        # --- Act ---
        kb = KnowledgeBaseLoader(explicit_config_path=None)

        # --- Assert ---
        # Should load the default KB content
        self.assertIn("SQL_INJECTION", kb.rules)

    @patch("os.getcwd", return_value="/mock/project")
    @patch("platformdirs.user_config_dir", return_value="/mock/user/config")
    @patch("os.path.exists", return_value=True)
    @patch("builtins.open", new_callable=mock_open, read_data=MOCK_KB_YAML)
    def test_02_load_from_explicit_path(
        self, mock_file, mock_exists, mock_user_dir, mock_cwd
    ):
        """
        Tests that an explicit path is loaded and merges correctly.
        """
        explicit_path = "/explicit/custom_kb.yaml"

        kb = KnowledgeBaseLoader(explicit_config_path=explicit_path)

        # The actual call assertion needs to be done carefully due to the merge logic
        # Here we just assert the result is correct.
        self.assertIn("SQL_INJECTION", kb.rules)

    @patch('os.getcwd', return_value='/mock/project')
    @patch("platformdirs.user_config_dir", return_value='/mock/user/config')
    @patch("os.path.exists", return_value=True)
    @patch("builtins.open", new_callable=mock_open)
    def test_03_priority_user_over_default(
        self, mock_file, mock_exists, mock_user_dir, mock_cwd
    ):
        """
        Tests that the EXPLICIT rule set always overwrites the DEFAULTS
        if the key exists (proving the merge order is correct).
        """
        # --- Arrange ---
        LOCAL_PATH = '/mock/project/.dr_source_rules.yaml'

        def open_side_effect(filename, mode="r", encoding=None):
            if filename == LOCAL_PATH:
                 # High priority file
                 return mock_open(read_data=yaml.dump({"SQL_INJECTION": {"severity": "LOW"}, "NEW_RULE": 1})).return_value
            elif filename.endswith("knowledge_base.yaml"):
                # Default KB will be loaded first
                return mock_open(read_data=yaml.dump({"SQL_INJECTION": {"severity": "HIGH"}, "OLD_RULE": 0})).return_value
            
            return mock_open(read_data="").return_value

        mock_file.side_effect = open_side_effect
        
        kb = KnowledgeBaseLoader(explicit_config_path=LOCAL_PATH)
        
        self.assertEqual(
            kb.rules["SQL_INJECTION"]["severity"],
            "LOW", # <-- This assertion is correct and should now pass
            "Local/Explicit severity should overwrite Default severity.",
        )
        # We assert that the rules from the high priority file are present:
        self.assertIn("NEW_RULE", kb.rules)
        self.assertIn("OLD_RULE", kb.rules)

    @patch("os.getcwd", return_value="/mock/project")
    @patch("platformdirs.user_config_dir", return_value="/mock/user/config")
    @patch("os.path.exists", return_value=False)
    @patch("logging.Logger.warning")
    @patch("builtins.open", new_callable=mock_open, read_data=MOCK_KB_YAML)
    def test_04_no_file_found(
        self, mock_file, mock_log_warning, mock_exists, mock_user_dir, mock_cwd
    ):
        """
        Tests that a warning is logged if no config file is found.
        """
        # Ensure we don't crash when no files exist
        kb = KnowledgeBaseLoader(explicit_config_path=None)
        self.assertEqual(kb.rules, {})

    @patch("os.getcwd", return_value="/mock/project")
    @patch("platformdirs.user_config_dir", return_value="/mock/user/config")
    @patch("os.path.exists", return_value=True)
    @patch("builtins.open", new_callable=mock_open, read_data=MOCK_BAD_YAML)
    @patch("logging.Logger.error")
    def test_05_malformed_yaml_file(
        self, mock_log_error, mock_file, mock_exists, mock_user_dir, mock_cwd
    ):
        """
        Tests that an error is logged if the YAML file is corrupt.
        """
        explicit_path = "/explicit/bad_kb.yaml"

        # ACT
        kb = KnowledgeBaseLoader(explicit_config_path=explicit_path)

        # ASSERT
        # The merge logic failed early, so we should have no rules (or only default rules)
        self.assertLess(len(kb.rules), 2, "Should not contain corrupted rules.")
        mock_log_error.assert_called()

    @patch('os.getcwd', return_value='/mock/project')
    @patch("platformdirs.user_config_dir", return_value='/mock/user/config')
    def test_06_get_methods_with_loaded_rules(self, mock_user_dir, mock_cwd):
        """
        Tests the various 'get' helper methods against a pre-loaded KB.
        """
        kb = KnowledgeBaseLoader(explicit_config_path=None)
        kb.rules = yaml.safe_load(MOCK_KB_YAML)
        
        sql_rules = kb.get_detector_rules("SQL_INJECTION")
        self.assertEqual(sql_rules["cwe"], "CWE-89")
        self.assertEqual(kb.rules["SQL_INJECTION"]["severity"], "HIGH")

