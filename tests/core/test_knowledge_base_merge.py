import unittest
import os
import tempfile
import yaml
from unittest.mock import patch, mock_open

from dr_source.core.knowledge_base import KnowledgeBaseLoader
from dr_source.core.utils import deep_merge


class TestKnowledgeBaseMerge(unittest.TestCase):
    def test_deep_merge_utility(self):
        """Tests the recursive merge logic (dictionaries, lists, overwrite)."""

        target = {
            "A": "initial",
            "B": {"key1": 10, "key2": 20},
            "C": [1, 2],
            "D": "keep",
        }

        source = {
            "A": "overwritten",  # Should overwrite
            "B": {"key1": 50, "key3": 70},  # Should merge B
            "C": [3, 4],  # Should extend C
            "E": "new",  # Should add E
        }

        result = deep_merge(target, source)

        self.assertEqual(result["A"], "overwritten")
        self.assertEqual(result["D"], "keep")
        self.assertEqual(result["E"], "new")

        # Test recursive merge (B)
        self.assertEqual(result["B"]["key1"], 50)
        self.assertEqual(result["B"]["key2"], 20)
        self.assertEqual(result["B"]["key3"], 70)

        # Test list extension (C)
        self.assertEqual(result["C"], [1, 2, 3, 4])

    @patch("os.path.exists")
    @patch("builtins.open", new_callable=lambda: mock_open(read_data=""))
    @patch("os.getcwd", return_value="/mock/project")
    @patch("platformdirs.user_config_dir", return_value="/mock/user/config")
    def test_multi_layer_loading_and_merge(
        self, mock_user_dir, mock_cwd, mock_open_func, mock_exists
    ):
        """
        Tests that the loader finds and merges rules from multiple locations
        (Default -> Local -> Explicit) in the correct order.
        """
        # --- Arrange Simulated File Paths ---
        DEFAULT_PATH = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                "..",
                "..",
                "dr_source",
                "config",
                "knowledge_base.yaml",
            )
        )
        LOCAL_PATH = "/mock/project/.dr_source_rules.yaml"
        EXPLICIT_PATH = "/mock/explicit_rules.yaml"

        MOCK_FILES = {
            # 1. Default: Loaded first (LOWEST PRIORITY)
            DEFAULT_PATH: yaml.dump({"A": "default", "B": ["def", "ault"]}),
            # 2. Local: Loaded later (HIGHER PRIORITY)
            LOCAL_PATH: yaml.dump({"A": "local", "C": 3}),
            # 3. Explicit: Loaded last (HIGHEST PRIORITY)
            EXPLICIT_PATH: yaml.dump({"B": ["loc", "al", "override"], "D": 4}),
        }

        # Simulate file existence
        def exists_side_effect(path):
            return path in MOCK_FILES

        mock_exists.side_effect = exists_side_effect

        # Simulate file opening and reading
        def open_side_effect(filename, mode="r", encoding=None):
            if filename in MOCK_FILES:
                return mock_open(read_data=MOCK_FILES[filename]).return_value
            raise FileNotFoundError(f"File not found: {filename}")

        mock_open_func.side_effect = open_side_effect

        kb = KnowledgeBaseLoader(explicit_config_path=EXPLICIT_PATH)

        self.assertEqual(
            kb.rules["A"],
            "local",
            "A should be overwritten by LOCAL path.",
        )

        self.assertEqual(
            kb.rules["B"],
            ["def", "ault", "loc", "al", "override"],
            "List B should be extended by Explicit rules.",
        )
