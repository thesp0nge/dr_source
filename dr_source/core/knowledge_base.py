import os
import yaml
import logging
import platformdirs
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class KnowledgeBaseLoader:
    """
    Loads and provides access to the multi-language YAML rule
    knowledge base.
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Loads the rules from the first valid path found.
        """
        self.rules: Dict[str, Any] = {}

        # 1. Define all potential paths
        in_package_path = os.path.join(
            os.path.dirname(__file__), "..", "config", "knowledge_base.yaml"
        )
        user_config_path = os.path.join(
            platformdirs.user_config_dir("dr_source"), "knowledge_base.yaml"
        )
        system_config_path = os.path.join(
            platformdirs.site_config_dir("dr_source"), "knowledge_base.yaml"
        )

        # 2. Build the list of paths that might include None
        potential_paths: List[Optional[str]] = [
            config_path,
            user_config_path,
            system_config_path,
            in_package_path,
        ]

        # 3. Create a clean, type-safe list containing only strings
        search_paths: List[str] = [p for p in potential_paths if p is not None]

        # 4. Iterate and load.
        loaded_path = None
        for path in search_paths:
            logger.debug("Checking for knowledge base at: %s", path)

            if os.path.exists(path):
                try:
                    with open(path, "r") as f:
                        self.rules = yaml.safe_load(f)

                    logger.info("Knowledge base loaded successfully from: %s", path)
                    loaded_path = path
                    break
                except Exception as e:
                    logger.error("Error loading knowledge base from %s: %s", path, e)
                    break

        if not loaded_path:
            logger.warning(
                "No knowledge base file was found or loaded. "
                "The tool will run with no rules."
            )

    # --- ALL GETTER METHODS (This fixes the AttributeError) ---

    def get_detector_rules(self, detector_name: str) -> Dict[str, Any]:
        """Gets the specific rule block for a given detector."""
        return self.rules.get(detector_name, {})

    def get_general_regex(self, detector_name: str) -> List[Dict[str, Any]]:
        """Gets the general, language-agnostic regex patterns for a detector."""
        detector_rules = self.get_detector_rules(detector_name)
        return detector_rules.get("general_regex_patterns", [])

    def _get_lang_rules(self, detector_name: str, language: str) -> Dict[str, Any]:
        """Helper to get the language-specific block."""
        detector_rules = self.get_detector_rules(detector_name)
        lang_specific = detector_rules.get("language_specific", {})
        return lang_specific.get(language, {})

    def get_lang_regex(self, detector_name: str, language: str) -> List[Dict[str, Any]]:
        """Gets the regex patterns for a *specific* language."""
        lang_rules = self._get_lang_rules(detector_name, language)
        return lang_rules.get("regex_patterns", [])

    def get_lang_ast_sources(self, detector_name: str, language: str) -> List[str]:
        """Gets the AST sources for a *specific* language."""
        lang_rules = self._get_lang_rules(detector_name, language)
        return lang_rules.get("ast_sources", [])

    def get_lang_ast_sinks(self, detector_name: str, language: str) -> List[str]:
        """Gets the AST sinks for a *specific* language."""
        lang_rules = self._get_lang_rules(detector_name, language)
        return lang_rules.get("ast_sinks", [])
