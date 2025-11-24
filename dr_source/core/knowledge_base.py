import os
import yaml
import logging
import platformdirs
from typing import Dict, Any, List, Optional
from .utils import deep_merge  # <-- Import our new utility

logger = logging.getLogger(__name__)


class KnowledgeBaseLoader:
    """
    Loads and provides access to the multi-language YAML rule
    knowledge base, merging rules from multiple sources.
    """

    def __init__(self, explicit_config_path: Optional[str] = None):
        self.rules: Dict[str, Any] = {}
        self.load_and_merge_rules(explicit_config_path)

    def _get_default_search_paths(self, explicit_path: Optional[str]) -> List[str]:
        """Defines the prioritized list of locations to search for KB files."""

        # 1. Factory Default (The KB shipped with the application) - LOWEST PRIORITY
        in_package_path = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__), "..", "config", "knowledge_base.yaml"
            )
        )

        # 2. User Config (OS-specific standard location)
        user_config_path = os.path.join(
            platformdirs.user_config_dir("dr_source"), "knowledge_base.yaml"
        )

        # 3. Project Local Config
        local_project_path = os.path.join(os.getcwd(), ".dr_source_rules.yaml")

        # 4. Explicit Path - HIGHEST PRIORITY

        # Build the sequence from LOWEST to HIGHEST PRIORITY
        search_paths: List[Optional[str]] = [
            in_package_path,  # 1. Default (LOWEST)
            user_config_path,  # 2. User Home
            local_project_path,  # 3. Local Project
            explicit_path,  # 4. Explicit CLI (HIGHEST)
        ]

        # Filter out None/non-existent paths, preserving the exact order
        final_paths = []
        for p in search_paths:
            if p and p not in final_paths:
                final_paths.append(p)

        return final_paths

    def load_and_merge_rules(self, explicit_path: Optional[str]):
        """
        Loads and merges all KB files found in the priority search paths.
        The last file loaded wins.
        """
        search_paths = self._get_default_search_paths(explicit_path)
        
        if not search_paths:
            logger.warning("No knowledge base files were found.")
            return

        # Initialize the final rules with the lowest priority default first
        final_rules = {}

        for path in search_paths:
            if not os.path.exists(path):
                continue
            
            try:
                with open(path, "r") as f:
                    new_rules = yaml.safe_load(f)
                    
                if new_rules:
                    # --- CRITICAL FIX ---
                    # We merge the NEW rules (Source) INTO the existing final_rules (Target).
                    # Since deep_merge(target, source) makes SOURCE win, 
                    # we must treat the cumulative state as the target.
                    
                    # final_rules = deep_merge(final_rules, new_rules) is the mathematically correct call.
                    
                    # If this is still failing, the issue is that deep_merge is performing the 
                    # assignment in the wrong order inside the loop.
                    
                    # Let's use the simplest possible logic:
                    self.rules = deep_merge(self.rules, new_rules)
                    
                    logger.info(f"Successfully merged rules from: {path}")

            except Exception as e:
                logger.error(f"CRITICAL: Error loading/merging knowledge base from {path}: {e}")

    def get_detector_rules(self, detector_name: str) -> Dict[str, Any]:
        return self.rules.get(detector_name, {})

    def get_general_regex(self, detector_name: str) -> List[Dict[str, Any]]:
        detector_rules = self.get_detector_rules(detector_name)
        return detector_rules.get("general_regex_patterns", [])

    def _get_lang_rules(self, detector_name: str, language: str) -> Dict[str, Any]:
        detector_rules = self.get_detector_rules(detector_name)
        lang_specific = detector_rules.get("language_specific", {})
        return lang_specific.get(language, {})

    def get_lang_regex(self, detector_name: str, language: str) -> List[Dict[str, Any]]:
        lang_rules = self._get_lang_rules(detector_name, language)
        return lang_rules.get("regex_patterns", [])

    def get_lang_ast_sources(self, detector_name: str, language: str) -> List[str]:
        lang_rules = self._get_lang_rules(detector_name, language)
        return lang_rules.get("ast_sources", [])

    def get_lang_ast_sinks(self, detector_name: str, language: str) -> List[str]:
        lang_rules = self._get_lang_rules(detector_name, language)
        return lang_rules.get("ast_sinks", [])
