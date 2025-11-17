import re
import os
import logging
from typing import List, Tuple, Any, Dict

from dr_source.api import AnalyzerPlugin, Vulnerability, Severity
from dr_source.core.knowledge_base import KnowledgeBaseLoader

logger = logging.getLogger(__name__)


def _to_severity(sev_str: str) -> Severity:
    """Validates and casts a string to the Severity literal type."""
    sev_upper = sev_str.upper()
    if sev_upper in ("HIGH", "MEDIUM", "LOW", "INFO"):
        # We know it's a valid literal, but pyright doesn't,
        # so we use type: ignore
        return sev_upper  # type: ignore

    logger.warning(
        f"Invalid severity '{sev_str}' in knowledge base. Defaulting to INFO."
    )
    return "INFO"


# Maps file extensions to the language name used in the Knowledge Base
EXTENSION_TO_LANG_MAP: Dict[str, str] = {
    ".py": "python",
    ".java": "java",
    ".php": "php",
    ".rb": "ruby",
}


class RegexAnalyzer(AnalyzerPlugin):
    """
    A general-purpose plugin that scans files using all regex
    rules defined in the knowledge base.
    """

    def __init__(self):
        self.kb = KnowledgeBaseLoader()
        self.general_rules: List[Tuple[Any, str, str, str, str]] = []
        self.lang_rules: Dict[str, List[Tuple[Any, str, str, str, str]]] = {}
        self._compile_rules()

    def _compile_rules(self):
        """
        Loads and compiles all regex rules from the KB into
        their appropriate "general" or "language-specific" bucket.
        """
        for vuln_type, vuln_data in self.kb.rules.items():
            top_severity = vuln_data.get("severity", "MEDIUM")

            # 1. Compile general rules
            general_patterns = vuln_data.get("general_regex_patterns", [])
            if general_patterns:
                self._compile_and_store(
                    general_patterns, vuln_type, top_severity, "general"
                )

            # 2. Compile language-specific rules
            for lang_name, lang_data in vuln_data.get("language_specific", {}).items():
                lang_patterns = lang_data.get("regex_patterns", [])
                if lang_patterns:
                    self._compile_and_store(
                        lang_patterns, vuln_type, top_severity, lang_name
                    )

        logger.info(
            f"RegexAnalyzer loaded and compiled {len(self.general_rules)} general rules "
            f"and {sum(len(v) for v in self.lang_rules.values())} language-specific rules."
        )

    def _compile_and_store(
        self,
        pattern_list: List[dict],
        vuln_type: str,
        default_severity: str,
        lang_name: str,  # <-- The new bucket key ("general", "python", "java")
    ):
        """Helper to compile and store a list of regex rules."""
        for rule in pattern_list:
            try:
                pattern = rule["pattern"].strip()
                message = rule["message"]
                rule_id = rule["id"]
                severity = rule.get("severity", default_severity).upper()

                compiled_regex = re.compile(pattern, re.DOTALL | re.MULTILINE)
                rule_tuple = (compiled_regex, message, severity, vuln_type, rule_id)

                if lang_name == "general":
                    self.general_rules.append(rule_tuple)
                else:
                    if lang_name not in self.lang_rules:
                        self.lang_rules[lang_name] = []
                    self.lang_rules[lang_name].append(rule_tuple)
            except re.error as e:
                logger.warning(
                    f"Failed to compile regex rule {rule_id} for {vuln_type}: {e}"
                )
            except KeyError as e:
                logger.warning(
                    f"Skipping incomplete regex rule for {vuln_type}: Missing key {e}"
                )

    @property
    def name(self) -> str:
        return "General Regex Analyzer"

    def get_supported_extensions(self) -> List[str]:
        """This plugin scans all files."""
        return [".*"]

    def analyze(self, file_path: str) -> List[Vulnerability]:
        """
        Scans the *entire file content* against all compiled regex rules
        that apply to this file's language.
        """
        findings = []
        _, ext = os.path.splitext(file_path)
        lang_name = EXTENSION_TO_LANG_MAP.get(ext)

        # 1. Start with the general rules
        rules_to_run = self.general_rules.copy()

        # 2. Add the language-specific rules
        if lang_name:
            rules_to_run.extend(self.lang_rules.get(lang_name, []))

        if not rules_to_run:
            return []  # No regex rules for this file type
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            for regex, msg, sev, v_type, r_id in rules_to_run:
                for match in regex.finditer(content):
                    line_number = self._get_line_number(content, match.start())

                    findings.append(
                        Vulnerability(
                            vulnerability_type=v_type,
                            message=f"({r_id}) {msg}",
                            severity=_to_severity(sev),
                            file_path=file_path,
                            line_number=line_number,
                            plugin_name=self.name,
                        )
                    )
        except Exception as e:
            logger.error(f"Error analyzing {file_path} with RegexAnalyzer: {e}")

        # Remove duplicate findings on the same line
        # (This is a common issue with regex-all)
        unique_findings = {}
        for f in findings:
            key = (f.file_path, f.line_number, f.vulnerability_type, f.message)
            if key not in unique_findings:
                unique_findings[key] = f

        return list(unique_findings.values())

    def _get_line_number(self, content: str, span_start: int) -> int:
        """Helper to find the line number from a character offset."""
        # count '\n' up to the match start, and add 1
        return content.count("\n", 0, span_start) + 1
