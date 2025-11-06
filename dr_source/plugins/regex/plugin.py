import re
import logging
from typing import List, Tuple, Any

from dr_source.api import AnalyzerPlugin, Vulnerability
from dr_source.core.knowledge_base import KnowledgeBaseLoader

logger = logging.getLogger(__name__)


class RegexAnalyzer(AnalyzerPlugin):
    """
    A general-purpose plugin that scans files using all regex
    rules defined in the knowledge base.
    """

    def __init__(self):
        self.kb = KnowledgeBaseLoader()
        self.compiled_rules: List[Tuple[Any, str, str, str]] = []
        self._compile_rules()

    def _compile_rules(self):
        """
        Loads and compiles all regex rules from the KB for
        all vulnerability types and all languages.
        """
        for vuln_type, vuln_data in self.kb.rules.items():
            top_severity = vuln_data.get("severity", "MEDIUM")

            # 1. Get general regex patterns
            patterns = vuln_data.get("general_regex_patterns", [])
            self._compile_and_store(patterns, vuln_type, top_severity)

            # 2. Get language-specific regex patterns
            for lang_data in vuln_data.get("language_specific", {}).values():
                lang_patterns = lang_data.get("regex_patterns", [])
                self._compile_and_store(lang_patterns, vuln_type, top_severity)

        logger.info(
            f"RegexAnalyzer loaded and compiled {len(self.compiled_rules)} rules."
        )

    def _compile_and_store(
        self, pattern_list: List[dict], vuln_type: str, default_severity: str
    ):
        """Helper to compile and store a list of regex rules."""
        for rule in pattern_list:
            try:
                pattern = rule["pattern"].strip()
                message = rule["message"]
                rule_id = rule["id"]
                # Allow rule-specific severity to override top-level
                severity = rule.get("severity", default_severity).upper()

                compiled_regex = re.compile(pattern, re.DOTALL | re.MULTILINE)

                self.compiled_rules.append(
                    (compiled_regex, message, severity, vuln_type, rule_id)
                )
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
        Scans the *entire file content* against all compiled regex rules.
        """
        findings = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            content_lines = [None] + content.splitlines()

            for regex, msg, sev, v_type, r_id in self.compiled_rules:
                # Use finditer to find all matches in the file
                for match in regex.finditer(content):
                    # Calculate the line number of the match
                    line_number = self._get_line_number(content, match.start())

                    findings.append(
                        Vulnerability(
                            vulnerability_type=v_type,
                            message=f"({r_id}) {msg}",
                            severity=sev,
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
