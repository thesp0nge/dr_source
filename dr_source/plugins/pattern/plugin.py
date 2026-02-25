import ast
import logging
from typing import List

from dr_source.api import AnalyzerPlugin, Vulnerability
from dr_source.core.knowledge_base import KnowledgeBaseLoader
from .matcher import PatternMatcher

logger = logging.getLogger(__name__)


class PatternAnalyzer(AnalyzerPlugin):
    """
    A Semgrep-like pattern matching plugin for DRSource.
    """

    def __init__(self):
        self.kb = KnowledgeBaseLoader()

    @property
    def name(self) -> str:
        return "Pattern Matcher"

    def get_supported_extensions(self) -> List[str]:
        return [".py"]

    def analyze(self, file_path: str) -> List[Vulnerability]:
        logger.debug(f"PatternAnalyzer analyzing: {file_path}")
        findings = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()

            target_ast = ast.parse(code, filename=file_path)

            all_vuln_types = self.kb.get_all_vuln_types()

            for vuln_type in all_vuln_types:
                pattern = self.kb.get_pattern(vuln_type, "python")
                if not pattern:
                    continue

                rules = self.kb.get_detector_rules(vuln_type)
                severity = rules.get("severity", "MEDIUM").upper()
                message = rules.get("message", "Vulnerability found via pattern matching.")

                matcher = PatternMatcher(pattern)

                for node in ast.walk(target_ast):
                    if matcher.match(node):
                        vuln = Vulnerability(
                            vulnerability_type=f"{vuln_type} (Pattern)",
                            message=message,
                            severity=severity,
                            file_path=file_path,
                            line_number=node.lineno,
                            plugin_name=self.name,
                        )
                        findings.append(vuln)

        except SyntaxError as e:
            logger.warning(f"Could not parse Python file {file_path}: {e}")
        except Exception as e:
            logger.error(f"Error analyzing {file_path} with {self.name}: {e}")

        return findings
