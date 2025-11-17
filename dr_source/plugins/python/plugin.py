import ast
import logging
from typing import List, Dict, Any

from dr_source.api import AnalyzerPlugin, Vulnerability
from dr_source.core.knowledge_base import KnowledgeBaseLoader
from .taint_visitor import PythonTaintVisitor

logger = logging.getLogger(__name__)


class PythonAstAnalyzer(AnalyzerPlugin):
    """
    The official Python AST Taint Analyzer plugin for DRSource.
    """

    def __init__(self):
        self.kb = KnowledgeBaseLoader()

    @property
    def name(self) -> str:
        return "Python AST Analyzer"

    def get_supported_extensions(self) -> List[str]:
        return [".py"]

    def analyze(self, file_path: str) -> List[Vulnerability]:
        findings = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()

            tree = ast.parse(code, filename=file_path)

            all_vuln_types = self.kb.rules.keys()

            for vuln_type in all_vuln_types:
                sources = self.kb.get_lang_ast_sources(vuln_type, "python")
                sinks = self.kb.get_lang_ast_sinks(vuln_type, "python")

                if not sources or not sinks:
                    continue  # This rule doesn't apply to Python AST

                rules = self.kb.get_detector_rules(vuln_type)
                severity = rules.get("severity", "MEDIUM").upper()

                # Create and run the visitor for each vuln type
                visitor = PythonTaintVisitor(source_list=sources, sink_list=sinks)
                visitor.visit(tree)

                raw_issues = visitor.vulnerabilities

                for issue in raw_issues:
                    vuln = Vulnerability(
                        vulnerability_type=f"{vuln_type} (AST Taint)",
                        message=f"Taint flow from source to sink '{issue['sink']}' via variable '{issue['variable']}'",
                        severity=severity,
                        file_path=file_path,
                        line_number=issue["line"],
                        plugin_name=self.name,
                        trace=issue.get("trace", []),
                    )
                    findings.append(vuln)

        except SyntaxError as e:
            logger.warning(f"Could not parse Python file {file_path}: {e}")
        except Exception as e:
            logger.error(f"Error analyzing {file_path} with {self.name}: {e}")

        return findings
