import ast
import logging
from typing import Any, List
from dr_source.api import AnalyzerPlugin, Vulnerability
from dr_source.core.knowledge_base import KnowledgeBaseLoader
from .taint_visitor import PythonTaintVisitor

logger = logging.getLogger(__name__)

class PythonAstAnalyzer(AnalyzerPlugin):
    def __init__(self):
        self.kb = KnowledgeBaseLoader()
        self.project_index = None

    @property
    def name(self) -> str:
        return "Python AST Analyzer"

    def index(self, file_path: str, project_index: Any):
        """Register top-level Python functions for inter-file analysis."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as source:
                tree = ast.parse(source.read(), filename=file_path)
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    project_index.register_function(
                        node.name, file_path, node, "python",
                        declaration_position=(node.lineno, node.col_offset),
                    )
        except (OSError, SyntaxError) as error:
            logger.error(f"Error indexing Python file {file_path}: {error}")

    def analyze(self, file_path: str) -> List[Vulnerability]:
        findings = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
            
            tree = ast.parse(code)
            all_vuln_types = self.kb.get_all_vuln_types()
            
            # 1. Structural Analysis (Perform once per file)
            structural_visitor = PythonTaintVisitor([], [], [])
            structural_visitor.visit(tree)
            for v in structural_visitor.vulnerabilities:
                findings.append(Vulnerability(
                    file_path=file_path,
                    line_number=v["line"],
                    vulnerability_type=v["sink"],
                    message=v["trace"][0],
                    severity="HIGH",
                    plugin_name=self.name
                ))

            # 2. Taint Analysis (Perform for each category)
            for vuln_type in all_vuln_types:
                sources = self.kb.get_lang_ast_sources(vuln_type, "python")
                sinks = self.kb.get_lang_ast_sinks(vuln_type, "python")
                sanitizers = self.kb.get_lang_ast_sanitizers(vuln_type, "python")

                if not sinks:
                    continue

                rules = self.kb.get_detector_rules(vuln_type)
                severity = rules.get("severity", "MEDIUM").upper()
                visitor = PythonTaintVisitor(
                    sources,
                    sinks,
                    sanitizers,
                    project_index=self.project_index,
                    structural_analysis=False,
                )
                
                visitor.visit(tree)

                for v in visitor.vulnerabilities:
                    findings.append(Vulnerability(
                        file_path=file_path,
                        line_number=v["line"],
                        vulnerability_type=f"{vuln_type} (AST Taint)",
                        message=f"Taint flow from source to sink '{v['sink']}' via variable '{v['variable']}'",
                        severity=severity,
                        trace=v["trace"],
                        plugin_name=self.name
                    ))
        except Exception as e:
            logger.error(f"Error analyzing {file_path} with Python AST Analyzer: {e}")

        return findings

    def get_supported_extensions(self) -> List[str]:
        return [".py"]
