import ast
import logging
from typing import List
from dr_source.api import AnalyzerPlugin, Vulnerability
from dr_source.core.knowledge_base import KnowledgeBaseLoader
from .taint_visitor import PythonTaintVisitor

logger = logging.getLogger(__name__)

class PythonAstAnalyzer(AnalyzerPlugin):
    def __init__(self):
        self.kb = KnowledgeBaseLoader()

    @property
    def name(self) -> str:
        return "Python AST Analyzer"

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

                visitor = PythonTaintVisitor(sources, sinks, sanitizers)
                # Hack: disable structural reporting for the taint pass
                visitor.framework_mappers = [m for m in visitor.framework_mappers if not hasattr(m, 'analyze_node')]
                
                visitor.visit(tree)

                for v in visitor.vulnerabilities:
                    # We need a helper to get severity, but for now we default to HIGH
                    findings.append(Vulnerability(
                        file_path=file_path,
                        line_number=v["line"],
                        vulnerability_type=f"{vuln_type} (AST Taint)",
                        message=f"Taint flow from source to sink '{v['sink']}' via variable '{v['variable']}'",
                        severity="HIGH",
                        trace=v["trace"],
                        plugin_name=self.name
                    ))
        except Exception as e:
            logger.error(f"Error analyzing {file_path} with Python AST Analyzer: {e}")

        return findings

    def get_supported_extensions(self) -> List[str]:
        return [".py"]
