import logging
from typing import List, Any
from tree_sitter import Parser, Language
import tree_sitter_php

from dr_source.api import AnalyzerPlugin, Vulnerability
from dr_source.core.knowledge_base import KnowledgeBaseLoader
from .taint_visitor import PHPTaintVisitor

logger = logging.getLogger(__name__)

try:
    PHP_LANGUAGE = Language(tree_sitter_php.language_php())
except Exception as e:
    PHP_LANGUAGE = None
    logger.error(f"PHP Tree-sitter failed to load: {e}")

class PHPAstAnalyzer(AnalyzerPlugin):
    def __init__(self):
        self.kb = KnowledgeBaseLoader()
        self.parser = Parser()
        self.project_index = None
        if PHP_LANGUAGE:
            self.parser.language = PHP_LANGUAGE
        else:
            self.parser = None

    @property
    def name(self) -> str:
        return "PHP AST Analyzer (Tree-sitter)"

    def get_supported_extensions(self) -> List[str]:
        return [".php", ".phtml", ".php4", ".php5"]

    def analyze(self, file_path: str) -> List[Vulnerability]:
        findings = []
        if not self.parser: return []

        try:
            with open(file_path, "rb") as f:
                code_bytes = f.read()

            tree = self.parser.parse(code_bytes)
            all_vuln_types = self.kb.get_all_vuln_types()

            for vuln_type in all_vuln_types:
                sources = self.kb.get_lang_ast_sources(vuln_type, "php")
                sinks = self.kb.get_lang_ast_sinks(vuln_type, "php")
                sanitizers = self.kb.get_lang_ast_sanitizers(vuln_type, "php")

                if not sources or not sinks: continue

                rules = self.kb.get_detector_rules(vuln_type)
                severity = rules.get("severity", "MEDIUM").upper()

                visitor = PHPTaintVisitor(
                    sources=set(sources), 
                    sinks=sinks, 
                    sanitizers=set(sanitizers),
                    source_code=code_bytes,
                    project_index=self.project_index
                )
                visitor.visit(tree.root_node)

                for issue in visitor.vulnerabilities:
                    findings.append(
                        Vulnerability(
                            vulnerability_type=f"{vuln_type} (AST Taint)",
                            message=f"Sink function '{issue['sink']}' called with tainted var '{issue['variable']}'",
                            severity=severity,
                            file_path=file_path,
                            line_number=issue["line"],
                            plugin_name=self.name,
                            trace=issue.get("trace", []),
                        )
                    )

        except Exception as e:
            logger.error(f"Error analyzing PHP file {file_path}: {e}")

        return findings
