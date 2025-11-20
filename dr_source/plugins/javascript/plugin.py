import logging
from typing import List
from types import SimpleNamespace

from tree_sitter import Parser, Language

# Ensure this is installed via pip install tree-sitter-javascript
import tree_sitter_javascript

from dr_source.api import AnalyzerPlugin, Vulnerability
from dr_source.core.knowledge_base import KnowledgeBaseLoader
from .taint_visitor import JavaScriptTaintVisitor  # <-- The visitor we just defined

logger = logging.getLogger(__name__)

# Load the language object once at module startup
try:
    # Use the correct loading pattern: get the C capsule, wrap it in Language()
    JS_LANGUAGE = Language(tree_sitter_javascript.language())
except ImportError:
    JS_LANGUAGE = None
    logger.error("JavaScript Tree-sitter package not found. JS analysis disabled.")


class JavaScriptAstAnalyzer(AnalyzerPlugin):
    """
    AST Analyzer for JavaScript/TypeScript using Tree-sitter.
    """

    def __init__(self):
        self.kb = KnowledgeBaseLoader()
        self.parser = Parser()
        if JS_LANGUAGE:
            self.parser.language = JS_LANGUAGE
        else:
            self.parser = None

    @property
    def name(self) -> str:
        return "JavaScript AST Analyzer (Tree-sitter)"

    def get_supported_extensions(self) -> List[str]:
        return [".js", ".jsx", ".ts", ".tsx"]

    def analyze(self, file_path: str) -> List[Vulnerability]:
        findings = []
        if not self.parser:
            return []

        try:
            with open(file_path, "rb") as f:  # Tree-sitter needs bytes
                code_bytes = f.read()

            tree = self.parser.parse(code_bytes)

            # 1. Prepare data for visitor
            all_vuln_types = self.kb.rules.keys()
            sources = set()
            sinks = set()
            for vuln_type in all_vuln_types:
                sources.update(self.kb.get_lang_ast_sources(vuln_type, "javascript"))
                sinks.update(self.kb.get_lang_ast_sinks(vuln_type, "javascript"))

            # 2. Instantiate and Run Visitor
            visitor = JavaScriptTaintVisitor(sources, sinks, code_bytes)
            visitor.visit(tree.root_node)

            # 3. Collect findings and format
            for issue in visitor.vulnerabilities:
                rules = self.kb.get_detector_rules(issue["vuln_type"])
                severity = rules.get(
                    "severity", "CRITICAL"
                ).upper()  # Use CRITICAL as a safer default

                findings.append(
                    Vulnerability(
                        vulnerability_type=f"{issue['vuln_type']} (AST Taint)",
                        message=f"Sink method '{issue['sink']}' called with tainted var '{issue['variable']}'",
                        severity=severity,
                        file_path=file_path,
                        line_number=issue["line"],
                        plugin_name=self.name,
                        trace=issue.get("trace", []),
                    )
                )

        except Exception as e:
            logger.error(
                f"Error analyzing {file_path} with {self.name}: {e}", exc_info=True
            )

        return findings
