import logging
from typing import List, Any
from types import SimpleNamespace
from tree_sitter import Parser, Language
import tree_sitter_javascript

from dr_source.api import AnalyzerPlugin, Vulnerability
from dr_source.core.knowledge_base import KnowledgeBaseLoader
from .taint_visitor import JavaScriptTaintVisitor

logger = logging.getLogger(__name__)

try:
    JS_LANGUAGE = Language(tree_sitter_javascript.language())
except Exception as e:
    JS_LANGUAGE = None
    logger.error(f"JavaScript Tree-sitter failed to load: {e}")


class JavaScriptAstAnalyzer(AnalyzerPlugin):
    def __init__(self):
        self.kb = KnowledgeBaseLoader()
        self.parser = Parser()
        self.project_index = None
        if JS_LANGUAGE:
            self.parser.language = JS_LANGUAGE
        else:
            self.parser = None

    @property
    def name(self) -> str:
        return "JavaScript AST Analyzer (Tree-sitter)"

    def get_supported_extensions(self) -> List[str]:
        return [".js", ".jsx", ".ts", ".tsx"]

    def index(self, file_path: str, project_index: Any):
        """Indexes function declarations in JS/TS files."""
        if not self.parser: return
        try:
            with open(file_path, "rb") as f:
                code_bytes = f.read()
            tree = self.parser.parse(code_bytes)
            
            def find_functions(node):
                if node.type == "function_declaration":
                    name_node = node.child_by_field_name("name")
                    if name_node:
                        func_name = code_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8")
                        project_index.register_function(
                            func_name, 
                            file_path, 
                            {"node": node, "code": code_bytes}, 
                            "javascript"
                        )
                for child in node.children:
                    find_functions(child)
            
            find_functions(tree.root_node)
        except Exception as e:
            logger.error(f"Error indexing JS file {file_path}: {e}")

    def analyze(self, file_path: str) -> List[Vulnerability]:
        findings = []
        if not self.parser:
            return []

        try:
            with open(file_path, "rb") as f:
                code_bytes = f.read()

            tree = self.parser.parse(code_bytes)
            all_vuln_types = self.kb.rules.keys()

            for vuln_type in all_vuln_types:
                sources = self.kb.get_lang_ast_sources(vuln_type, "javascript")
                sinks = self.kb.get_lang_ast_sinks(vuln_type, "javascript")
                sanitizers = self.kb.get_lang_ast_sanitizers(vuln_type, "javascript")

                if not sources or not sinks:
                    continue

                rules = self.kb.get_detector_rules(vuln_type)
                severity = rules.get("severity", "MEDIUM").upper()

                visitor = JavaScriptTaintVisitor(
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
                            message=f"Sink method '{issue['sink']}' called with tainted var '{issue['variable']}'",
                            severity=severity,
                            file_path=file_path,
                            line_number=issue["line"],
                            plugin_name=self.name,
                            trace=issue.get("trace", []),
                        )
                    )

        except Exception as e:
            logger.error(f"Error analyzing {file_path} with {self.name}: {e}")

        return findings
