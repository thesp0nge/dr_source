import logging
from typing import List, Dict, Any, Optional
from types import SimpleNamespace

# Tree-sitter imports
from tree_sitter import Parser, Language
import tree_sitter_java

from dr_source.api import AnalyzerPlugin, Vulnerability
from dr_source.core.knowledge_base import KnowledgeBaseLoader
from .taint_detector import TaintDetector

logger = logging.getLogger(__name__)


class JavaAstAnalyzer(AnalyzerPlugin):
    """
    The official Java AST Taint Analyzer plugin for DRSource.
    Now powered by Tree-sitter for robust parsing of modern Java.
    """

    def __init__(self):
        self.kb = KnowledgeBaseLoader()
        self.detector = TaintDetector()
        self.project_index = None
        
        # Initialize Tree-sitter Java parser
        try:
            # Correct way to load from the pip package
            JAVA_LANGUAGE = Language(tree_sitter_java.language())
            self.parser = Parser()
            self.parser.language = JAVA_LANGUAGE
        except Exception as e:
            logger.error(f"Failed to initialize Tree-sitter Java parser: {e}")
            self.parser = None

    @property
    def name(self) -> str:
        return "Java AST Analyzer (Tree-sitter)"

    def get_supported_extensions(self) -> List[str]:
        return [".java"]

    def index(self, file_path: str, project_index: Any):
        """Indexes public-ish methods in Java files."""
        if not self.parser: return
        try:
            with open(file_path, "rb") as f:
                code_bytes = f.read()
            tree = self.parser.parse(code_bytes)
            
            # Use a simple query or walk to find method declarations
            def find_methods(node):
                if node.type == "method_declaration":
                    name_node = node.child_by_field_name("name")
                    if name_node:
                        method_name = code_bytes[name_node.start_byte:name_node.end_byte].decode("utf-8")
                        # For Java, we store the node AND the source code because 
                        # Tree-sitter nodes need the original bytes to extract text
                        project_index.register_function(
                            method_name, 
                            file_path, 
                            {"node": node, "code": code_bytes}, 
                            "java"
                        )
                for child in node.children:
                    find_methods(child)
            
            find_methods(tree.root_node)
        except Exception as e:
            logger.error(f"Error indexing Java file {file_path}: {e}")

    def analyze(self, file_path: str) -> List[Vulnerability]:
        findings = []
        if not self.parser:
            return []

        try:
            with open(file_path, "rb") as f:  # Tree-sitter needs bytes
                code_bytes = f.read()

            # 1. Parse with Tree-sitter
            tree = self.parser.parse(code_bytes)

            file_object = SimpleNamespace(path=file_path)
            all_vuln_types = self.kb.rules.keys()

            for vuln_type in all_vuln_types:
                sources = self.kb.get_lang_ast_sources(vuln_type, "java")
                sinks = self.kb.get_lang_ast_sinks(vuln_type, "java")
                sanitizers = self.kb.get_lang_ast_sanitizers(vuln_type, "java")

                if not sources or not sinks:
                    continue

                rules = self.kb.get_detector_rules(vuln_type)
                severity = rules.get("severity", "MEDIUM").upper()

                # 2. Run Taint Analysis
                raw_issues = self.detector.detect_ast_taint(
                    file_object=file_object,
                    ast_tree=tree,
                    source_code=code_bytes,
                    source_list=sources,
                    sink_list=sinks,
                    sanitizer_list=sanitizers,
                    vuln_prefix=vuln_type,
                    project_index=self.project_index
                )

                for issue in raw_issues:
                    vuln = Vulnerability(
                        vulnerability_type=issue["vuln_type"],
                        message=issue["match"],
                        severity=severity,
                        file_path=issue["file"],
                        line_number=issue["line"],
                        plugin_name=self.name,
                        trace=issue.get("trace", []),
                    )
                    findings.append(vuln)

        except Exception as e:
            logger.error(f"Error analyzing {file_path} with {self.name}: {e}")

        return findings
