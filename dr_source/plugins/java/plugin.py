import logging
from typing import List, Dict, Any
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

    def analyze(self, file_path: str) -> List[Vulnerability]:
        findings = []
        if not self.parser:
            return []

        try:
            with open(file_path, "rb") as f:  # Tree-sitter needs bytes
                code_bytes = f.read()

            # 1. Parse with Tree-sitter
            # This never throws syntax errors; it produces error nodes instead.
            tree = self.parser.parse(code_bytes)

            # Optional: Log if there are syntax errors in the tree
            if tree.root_node.has_error:
                logger.debug(
                    f"Tree-sitter found syntax errors in {file_path}, but analysis will proceed."
                )

            file_object = SimpleNamespace(path=file_path)
            all_vuln_types = self.kb.rules.keys()

            for vuln_type in all_vuln_types:
                sources = self.kb.get_lang_ast_sources(vuln_type, "java")
                sinks = self.kb.get_lang_ast_sinks(vuln_type, "java")

                if not sources or not sinks:
                    continue

                rules = self.kb.get_detector_rules(vuln_type)
                severity = rules.get("severity", "MEDIUM").upper()

                # 2. Run Taint Analysis (Using source code for value extraction)
                raw_issues = self.detector.detect_ast_taint(
                    file_object=file_object,
                    ast_tree=tree,
                    source_code=code_bytes,  # Pass raw code to extract strings
                    source_list=sources,
                    sink_list=sinks,
                    vuln_prefix=vuln_type,
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
