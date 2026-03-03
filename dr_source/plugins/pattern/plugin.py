import ast
import logging
from typing import List, Any, Dict

from dr_source.api import AnalyzerPlugin, Vulnerability
from dr_source.core.knowledge_base import KnowledgeBaseLoader
from .matcher import PatternMatcher
from tree_sitter import Parser, Language
import tree_sitter_javascript
import tree_sitter_java
import tree_sitter_php
import tree_sitter_ruby

logger = logging.getLogger(__name__)

class PatternAnalyzer(AnalyzerPlugin):
    """
    A Semgrep-like pattern matching plugin for DRSource.
    Supports Python (native AST) and Java/JS/PHP/Ruby (Tree-sitter).
    """

    def __init__(self):
        self.kb = KnowledgeBaseLoader()
        self.parsers = {}
        self._init_parsers()

    def _init_parsers(self):
        try:
            js_lang = Language(tree_sitter_javascript.language())
            js_parser = Parser()
            js_parser.language = js_lang
            self.parsers["javascript"] = js_parser
        except Exception as e:
            logger.error(f"Failed to load javascript parser: {e}")

        try:
            java_lang = Language(tree_sitter_java.language())
            java_parser = Parser()
            java_parser.language = java_lang
            self.parsers["java"] = java_parser
        except Exception as e:
            logger.error(f"Failed to load java parser: {e}")

        try:
            php_lang = Language(tree_sitter_php.language_php())
            php_parser = Parser()
            php_parser.language = php_lang
            self.parsers["php"] = php_parser
        except Exception as e:
            logger.error(f"Failed to load php parser: {e}")

        try:
            ruby_lang = Language(tree_sitter_ruby.language())
            ruby_parser = Parser()
            ruby_parser.language = ruby_lang
            self.parsers["ruby"] = ruby_parser
        except Exception as e:
            logger.error(f"Failed to load ruby parser: {e}")

    @property
    def name(self) -> str:
        return "Pattern Matcher"

    def get_supported_extensions(self) -> List[str]:
        return [".py", ".js", ".java", ".php", ".rb"]

    def _walk_ts_tree(self, node):
        yield node
        for child in node.children:
            yield from self._walk_ts_tree(child)

    def analyze(self, file_path: str) -> List[Vulnerability]:
        findings = []
        ext = "." + file_path.split(".")[-1]
        lang_map = {
            ".py": "python",
            ".js": "javascript",
            ".java": "java",
            ".php": "php",
            ".rb": "ruby"
        }
        lang = lang_map.get(ext, "unknown")
        if lang == "unknown": return []
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()

            all_vuln_types = self.kb.get_all_vuln_types()

            if lang == "python":
                target_ast = ast.parse(code, filename=file_path)
                nodes = ast.walk(target_ast)
            elif lang in self.parsers:
                parser = self.parsers[lang]
                # PHP fix: ensure code starts with <?php for tree-sitter
                effective_code = code
                if lang == "php" and not code.strip().startswith("<?"):
                    effective_code = "<?php " + code
                
                tree = parser.parse(bytes(effective_code, "utf-8"))
                nodes = self._walk_ts_tree(tree.root_node)
            else:
                return []

            for vuln_type in all_vuln_types:
                logic = self.kb.get_patterns_logic(vuln_type, lang)
                if not logic:
                    continue
                
                logger.debug(f"Evaluating {vuln_type} pattern logic for {lang}")

                rules = self.kb.get_detector_rules(vuln_type)
                severity = rules.get("severity", "MEDIUM").upper()
                message = rules.get("message", "Vulnerability found via pattern matching.")

                for node in nodes:
                    # Avoid double reporting: skip expression_statement as it wraps call_expression
                    if node.type == "expression_statement":
                        continue
                        
                    if self._evaluate_logic(node, logic, lang, code):
                        vuln = Vulnerability(
                            vulnerability_type=f"{vuln_type} (Pattern)",
                            message=message,
                            severity=severity,
                            file_path=file_path,
                            line_number=node.lineno if lang == "python" else node.start_point[0] + 1,
                            plugin_name=self.name,
                        )
                        findings.append(vuln)

        except Exception as e:
            logger.error(f"Error analyzing {file_path} with {self.name}: {e}")

        return findings

    def _evaluate_logic(self, node: Any, logic: Any, lang: str, source_code: str = "") -> bool:
        if isinstance(logic, str):
            if lang == "python":
                return PatternMatcher(logic).match(node)
            else:
                from .ts_matcher import TreeSitterPatternMatcher
                return TreeSitterPatternMatcher(logic, lang).match(node, source_code)
        
        if not isinstance(logic, dict):
            return False

        if "pattern" in logic:
            if not self._evaluate_logic(node, logic["pattern"], lang, source_code):
                return False

        if "patterns" in logic:
            for sub_logic in logic["patterns"]:
                if not self._evaluate_logic(node, sub_logic, lang, source_code):
                    return False

        if "pattern-either" in logic:
            found_match = False
            for sub_logic in logic["pattern-either"]:
                if self._evaluate_logic(node, sub_logic, lang, source_code):
                    found_match = True; break
            if not found_match: return False

        if "pattern-not" in logic:
            if self._evaluate_logic(node, logic["pattern-not"], lang, source_code):
                return False

        return True
