import logging
import re
from typing import Optional, Dict, Any, List
from tree_sitter import Node, Parser, Language
import tree_sitter_javascript
import tree_sitter_java

logger = logging.getLogger(__name__)

class TreeSitterPatternMatcher:
    """
    Structural pattern matching using Tree-sitter for Java/JavaScript.
    Supports metavariables ($X) and ellipsis (...).
    """
    METAVARIABLE_PATTERN = r'\$([A-Z_][A-Z0-9_]*)'

    def __init__(self, pattern: str, language: str):
        self.pattern = pattern
        self.language = language
        self.parser = Parser()
        self._init_parser(language)
        self.pattern_tree = self.parser.parse(bytes(pattern, "utf-8"))
        self.metavariables: Dict[str, str] = {}

    def _init_parser(self, language: str):
        try:
            if language == "javascript":
                lang = Language(tree_sitter_javascript.language())
            elif language == "java":
                lang = Language(tree_sitter_java.language())
            else:
                return
            self.parser.language = lang
        except Exception as e:
            logger.error(f"Failed to init TS parser for {language} in matcher: {e}")

    def _get_node_text(self, node: Node, source: str) -> str:
        if isinstance(source, str):
            source_bytes = bytes(source, "utf-8")
        else:
            source_bytes = source
        return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")

    def match(self, target_node: Node, target_source: str) -> bool:
        self.metavariables = {}
        
        # 1. Prepare Pattern Node
        pattern_node = self.pattern_tree.root_node
        # Unwrap 'program' and 'expression_statement' from pattern
        while pattern_node.child_count == 1 and pattern_node.type in ["program", "expression_statement"]:
            pattern_node = pattern_node.children[0]
        
        # 2. Prepare Target Node
        # If the target is an expression_statement, we might want to match its content
        current_target = target_node
        if current_target.type == "expression_statement" and pattern_node.type != "expression_statement":
            if current_target.child_count > 0:
                current_target = current_target.children[0]
        
        return self._match_nodes(pattern_node, self.pattern, current_target, target_source)

    def _match_nodes(self, p_node: Node, p_source: str, t_node: Node, t_source: str) -> bool:
        p_text = self._get_node_text(p_node, p_source)
        
        # 1. Handle Metavariables ($X)
        mv_match = re.fullmatch(self.METAVARIABLE_PATTERN, p_text)
        if mv_match:
            var_name = mv_match.group(1)
            t_text = self._get_node_text(t_node, t_source)
            if var_name in self.metavariables:
                return self.metavariables[var_name] == t_text
            else:
                self.metavariables[var_name] = t_text
                return True

        # 2. Handle Ellipsis (...)
        if p_text == "...":
            return True

        # 3. Structural Comparison
        # Remove wrapper types for comparison if needed
        p_type = p_node.type
        t_type = t_node.type
        
        if p_type != t_type:
            return False

        if p_node.child_count == 0:
            return p_text == self._get_node_text(t_node, t_source)

        p_children = [c for c in p_node.children if c.is_named]
        t_children = [c for c in t_node.children if c.is_named]
        
        if not any(self._get_node_text(c, p_source) == "..." for c in p_children):
            if len(p_children) != len(t_children):
                return False

        p_idx, t_idx = 0, 0
        while p_idx < len(p_children) and t_idx < len(t_children):
            p_child = p_children[p_idx]
            if self._get_node_text(p_child, p_source) == "...":
                if p_idx == len(p_children) - 1:
                    return True
                p_idx += 1
                next_p_child = p_children[p_idx]
                while t_idx < len(t_children):
                    if self._match_nodes(next_p_child, p_source, t_children[t_idx], t_source):
                        break
                    t_idx += 1
                continue
            
            if not self._match_nodes(p_child, p_source, t_children[t_idx], t_source):
                return False
            p_idx += 1
            t_idx += 1

        return p_idx == len(p_children) and t_idx == len(t_children)
