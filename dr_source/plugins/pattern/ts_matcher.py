import logging
import re
from typing import Optional, Dict, Any, List
from tree_sitter import Node, Parser, Language
import tree_sitter_javascript
import tree_sitter_java
import tree_sitter_php
import tree_sitter_ruby

logger = logging.getLogger(__name__)

class TreeSitterPatternMatcher:
    """
    Structural pattern matching using Tree-sitter for Java/JavaScript/PHP/Ruby.
    Supports metavariables ($X) and ellipsis (...).
    """
    METAVARIABLE_PATTERN = r'\$([A-Z_][A-Z0-9_]*)'

    def __init__(self, pattern: str, language: str):
        self.language = language
        self.pattern_str = pattern
        self.parser = Parser()
        self._init_parser(language)
        
        self.effective_pattern = pattern
        if language == "php" and not pattern.startswith("<?php"):
            self.effective_pattern = "<?php " + pattern
            
        self.pattern_tree = self.parser.parse(bytes(self.effective_pattern, "utf-8"))
        self.metavariables: Dict[str, str] = {}

    def _init_parser(self, language: str):
        try:
            if language == "javascript":
                lang = Language(tree_sitter_javascript.language())
            elif language == "java":
                lang = Language(tree_sitter_java.language())
            elif language == "php":
                lang = Language(tree_sitter_php.language_php())
            elif language == "ruby":
                lang = Language(tree_sitter_ruby.language())
            else:
                return
            self.parser.language = lang
        except Exception as e:
            logger.error(f"Failed to init TS parser for {language} in matcher: {e}")

    def _get_node_text(self, node: Node, source: str) -> str:
        if isinstance(source, str): source_bytes = bytes(source, "utf-8")
        else: source_bytes = source
        return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")

    def match(self, target_node: Node, target_source: str) -> bool:
        self.metavariables = {}
        
        # 1. Structural Match attempt
        pattern_node = self.pattern_tree.root_node
        while pattern_node.child_count == 1 and pattern_node.type in ["program", "expression_statement", "text"]:
            pattern_node = pattern_node.children[0]
        
        current_target = target_node
        if current_target.type == "expression_statement" and pattern_node.type != "expression_statement":
            if current_target.child_count > 0: current_target = current_target.children[0]
        
        if self._match_nodes(pattern_node, self.effective_pattern, current_target, target_source):
            return True
            
        # 2. Textual Fallback with Metavariable Support
        # This is for nodes where AST structure is too deep or different
        target_text = self._get_node_text(target_node, target_source)
        return self._textual_match(self.pattern_str, target_text)

    def _textual_match(self, pattern: str, text: str) -> bool:
        # Simple regex based matching for $X == $X
        regex_p = re.escape(pattern)
        regex_p = regex_p.replace(r'\.\.\.', r'.*?')
        
        mvs = re.findall(self.METAVARIABLE_PATTERN, pattern)
        if not mvs: return pattern.strip() in text.strip()
        
        # Replace $X with a capture group for identifiers/variables
        # We handle PHP variables ($var) vs Ruby/JS (var)
        identifier_regex = r'(\$?[a-zA-Z_][a-zA-Z0-9_]*)'
        
        for mv in set(mvs):
            regex_p = regex_p.replace(re.escape(f"${mv}"), identifier_regex)
            
        try:
            match = re.search(f"^{regex_p}$", text.strip())
            if not match: return False
            
            # Unification check if multiple groups matched
            groups = match.groups()
            if len(groups) > 1:
                # If the same metavariable is used multiple times, all captured values must be equal
                # This is a bit complex with regex. For now, if groups exist, we just check if they match.
                # In $X == $X, groups[0] should be equal to groups[1]
                if mvs[0] == mvs[1] and groups[0] != groups[1]:
                    return False
            return True
        except Exception:
            return False

    def _match_nodes(self, p_node: Node, p_source: str, t_node: Node, t_source: str) -> bool:
        p_text = self._get_node_text(p_node, p_source)
        mv_match = re.fullmatch(self.METAVARIABLE_PATTERN, p_text)
        if mv_match:
            var_name = mv_match.group(1)
            t_text = self._get_node_text(t_node, t_source)
            if var_name in self.metavariables: return self.metavariables[var_name] == t_text
            else:
                self.metavariables[var_name] = t_text
                return True

        if p_text == "...": return True
        if p_node.type != t_node.type:
            if p_node.type in ["variable", "variable_name", "identifier"] and t_node.type in ["variable", "variable_name", "identifier"]: pass
            else: return False

        if p_node.child_count == 0: return p_text == self._get_node_text(t_node, t_source)

        p_children = [c for c in p_node.children if c.is_named]
        t_children = [c for c in t_node.children if c.is_named]
        if not any(self._get_node_text(c, p_source) == "..." for c in p_children):
            if len(p_children) != len(t_children): return False

        p_idx, t_idx = 0, 0
        while p_idx < len(p_children) and t_idx < len(t_children):
            p_child = p_children[p_idx]
            if self._get_node_text(p_child, p_source) == "...":
                if p_idx == len(p_children) - 1: return True
                p_idx += 1
                next_p_child = p_children[p_idx]
                while t_idx < len(t_children):
                    if self._match_nodes(next_p_child, p_source, t_children[t_idx], t_source): break
                    t_idx += 1
                continue
            if not self._match_nodes(p_child, p_source, t_children[t_idx], t_source): return False
            p_idx += 1; t_idx += 1
        return p_idx == len(p_children) and t_idx == len(t_children)
