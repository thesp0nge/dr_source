import ast
from typing import Optional, Union, List, Tuple
import logging
import re

logger = logging.getLogger(__name__)

class PatternMatcher:
    """
    Parses a pattern and matches it against an AST node.
    """
    METAVARIABLE_PREFIX = "__DRVAR_"
    ELLIPSIS_PLACEHOLDER = "__DRSOURCE_ELLIPSIS__"

    def __init__(self, pattern: str):
        self.pattern = pattern
        self.pattern_ast = self._parse_pattern(pattern)
        self.metavariables = {} # Stores matched metavariable name -> AST node

    def _get_metavariable_name(self, node: ast.AST) -> Optional[str]:
        """Checks if an AST node represents a metavariable and returns its name."""
        if isinstance(node, ast.Name) and node.id.startswith(self.METAVARIABLE_PREFIX):
            return node.id[len(self.METAVARIABLE_PREFIX):]
        return None

    def _is_ellipsis(self, node: ast.AST) -> bool:
        """Checks if an AST node represents an ellipsis."""
        return isinstance(node, ast.Name) and node.id == self.ELLIPSIS_PLACEHOLDER

    def _parse_pattern(self, pattern: str) -> Optional[ast.AST]:
        """
        Parses the pattern string into an AST.
        This handles metavariables like $X and '...'.
        """
        # Replace metavariables like $X with unique placeholders like __DRVAR_X__
        sanitized_pattern = re.sub(r'\$([A-Z_]+)', r'__DRVAR_\1__', pattern)
        sanitized_pattern = sanitized_pattern.replace('...', self.ELLIPSIS_PLACEHOLDER)
        
        try:
            return ast.parse(sanitized_pattern, mode='eval').body # For expressions
        except (SyntaxError, TypeError):
            # Fallback to exec for statements
            try:
                tree = ast.parse(sanitized_pattern, mode='exec')
                return tree.body[0] if tree.body else None # For statements
            except Exception:
                return None

    def _nodes_equal(self, node1: ast.AST, node2: ast.AST) -> bool:
        """Deep structural comparison of two AST nodes."""
        if type(node1) != type(node2):
            return False
        
        for field, value1 in ast.iter_fields(node1):
            value2 = getattr(node2, field, None)
            
            if isinstance(value1, list):
                if not isinstance(value2, list) or len(value1) != len(value2):
                    return False
                if not all(self._nodes_equal(n1, n2) if isinstance(n1, ast.AST) else n1 == n2 
                           for n1, n2 in zip(value1, value2)):
                    return False
            elif isinstance(value1, ast.AST):
                if not self._nodes_equal(value1, value2):
                    return False
            elif value1 != value2:
                return False
        return True

    def match(self, node: ast.AST) -> bool:
        """
        Matches the pattern against a given AST node.
        """
        if not self.pattern_ast:
            return False
        self.metavariables = {} # Reset metavariables for each new match attempt
        return self._match_nodes(self.pattern_ast, node)

    def _match_nodes(self, pattern_node: ast.AST, target_node: ast.AST) -> bool:
        """
        Recursively checks if a pattern AST node matches a target AST node,
        handling metavariables and ellipses.
        """
        if pattern_node is None:
            return target_node is None
        if target_node is None:
            return False

        # Handle metavariables in pattern_node
        var_name = self._get_metavariable_name(pattern_node)
        if var_name:
            if var_name in self.metavariables:
                # Unification: must match the previously stored node for this metavariable
                return self._nodes_equal(self.metavariables[var_name], target_node)
            else:
                # Capture: store this node for future unification
                self.metavariables[var_name] = target_node
                return True

        if type(pattern_node) != type(target_node):
            return False

        # Compare fields
        for field, pattern_field_value in ast.iter_fields(pattern_node):
            target_field_value = getattr(target_node, field, None)
            
            # Handle lists of nodes (e.g., func.args, stmt.body)
            if isinstance(pattern_field_value, list) and isinstance(target_field_value, list):
                if not self._match_node_lists(pattern_field_value, target_field_value):
                    return False
            # Handle single sub-nodes
            elif isinstance(pattern_field_value, ast.AST) and isinstance(target_field_value, ast.AST):
                if not self._match_nodes(pattern_field_value, target_field_value):
                    return False
            # Handle literal values (e.g., names, constants)
            elif pattern_field_value != target_field_value:
                return False
        
        return True

    def _match_node_lists(self, pattern_list: List[ast.AST], target_list: List[ast.AST]) -> bool:
        """
        Matches two lists of AST nodes, handling ellipsis (which can match 0 or more nodes).
        This is a simplified greedy match for now.
        """
        p_idx = 0
        t_idx = 0

        while p_idx < len(pattern_list):
            pattern_item = pattern_list[p_idx]
            
            # Check for ellipsis
            if self._is_ellipsis(pattern_item):
                # Greedy match: ellipsis matches until the rest of the pattern matches
                # Or if ellipsis is last, it matches remaining target_list
                if p_idx == len(pattern_list) - 1: # Ellipsis is at the end of the pattern list
                    return True # Matches all remaining target items
                
                # Try to match the remainder of the pattern with various slices of the target list
                for i in range(t_idx, len(target_list) + 1):
                    if self._match_node_lists(pattern_list[p_idx+1:], target_list[i:]):
                        return True
                return False
            else:
                if t_idx >= len(target_list):
                    return False # No more target items to match against non-ellipsis pattern item
                if not self._match_nodes(pattern_item, target_list[t_idx]):
                    return False
                p_idx += 1
                t_idx += 1

        return t_idx == len(target_list) # All pattern items matched and no extra target items

