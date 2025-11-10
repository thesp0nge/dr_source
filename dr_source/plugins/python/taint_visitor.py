import ast
import logging
from typing import List, Set, Dict, Any

logger = logging.getLogger(__name__)


class PythonTaintVisitor(ast.NodeVisitor):
    """
    Walks the Python AST to find taint flows from
    fully-qualified sources to fully-qualified sinks.

    The ast.NodeVisitor base class handles the tree traversal (recursion).
    We just implement the 'visit_...' methods for the nodes we care about.
    """

    def __init__(self, source_list: List[str], sink_list: List[str]):
        self.sources = set(source_list)
        self.sinks = set(sink_list)
        self.tainted_vars: Set[str] = set()
        self.vulnerabilities: List[Dict[str, Any]] = []

    def _get_full_call_name(self, node: ast.Call) -> str:
        # (This helper method is correct, no changes)
        def resolve_attribute(attr_node: ast.Attribute) -> str:
            value = attr_node.value
            if isinstance(value, ast.Name):
                return f"{value.id}.{attr_node.attr}"
            if isinstance(value, ast.Attribute):
                return f"{resolve_attribute(value)}.{attr_node.attr}"
            if isinstance(value, ast.Call):
                base = self._get_full_call_name(value)
                if base.endswith("cursor"):
                    return f"cursor.{attr_node.attr}"
            return f"UNKNOWN.{attr_node.attr}"

        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return resolve_attribute(node.func)
        return "UNKNOWN_CALL"

    def _get_ids_from_node(self, node: ast.AST) -> Set[str]:
        """
        Recursively finds all variable names (ast.Name)
        in a given node.
        """
        ids = set()
        # Use ast.walk to visit every single node in the subtree
        if node is None:
            return ids

        for n in ast.walk(node):
            if isinstance(n, ast.Name):
                ids.add(n.id)
        return ids

    def visit_Assign(self, node: ast.Assign):
        """
        Called when the NodeVisitor visits an Assignment node.
        """
        target_var = ""
        if node.targets and isinstance(node.targets[0], ast.Name):
            target_var = node.targets[0].id
        if not target_var:
            self.generic_visit(node)  # We MUST call this if we don't handle the node
            return

        # 1. Taint Source
        if isinstance(node.value, ast.Call):
            func_name = self._get_full_call_name(node.value)
            if func_name in self.sources:
                logger.debug(f"Tainted variable '{target_var}' from source {func_name}")
                self.tainted_vars.add(target_var)

        # 2. Taint Propagation
        else:
            value_ids = self._get_ids_from_node(node.value)
            for var_id in value_ids:
                if var_id in self.tainted_vars:
                    logger.debug(f"Propagating taint to '{target_var}' from '{var_id}'")
                    self.tainted_vars.add(target_var)
                    break

        # --- FIX: We call generic_visit to ensure children are visited ---
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """
        Called when the NodeVisitor visits a Call node.
        """
        func_name = self._get_full_call_name(node)

        if func_name in self.sinks:
            logger.debug(f"Found potential sink: {func_name} on line {node.lineno}")

            tainted_in_arg = False
            found_var = ""

            for arg in node.args:
                arg_ids = self._get_ids_from_node(arg)
                for var in arg_ids:
                    if var in self.tainted_vars:
                        tainted_in_arg = True
                        found_var = var
                        break
                if tainted_in_arg:
                    break

            if tainted_in_arg:
                self.vulnerabilities.append(
                    {
                        "sink": func_name,
                        "variable": found_var,
                        "line": node.lineno,  # This will now be correct
                    }
                )

        # --- FIX: We call generic_visit to ensure children are visited ---
        self.generic_visit(node)
